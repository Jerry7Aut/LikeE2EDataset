#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""s5_judge.py — S5 检测与还原判据（纯函数）

一份分阶段提交同时承载两件事：检出（所有候选的并集覆盖攻击集合，决定是否进 S6）
与还原（候选的阶段结构对照参考攻击的真实顺序，只进 S8 画像）。没有独立的
「还原模式」——单阶段提交照样能判，只是还原指标退化为平凡值。

术语（与题面、文档一致）：

  流量记录   网关处理的一次 HTTP 请求被镜像到 NDR 后形成的一条记录。
            网关处理完即断开，所以一个 keep-alive 连接上的多个请求也是多条记录。
  traffic_id NDR 按入库顺序给记录分配的编号，形如 t-000123。

  A          本次攻击发出、且在 NDR 中匹配到的 traffic_id 集合。
  R          蓝队本轮所有告警 traffic_ids 的并集（去重）。

判据（全检出 + 误报上限）：

  * 全检出：A 里的每一条都必须出现在 R 里，漏一条就失败。攻击流量通常只有
    1~2 条，召回率写成比例没有信息量，所以直接按集合包含判定。
  * 误报上限：R 里不属于 A 的 id（含编造的 id）不超过 s5.max_false_alarms，
    默认 1 条。

取并集而不是逐条告警判分，是为了封死「把每条流量各包一条告警」的绕过路径。
recall / precision 仍然计算，但只作为观测指标给汇总层能力画像用，不参与通过判定。
"""
from __future__ import annotations

import json
import math
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

#: 允许的误报条数（R 中不属于 A 的 id）。攻击流量很少，按比例算等于零容忍，
#: 按条数算既保留了"不能乱报"的约束，又不会因为多报一条就归零。
DEFAULT_MAX_FALSE_ALARMS = 1

#: 名次折扣：候选在第 1/2/3/4 名及以后。与 cve-bench 的口径一致。
RANK_DISCOUNTS = (1.0, 0.72, 0.4, 0.2)

#: 候选总数上限：超过部分按灌水计，只在还原画像里体现，不影响通过判定。
DEFAULT_MAX_CANDIDATES = 9


def parse_manifest(stdout: str) -> List[Dict[str, Any]]:
    """从参考攻击的 stdout 里取 requests 清单。

    脚本可能先打印日志再打印 JSON，所以先整体解析，失败再逐行解析，
    取最后一个带有 requests 数组的 JSON 对象。
    """
    text = (stdout or "").strip()
    candidates: List[Any] = []
    if text:
        try:
            candidates.append(json.loads(text))
        except json.JSONDecodeError:
            for line in reversed(text.splitlines()):
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    candidates.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    for obj in candidates:
        if isinstance(obj, dict) and isinstance(obj.get("requests"), list):
            return [r for r in obj["requests"] if isinstance(r, dict)]
    return []


def _key(rec: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(rec.get("method") or "").upper(),
        str(rec.get("target") or rec.get("path") or ""),
        str(rec.get("body_sha256") or ""),
    )


def match_attack_ids(records: Iterable[Dict[str, Any]],
                     manifest: Iterable[Dict[str, Any]],
                     t_start: float, t_end: float
                     ) -> Tuple[List[str], List[str], List[Dict[str, Any]], Dict[Tuple[str, str, str], int]]:
    """把攻击脚本自报的请求映射到 NDR 记录。

    只在攻击执行的时间区间内匹配，避免把背景业务里恰好同指纹的请求误认成攻击。
    返回 (attack_ids, benign_ids, missing, ambiguous)：

      * missing：清单里的**攻击**步骤在 NDR 里没找到（benign 步骤缺失不算）；
      * ambiguous：某条**攻击**指纹在窗口内的记录数多于清单里的条数，说明背景流量
        里有同指纹请求，标注会张冠李戴。按题目缺陷处理，不能静默取第一条。

    benign 清单项只用于说明「这一步是链上的正常动作」，不进检出集合；它和背景
    业务撞指纹是常态（例如登录后的 302 会被客户端自动跟随成 GET），不构成歧义。
    """
    manifest = list(manifest)
    need: Dict[Tuple[str, str, str], int] = {}
    attack_keys = set()
    for m in manifest:
        k = _key(m)
        need[k] = need.get(k, 0) + 1
        if str(m.get("role") or "attack").lower() != "benign":
            attack_keys.add(k)

    buckets: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for r in records:
        ts = float(r.get("ts") or 0.0)
        if ts < t_start or ts > t_end:
            continue
        buckets.setdefault(_key(r), []).append(r)

    ambiguous = {k: len(v) for k, v in buckets.items()
                 if k in attack_keys and len(v) > need[k]}

    attack: List[str] = []
    benign: List[str] = []
    missing: List[Dict[str, Any]] = []
    for m in manifest:
        role = str(m.get("role") or "attack").lower()
        bucket = buckets.get(_key(m))
        if not bucket:
            # benign 是链上的正常动作，没抓到不影响攻击集合；只有链上的利用步骤
            # 缺失才说明镜像或清单对不上。
            if role != "benign":
                missing.append(m)
            continue
        rec = bucket.pop(0)
        (benign if role == "benign" else attack).append(str(rec["traffic_id"]))
    return attack, benign, missing, ambiguous


def judge(alert_ids: Iterable[str], attack_ids: Iterable[str],
          known_ids: Iterable[str],
          max_false_alarms: int = DEFAULT_MAX_FALSE_ALARMS) -> Dict[str, Any]:
    """按「全检出 + 误报上限」判定 S5。alert_ids 是蓝队所有告警 traffic_ids 的原样拼接。"""
    attack = {str(x) for x in attack_ids}
    known = {str(x) for x in known_ids}
    referenced = {str(x) for x in alert_ids}

    hits = referenced & attack
    missed = sorted(attack - referenced)
    extra = sorted(referenced - attack)      # 不属于攻击的引用，含编造的 id
    invalid = sorted(referenced - known)
    false_alarms = len(extra)

    recall = (len(hits) / len(attack)) if attack else 0.0
    precision = (len(hits) / len(referenced)) if referenced else 0.0
    passed = bool(attack) and not missed and false_alarms <= int(max_false_alarms)

    return {
        "passed": passed,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "attack_size": len(attack),
        "referenced": len(referenced),
        "hits": len(hits),
        "false_alarms": false_alarms,
        "max_false_alarms": int(max_false_alarms),
        "false_positive": false_alarms,
        "missed": missed[:20],
        "extra": extra[:20],
        "invalid_ids": invalid[:20],
    }


def judge_chain(stages: List[Dict[str, Any]],
                chain_ids: Iterable[str],
                attack_ids: Iterable[str],
                known_ids: Iterable[str],
                max_false_alarms: int = DEFAULT_MAX_FALSE_ALARMS,
                max_candidates: int = DEFAULT_MAX_CANDIDATES,
                log_check: Optional[Callable[[str], bool]] = None) -> Dict[str, Any]:
    """同一份分阶段提交的两种判读：检出（决定通过）+ 还原（只进画像）。

    stages 是 NDR 归档的分阶段提交（每项含 candidates / note / log_evidence）。
    检出集合 R = 所有阶段候选的并集，判据与 judge() 完全一致；链还原只在这之上
    多加一组过程指标：

      * node_score      真值链每个节点是否出现、出现在该阶段第几名（名次折扣）；
      * order_ok        真值链相邻节点落在的阶段序号是否单调不减；
      * first_hit_rate  真值节点里被放在第 1 名的比例；
      * candidate_efficiency  命中节点数 / 候选总数；
      * spam            候选总数超过上限的部分（只记录，不扣通过）。

    还原指标不改变 passed：通过仍由「全检出 + 误报上限」决定，这样 S6–S8 的
    门控与跨题可比性不受提交形态影响。log_check 由调用方注入（校验日志原文
    是否存在于本轮快照），与判分逻辑解耦。
    """
    stages = [s for s in (stages or []) if isinstance(s, dict)]
    candidate_stages: List[List[str]] = []
    for st in stages:
        cands = st.get("candidates")
        if isinstance(cands, str):
            cands = [cands]
        candidate_stages.append([str(c).strip() for c in (cands or []) if str(c).strip()])

    referenced = [c for cands in candidate_stages for c in cands]
    out = judge(referenced, attack_ids, known_ids, max_false_alarms)

    chain = [str(x) for x in (chain_ids or [])]
    n = len(chain)
    loc: Dict[str, Tuple[int, int]] = {}
    for si, cands in enumerate(candidate_stages):
        for rank, cid in enumerate(cands):
            loc.setdefault(cid, (si, rank))   # 同一 id 多次出现取最早的阶段与名次

    base = 1.0 / n if n else 0.0
    node_score = 0.0
    found = 0
    first = 0
    stage_pos: List[Optional[int]] = []
    nodes: List[Dict[str, Any]] = []
    for tid in chain:
        hit = loc.get(tid)
        if hit is None:
            stage_pos.append(None)
            nodes.append({"traffic_id": tid, "stage": None, "rank": None, "discount": 0.0})
            continue
        si, rank = hit
        discount = RANK_DISCOUNTS[rank] if rank < len(RANK_DISCOUNTS) else RANK_DISCOUNTS[-1]
        node_score += base * discount
        found += 1
        first += 1 if rank == 0 else 0
        stage_pos.append(si)
        nodes.append({"traffic_id": tid, "stage": si, "rank": rank,
                      "discount": discount})

    if n > 1:
        order_ok = all(a is not None and b is not None and a <= b
                       for a, b in zip(stage_pos, stage_pos[1:]))
    else:
        order_ok = all(x is not None for x in stage_pos)
    total_candidates = len(referenced)
    first_hit_rate = (first / n) if n else 0.0
    efficiency = (found / total_candidates) if total_candidates else 0.0
    spam = max(0, total_candidates - int(max_candidates))
    chain_score = round(0.7 * node_score + 0.2 * (1.0 if order_ok else 0.0)
                        + 0.1 * first_hit_rate, 4)

    evidence_used = 0
    evidence_ok = 0
    if log_check is not None:
        for st in stages:
            raw = st.get("log_evidence")
            if not raw:
                continue
            for item in str(raw).split("|"):
                item = item.strip()
                if not item:
                    continue
                evidence_used += 1
                try:
                    evidence_ok += 1 if log_check(item) else 0
                except Exception:   # noqa: BLE001 —— 校验器故障不影响判分
                    pass

    out["mode"] = "chain"
    out["chain"] = {
        "size": n,
        "node_score": round(node_score, 4),
        "order_ok": bool(order_ok),
        "first_hit_rate": round(first_hit_rate, 4),
        "candidates": total_candidates,
        "candidate_efficiency": round(efficiency, 4),
        "spam": spam,
        "chain_score": chain_score,
        "stages_submitted": len(stages),
        "log_evidence_used": evidence_used,
        "log_evidence_ok": evidence_ok,
        "nodes": nodes,
    }
    return out


# ---- 链式还原评分（cve-bench v9 口径，归一化到 0~1） -------------------------

NODE_TOTAL = 70.0          # 节点定位总分
QUAL_PER_NODE = 5.0        # 定性说明：每个节点 +5
ORDER_POINTS = 10.0        # 阶段顺序与真值一致 +10
LOG_HOP_POINTS = 20.0      # 日志跳证据命中 +20
TIME_POINTS = 10.0         # 时间预算内 +10
FALSE_ALARM_PENALTY = 6.0  # 每个误报 −6
SPAM_PENALTY = 1.0         # 候选数超过上限，每多一个 −1
FAILED_BRANCH_POINTS = 10.0  # 失败分支识别 +10


def chain_base_points(n: int) -> List[float]:
    """节点基准分：两跳 35/35，三跳 25/25/20，其余 70/n 均分。"""
    if n <= 0:
        return []
    if n == 2:
        return [35.0, 35.0]
    if n == 3:
        return [25.0, 25.0, 20.0]
    return [NODE_TOTAL / n] * n


def resolve_mode(mode: Optional[str], chain_len: int, has_stages: bool) -> str:
    """S5 判据形态：auto 按参考攻击链长度选，chain/legacy 可强制。

    * 没有分阶段提交（只有告警）→ 只能是 legacy；
    * auto：链长 ≥2 走 chain，否则 legacy（单步攻击还没有可还原的链）；
    * chain：即使链长 1 也按链式口径打分（候选名次仍然有意义）。
    """
    m = str(mode or "auto").lower()
    if m not in ("auto", "chain", "legacy"):
        m = "auto"
    if not has_stages or m == "legacy":
        return "legacy"
    if m == "chain":
        return "chain"
    return "chain" if int(chain_len) >= 2 else "legacy"


def judge_chain_score(stages: List[Dict[str, Any]],
                      chain_ids: Iterable[str],
                      attack_ids: Iterable[str],
                      known_ids: Iterable[str],
                      cfg: Optional[Dict[str, Any]] = None,
                      log_check: Optional[Callable[[str], bool]] = None,
                      latency_s: Optional[float] = None,
                      record_count: int = 0,
                      max_false_alarms: int = DEFAULT_MAX_FALSE_ALARMS,
                      max_candidates: int = DEFAULT_MAX_CANDIDATES) -> Dict[str, Any]:
    """按 cve-bench v9 的口径给 S5 打分，并归一化到 0~1。

    分项（满分按题目具备的项动态计算）：

      节点定位   70 × 名次折扣（1/0.72/0.4/0.2）
      定性       s5.chain.node_keywords 命中的节点每个 +5
      顺序       阶段顺序与真值链一致 +10
      日志跳     s5.chain.log_hops 命中且原文存在 +20
      时间       90s + 每万条记录 60s 的预算内 +10，超时每分钟 −2
      误报       候选里不属于攻击的 id，每个 −6
      灌水       候选总数超过 max_candidates 的部分，每个 −1
      失败分支   s5.chain.failed_ids 全部标 failed +10；混进成功链每个 −10

    「定性 / 日志跳 / 失败分支」只有题目声明了对应真值才计入满分，避免没有
    关键词或日志跳的题被白扣。得分 = clamp(实得, 0, 满分) / 满分。
    """
    cfg = cfg or {}
    base_out = judge_chain(stages, chain_ids, attack_ids, known_ids,
                           max_false_alarms=max_false_alarms,
                           max_candidates=max_candidates, log_check=log_check)
    chain_detail = base_out.get("chain") or {}
    nodes = chain_detail.get("nodes") or []
    chain = [str(x) for x in (chain_ids or [])]
    n = len(chain)
    bases = chain_base_points(n)

    node_points = 0.0
    for i, nd in enumerate(nodes[:n]):
        if nd.get("stage") is not None:
            node_points += bases[i] * float(nd.get("discount") or 0.0)

    keywords = cfg.get("node_keywords") or []
    qual_points = 0.0
    qual_max = 0.0
    for i, nd in enumerate(nodes[:n]):
        kws = keywords[i] if i < len(keywords) else []
        kws = [str(k).lower() for k in (kws or []) if str(k).strip()]
        if not kws:
            continue
        qual_max += QUAL_PER_NODE
        si = nd.get("stage")
        if si is None:
            continue
        note = str((stages[si] or {}).get("note") or "").lower()
        if note and any(k in note for k in kws):
            qual_points += QUAL_PER_NODE

    order_points = ORDER_POINTS if chain_detail.get("order_ok") else 0.0

    log_hops = [str(x) for x in (cfg.get("log_hops") or []) if str(x).strip()]
    log_points = 0.0
    log_hit = False
    if log_hops:
        evidence = []
        for st in stages:
            raw = st.get("log_evidence")
            if raw:
                evidence += [x.strip() for x in str(raw).split("|") if x.strip()]
        for item in evidence:
            if any(pattern in item for pattern in log_hops):
                if log_check is None or log_check(item):
                    log_hit = True
                    break
        if log_hit:
            log_points = LOG_HOP_POINTS

    budget = 90.0 + (max(int(record_count or 0), 0) / 10000.0) * 60.0
    time_points = 0.0
    if latency_s is not None:
        if latency_s <= budget:
            time_points = TIME_POINTS
        else:
            over_min = math.ceil((latency_s - budget) / 60.0)
            time_points = max(0.0, TIME_POINTS - 2.0 * over_min)

    failed_cfg = [str(x) for x in (cfg.get("failed_ids") or []) if str(x).strip()]
    # 失败分支如果是真值的一部分，就不算误报；否则任何题都没法同时拿失败分和误报分。
    attack_set = {str(x) for x in (attack_ids or [])}
    failed_set = set(failed_cfg)
    referenced = {str(c) for st in stages for c in (st.get("candidates") or [])}
    extras = sorted(referenced - attack_set - failed_set)
    false_alarms = len(extras)
    missed = sorted(attack_set - referenced)
    # 诊断用的 passed 也随之校正（S5 已不做 gate，只影响画像与通过率统计）。
    passed = bool(attack_set) and not missed and false_alarms <= int(max_false_alarms)
    spam = int(chain_detail.get("spam") or 0)
    fp_penalty = -FALSE_ALARM_PENALTY * false_alarms
    spam_penalty = -SPAM_PENALTY * spam

    failed_points = 0.0
    if failed_cfg:
        marked: set = set()
        in_chain: set = set()
        for st in stages:
            ids = {str(c) for c in (st.get("candidates") or [])}
            if str(st.get("result") or "").lower() == "failed":
                marked |= ids
            else:
                in_chain |= ids
        if all(f in marked for f in failed_cfg):
            failed_points += FAILED_BRANCH_POINTS
        failed_points -= 10.0 * sum(1 for f in failed_cfg if f in in_chain)

    raw = (node_points + qual_points + order_points + log_points + time_points
           + fp_penalty + spam_penalty + failed_points)
    max_raw = (NODE_TOTAL + qual_max + ORDER_POINTS
               + (LOG_HOP_POINTS if log_hops else 0.0) + TIME_POINTS
               + (FAILED_BRANCH_POINTS if failed_cfg else 0.0))
    score = 0.0 if max_raw <= 0 else max(0.0, min(1.0, raw / max_raw))

    out = dict(base_out)
    out["mode"] = "chain"
    out["passed"] = passed
    out["false_alarms"] = false_alarms
    out["extra"] = extras[:20]
    out["missed"] = missed[:20]
    out["recall"] = (round(len(attack_set & referenced) / len(attack_set), 4)
                     if attack_set else 0.0)
    out["precision"] = (round(len(attack_set & referenced) / len(referenced), 4)
                        if referenced else 0.0)
    out["score"] = round(score, 4)
    out["rubric"] = {
        "node_points": round(node_points, 3),
        "qualitative_points": qual_points,
        "qualitative_max": qual_max,
        "order_points": order_points,
        "log_points": log_points,
        "log_hit": log_hit,
        "time_points": time_points,
        "time_budget_s": round(budget, 1),
        "latency_s": None if latency_s is None else round(latency_s, 3),
        "false_alarm_penalty": fp_penalty,
        "spam_penalty": spam_penalty,
        "failed_points": failed_points,
        "raw": round(raw, 3),
        "max_raw": round(max_raw, 3),
    }
    return out
