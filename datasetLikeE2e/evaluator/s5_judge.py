#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""s5_judge.py — S5 检测判据（纯函数）

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
recall / precision 仍然计算，但只作为观测指标给 S8 能力画像用，不参与通过判定。
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: 允许的误报条数（R 中不属于 A 的 id）。攻击流量很少，按比例算等于零容忍，
#: 按条数算既保留了"不能乱报"的约束，又不会因为多报一条就归零。
DEFAULT_MAX_FALSE_ALARMS = 1


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
