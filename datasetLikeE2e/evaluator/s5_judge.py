#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""s5_judge.py — S5 检测判据（纯函数）

术语（与题面、文档一致）：

  流量记录   网关处理的一次 HTTP 请求被镜像到 NDR 后形成的一条记录。
            网关处理完即断开，所以一个 keep-alive 连接上的多个请求也是多条记录。
  traffic_id NDR 按入库顺序给记录分配的编号，形如 t-000123。

  A          本次攻击发出、且在 NDR 中匹配到的 traffic_id 集合。
  R          蓝队本轮所有告警 traffic_ids 的并集（去重）。

判据：召回 = |R∩A|/|A| 必须为 100%，精确率 = |R∩A|/|R| 不低于阈值（默认 90%）。
不存在的 id 计入 R，因此编造 id 会拉低精确率。

取并集而不是逐条告警判分，是为了封死「把每条流量各包一条告警」的绕过路径。
"""
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_MIN_PRECISION = 0.9


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

      * missing：脚本声明了但 NDR 里没找到的请求；
      * ambiguous：某条攻击指纹在窗口内的记录数多于清单里的条数，说明背景流量
        里有同指纹请求，标注会张冠李戴。按题目缺陷处理，不能静默取第一条。
    """
    manifest = list(manifest)
    need: Dict[Tuple[str, str, str], int] = {}
    for m in manifest:
        need[_key(m)] = need.get(_key(m), 0) + 1

    buckets: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
    for r in records:
        ts = float(r.get("ts") or 0.0)
        if ts < t_start or ts > t_end:
            continue
        buckets.setdefault(_key(r), []).append(r)

    ambiguous = {k: len(v) for k, v in buckets.items()
                 if k in need and len(v) > need[k]}

    attack: List[str] = []
    benign: List[str] = []
    missing: List[Dict[str, Any]] = []
    for m in manifest:
        bucket = buckets.get(_key(m))
        if not bucket:
            missing.append(m)
            continue
        rec = bucket.pop(0)
        role = str(m.get("role") or "attack").lower()
        (benign if role == "benign" else attack).append(str(rec["traffic_id"]))
    return attack, benign, missing, ambiguous


def judge(alert_ids: Iterable[str], attack_ids: Iterable[str],
          known_ids: Iterable[str],
          min_precision: float = DEFAULT_MIN_PRECISION) -> Dict[str, Any]:
    """按集合口径判定 S5。alert_ids 是蓝队所有告警 traffic_ids 的原样拼接。"""
    attack = {str(x) for x in attack_ids}
    known = {str(x) for x in known_ids}
    referenced = {str(x) for x in alert_ids}

    hits = referenced & attack
    missed = sorted(attack - referenced)
    extra = sorted(referenced - attack)
    invalid = sorted(referenced - known)

    recall = (len(hits) / len(attack)) if attack else 0.0
    precision = (len(hits) / len(referenced)) if referenced else 0.0
    passed = bool(attack) and recall >= 1.0 and precision >= min_precision

    return {
        "passed": passed,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "attack_size": len(attack),
        "referenced": len(referenced),
        "hits": len(hits),
        "false_positive": len(referenced) - len(hits),
        "missed": missed[:20],
        "extra": extra[:20],
        "invalid_ids": invalid[:20],
    }
