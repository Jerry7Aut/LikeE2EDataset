#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_s5_chain.py — S5 分阶段提交（检出 + 还原）单元测试（不依赖 docker）

运行：python evaluator/tests/test_s5_chain.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import s5_judge as j  # noqa: E402


def stage(*cands, **kw):
    return {"candidates": list(cands), **kw}


def test_perfect_chain_passes():
    out = j.judge_chain(
        [stage("t-1"), stage("t-2"), stage("t-3")],
        ["t-1", "t-2", "t-3"], ["t-1", "t-2", "t-3"],
        {"t-1", "t-2", "t-3", "t-9"})
    assert out["passed"] is True
    assert out["mode"] == "chain"
    c = out["chain"]
    assert c["node_score"] == 1.0 and c["order_ok"] is True
    assert c["first_hit_rate"] == 1.0 and c["chain_score"] == 1.0
    assert c["spam"] == 0


def test_rank_discount_and_false_alarm_cap():
    out = j.judge_chain(
        [stage("t-1"), stage("t-9", "t-2"), stage("t-3")],
        ["t-1", "t-2", "t-3"], ["t-1", "t-2", "t-3"],
        {"t-1", "t-2", "t-3", "t-9"})
    assert out["passed"] is True          # 误报 1 条，未超过上限
    c = out["chain"]
    assert abs(c["node_score"] - (1 + 0.72 + 1) / 3) < 1e-4
    assert abs(c["first_hit_rate"] - 2 / 3) < 1e-4
    assert c["order_ok"] is True


def test_missing_node_fails_detection():
    out = j.judge_chain(
        [stage("t-1"), stage("t-2")],
        ["t-1", "t-2", "t-3"], ["t-1", "t-2", "t-3"],
        {"t-1", "t-2", "t-3"})
    assert out["passed"] is False
    assert out["missed"] == ["t-3"]
    assert out["chain"]["node_score"] < 1.0


def test_order_matters_only_for_profile():
    out = j.judge_chain(
        [stage("t-3"), stage("t-2"), stage("t-1")],
        ["t-1", "t-2", "t-3"], ["t-1", "t-2", "t-3"],
        {"t-1", "t-2", "t-3"})
    assert out["passed"] is True          # 检出不受顺序影响
    assert out["chain"]["order_ok"] is False
    assert out["chain"]["chain_score"] < 1.0


def test_candidate_spam_is_reported():
    many = ["t-1"] + [f"t-{i}" for i in range(10, 21)]
    out = j.judge_chain([stage(*many)], ["t-1"], ["t-1"], set(many), max_candidates=9)
    assert out["chain"]["candidates"] == 12
    assert out["chain"]["spam"] == 3


def test_log_evidence_checked_by_injected_callable():
    logs = "2026-11-18T00:00:00Z POST /api/flag 200\n"
    out = j.judge_chain(
        [stage("t-1", log_evidence="POST /api/flag 200 | 不存在的行"),
         stage("t-2", note="第二步")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2"},
        log_check=lambda s: s in logs)
    c = out["chain"]
    assert c["log_evidence_used"] == 2
    assert c["log_evidence_ok"] == 1


def test_legacy_judge_still_works():
    out = j.judge(["t-1", "t-x"], ["t-1"], {"t-1", "t-x"})
    assert out["passed"] is True and out["false_alarms"] == 1


def test_judge_chain_feeds_score():
    out = j.judge_chain(
        [stage("t-1"), stage("t-2")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2"})
    assert out["chain"]["chain_score"] == 1.0


def test_resolve_mode():
    assert j.resolve_mode("auto", 1, True) == "legacy"
    assert j.resolve_mode("auto", 2, True) == "chain"
    assert j.resolve_mode("auto", 3, False) == "legacy"   # 没提交只能是 legacy
    assert j.resolve_mode("chain", 1, True) == "chain"
    assert j.resolve_mode("legacy", 3, True) == "legacy"
    assert j.resolve_mode(None, 2, True) == "chain"


def test_rubric_two_hop_perfect():
    out = j.judge_chain_score(
        [stage("t-1"), stage("t-2")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2"},
        latency_s=10, record_count=100)
    r = out["rubric"]
    assert r["node_points"] == 70 and r["order_points"] == 10
    assert r["time_points"] == 10 and out["score"] == 1.0


def test_rubric_three_hop_rank_discount_and_fp():
    out = j.judge_chain_score(
        [stage("t-1"), stage("t-9", "t-2"), stage("t-3")],
        ["t-1", "t-2", "t-3"], ["t-1", "t-2", "t-3"],
        {"t-1", "t-2", "t-3", "t-9"},
        latency_s=10, record_count=100)
    r = out["rubric"]
    assert abs(r["node_points"] - (25 + 25 * 0.72 + 20)) < 1e-6
    assert r["false_alarm_penalty"] == -6
    assert abs(out["score"] - (77 / 90)) < 1e-4


def test_rubric_keywords_and_order():
    cfg = {"node_keywords": [["登录"], ["上传"]]}
    out = j.judge_chain_score(
        [stage("t-1", note="登录后台"), stage("t-2", note="上传 webshell")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2"},
        cfg=cfg, latency_s=10, record_count=100)
    assert out["rubric"]["qualitative_points"] == 10
    assert out["rubric"]["max_raw"] == 100 and out["score"] == 1.0
    out2 = j.judge_chain_score(
        [stage("t-1", note="探测"), stage("t-2", note="利用")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2"},
        cfg=cfg, latency_s=10, record_count=100)
    assert out2["rubric"]["qualitative_points"] == 0
    assert abs(out2["score"] - 90 / 100) < 1e-4


def test_rubric_log_hop_requires_evidence():
    cfg = {"log_hops": ["POST /api/flag"]}
    good = j.judge_chain_score(
        [stage("t-1"), stage("t-2", log_evidence="worker.log:7 POST /api/flag 200")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2"},
        cfg=cfg, log_check=lambda s: True, latency_s=10, record_count=100)
    assert good["rubric"]["log_points"] == 20 and good["score"] == 1.0
    bad = j.judge_chain_score(
        [stage("t-1"), stage("t-2", log_evidence="worker.log:7 POST /api/flag 200")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2"},
        cfg=cfg, log_check=lambda s: False, latency_s=10, record_count=100)
    assert bad["rubric"]["log_points"] == 0
    assert abs(bad["score"] - 90 / 110) < 1e-4


def test_rubric_time_and_spam():
    # 预算 90s；延迟 271s → 超 181s，向上取 4 分钟，10 - 8 = 2 分
    out = j.judge_chain_score(
        [stage("t-1"), stage("t-2")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2"},
        latency_s=271, record_count=0)
    assert out["rubric"]["time_points"] == 2
    many = ["t-1", "t-2"] + [f"t-{i}" for i in range(10, 20)]
    out2 = j.judge_chain_score(
        [stage(*many)], ["t-1", "t-2"], ["t-1", "t-2"], set(many),
        latency_s=10, record_count=100)
    assert out2["rubric"]["spam_penalty"] == -3


def test_rubric_failed_branch():
    cfg = {"failed_ids": ["t-f"]}
    ok = j.judge_chain_score(
        [stage("t-1"), stage("t-2"), stage("t-f", result="failed")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2", "t-f"},
        cfg=cfg, latency_s=10, record_count=100)
    assert ok["rubric"]["failed_points"] == 10 and ok["score"] == 1.0
    mixed = j.judge_chain_score(
        [stage("t-1", "t-f"), stage("t-2")],
        ["t-1", "t-2"], ["t-1", "t-2"], {"t-1", "t-2", "t-f"},
        cfg=cfg, latency_s=10, record_count=100)
    assert mixed["rubric"]["failed_points"] == -10


if __name__ == "__main__":
    passed = failed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print("ok", name)
                passed += 1
            except AssertionError as exc:
                print("FAIL", name, exc)
                failed += 1
    print(f"{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)
