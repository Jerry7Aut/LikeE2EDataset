#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_s5_judge.py — S5 判据单元测试（不依赖 docker）

运行：python evaluator/tests/test_s5_judge.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import s5_judge as j  # noqa: E402

ATTACK = ["t-000010"]
NORMAL = ["t-%06d" % i for i in range(1, 103) if i != 10]
KNOWN = ATTACK + NORMAL


def test_exact_hit_passes():
    out = j.judge(ATTACK, ATTACK, KNOWN)
    assert out["passed"] and out["recall"] == 1.0 and out["precision"] == 1.0


def test_report_everything_fails():
    # 把全部 102 条都告警：召回 100%，但精确率 1/102，必须判 0。
    out = j.judge(ATTACK + NORMAL, ATTACK, KNOWN)
    assert not out["passed"]
    assert out["recall"] == 1.0 and out["precision"] < 0.9


def test_split_alerts_do_not_bypass():
    # 拆成多条告警、每条引用一条流量：并集仍是全量，和「全量告警」等价。
    split = [[x] for x in ATTACK + NORMAL]
    flat = [x for one in split for x in one]
    out = j.judge(flat, ATTACK, KNOWN)
    assert not out["passed"]


def test_missing_attack_fails():
    attack = ["t-000010", "t-000011"]
    known = attack + NORMAL
    out = j.judge(["t-000010"], attack, known)
    assert not out["passed"] and out["recall"] == 0.5
    assert out["missed"] == ["t-000011"]


def test_fabricated_id_lowers_precision():
    out = j.judge(ATTACK + ["t-999999"], ATTACK, KNOWN)
    assert not out["passed"]
    assert out["precision"] == 0.5 and out["invalid_ids"] == ["t-999999"]


def test_empty_alerts_fail():
    out = j.judge([], ATTACK, KNOWN)
    assert not out["passed"] and out["recall"] == 0.0


def test_precision_boundary():
    # 9 条攻击 + 1 条正常：精确率正好 0.9，达到阈值。
    attack = ["a-%02d" % i for i in range(9)]
    normal = ["n-%03d" % i for i in range(20)]
    out = j.judge(attack + normal[:1], attack, attack + normal)
    assert out["precision"] == 0.9 and out["passed"]
    # 再多一条正常，精确率 9/11 ≈ 0.818，不达标。
    out2 = j.judge(attack + normal[:2], attack, attack + normal)
    assert not out2["passed"]


def test_manifest_parse_from_log_tail():
    stdout = "starting\n" + json.dumps({"requests": [
        {"method": "GET", "target": "/x", "body_sha256": "aa", "role": "attack"}]})
    reqs = j.parse_manifest(stdout)
    assert len(reqs) == 1 and reqs[0]["target"] == "/x"


def test_match_attack_ids():
    records = [
        {"traffic_id": "t-000001", "ts": 100.0, "method": "GET", "target": "/login",
         "body_sha256": "e3b0c442"},
        {"traffic_id": "t-000002", "ts": 105.0, "method": "POST", "target": "/upload",
         "body_sha256": "abc"},
        {"traffic_id": "t-000003", "ts": 110.0, "method": "GET", "target": "/login",
         "body_sha256": "e3b0c442"},
    ]
    manifest = [{"method": "POST", "target": "/upload", "body_sha256": "abc",
                 "role": "attack"}]
    attack, benign, missing, ambiguous = j.match_attack_ids(records, manifest, 104.0, 106.0)
    assert attack == ["t-000002"] and not benign and not missing and not ambiguous


def test_match_is_time_bounded():
    records = [{"traffic_id": "t-000001", "ts": 10.0, "method": "POST",
                "target": "/upload", "body_sha256": "abc"}]
    manifest = [{"method": "POST", "target": "/upload", "body_sha256": "abc"}]
    attack, _, missing, _ = j.match_attack_ids(records, manifest, 100.0, 200.0)
    assert not attack and missing


def test_fingerprint_collision_detected():
    # 背景流量里出现与攻击相同指纹的请求：窗口内记录数多于清单条数，必须报歧义，
    # 不能静默把背景记录标成攻击。
    records = [
        {"traffic_id": "t-000001", "ts": 100.0, "method": "GET", "target": "/x",
         "body_sha256": "aa"},
        {"traffic_id": "t-000002", "ts": 101.0, "method": "GET", "target": "/x",
         "body_sha256": "aa"},
    ]
    manifest = [{"method": "GET", "target": "/x", "body_sha256": "aa", "role": "attack"}]
    attack, _, missing, ambiguous = j.match_attack_ids(records, manifest, 99.0, 102.0)
    assert len(attack) == 1 and not missing
    assert ambiguous == {("GET", "/x", "aa"): 2}


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("ok", t.__name__)
    print(f"{len(tests)} passed")


if __name__ == "__main__":
    main()
