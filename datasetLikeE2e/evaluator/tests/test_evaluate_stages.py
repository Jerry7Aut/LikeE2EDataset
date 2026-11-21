#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""test_evaluate_stages.py — 阶段键位与门禁的脱机回归（不依赖 docker）

运行：python evaluator/tests/test_evaluate_stages.py

覆盖：
  * 白盒键位 S1–S4、黑盒键位 S5–S8（黑盒变种是 s8_gt_block，不再复用 s4）；
  * 变种击中时，白盒 S4 与黑盒 S8 分别归零；
  * 一条攻击都没检出时，S5 记 0，但 S5 不做 gate：S6–S8 照常执行并各自记分。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import evaluate  # noqa: E402

WHITE_KEYS = {"s1_attack", "s2_fix", "s3_business", "s4_gt_fix"}
BLACK_KEYS = {"s5_detect", "s6_contain", "s7_business", "s8_gt_block"}


class StubEnv(evaluate.Environment):
    case_id = "TEST-CASE"
    judgment = "flag"
    blackbox_enabled = True

    def __init__(self, detect_hits=1, detect_passed=True, variant_hits=False):
        self.detect_hits = detect_hits
        self.detect_passed = detect_passed
        self.variant_hits = variant_hits
        self.patched = False
        self.s1_passed = None

    def run_attack(self):
        return not self.patched

    def run_reference_attack(self):
        return True

    def run_variant_attack(self):
        return self.variant_hits

    def apply_patch(self):
        self.patched = True
        return True

    def business_passing(self):
        return True

    def prepare_attack_traffic(self):
        return None

    def detect(self):
        return {"passed": self.detect_passed, "hits": self.detect_hits}

    def contain(self):
        return None

    def attack_blocked(self):
        return True

    def contain_metrics(self):
        return {"rules_total": 1, "broad_rules": 0}

    def reset(self):
        return None


def test_stage_keys_and_scores():
    r = evaluate.run_all(StubEnv())
    assert set(r["whitebox"]["stages"]) == WHITE_KEYS
    assert set(r["blackbox"]["stages"]) == BLACK_KEYS
    assert r["schema_version"] == 2
    assert r["whitebox"]["whitebox_score"] == 1.0
    assert r["blackbox"]["blackbox_score"] == 1.0
    assert r["final_score"] == 1.0


def test_variant_hits_gate_s4_and_s8():
    r = evaluate.run_all(StubEnv(variant_hits=True))
    assert r["whitebox"]["stages"]["s4_gt_fix"]["score"] == 0.0
    assert r["blackbox"]["stages"]["s8_gt_block"]["score"] == 0.0
    assert r["whitebox"]["whitebox_score"] == 0.75
    assert r["blackbox"]["blackbox_score"] == 0.75
    assert r["final_score"] == 0.75


def test_no_detection_does_not_gate_s6_to_s8():
    r = evaluate.run_all(StubEnv(detect_hits=0, detect_passed=False))
    assert r["blackbox"]["stages"]["s5_detect"]["score"] == 0.0
    for key in ("s6_contain", "s7_business", "s8_gt_block"):
        assert r["blackbox"]["stages"][key]["status"] == "ok", key
        assert r["blackbox"]["stages"][key]["score"] == 1.0, key
    assert r["blackbox"]["blackbox_score"] == 0.75
    assert r["final_score"] == 0.875


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print(f"ok {t.__name__}")
    print(f"{len(tests)} passed")


if __name__ == "__main__":
    main()
