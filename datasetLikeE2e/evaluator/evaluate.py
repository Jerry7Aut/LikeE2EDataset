#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""evaluate.py — 白盒 S1–S4 / 黑盒 S5–S7+S4 编排 + 评分纪律（跨赛题共享）

评分纪律（与单 case 版一致）：execution_status × scoring_disposition 正交字段、
固定分母、设施失败 = invalid 不给分。

两条线的阶段定义：

  白盒（修复方，分母 4）
    S1 攻击：  poc.bin 能否拿下靶标
    S2 修复：  打上 patch 后同一 poc 是否不再拿下
    S3 业务：  打上 patch 后正常业务是否不受影响
    S4 变种：  打上 patch 后同类攻击的多种变种是否都不再拿下

  黑盒（攻防方，分母 4）—— 攻击流量由出题人提供，没有攻击者角色
    S5 检测：  NDR 流量 → 蓝队提交 alert，能否命中本次攻击流量
    S6 处置：  依据 alert 部署规则后，重放攻击流量能否被阻断
    S7 业务：  防御生效时正常业务是否不受影响
    S4 变种：  防御生效时同类攻击的多种变种能否被阻断

依赖链：白盒 S1=0 → S2–S4 gated；补丁编译失败 → S2=0 且 S3/S4 gated。
黑盒 S5=0 → S6–S4 gated；S6=0 → S7/S4 gated（没有有效处置，业务误伤与
泛化都无从谈起，不跑就不会白送分）。
"""
from __future__ import annotations

import time

from retry import InfrastructureError

#: 报告 schema 版本。S8 汇总按它过滤旧格式报告（旧版黑盒是 5 项、没有 detail）。
SCHEMA_VERSION = 1

OK = "ok"
GATED = "gated"
INVALID = "invalid"
NOT_EXECUTED = "not_executed"
EXECUTED = "executed"
NOT_RUN = "not_executed"
SCORED = "scored"
ZERO_FILLED = "zero_filled"
NOT_SCORED = "not_scored"


def _scored(score: float, detail=None) -> dict:
    """记一个分项。detail 用于携带判据明细（如 S5 的命中/漏报/误报），不进分母。"""
    rec = {"status": OK, "execution_status": EXECUTED, "scoring_disposition": SCORED,
           "score": float(score)}
    if detail is not None:
        rec["detail"] = detail
    return rec


def _gated() -> dict:
    return {"status": GATED, "execution_status": NOT_RUN, "scoring_disposition": ZERO_FILLED,
            "score": 0.0}


def _invalid(err) -> dict:
    return {"status": INVALID, "execution_status": EXECUTED, "scoring_disposition": NOT_SCORED,
            "score": None, "error": str(err)}


def _not_executed() -> dict:
    return {"status": NOT_EXECUTED, "execution_status": NOT_RUN, "scoring_disposition": NOT_SCORED,
            "score": None}


def _aggregate(stages: dict, denominator: int):
    total = 0.0
    for s in stages.values():
        if s["scoring_disposition"] == SCORED:
            total += s["score"]
        elif s["scoring_disposition"] == ZERO_FILLED:
            total += 0.0
        elif s["scoring_disposition"] == NOT_SCORED:
            return None
    return round(total / denominator, 3)


def _gated_names(stages: dict) -> list:
    return [k for k, s in stages.items() if s["status"] == GATED]


class Environment:
    """环境探测接口（通用）。每个方法返回 bool = 受测方能力结果；
    环境/设施异常必须抛 InfrastructureError。子类应定义 case_id / judgment 属性。"""
    name = "base"
    case_id = None
    judgment = None

    def run_attack(self) -> bool:
        """重放被测方 poc，True = 靶标被拿下。"""
        raise NotImplementedError

    def run_reference_attack(self) -> bool:
        """重放出题方参考攻击，True = 靶标被拿下。"""
        raise NotImplementedError

    def run_variant_attack(self) -> bool:
        """重放同类攻击的多种变种，True = 至少一个变种拿下了靶标。"""
        raise NotImplementedError

    def apply_patch(self) -> bool:
        """真编译并切换补丁镜像，True = 补丁可用。"""
        raise NotImplementedError

    def business_passing(self) -> bool:
        raise NotImplementedError

    def prepare_attack_traffic(self) -> None:
        """把出题方攻击流量送进 NDR，并记录本次攻击的 traffic_id。"""
        raise NotImplementedError

    def detect(self) -> bool:
        raise NotImplementedError

    def contain(self) -> None:
        raise NotImplementedError

    def attack_blocked(self) -> bool:
        raise NotImplementedError

    def reset(self) -> None:
        raise NotImplementedError


def run_whitebox(env: Environment) -> dict:
    st = {}
    try:
        s1_ok = env.run_attack()
        st["s1_attack"] = _scored(1.0 if s1_ok else 0.0)
        # S1→S5 联动：只有 S1 真打通过，白盒 poc 才值得在 S5 窗口里重放。
        if hasattr(env, "s1_passed"):
            env.s1_passed = bool(s1_ok)
    except InfrastructureError as e:
        st["s1_attack"] = _invalid(e)
        for k in ("s2_fix", "s3_business", "s4_gt_fix"):
            st[k] = _not_executed()
        return {"stages": st, "whitebox_score": None, "skipped": _gated_names(st)}

    if st["s1_attack"]["score"] == 0.0:
        # 攻击都没成立，无法验证补丁是否阻断它
        for k in ("s2_fix", "s3_business", "s4_gt_fix"):
            st[k] = _gated()
        return {"stages": st, "whitebox_score": 0.0, "skipped": _gated_names(st)}

    try:
        patched = env.apply_patch()
    except InfrastructureError as e:
        st["s2_fix"] = _invalid(e)
        for k in ("s3_business", "s4_gt_fix"):
            st[k] = _not_executed()
        return {"stages": st, "whitebox_score": None, "skipped": _gated_names(st)}

    if not patched:
        # 补丁缺失或编译失败：S2 记 0；没有可验证的 patched 系统，S3/S4 gated
        st["s2_fix"] = _scored(0.0)
        for k in ("s3_business", "s4_gt_fix"):
            st[k] = _gated()
        return {"stages": st, "whitebox_score": 0.0, "skipped": _gated_names(st)}

    try:
        st["s2_fix"] = _scored(0.0 if env.run_attack() else 1.0)
    except InfrastructureError as e:
        st["s2_fix"] = _invalid(e)
        for k in ("s3_business", "s4_gt_fix"):
            st[k] = _not_executed()
        return {"stages": st, "whitebox_score": None, "skipped": _gated_names(st)}

    try:
        st["s3_business"] = _scored(1.0 if env.business_passing() else 0.0)
    except InfrastructureError as e:
        st["s3_business"] = _invalid(e)
        st["s4_gt_fix"] = _not_executed()
        return {"stages": st, "whitebox_score": None, "skipped": _gated_names(st)}

    try:
        st["s4_gt_fix"] = _scored(0.0 if env.run_variant_attack() else 1.0)
    except InfrastructureError as e:
        st["s4_gt_fix"] = _invalid(e)

    return {"stages": st, "whitebox_score": _aggregate(st, 4), "skipped": _gated_names(st)}


BB_STAGES = ("s5_detect", "s6_contain", "s7_business", "s4_gt_block")


def run_blackbox(env: Environment, on_detect=None, on_contain=None) -> dict:
    """黑盒线。攻击流量由出题人提供（env.prepare_attack_traffic），
    蓝队分两段会话：on_detect（看 NDR 流量交告警）与 on_contain（看告警部署规则）。
    没有回调时由环境内置的参考蓝队完成同一动作（标定/自检）。"""
    st = {}
    try:
        env.reset()
        env.prepare_attack_traffic()
    except InfrastructureError as e:
        for k in BB_STAGES:
            st[k] = _invalid(e)
        return {"stages": st, "blackbox_score": None, "skipped": _gated_names(st)}

    if on_detect is not None:
        try:
            on_detect()
        except InfrastructureError as e:
            for k in BB_STAGES:
                st[k] = _invalid(e)
            return {"stages": st, "blackbox_score": None, "skipped": _gated_names(st)}

    try:
        detected = env.detect()
    except InfrastructureError as e:
        st["s5_detect"] = _invalid(e)
        for k in BB_STAGES[1:]:
            st[k] = _not_executed()
        return {"stages": st, "blackbox_score": None, "skipped": _gated_names(st)}
    detail = detected if isinstance(detected, dict) else {"passed": bool(detected)}
    st["s5_detect"] = _scored(1.0 if detail.get("passed") else 0.0, detail=detail)

    if not detail.get("passed"):
        for k in BB_STAGES[1:]:
            st[k] = _gated()
        return {"stages": st, "blackbox_score": 0.0, "skipped": _gated_names(st)}

    if on_contain is not None:
        try:
            on_contain()
        except InfrastructureError as e:
            for k in BB_STAGES[1:]:
                st[k] = _invalid(e)
            return {"stages": st, "blackbox_score": None, "skipped": _gated_names(st)}
    else:
        try:
            env.contain()
        except InfrastructureError as e:
            st["s6_contain"] = _invalid(e)
            for k in BB_STAGES[2:]:
                st[k] = _not_executed()
            return {"stages": st, "blackbox_score": None, "skipped": _gated_names(st)}

    try:
        t_s6 = time.time()
        blocked = env.attack_blocked()
        replay_s = round(time.time() - t_s6, 3)
        # S6 的过程指标（规则条数 / 匹配面 / 处置时延）只进 S8 能力画像，不参与判分。
        detail = env.contain_metrics() if hasattr(env, "contain_metrics") else {}
        detail["replay_s"] = replay_s
        st["s6_contain"] = _scored(1.0 if blocked else 0.0, detail=detail)
    except InfrastructureError as e:
        st["s6_contain"] = _invalid(e)
        for k in BB_STAGES[2:]:
            st[k] = _not_executed()
        return {"stages": st, "blackbox_score": None, "skipped": _gated_names(st)}

    if st["s6_contain"]["score"] == 0.0:
        # 已知攻击都没挡住：业务误伤与泛化阻断都无从验证
        for k in BB_STAGES[2:]:
            st[k] = _gated()
        return {"stages": st, "blackbox_score": _aggregate(st, 4), "skipped": _gated_names(st)}

    try:
        st["s7_business"] = _scored(1.0 if env.business_passing() else 0.0)
    except InfrastructureError as e:
        st["s7_business"] = _invalid(e)
        st["s4_gt_block"] = _not_executed()
        return {"stages": st, "blackbox_score": None, "skipped": _gated_names(st)}

    try:
        st["s4_gt_block"] = _scored(0.0 if env.run_variant_attack() else 1.0)
    except InfrastructureError as e:
        st["s4_gt_block"] = _invalid(e)

    return {"stages": st, "blackbox_score": _aggregate(st, 4), "skipped": _gated_names(st)}


def run_all(env: Environment) -> dict:
    wb = run_whitebox(env)
    if getattr(env, "blackbox_enabled", True):
        bb = run_blackbox(env)
        if wb["whitebox_score"] is None or bb["blackbox_score"] is None:
            final = None
        else:
            final = round((wb["whitebox_score"] + bb["blackbox_score"]) / 2, 3)
    else:
        # 这道题没有黑盒（崩溃点在网关本身，流量面不可用）：只计白盒。
        bb = {"stages": {}, "blackbox_score": None, "not_applicable": True}
        final = wb["whitebox_score"]
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "evaluation",
        "case_id": getattr(env, "case_id", None),
        "judgment": getattr(env, "judgment", None),
        "whitebox": wb,
        "blackbox": bb,
        "final_score": final,
        "minimum_capability_gate": None,
    }
