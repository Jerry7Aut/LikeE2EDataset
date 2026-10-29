#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""validate_case.py — 校验一个赛题目录是否符合 Case Schema（docs/CASE_SCHEMA.md）。

静态检查，不需要 docker。在标定（--calibrate）之前拦住低级错误，避免把不合格的
题丢给评测器浪费一次 1 小时的跑。校验维度：

  1. 目录结构     —— run.py 能否发现它（agent_task.json + case.json）
  2. agent_task.json —— 合法 JSON + 三角色 + 必填字段 + 交付物路径
  3. case.env     —— 拓扑必填键
  4. case.json    —— 评测配置（判据/目标/重放/补丁/业务/防御段齐全且取值合法）
  5. ground_truth —— reference_patch.diff 存在且非空
  6. blackbox/docker-compose.yml —— 含目标/网关/共享出口服务 + 必需网络

用法：
  python validate_case.py <case_dir>           # 校验单个赛题
  python validate_case.py --all                # 校验 cases/ 下全部（跳过 _ 开头）
退出码：0 = 全部通过；1 = 有 FAIL。
"""
import argparse
import json
import os
import sys

DATASET_DIR = os.path.dirname(os.path.abspath(__file__))
CASES_DIR = os.path.join(DATASET_DIR, "cases")

REQUIRED_ROLES = ("whitebox_attacker", "blackbox_defender_s5", "blackbox_defender_s6")
REQUIRED_ENV_KEYS = ("CASE_ID", "COMPOSE_PROJECT", "AGENT_NETWORK", "EGRESS_PROXY",
                     "BLACKBOX_ATTACKER_NETWORK", "BLACKBOX_DEFENDER_NETWORK", "NDR_API")


def _parse_env(path):
    kv = {}
    if not os.path.isfile(path):
        return kv
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def _check_structure(case, errs, warns):
    def need(rel):
        p = os.path.join(case, rel)
        if not os.path.exists(p):
            errs.append(f"缺少 {rel}")
        return os.path.exists(p)

    need("agent_task.json")
    need("case.env")
    need("case.json")
    need("organizer/evaluator/prepare_case.py")
    need("blackbox/docker-compose.yml")
    need("ground_truth/reference_patch.diff")
    if not os.path.isdir(os.path.join(case, "whitebox")):
        errs.append("缺少 whitebox/ 目录（白盒源码挂载点）")
    if not os.path.isdir(os.path.join(case, "blackbox")):
        errs.append("缺少 blackbox/ 目录")


def _check_task(case, errs):
    p = os.path.join(case, "agent_task.json")
    if not os.path.isfile(p):
        return
    try:
        with open(p, encoding="utf-8") as f:
            task = json.load(f)
    except json.JSONDecodeError as e:
        errs.append(f"agent_task.json 不是合法 JSON：{e}")
        return
    if not task.get("case_id"):
        errs.append("agent_task.json 缺少 case_id")
    roles = task.get("roles") or {}
    for r in REQUIRED_ROLES:
        if r not in roles:
            errs.append(f"agent_task.json 缺角色 roles.{r}")
            continue
        role = roles[r]
        if not role.get("goal"):
            errs.append(f"roles.{r} 缺 goal")
        out = role.get("output") or {}
        if not out:
            errs.append(f"roles.{r} 缺 output")
    # 交付物路径：白盒两个产物；蓝队两段各一个存档文件
    wb_out = (roles.get("whitebox_attacker") or {}).get("output") or {}
    for rel in ("/submission/whitebox/poc.bin", "/submission/whitebox/patch.diff"):
        if rel not in wb_out:
            errs.append(f"whitebox_attacker.output 缺 {rel}")
    if not ((roles.get("blackbox_defender_s5") or {}).get("output") or {}):
        errs.append("blackbox_defender_s5 缺 output（告警存档）")
    if not ((roles.get("blackbox_defender_s6") or {}).get("output") or {}):
        errs.append("blackbox_defender_s6 缺 output（处置计划存档）")
    for r in ("blackbox_defender_s5", "blackbox_defender_s6"):
        role = roles.get(r) or {}
        if role and not role.get("ndr_api"):
            errs.append(f"roles.{r} 缺 ndr_api（蓝队只通过 NDR 工作）")


def _check_env(case, errs):
    kv = _parse_env(os.path.join(case, "case.env"))
    for k in REQUIRED_ENV_KEYS:
        if k not in kv:
            errs.append(f"case.env 缺键 {k}")


def _check_case_json(case, errs):
    """校验 case.json（评测配置）：段齐全、取值合法、按判据类型查特有字段。

    出题人不写评测代码，判分全靠这份配置，所以这里查得细一点 —— 配置写错
    在标定阶段只会表现为「某阶段莫名 0 分」，很难定位。
    """
    p = os.path.join(case, "case.json")
    if not os.path.isfile(p):
        return
    try:
        with open(p, encoding="utf-8") as f:
            cfg = json.load(f)
    except json.JSONDecodeError as e:
        errs.append(f"case.json 不是合法 JSON：{e}")
        return

    if not cfg.get("case_id"):
        errs.append("case.json 缺 case_id")

    judgment = cfg.get("judgment") or {}
    jtype = judgment.get("type")
    if jtype not in ("flag", "crash"):
        errs.append(f"judgment.type 必须是 flag/crash，实际 {jtype!r}")
    if jtype == "flag":
        for k in ("flag_path", "nonce_write"):
            if not judgment.get(k):
                errs.append(f"flag 型必须给 judgment.{k}")

    target = cfg.get("target") or {}
    for k in ("image", "patched_image", "compose_service", "target_image_env", "healthy_check"):
        if not target.get(k):
            errs.append(f"target 缺 {k}")
    if target.get("healthy_check") not in (None, "container", "http", "sleep"):
        errs.append(f"target.healthy_check 取值非法：{target.get('healthy_check')!r}")

    replay = cfg.get("replay") or {}
    if replay.get("driver") != "command":
        errs.append(f"replay.driver 必须是 command（唯一重放形态），实际 {replay.get('driver')!r}")
    if not replay.get("attack_cmd"):
        errs.append("replay 缺 attack_cmd（dc run 参数列表）")
    # 黑盒线的攻击流量全部由出题人提供：S5/S6 用 reference_attack_cmd，
    # S4 用 variant_cmd。缺任何一个，对应阶段就无法真重放。
    if not replay.get("reference_attack_cmd"):
        errs.append("replay 缺 reference_attack_cmd（黑盒 S5/S6 的攻击流量）")
    if not replay.get("variant_cmd"):
        errs.append("replay 缺 variant_cmd（S4 的多种攻击变种）")
    for stale in ("traffic_container", "gateway", "reference_cmd"):
        if stale in replay:
            errs.append(f"replay.{stale} 已废弃：重放统一为 command，路径写在命令列表里")

    ndr = cfg.get("ndr") or {}
    if not ndr.get("url"):
        errs.append("ndr 缺 url（S5 的观测面必须部署 NDR）")

    if not (cfg.get("patch") or {}).get("build_cmd"):
        errs.append("patch 缺 build_cmd（补丁必须真编译）")
    biz = cfg.get("business") or {}
    if biz.get("driver") != "command":
        errs.append(f"business.driver 必须是 command，实际 {biz.get('driver')!r}")
    if not biz.get("command"):
        errs.append("business 缺 command（dc run 参数列表）")

    s5 = cfg.get("s5") or {}
    bg = s5.get("background_cmd") or []
    if not bg:
        errs.append("s5 缺 background_cmd（S5 窗口内必须持续产生正常业务流量）")
    elif len(bg) < 2:
        errs.append("s5.background_cmd 需要 [compose 服务名, 容器内命令...]")
    if "window_s" in s5 and float(s5["window_s"]) <= 0:
        errs.append("s5.window_s 必须为正（背景流量的持续秒数）")
    if "warmup_s" in s5 and float(s5["warmup_s"]) < 0:
        errs.append("s5.warmup_s 不能为负")
    if "min_background" in s5 and int(s5["min_background"]) < 10:
        errs.append("s5.min_background 至少 10（负例太少，检测判据没有区分力）")
    if "min_precision" in s5 and not (0 < float(s5["min_precision"]) <= 1.0):
        errs.append("s5.min_precision 必须在 (0, 1] 内")

    if not (cfg.get("defense") or {}).get("driver"):
        errs.append("defense 缺 driver")


def _check_ground_truth(case, errs):
    p = os.path.join(case, "ground_truth", "reference_patch.diff")
    if os.path.isfile(p) and os.path.getsize(p) == 0:
        errs.append("ground_truth/reference_patch.diff 为空")


def _check_compose(case, errs):
    p = os.path.join(case, "blackbox", "docker-compose.yml")
    if not os.path.isfile(p):
        return
    with open(p, encoding="utf-8") as f:
        text = f.read()
    # 结构检查：服务/网络名是 case-specific（由 case.env 声明具体名），这里只查通用结构。
    if "services:" not in text:
        errs.append("compose 缺 services 段")
    if "networks:" not in text:
        errs.append("compose 缺 networks 段")


def validate_case(case_dir):
    case = os.path.abspath(case_dir)
    errs, warns = [], []
    _check_structure(case, errs, warns)
    _check_task(case, errs)
    _check_env(case, errs)
    _check_case_json(case, errs)
    _check_ground_truth(case, errs)
    _check_compose(case, errs)
    return errs, warns


def discover(directory=CASES_DIR):
    out = []
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        if name.startswith("_"):
            continue
        d = os.path.join(directory, name)
        if os.path.isdir(d):
            out.append((name, d))
    return out


def main():
    ap = argparse.ArgumentParser(description="校验赛题目录是否符合 Case Schema")
    ap.add_argument("case_dir", nargs="?", default=None, help="赛题目录路径")
    ap.add_argument("--all", action="store_true", help="校验 cases/ 下全部赛题")
    a = ap.parse_args()

    targets = []
    if a.all:
        targets = discover()
    elif a.case_dir:
        targets = [(os.path.basename(os.path.abspath(a.case_dir)), a.case_dir)]
    else:
        ap.error("请给 --all 或 <case_dir>")

    if not targets:
        print("[validate] 未找到可校验的赛题目录")
        return 1

    rc = 0
    for name, d in targets:
        errs, warns = validate_case(d)
        status = "PASS" if not errs else "FAIL"
        print(f"\n[{status}] {name}")
        for e in errs:
            print(f"  [x] {e}")
        for w in warns:
            print(f"  [!] {w}")
        if not errs:
            print("  [OK] 结构/题面/拓扑/评测器/补丁/compose 均符合 schema，可进入 prepare_case + --calibrate")
        else:
            rc = 1
    print(f"\n[validate] {'全部通过' if rc == 0 else '存在 FAIL，标定前先修复'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
