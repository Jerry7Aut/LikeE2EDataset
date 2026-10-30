#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""run.py — 顶层 runner：一键跑全部样例（或单个样例）

统一 case 接口：每个样例目录 cases/<CASE_ID>/ 必须包含
  - agent_task.json                      三角色任务
  - case.env                             拓扑
  - case.json                            评测配置（通用引擎 evaluator/generic_env.py 读它判分）

用法：
  python run.py --all                    # 跑 cases/ 下所有样例
  python run.py --case CVE-2025-24928    # 跑单个样例
  python run.py --all --agent codex --build-agent
"""
import argparse
import json
import os
import subprocess
import sys

DATASET_DIR = os.path.dirname(os.path.abspath(__file__))
CASES_DIR = os.path.join(DATASET_DIR, "cases")
RESULTS_DIR = os.path.join(DATASET_DIR, "results")


def discover_cases():
    """发现 cases/ 下所有符合统一接口的样例（含 .port-incomplete 标记的会被跳过并警告）。"""
    cases = []
    if not os.path.isdir(CASES_DIR):
        return cases
    for name in sorted(os.listdir(CASES_DIR)):
        if name.startswith("_"):   # 跳过 _template 等辅助目录
            continue
        case_dir = os.path.join(CASES_DIR, name)
        case_json = os.path.join(case_dir, "case.json")
        task_json = os.path.join(case_dir, "agent_task.json")
        if os.path.isdir(case_dir) and os.path.isfile(case_json) and os.path.isfile(task_json):
            cases.append((name, case_dir))
    return cases


def split_incomplete(cases):
    """把含 .port-incomplete 标记的样例从执行列表分离（port 未完成，不参与 --all）。"""
    ready, pending = [], []
    for name, case_dir in cases:
        if os.path.isfile(os.path.join(case_dir, ".port-incomplete")):
            pending.append(name)
        else:
            ready.append((name, case_dir))
    return ready, pending


def run_case(case_id, case_dir, agent, build_agent, report_out):
    """跑单个样例：调通用配置驱动引擎 generic_env.py --run-agent，报告落盘 report_out。"""
    generic = os.path.join(DATASET_DIR, "evaluator", "generic_env.py")
    cmd = [sys.executable, "-u", generic, "--case-dir", case_dir,
           "--run-agent", "--report-out", report_out]
    if agent:
        cmd += ["--agent", agent]
    if build_agent:
        cmd += ["--build-agent"]
    print(f"\n{'=' * 64}\n[run] 样例 {case_id}\n{'=' * 64}", flush=True)
    r = subprocess.run(cmd, cwd=case_dir)
    return r.returncode


def main():
    ap = argparse.ArgumentParser(description="datasetLikeE2e 顶层 runner")
    ap.add_argument("--case", default=None, help="只跑指定样例（缺省跑全部）")
    ap.add_argument("--all", action="store_true", help="跑 cases/ 下所有样例")
    ap.add_argument("--agent", default=None, choices=["codex", "qwencode", "custom"])
    ap.add_argument("--build-agent", action="store_true")
    a = ap.parse_args()

    all_cases = discover_cases()
    if not all_cases:
        print("[run] 未发现样例（cases/ 下没有同时含 case.json 与 agent_task.json 的目录）")
        return 1

    cases = all_cases
    if a.case:
        cases = [c for c in all_cases if c[0] == a.case]
        if not cases:
            print(f"[run] 未找到样例 {a.case}；可用：{[c[0] for c in all_cases]}")
            return 1

    cases, pending = split_incomplete(cases)
    for name in pending:
        print(f"[run] 跳过 {name}（port 未完成，含 .port-incomplete 标记）")
    if not cases:
        print("[run] 没有可执行的样例")
        return 1

    os.makedirs(RESULTS_DIR, exist_ok=True)
    summary = {"cases": []}
    for case_id, case_dir in cases:
        report_out = os.path.join(RESULTS_DIR, f"{case_id}.json")
        # 删掉上一轮的旧报告：docker_env 失败（异常退出）时不会写新报告，
        # 残留的旧文件会被误读成「本轮分数」（曾导致 6553 误报 12:04 的旧分）
        if os.path.isfile(report_out):
            os.remove(report_out)
        rc = run_case(case_id, case_dir, a.agent, a.build_agent, report_out)
        entry = {"case_id": case_id, "exit_code": rc}
        if os.path.isfile(report_out):
            try:
                with open(report_out, encoding="utf-8") as f:
                    report = json.load(f)
                entry["final_score"] = report.get("final_score")
                entry["whitebox_score"] = (report.get("whitebox") or {}).get("whitebox_score")
                entry["blackbox_score"] = (report.get("blackbox") or {}).get("blackbox_score")
            except Exception as e:
                entry["report_error"] = str(e)
        summary["cases"].append(entry)

    print(f"\n{'=' * 64}\n[run] 汇总\n{'=' * 64}")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    summary_out = os.path.join(RESULTS_DIR, "summary.json")
    with open(summary_out, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(f"[run] 汇总已写入 {summary_out}")

    # S8：双轨汇总与能力画像。只读本轮报告，不改单题分数。
    report_paths = [os.path.join(RESULTS_DIR, f"{cid}.json") for cid, _ in cases
                    if os.path.isfile(os.path.join(RESULTS_DIR, f"{cid}.json"))]
    if report_paths:
        s8 = os.path.join(DATASET_DIR, "evaluator", "s8_report.py")
        subprocess.run([sys.executable, s8, "--inputs", *report_paths,
                        "--out", os.path.join(RESULTS_DIR, "s8.json")], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
