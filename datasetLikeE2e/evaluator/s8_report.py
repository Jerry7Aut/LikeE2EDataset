#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""s8_report.py — S8：双轨综合与能力画像（数据集层面，不改单题分数）

输入是一组评测报告（generic_env.py 的 --report-out 产物），输出：

  * 双轨均分：白盒均值、黑盒均值、总分（各题 final_score 的均值）；
  * 八个阶段的通过率：gated 计 0，invalid/not_executed 排除，并注明样本数；
  * 四维能力画像：修复 / 检测 / 处置 / 业务；
  * 过程指标：S5 误报率与联动覆盖率、S6 规则条数与粗粒度规则数、检测/处置时延。

过程指标只做画像，不参与判分。标定报告（mode=calibration）与设施失败
（status=infrastructure_error）不参与统计。
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys
import time

SCHEMA_VERSION = 1

STAGES = [
    ("whitebox", "s1_attack", "S1 定位/攻击"),
    ("whitebox", "s2_fix", "S2 修复"),
    ("whitebox", "s3_business", "S3 修复业务"),
    ("whitebox", "s4_gt_fix", "S4 修复精准"),
    ("blackbox", "s5_detect", "S5 检测"),
    ("blackbox", "s6_contain", "S6 处置"),
    ("blackbox", "s7_business", "S7 处置业务"),
    ("blackbox", "s4_gt_block", "S4 处置泛化"),
]

#: 四维画像：图中的修复 / 检测 / 处置 / 业务。
CAPABILITIES = {
    "repair": [("whitebox", "s1_attack"), ("whitebox", "s2_fix"), ("whitebox", "s4_gt_fix")],
    "detect": [("blackbox", "s5_detect")],
    "contain": [("blackbox", "s6_contain"), ("blackbox", "s4_gt_block")],
    "business": [("whitebox", "s3_business"), ("blackbox", "s7_business")],
}


def load_reports(paths):
    reports, skipped = [], []
    for p in paths:
        try:
            with open(p, encoding="utf-8") as f:
                r = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            skipped.append({"path": p, "reason": f"读取失败：{e}"})
            continue
        if r.get("schema_version") != SCHEMA_VERSION:
            skipped.append({"path": p, "reason": "schema 版本不符（旧格式报告）"})
            continue
        if r.get("mode") == "calibration":
            skipped.append({"path": p, "reason": "标定报告，不计入成绩"})
            continue
        if r.get("status") == "infrastructure_error" or not _has_scores(r):
            skipped.append({"path": p, "reason": "设施失败/没有成绩，不计入"})
            continue
        reports.append(r)
    return reports, skipped


def _has_scores(r):
    wb = (r.get("whitebox") or {}).get("whitebox_score")
    bb = (r.get("blackbox") or {}).get("blackbox_score")
    return wb is not None or bb is not None


def _stage_rec(report, track, name):
    return ((report.get(track) or {}).get("stages") or {}).get(name)


def _mean(values):
    values = [v for v in values if v is not None]
    return round(sum(values) / len(values), 3) if values else None


def summarize(reports, skipped=None):
    cases = []
    for r in reports:
        wb = (r.get("whitebox") or {}).get("whitebox_score")
        bb = (r.get("blackbox") or {}).get("blackbox_score")
        cases.append({
            "case_id": r.get("case_id"),
            "mode": r.get("mode"),
            "agent": r.get("agent"),
            "whitebox_score": wb,
            "blackbox_score": bb,
            "final_score": r.get("final_score"),
        })

    stages = {}
    for track, name, label in STAGES:
        evaluated = passed = gated = 0
        for r in reports:
            rec = _stage_rec(r, track, name)
            if not rec:
                continue
            # invalid / not_executed 是设施失败或未跑，排除；gated 是前序失败导致的
            # 连带跳过，它本身就是一个能力信号，计入分母、按 0 通过。
            if rec.get("status") in ("invalid", "not_executed"):
                continue
            evaluated += 1
            if rec.get("status") == "gated":
                gated += 1
            elif rec.get("score") == 1.0:
                passed += 1
        stages[name] = {
            "label": label,
            "evaluated": evaluated,
            "passed": passed,
            "gated": gated,
            "rate": round(passed / evaluated, 3) if evaluated else None,
        }

    capabilities = {}
    for key, members in CAPABILITIES.items():
        passed = evaluated = 0
        for name in members:
            st = stages[name[1]]
            passed += st["passed"]
            evaluated += st["evaluated"]
        capabilities[key] = round(passed / evaluated, 3) if evaluated else None

    metrics = {
        "s5_false_alarm_rate": _mean([d.get("false_alarm_rate") for d in _details(reports, "blackbox", "s5_detect")]),
        "s6_rules_mean": _mean([d.get("rules_total") for d in _details(reports, "blackbox", "s6_contain")]),
        "s6_broad_rules_mean": _mean([d.get("broad_rules") for d in _details(reports, "blackbox", "s6_contain")]),
        "detection_latency_s": _mean([d.get("detection_latency_s") for d in _details(reports, "blackbox", "s5_detect")]),
        "response_latency_s": _mean([d.get("response_latency_s") for d in _details(reports, "blackbox", "s6_contain")]),
    }
    links = [d.get("link") for d in _details(reports, "blackbox", "s5_detect") if d.get("link")]
    metrics["s5_link_coverage"] = (round(sum(1 for x in links if x == "linked") / len(links), 3)
                                   if links else None)

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "cases": cases,
        "skipped": skipped or [],
        "dataset": {
            "cases_scored": len(reports),
            "whitebox_mean": _mean([c["whitebox_score"] for c in cases]),
            "blackbox_mean": _mean([c["blackbox_score"] for c in cases]),
            "total": _mean([c["final_score"] for c in cases]),
        },
        "stages": stages,
        "capabilities": capabilities,
        "metrics": metrics,
    }


def _details(reports, track, name):
    out = []
    for r in reports:
        rec = _stage_rec(r, track, name)
        if rec and isinstance(rec.get("detail"), dict):
            out.append(rec["detail"])
    return out


def render_markdown(summary):
    d = summary["dataset"]
    lines = [
        "# S8 双轨汇总",
        "",
        f"计分题数 {d['cases_scored']}；白盒均分 {_fmt(d['whitebox_mean'])}，"
        f"黑盒均分 {_fmt(d['blackbox_mean'])}，总分 {_fmt(d['total'])}。",
        "",
        "| 阶段 | 通过 / 有效 | gated | 通过率 |",
        "|---|---:|---:|---:|",
    ]
    for _track, name, label in STAGES:
        st = summary["stages"][name]
        lines.append(f"| {label} | {st['passed']} / {st['evaluated']} | {st['gated']} | "
                     f"{_fmt(st['rate'])} |")
    c = summary["capabilities"]
    lines += [
        "",
        f"能力画像：修复 {_fmt(c['repair'])}、检测 {_fmt(c['detect'])}、"
        f"处置 {_fmt(c['contain'])}、业务 {_fmt(c['business'])}。",
        "",
        f"过程指标：S5 误报率 {_fmt(summary['metrics']['s5_false_alarm_rate'])}，"
        f"S1→S5 联动覆盖 {_fmt(summary['metrics']['s5_link_coverage'])}，"
        f"S6 规则数 {_fmt(summary['metrics']['s6_rules_mean'])}"
        f"（粗粒度 {_fmt(summary['metrics']['s6_broad_rules_mean'])}），"
        f"检测时延 {_fmt(summary['metrics']['detection_latency_s'])}s，"
        f"处置时延 {_fmt(summary['metrics']['response_latency_s'])}s。",
    ]
    if summary["skipped"]:
        lines += ["", "未计入：" + "；".join(f"{os.path.basename(s['path'])}（{s['reason']}）"
                                              for s in summary["skipped"])]
    return "\n".join(lines)


def _fmt(v):
    return "—" if v is None else str(v)


def main():
    ap = argparse.ArgumentParser(description="S8 双轨汇总与能力画像")
    ap.add_argument("--inputs", nargs="*", default=None, help="报告文件，缺省扫描 --results")
    ap.add_argument("--results", default=None, help="报告目录（默认 datasetLikeE2e/results）")
    ap.add_argument("--out", default=None, help="输出 JSON 路径（默认 <results>/s8.json）")
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    results_dir = a.results or os.path.join(os.path.dirname(here), "results")
    paths = a.inputs or sorted(glob.glob(os.path.join(results_dir, "*.json")))
    paths = [p for p in paths if os.path.basename(p) != "s8.json"]

    reports, skipped = load_reports(paths)
    # 同一道题有多份报告时，取最后出现的一份（run.py 的顺序即执行顺序）。
    latest = {}
    for r in reports:
        latest[r.get("case_id")] = r
    reports = list(latest.values())

    summary = summarize(reports, skipped)
    out = a.out or os.path.join(results_dir, "s8.json")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(render_markdown(summary))
    print(f"\n[s8] 汇总已写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
