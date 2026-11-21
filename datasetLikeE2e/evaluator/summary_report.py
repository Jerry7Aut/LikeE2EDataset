#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""summary_report.py — 汇总层：双轨综合与能力画像（数据集层面，不改单题分数）

汇总层不占 S 编号。输入是一组评测报告（generic_env.py 的 --report-out 产物），输出：

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

SCHEMA_VERSION = 2
#: v1 报告的黑盒变种键是 s4_gt_block；v2 起改为 s8_gt_block（黑盒 S5–S8）。
SUPPORTED_SCHEMA = (1, 2)

STAGES = [
    ("whitebox", "s1_attack", "S1 定位/攻击"),
    ("whitebox", "s2_fix", "S2 修复"),
    ("whitebox", "s3_business", "S3 修复业务"),
    ("whitebox", "s4_gt_fix", "S4 修复精准"),
    ("blackbox", "s5_detect", "S5 检测"),
    ("blackbox", "s6_contain", "S6 处置"),
    ("blackbox", "s7_business", "S7 处置业务"),
    ("blackbox", "s8_gt_block", "S8 变种阻断"),
]

#: 四维画像：图中的修复 / 检测 / 处置 / 业务。
CAPABILITIES = {
    "repair": [("whitebox", "s1_attack"), ("whitebox", "s2_fix"), ("whitebox", "s4_gt_fix")],
    "detect": [("blackbox", "s5_detect")],
    "contain": [("blackbox", "s6_contain"), ("blackbox", "s8_gt_block")],
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
        if r.get("schema_version") not in SUPPORTED_SCHEMA:
            skipped.append({"path": p, "reason": "schema 版本不符（旧格式报告）"})
            continue
        _normalize_legacy(r)
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


def _normalize_legacy(report):
    """v1 报告的黑盒变种键是 s4_gt_block；v2 起改为 s8_gt_block。"""
    stages = ((report.get("blackbox") or {}).get("stages") or {})
    if "s4_gt_block" in stages and "s8_gt_block" not in stages:
        stages["s8_gt_block"] = stages.pop("s4_gt_block")
    return report


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
        scores = []
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
                continue
            scores.append(rec.get("score"))
            # 通过看判据的 passed（S5 的分可能是 0~1 的还原质量加权值）；
            # 没有 detail.passed 的旧报告退回「满分即通过」。
            detail = rec.get("detail") if isinstance(rec.get("detail"), dict) else {}
            ok = bool(detail.get("passed")) if "passed" in detail else rec.get("score") == 1.0
            if ok:
                passed += 1
        stages[name] = {
            "label": label,
            "evaluated": evaluated,
            "passed": passed,
            "gated": gated,
            "rate": round(passed / evaluated, 3) if evaluated else None,
            "score_mean": _mean(scores),
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
    # 还原画像：只有走分阶段提交的 run 才有 chain 细节；告警式提交的 run 不参与均值。
    chains = [d.get("chain") for d in _details(reports, "blackbox", "s5_detect")
              if isinstance(d.get("chain"), dict)]
    metrics["s5_chain_cases"] = len(chains)
    metrics["s5_chain_score_mean"] = _mean([c.get("chain_score") for c in chains])
    metrics["s5_chain_node_score_mean"] = _mean([c.get("node_score") for c in chains])
    metrics["s5_chain_order_ok_rate"] = (
        round(sum(1 for c in chains if c.get("order_ok")) / len(chains), 3) if chains else None)
    metrics["s5_chain_first_hit_rate"] = _mean([c.get("first_hit_rate") for c in chains])
    metrics["s5_candidate_efficiency"] = _mean([c.get("candidate_efficiency") for c in chains])
    # 链式评分分项（v9 口径）：只有 chain 判据的 run 才有 rubric。
    rubrics = [d.get("rubric") for d in _details(reports, "blackbox", "s5_detect")
               if isinstance(d.get("rubric"), dict)]
    metrics["s5_rubric_cases"] = len(rubrics)
    for key in ("node_points", "qualitative_points", "order_points", "log_points",
                "time_points", "false_alarm_penalty", "spam_penalty",
                "failed_points", "raw", "max_raw"):
        metrics[f"s5_rubric_{key}_mean"] = _mean([r.get(key) for r in rubrics])
    modes = [d.get("mode") for d in _details(reports, "blackbox", "s5_detect")
             if d.get("mode")]
    metrics["s5_chain_mode_rate"] = (
        round(sum(1 for m in modes if m == "chain") / len(modes), 3) if modes else None)
    used = sum(int(c.get("log_evidence_used") or 0) for c in chains)
    ok = sum(int(c.get("log_evidence_ok") or 0) for c in chains)
    metrics["s5_log_evidence_used"] = used
    metrics["s5_log_evidence_ok_rate"] = round(ok / used, 3) if used else None

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
        "# 汇总：双轨综合与能力画像",
        "",
        f"计分题数 {d['cases_scored']}；白盒均分 {_fmt(d['whitebox_mean'])}，"
        f"黑盒均分 {_fmt(d['blackbox_mean'])}，总分 {_fmt(d['total'])}。",
        "",
        "| 阶段 | 通过 / 有效 | gated | 通过率 | 均分 |",
        "|---|---:|---:|---:|---:|",
    ]
    for _track, name, label in STAGES:
        st = summary["stages"][name]
        lines.append(f"| {label} | {st['passed']} / {st['evaluated']} | {st['gated']} | "
                     f"{_fmt(st['rate'])} | {_fmt(st.get('score_mean'))} |")
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
        "",
        f"还原画像（{summary['metrics']['s5_chain_cases']} 题走分阶段提交）："
        f"链分 {_fmt(summary['metrics']['s5_chain_score_mean'])}，"
        f"节点分 {_fmt(summary['metrics']['s5_chain_node_score_mean'])}，"
        f"顺序一致率 {_fmt(summary['metrics']['s5_chain_order_ok_rate'])}，"
        f"首名命中 {_fmt(summary['metrics']['s5_chain_first_hit_rate'])}，"
        f"候选效率 {_fmt(summary['metrics']['s5_candidate_efficiency'])}，"
        f"日志证据 {summary['metrics']['s5_log_evidence_used']} 条"
        f"（原文命中率 {_fmt(summary['metrics']['s5_log_evidence_ok_rate'])}）。",
        "",
        f"链式评分（{summary['metrics']['s5_rubric_cases']} 题，chain 占比 "
        f"{_fmt(summary['metrics']['s5_chain_mode_rate'])}）：节点 "
        f"{_fmt(summary['metrics']['s5_rubric_node_points_mean'])}，定性 "
        f"{_fmt(summary['metrics']['s5_rubric_qualitative_points_mean'])}，顺序 "
        f"{_fmt(summary['metrics']['s5_rubric_order_points_mean'])}，日志 "
        f"{_fmt(summary['metrics']['s5_rubric_log_points_mean'])}，时间 "
        f"{_fmt(summary['metrics']['s5_rubric_time_points_mean'])}，误报 "
        f"{_fmt(summary['metrics']['s5_rubric_false_alarm_penalty_mean'])}，灌水 "
        f"{_fmt(summary['metrics']['s5_rubric_spam_penalty_mean'])}，失败分支 "
        f"{_fmt(summary['metrics']['s5_rubric_failed_points_mean'])}。",
    ]
    if summary["skipped"]:
        lines += ["", "未计入：" + "；".join(f"{os.path.basename(s['path'])}（{s['reason']}）"
                                              for s in summary["skipped"])]
    return "\n".join(lines)


def _fmt(v):
    return "—" if v is None else str(v)


def main():
    ap = argparse.ArgumentParser(description="双轨汇总与能力画像（汇总层，不改单题分）")
    ap.add_argument("--inputs", nargs="*", default=None, help="报告文件，缺省扫描 --results")
    ap.add_argument("--results", default=None, help="报告目录（默认 datasetLikeE2e/results）")
    ap.add_argument("--out", default=None, help="输出 JSON 路径（默认 <results>/summary_report.json）")
    a = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    results_dir = a.results or os.path.join(os.path.dirname(here), "results")
    paths = a.inputs or sorted(glob.glob(os.path.join(results_dir, "*.json")))
    skip_names = {"summary.json", "summary_report.json", "s8.json"}
    paths = [p for p in paths if os.path.basename(p) not in skip_names]

    reports, skipped = load_reports(paths)
    # 同一道题有多份报告时，取最后出现的一份（run.py 的顺序即执行顺序）。
    latest = {}
    for r in reports:
        latest[r.get("case_id")] = r
    reports = list(latest.values())

    summary = summarize(reports, skipped)
    out = a.out or os.path.join(results_dir, "summary_report.json")
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    print(render_markdown(summary))
    print(f"\n[summary] 汇总已写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
