#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""chain_audit.py — 盘点各 case 的 S5 链长与建议判据形态。

数据来源是已有的评测/标定报告（`results/*.json`）里 S5 的 detail：
`attack_size`（链长）或 `chain.size`。没有报告的 case 标为「未标定」，
需要先跑 `--calibrate` 才知道是「已有链」还是「需要构造链」。

用法（仓库根目录）：
  python tools/chain_audit.py
  python tools/chain_audit.py --results results --cases cases --out 汇总/链长盘点.md
"""
import argparse
import json
import os
from datetime import date

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SKIP_DIRS = {"_template", "_DUP_INDEX.md", "INDEX.md"}


def _load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def _chain_size(report):
    """从一份报告里取链长；优先 chain.size，其次 attack_size。"""
    bb = (report or {}).get("blackbox") or {}
    st = (bb.get("stages") or {}).get("s5_detect") or {}
    detail = st.get("detail") if isinstance(st.get("detail"), dict) else {}
    chain = detail.get("chain") if isinstance(detail.get("chain"), dict) else {}
    if chain.get("size") is not None:
        return int(chain["size"]), detail.get("mode")
    if detail.get("attack_size") is not None:
        return int(detail["attack_size"]), detail.get("mode")
    rubric = detail.get("rubric") if isinstance(detail.get("rubric"), dict) else {}
    if rubric.get("max_raw") is not None and detail.get("chain"):
        return len(detail["chain"].get("nodes") or []), detail.get("mode")
    return None, None


def collect(results_dir, cases_dir):
    rows = {}
    for name in sorted(os.listdir(results_dir)):
        if not name.endswith(".json"):
            continue
        report = _load(os.path.join(results_dir, name))
        if not report or not report.get("case_id"):
            continue
        size, mode = _chain_size(report)
        if size is None:
            continue
        rows[report["case_id"]] = {"size": size, "mode": mode, "report": name}
    cases = []
    if os.path.isdir(cases_dir):
        for d in sorted(os.listdir(cases_dir)):
            if d.startswith("CVE-") and os.path.isdir(os.path.join(cases_dir, d)):
                cases.append(d)
    return rows, cases


def suggest(size):
    if size is None:
        return "未标定（先 --calibrate）"
    if size >= 2:
        return "chain（已有链）"
    return "构造链（当前单步，可加侦察/后利用；无法构造则 legacy）"


def render(rows, cases):
    lines = [
        f"# S5 链长盘点（{date.today().isoformat()}）",
        "",
        "> 由 `tools/chain_audit.py` 从已有报告生成。链长 = 参考攻击在 NDR 里匹配到的攻击请求数；"
        "≥2 步走 chain 判据，单步需要构造攻击链，构造不了保持 legacy。",
        "",
        f"- 已标定：{sum(1 for c in cases if c in rows)} / {len(cases)}",
        "",
        "| case | 链长 | 报告 | 建议 |",
        "|---|---:|---|---|",
    ]
    for c in cases:
        r = rows.get(c)
        lines.append(f"| `{c}` | {r['size'] if r else '—'} | "
                     f"{r['report'] if r else '—'} | {suggest(r['size'] if r else None)} |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="盘点 S5 链长与判据形态")
    ap.add_argument("--results", default=os.path.join(ROOT, "results"))
    ap.add_argument("--cases", default=os.path.join(ROOT, "cases"))
    ap.add_argument("--out", default=None, help="输出 Markdown；缺省打印")
    a = ap.parse_args()
    rows, cases = collect(a.results, a.cases)
    text = render(rows, cases)
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(f"[chain_audit] 已写入 {a.out}（{len(rows)} 个已标定 / {len(cases)} 个 case）")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
