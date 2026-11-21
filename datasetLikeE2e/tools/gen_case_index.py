#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 cases/INDEX.md（题目总表）和 cases/_DUP_INDEX.md（同 CVE 多版本索引）。

用法（在仓库根目录执行）：
    python tools/gen_case_index.py

数据来源是每个 case 目录下的 case.json / README.md / DUPLICATE.md /
agent_task.json。新增、删除、改名 case 之后重跑本脚本即可；两个索引文件
均由脚本生成，不要手工编辑。
"""

from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "cases"
SKIP = {"_template"}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def read_json(path: Path) -> dict:
    try:
        return json.loads(read_text(path))
    except (json.JSONDecodeError, OSError):
        return {}


GENERIC_TITLES = {"datasetLikeE2e 赛题", "datasetLikeE2e 题目", "赛题"}


def readme_summary(case_dir: Path, limit: int = 60) -> str:
    """README 第一段正文，用作没有实际标题时的题面摘要。"""
    for line in read_text(case_dir / "README.md").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.sub(r"^[-*]\s*", "", line)
        return line if len(line) <= limit else line[: limit - 1] + "…"
    return ""


def case_title(case_dir: Path, case_id: str) -> str:
    """README 首行的题面标题，去掉开头的 CVE 编号（含 -alt- 后缀）和分隔符。

    标题只写「datasetLikeE2e 赛题」这类占位内容时，回退到第一段正文；
    没有 README 或标题只剩 CVE 编号时返回空串。
    """
    cve = case_id.split("-alt-")[0]
    title = ""
    for line in read_text(case_dir / "README.md").splitlines():
        line = line.strip()
        if not line:
            continue
        title = line.lstrip("#").strip()
        title = re.sub(rf"^{re.escape(case_id)}\s*", "", title)
        title = re.sub(rf"^{re.escape(cve)}\s*", "", title)
        title = re.sub(r"^(?:——|—|–|-{1,2})\s*", "", title).strip()
        break
    if title in GENERIC_TITLES:
        return readme_summary(case_dir)
    return title


def duplicate_info(case_dir: Path) -> tuple[str, str]:
    """从 DUPLICATE.md 读出来源包和主版本目录；非重复目录返回空串。"""
    text = read_text(case_dir / "DUPLICATE.md")
    if not text:
        return "", ""
    source = re.search(r"来源包[：:]\s*`([^`]+)`", text)
    main = re.search(r"其他收录目录[：:]\s*`([^`]+)`", text)
    return (source.group(1) if source else "", main.group(1) if main else "")


def has_placeholder(case_dir: Path) -> bool:
    text = read_text(case_dir / "agent_task.json")
    return "<一句话目标" in text or "<一句话目标：" in text


def collect() -> list[dict]:
    rows = []
    for case_dir in sorted(CASES.iterdir(), key=lambda p: p.name):
        if not case_dir.is_dir() or case_dir.name in SKIP:
            continue
        case_id = case_dir.name
        cfg = read_json(case_dir / "case.json")
        judgment = cfg.get("judgment", {}).get("type", "")
        image = cfg.get("target", {}).get("image", "")
        source, main = duplicate_info(case_dir)
        is_dup = bool(source or main)
        title = case_title(case_dir, case_id)
        if has_placeholder(case_dir):
            status = "⚠️ 占位待完善"
        elif not title or title.startswith("赛题模板"):
            status = "README 待补"
        else:
            status = "可用"
        note = f"重复版本（来源 {source or '未知'}）" if is_dup else ""
        rows.append(
            {
                "dir": case_id,
                "cve": case_id.split("-alt-")[0],
                "judgment": judgment or "?",
                "image": image or "-",
                "title": title or "（README 未写题面）",
                "status": status,
                "note": note,
                "dup": is_dup,
                "source": source,
                "main": main,
            }
        )
    return rows


def esc(text: str) -> str:
    return text.replace("|", "\\|")


def table(header: list[str], rows: list[list[str]]) -> list[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out.extend("| " + " | ".join(cells) + " |" for cells in rows)
    return out


def render_index(rows: list[dict]) -> str:
    today = date.today().isoformat()
    total = len(rows)
    cves = {r["cve"] for r in rows}
    multi = [cve for cve in cves if sum(1 for r in rows if r["cve"] == cve) > 1]
    flag = sum(1 for r in rows if r["judgment"] == "flag")
    crash = sum(1 for r in rows if r["judgment"] == "crash")
    ready = sum(1 for r in rows if r["status"] == "可用")
    need_readme = sum(1 for r in rows if r["status"] == "README 待补")
    placeholder = sum(1 for r in rows if r["status"].startswith("⚠️"))

    lines = [
        "# datasetLikeE2e 题目总表",
        "",
        f"> 生成时间：{today} · 由 `tools/gen_case_index.py` 自动生成，请勿手工编辑。",
        "> 新增、删除或改名 case 后，在仓库根目录运行 `python tools/gen_case_index.py` 重新生成本文件。",
        "",
        "## 总览",
        "",
        f"- 题目目录：**{total}**",
        f"- 不同 CVE：**{len(cves)}**",
        f"- 多版本 CVE：**{len(multi)}** 个（共 {sum(1 for r in rows if r['dup'])} 个 `-alt-` 重复实现）",
        f"- 判据分布：flag **{flag}** · crash **{crash}**",
        f"- 状态分布：可用 **{ready}** · README 待补 **{need_readme}** · 占位待完善 **{placeholder}**",
        "",
        "状态说明：`可用` = 目录结构与题面齐全；`README 待补` = 内容已填但 README 仍是模板或未写题面；"
        "`⚠️ 占位待完善` = agent_task.json 里仍有 `<一句话目标>` 占位符。"
        "备注里的 `重复版本` 表示同一 CVE 的另一种实现。",
        "",
        "## 题目清单",
        "",
    ]
    rows_for_table = [
        [
            f"`{r['dir']}`",
            r["judgment"],
            f"`{esc(r['image'])}`",
            esc(r["title"]),
            esc(r["status"]),
            esc(r["note"]),
        ]
        for r in rows
    ]
    lines += table(["目录", "判据", "目标镜像", "题面摘要", "状态", "备注"], rows_for_table)

    lines += [
        "",
        "## 同一 CVE 多版本",
        "",
        "同一 CVE 的不同交付各自独立成目录，`case_id` 已改为目录名，评测结果与汇总报告不会互相覆盖。",
        "",
    ]
    dup_rows = []
    for cve in sorted(multi):
        group = [r for r in rows if r["cve"] == cve]
        main_dir = next((r["dir"] for r in group if not r["dup"]), group[0]["dir"])
        for r in group:
            role = "主版本" if r["dir"] == main_dir else f"重复 · {r['source'] or '未知'}"
            dup_rows.append([cve, f"`{r['dir']}`", role])
    lines += table(["CVE", "收录目录", "角色"], dup_rows)

    lines += [
        "",
        "## 怎么用",
        "",
        "```bash",
        "# 静态校验单道 case",
        "python validate_case.py cases/CVE-2021-43798",
        "",
        "# 全链路标定（参考攻击代替 agent）",
        "python evaluator/generic_env.py --case-dir cases/CVE-2021-43798 --calibrate",
        "",
        "# 真实 agent 跑题",
        "python run.py --case CVE-2021-43798 --agent codex",
        "```",
        "",
        "候选 CVE 与出题规划见 [`docs/coverage_plan.md`](../docs/coverage_plan.md)，"
        "题目契约见 [`docs/CASE_SCHEMA.md`](../docs/CASE_SCHEMA.md)。",
        "",
    ]
    return "\n".join(lines)


def render_dup_index(rows: list[dict]) -> str:
    today = date.today().isoformat()
    cves = {r["cve"] for r in rows}
    multi = sorted(cve for cve in cves if sum(1 for r in rows if r["cve"] == cve) > 1)
    alt = [r for r in rows if r["dup"]]

    lines = [
        "# 同一 CVE 多版本索引",
        "",
        f"> 生成时间：{today} · 由 `tools/gen_case_index.py` 自动生成，请勿手工编辑。",
        "> 完整题目清单见 [`INDEX.md`](INDEX.md)。",
        "",
        "- 命名：主版本目录为 `CVE-xxxx-yyyy`；同 CVE 的其余版本为 `CVE-xxxx-yyyy-alt-<来源>`"
        "（来源：`zip` = cases.zip，`17cases` = likee2e_17cases，`yzy` = 12题_闫子怡，`w2` = cases-w2，`w3` = cases-w3，`cy` = likee2e_30cases，`hsk` = hsk-case）。",
        "- 每个 `-alt-` 目录内有 `DUPLICATE.md` 标记；`case_id` 已改为目录名，评测结果与汇总报告不会互相覆盖。",
        "",
        f"- 题目目录总数：{len(rows)}；不同 CVE：{len(cves)}；多版本 CVE：{len(multi)}；重复实现：{len(alt)}",
        "",
    ]
    dup_rows = []
    for cve in multi:
        group = [r for r in rows if r["cve"] == cve]
        main_dir = next((r["dir"] for r in group if not r["dup"]), group[0]["dir"])
        for r in group:
            role = "主版本" if r["dir"] == main_dir else f"重复 · {r['source'] or '未知'}"
            dup_rows.append([cve, f"`{r['dir']}`", role])
    lines += table(["CVE", "收录目录", "角色"], dup_rows)
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    rows = collect()
    (CASES / "INDEX.md").write_text(render_index(rows), encoding="utf-8", newline="\n")
    (CASES / "_DUP_INDEX.md").write_text(render_dup_index(rows), encoding="utf-8", newline="\n")
    print(f"已生成 cases/INDEX.md 与 cases/_DUP_INDEX.md（{len(rows)} 道 case）")


if __name__ == "__main__":
    main()
