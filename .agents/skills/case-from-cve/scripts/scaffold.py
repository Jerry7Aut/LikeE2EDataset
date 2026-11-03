#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scaffold.py — 从 _template 生成一道新 case 的骨架。

用法：
  python .claude/skills/case-from-cve/scripts/scaffold.py CVE-2024-36401
  python .claude/skills/case-from-cve/scripts/scaffold.py CVE-2024-36401 --force

做的事：
  1. 复制 datasetLikeE2e/cases/_template 到 cases/<CASE_ID>
  2. 把文本文件里的 <CASE_ID> 替换成实际编号
  3. 扫描剩余占位符，列出来交给后续步骤填写

不做的事：不写业务、不生成攻击、不改判据。这些必须按 SKILL.md 的流程完成。
"""
import argparse
import os
import re
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
TEMPLATE = os.path.join(ROOT, "datasetLikeE2e", "cases", "_template")
CASES = os.path.join(ROOT, "datasetLikeE2e", "cases")

TEXT_EXT = {".json", ".yml", ".yaml", ".env", ".md", ".py", ".sh", ".conf", ".txt"}
PLACEHOLDER = re.compile(r"<[^<>\n]{1,40}>")


def main() -> int:
    ap = argparse.ArgumentParser(description="从模板生成 case 骨架")
    ap.add_argument("case_id", help="case 编号，建议用 CVE 编号")
    ap.add_argument("--force", action="store_true", help="目标目录已存在时覆盖")
    args = ap.parse_args()

    case_id = args.case_id.strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]+", case_id):
        print("case_id 只能包含字母、数字、点、下划线和短横线", file=sys.stderr)
        return 2

    dest = os.path.join(CASES, case_id)
    if os.path.exists(dest):
        if not args.force:
            print(f"目标已存在：{dest}\n加 --force 覆盖", file=sys.stderr)
            return 1
        shutil.rmtree(dest)

    shutil.copytree(TEMPLATE, dest)

    remaining = []
    for base, _, files in os.walk(dest):
        for name in files:
            path = os.path.join(base, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in TEXT_EXT and name not in ("Makefile",):
                continue
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read()
            if "<CASE_ID>" in text:
                text = text.replace("<CASE_ID>", case_id)
                with open(path, "w", encoding="utf-8", newline="") as f:
                    f.write(text)
            for m in PLACEHOLDER.findall(text):
                remaining.append((os.path.relpath(path, dest), m))

    print(f"已生成 {dest}")
    if remaining:
        print("\n待填占位符：")
        seen = set()
        for rel, token in remaining:
            key = (rel, token)
            if key in seen:
                continue
            seen.add(key)
            print(f"  {rel}: {token}")
    else:
        print("没有剩余占位符")

    print("\n下一步：")
    print("  1. 可行性判断：源码可得、可编译、HTTP 可达、判据稳定")
    print("  2. 设计业务场景与正常业务流量")
    print("  3. 写 target、参考攻击、变种、参考防御、业务回归")
    print("  4. 写 whitebox 源码与真编译脚本")
    print("  5. 写 case.json / agent_task.json / case.env")
    print(f"  6. python datasetLikeE2e/validate_case.py {dest}")
    print(f"  7. python datasetLikeE2e/evaluator/generic_env.py --case-dir {dest} --calibrate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
