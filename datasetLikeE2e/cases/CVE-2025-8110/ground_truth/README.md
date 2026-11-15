# ground_truth/ —— 出题方答案（模板说明）

评测器判分依赖这里，agent 看不到这些（不会挂载给受测容器）：

| 文件 | 说明 |
|---|---|
| `reference_patch.diff` | 修复根因的统一 diff（`git diff` 格式，`a/` `b/` 前缀，`-p1` 可应用）。S2 会把它（或受测方 patch）打进干净源码树**真编译** |
| `vulnerable_code.<ext>` | 漏洞代码片段（存档/人工复核用） |
| `fixed_code.<ext>` | 修复后代码片段 |
| `business_assertions.json` | S3/S7 业务回归的冻结断言（分母固定） |
| `defense_family.yaml` | 防御家族 + **真值变种**（S4 用不同写法/独立来源重放，验泛化阻断、防浅封） |

**参考补丁要能真编译**：不能只是 diff 文本，必须是"应用后能编译通过、漏洞确实消除"的补丁。
验收：`--calibrate` 里 S2 真编译通过、S4 真值变种不再触发。
