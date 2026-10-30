# 赛题模板（_template）

出题人从本目录复制一份、改名成 `<CASE_ID>`（建议 CVE 编号），按下面的顺序填内容即可。
完整契约见 [`docs/CASE_SCHEMA.md`](../../docs/CASE_SCHEMA.md)。
判分由框架通用引擎 `evaluator/generic_env.py` 读 `case.json` 完成。

## 产题顺序（重要：先想业务，再想漏洞）

1. **写业务场景描述**（第一步，不是搭环境）：这个系统是干什么的、正常用户怎么用、
   攻击者怎么穿过业务逻辑走到漏洞。这一步决定后面的攻击链和回归测试。
2. **定判据类型**：崩溃型（crash）还是 flag 型（flag，见 schema §7）。
3. 搭 `blackbox/` 环境：业务外壳（target）+ 网关 + 出口 + 正常流量 + 参考 PoC + 业务回归。
4. 写 `ground_truth/`：参考补丁 + 业务断言 + 防御家族（真值变种）。
5. 搭 `whitebox/`：源码能拉取、能真编译、agent 能挂载审计。
6. 写 `case.json`（评测配置）+ `agent_task.json`（三份题面，写法见 schema §4：白盒只给源码和
   部署事实，蓝队不给任何漏洞线索）+ `case.env`（拓扑）。
7. 跑 `python ../../validate_case.py <case_dir>` 静态校验。
8. 跑 `python ../../evaluator/generic_env.py --case-dir <case_dir> --calibrate`，标定到 `final_score==1.0`。
9. 删 `.port-incomplete`，纳入 `run.py --all`。

## 哪些是"复制即可"、哪些是"必须自己写"

| 文件 | 说明 |
|---|---|
| `case.json` | **必须写**：评测配置（判据/重放/补丁/业务/防御，见 schema §3）。S5 段至少要有 `background_cmd`；`max_false_alarms` 默认 1，`include_whitebox_poc` 默认 true，crash 型必须写 false |
| `agent_task.json` | **必须写**：白盒攻击者与两段蓝队题面（见 schema §4） |
| `case.env` | **必须写**：网络拓扑（见 schema §5.4 / §5.5） |
| `traffic/replay_poc.py` | 可从任意既有 case（如 CVE-2021-41773）原样复制 |
| gateway / ndr / egress / runner | **不用复制**：compose 直接引用 `../../../components/` 下的公用镜像，见 `components/README.md` |
| `blackbox/docker-compose.yml` | 拓扑骨架（复制改名字即可，服务/网络结构固定） |
| `blackbox/target/`（业务外壳 + 漏洞载体） | **必须搭** |
| `blackbox/traffic/reference_poc.py`（攻击链）、`normal_traffic.py`（正常业务） | **必须写** |
| `blackbox/defense/blue_controller.py`（参考防御）+ `business_tests/`（回归） | **必须写** |
| `ground_truth/reference_patch.diff` 等 | **必须写** |
| `whitebox/service/`（fetch_source.sh + build.sh + Dockerfile） | **必须写**：源码拉取 + **补丁真编译**（`case.json` 的 `patch.build_cmd` 调它） |
| `organizer/evaluator/prepare_case.py` | **必须写**：一次性环境准备（拉源码 + 建镜像） |

## 快速上手

```bash
cp -r cases/_template cases/CVE-XXXX-XXXXX
# 1. 改 case.json / agent_task.json / case.env 里的占位符
# 2. 搭 blackbox 环境 + 写 ground_truth + whitebox 源码
# 3. 校验 + 标定
python ../../validate_case.py cases/CVE-XXXX-XXXXX
python ../../evaluator/generic_env.py --case-dir cases/CVE-XXXX-XXXXX --calibrate
```
