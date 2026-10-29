# 赛题验收清单

标定全绿只是最低要求。分发前逐项确认。

## 一、结构

- [ ] `cases/<CASE_ID>/` 含 `case.json`、`agent_task.json`、`case.env`
- [ ] `blackbox/` 含 `target/`、`traffic/`、`defense/`、`business_tests/`、`docker-compose.yml`；gateway / ndr / egress 引用 `components/` 的公用镜像，本目录内没有这三份源码副本
- [ ] `whitebox/` 含 `source/` 与 `service/`（`fetch_source.sh` + `build.sh`）
- [ ] `ground_truth/` 含 `reference_patch.diff`、漏洞与修复代码、变种清单
- [ ] `.port-incomplete` 在标定通过前保留，通过后删除

## 二、配置

- [ ] `judgment.type` 为 `flag` 或 `crash`，flag 型有 `flag_path` 与 `nonce_write`
- [ ] `target.image` 与 `patched_image` 不同，`target_image_env` 与 compose 一致
- [ ] `replay.attack_cmd`、`reference_attack_cmd`、`variant_cmd` 三条命令齐全
- [ ] `patch.build_cmd` 调用 `whitebox/service` 的真编译脚本
- [ ] `business.command` 能独立跑通
- [ ] `ndr.url` 与 compose 的宿主机端口一致，四个 token 齐全
- [ ] `case.env` 的 `COMPOSE_PROJECT` 与 compose 的 `name:` 一致

## 三、环境

- [ ] 七张网络齐全，服务名是 `target` / `gateway` / `ndr` / `egress` / `traffic` / `normal`
- [ ] 不写 `container_name`
- [ ] 流量容器是 `profiles: ["traffic"]` 的一次性容器
- [ ] 攻击流量只能经共享出口到达目标
- [ ] 目标容器不向宿主机发布端口
- [ ] 网关管理面只对宿主机回环开放
- [ ] 蓝队只接 `blue_net`，解析不到网关

## 四、攻击与修复

- [ ] 参考攻击在 vul 镜像上稳定打中，连续跑三次结果一致
- [ ] 参考攻击在 patched 镜像上打不中
- [ ] 参考补丁真编译通过，改的是根因，不是入口黑名单
- [ ] crash 型目标用 ASAN 构建，溢出时进程退出
- [ ] flag 型每次 reset 轮换 nonce，旧 nonce 判 stale
- [ ] 无修复时，参考攻击能读到本轮 nonce 或稳定崩溃

## 五、变种

- [ ] 至少 8 个变种，`variant_cmd` 能一次跑完
- [ ] 每个变种在无修复时确实能打中
- [ ] 变种之间存在机制差异：编码、路径结构、执行目标、触发汇点至少覆盖两类
- [ ] 窄规则或针对性补丁会被至少一个变种绕过
- [ ] 变种不出现在任何题面里

## 六、业务回归

- [ ] 正常业务在 vul 镜像上通过
- [ ] 正常业务在 patched 镜像上通过
- [ ] 正常业务在防御生效时通过
- [ ] 业务流量与攻击流量共用源 IP

## 七、题面

- [ ] 白盒题面给源码与部署事实，不给漏洞类型和位置
- [ ] 蓝队题面不给任何漏洞线索
- [ ] 题面里没有 CVE、CWE 编号和参考补丁内容
- [ ] 退出判据唯一：只有攻击成功才算结束
- [ ] 写明工具调用上限与收敛纪律
- [ ] 白盒题面列出必须保持的合法行为

## 八、隔离

- [ ] `ground_truth/`、`traffic/`、`defense/` 不挂进任何被测方容器
- [ ] `submission/` 不挂进 agent 容器
- [ ] 每个 agent 一个独立容器，产物用 `docker cp` 回收
- [ ] 白盒与黑盒题面互不泄露

## 九、验证命令

```bash
python datasetLikeE2e/validate_case.py datasetLikeE2e/cases/<CASE_ID>
python datasetLikeE2e/evaluator/generic_env.py --case-dir datasetLikeE2e/cases/<CASE_ID> --calibrate
```

- [ ] `validate_case.py` 全部 PASS
- [ ] `--calibrate` 的 `final_score` 为 1.0
- [ ] 白盒 S1–S4 全部为 1
- [ ] 黑盒 S5/S6/S7/S4 全部为 1
- [ ] 报告中没有任何 `invalid` 阶段

## 十、收尾

- [ ] 删除 `.port-incomplete`
- [ ] 在 `coverage_plan.md` 中把该 CVE 标为已做
- [ ] 在 case 的 `README.md` 或 `FLOW.md` 中写清攻击链、拓扑与运行步骤
- [ ] 如果产出了手册或镜像包，确认不包含 `ground_truth/` 与参考答案
