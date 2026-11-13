# blackbox/ —— 黑盒环境（模板说明）

黑盒线的攻击流量由出题人提供，蓝队只能看到 NDR 的流量。这里要建：

| 子目录 | 说明 | 谁写 |
|---|---|---|
| `<target>/` | **业务外壳 + 漏洞载体**：Dockerfile + 配置 + 合法业务（页面/功能）。漏洞藏在某个功能里 | 出题人 |
| `security_gateway/` | 网关（策略执行点 + 流量镜像投递；管理 API 只给宿主机） | **复制**（从 CVE-2021-41773 等） |
| `ndr/` | 旁路 NDR（`/traffic` 流量、`/alerts` 告警、`/rules` 规则下发） | **复制**（从 CVE-2021-41773 等） |
| `shared_egress/` | 透明 TCP 出口（数据面三类流量共用同一源 IP） | **复制** |
| `traffic/replay_poc.py` | poc.bin 逐字节重放驱动（通用） | **复制** |
| `traffic/reference_poc.py` | 参考攻击：无防御时能稳定打中漏洞（黑盒 S5/S6 的攻击流量） | 出题人 |
| `traffic/mutated_pocs.py` | 同类攻击的多种变种（S4），实现 `--run-all` | 出题人 |
| `traffic/normal_traffic.py` | 正常业务流量（真实用户怎么用） | 出题人 |
| `defense/blue_controller.py` | 参考防御：`NdrClient` + `detect(ndr)` + `contain(ndr)` | 出题人 |
| `defense/strategies.json` | 防御策略（检测特征 + 处置规则） | 出题人 |
| `business_tests/test_business.py` | 业务回归（pytest，S3/S7 判据） | 出题人 |
| `runner/Dockerfile` | 通用 runner 镜像（跑 traffic/defense/business） | **复制** |

**关键点**：蓝队是评测器临时起的独立 agent 容器，只通过 NDR 工作——compose 里**没有**蓝队服务，也不给任何容器挂答案（defense/traffic/ground_truth 都不挂）。蓝队与执行点之间隔着 NDR，看不到规则命中结果。

**服务命名**：语义裸名（`target` / `gateway` / `ndr` / `egress` / `traffic` / `normal`），不加前缀，不写 `container_name`；流量容器一律 `profiles: ["traffic"]` 一次性。
