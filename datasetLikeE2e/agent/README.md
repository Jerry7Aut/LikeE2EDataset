# agent 标准接口（datasetLikeE2e/agent）

> **通用基础设施，独立于赛题。** 一套 agent+model 环境用于所有赛题；赛题只提供一份
> `agent_task.json`（逐题替换的任务内容，位于赛题根目录）+ 源码/日志挂载。评测对象 = **完整
> agent**（harness + 模型），不是单模型。

## 1. 两种参赛方式

| | 方式 | 做题方提供什么 | 测什么 |
|---|---|---|---|
| **Option 1** | 预置 agent + 自接模型 | 只有模型（端点/key） | 用开源 harness 接自己模型的能力 |
| **Option 2** | 自研 agent + 自接模型 | 完整 harness + 模型 | 完整 agent 工程能力 |

- Option 1：镜像已预置 **Codex CLI**（`codex exec`）和 **Qwen Code**（`qwen -p`），
  做题方只注入 `OPENAI_*` 环境变量接自己的模型即可。
- Option 2：做题方把自研 harness 挂到 `/challenge/agent/entrypoint.sh`，覆盖预置入口。

## 2. 标准接口（固定，不可改）

宿主这样拉起 agent 容器（容器内 `run_agent.sh` 是组织方固定启动器）：

```
docker run --rm <agent镜像> run_agent.sh \
    --mode whitebox|blackbox --role attacker|defender \
    --task /challenge/task.json --output /submission/ --timeout 1800
```

`run_agent.sh` 校验并调用 `/challenge/agent/entrypoint.sh`（做题方交付的 harness 入口），
用 `timeout` 兜底，透传退出码：**0 = 该阶段正常完成，非 0 = 该阶段记 0 分**。

### 模型访问（环境变量，OpenAI 兼容）

| 变量 | 含义 |
|---|---|
| `OPENAI_BASE_URL` | 模型端点，如 `https://api.deepseek.com/v1` |
| `OPENAI_API_KEY` | 模型密钥 |
| `OPENAI_MODEL` | 模型名，如 `deepseek-chat` |

- Qwen Code 直接读这三个变量（也兼容 `ANTHROPIC_*` / `GEMINI_*`）。
- Codex 由 `entrypoint.codex.sh` 生成 `~/.codex/config.toml`（`wire_api="responses"`）。
  **注意**：端点必须支持所选 agent 的协议 —— Codex 走 Responses，Qwen Code 走 chat
  completions。实测 `open.bigmodel.cn` 的 `glm-5.3` 只有 Responses 可用
  （`/chat/completions` 返回 403 `model_access_denied`），这类端点只能配 codex，
  配 qwencode 会一次都调不通。

### codex 行为开关（默认值就是评测口径）

`entrypoint.codex.sh` 默认往 config.toml 写两项配置，它们直接改变被测 agent 的实际
能力，不要随手删：

| 配置 | 默认 | 为什么 |
|---|---|---|
| `model_reasoning_effort` | `high` | codex 只对内置元数据认识的模型名决定推理强度，遇到不认识的模型名（国产端点常见）会回落到 `none`，等于把推理模型的思维链整个关掉，评测会系统性低估推理型模型 |
| `web_search` | `disabled` | codex 默认开启联网搜索，而且这个工具由**模型服务端**执行、不经过容器的 egress 代理，题目侧的网络隔离拦不住（实测能搜到上游安全公告与 oss-security 邮件列表）。评测要防「搜到现成 PoC」，所以默认关掉 |

两项都可以由 `team.env` 的 `MODEL_REASONING_EFFORT` / `MODEL_WEB_SEARCH` 覆盖
（`host_run.py` 把它们透传成容器里的 `CODEX_REASONING_EFFORT` / `CODEX_WEB_SEARCH`）。

## 3. 逐题替换：agent_task.json

每道赛题在 `agent_task.json`（赛题根目录）提供角色任务内容（`roles` 下按
`whitebox_attacker` / `blackbox_defender_s5` / `blackbox_defender_s6` 命名），`gen_task.py`
据此生成 task.json。黑盒线没有攻击者角色，攻击流量由出题人提供。字段：

| mode/role | 输入字段 | 产出文件 |
|---|---|---|
| whitebox / attacker | `src_dir` + 漏洞描述 | `whitebox/poc.bin` + `whitebox/patch.diff` |
| blackbox / defender（phase=s5） | `ndr_api` + `deploy_instructions`（读流量 + 交告警） | `blackbox/alerts.json`（存档，不判分） |
| blackbox / defender（phase=s6） | `ndr_api` + `deploy_instructions`（读告警 + 部署规则） | `blackbox/block.policy`（存档，不判分） |

## 4. 文件清单（全通用，无赛题内容）

| 文件 | 谁提供 | 作用 |
|---|---|---|
| `Dockerfile` | 组织方 | 预置 codex + qwen-code 的 agent 镜像 |
| `run_agent.sh` | 组织方（固定） | 标准接口容器侧启动器 |
| `entrypoint.codex.sh` / `entrypoint.qwencode.sh` | 组织方（参考） | option 1 的预置 harness 入口 |
| `prompt.py` | 组织方 | task.json → 任务指令 |
| `gen_task.py` | 组织方 | 读赛题 agent_task.json → task.json |
| `host_run.py` | 组织方 | 宿主侧驱动（跑 agent + 收产物） |
| `/challenge/agent/entrypoint.sh` | **做题方** | 真正的 harness 入口（option 1 用参考入口，option 2 自研） |

## 5. 跑一次（示例：白盒攻击者 + Codex）

```bash
export OPENAI_BASE_URL=https://api.deepseek.com/v1 OPENAI_API_KEY=sk-... OPENAI_MODEL=deepseek-chat
docker compose -f datasetLikeE2e/samples/CVE-2025-24928/organizer/docker-compose.yml up -d
python datasetLikeE2e/agent/host_run.py \
    --case-dir datasetLikeE2e/samples/CVE-2025-24928 \
    --mode whitebox --role attacker --agent codex --build
```

## 6. 与判分管线的衔接

`host_run.py` 只「跑 agent 收产物」，判分由通用引擎 `evaluator/generic_env.py` 读各赛题的
`case.json` 完成（**出题人不写评测代码**）。`generic_env.py --run-agent` 已把 agent
接入闭环：白盒攻击者（poc.bin + patch.diff）→ 出题方攻击流量进 NDR → 蓝队检测会话
（读 `/traffic` + 交 `/alerts`）→ 蓝队处置会话（读 `/alerts` + 部署 `/rules`），
S5/S6/S8 按「部署后的真实重放效果」判分。黑盒线没有攻击者角色。`alerts.json` 与
`block.policy` 只是存档形式（自然语言/JSON 均可），不参与判分 —— 防御的**真实交付物是
NDR 里实际提交的告警与规则**。

> 产物命名对齐既有代码：白盒修复产物用 **`patch.diff`**（`patch_build.py` 实际读取）。

## 7. 配置两文件：team.env（被测方）+ case.env（赛题）

agent 环境读两个 `.env`，不再硬编码任何网络名/端点：

| 文件 | 谁维护 | 内容 |
|---|---|---|
| `datasetLikeE2e/team.env` | **被测方**（一份） | 模型 `MODEL_BASE_URL`/`MODEL_API_KEY`/`MODEL_NAME`、agent 选择 `AGENT`（`codex`\|`qwencode`\|`custom`）+ `CUSTOM_ENTRYPOINT`、队伍 `TEAM_ID` |
| `<case>/case.env` | **赛题**（一份） | 网络拓扑 `COMPOSE_PROJECT` + 网络名、`AGENT_NETWORK`/`EGRESS_PROXY`/`NO_PROXY`、白盒攻击者 join 的 `BLACKBOX_ATTACKER_NETWORK`、蓝队 join 的 `BLACKBOX_DEFENDER_NETWORK` + `NDR_API` |

模板见 `datasetLikeE2e/team.env.example`（复制为 `team.env` 填真实值；`MODEL_API_KEY` 是机密，
建议不进版本库）。`team.env` 缺失时回落到宿主机 `OPENAI_*` 环境变量（旧用法仍可用）。

### 出网管控（禁止联网搜索）

agent 容器**无直连外网**：它只 join `agent_net`（internal，无公网路由），模型访问经
`egress_proxy`（squid）出网，白名单 = `MODEL_BASE_URL` 的 host，其余全拒（`gen_squid.py`
在 compose up 前自动生成 `organizer/egress/squid.conf`）。白盒攻击者额外 join
`case.env` 的 `BLACKBOX_ATTACKER_NETWORK`（entry_net，已 `internal` 关闭外网），经
`NO_PROXY` 直连共享出口。黑盒蓝队分两段会话（检测、处置），额外 join
`BLACKBOX_DEFENDER_NETWORK`（blue_net），经 `NDR_API`（`http://ndr:8080`）读流量、
提交告警、部署规则，`ndr` 已列入 `NO_PROXY` 直连。

> 待验证点：codex/qwen-code 是否认 `HTTPS_PROXY`——若不认，模型调用会失败，需在 agent
> 镜像里装 `global-agent` 或设 `NODE_USE_ENV_PROXY=1`，或改透明代理。
