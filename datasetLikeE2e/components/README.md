# components —— 公用镜像

黑盒环境里有三个组件对所有 case 完全一致，只是环境变量不同：安全网关、旁路 NDR、透明代理。它们放在这里各存一份，各 case 的 `docker-compose.yml` 用相对路径引用源码，并用仓库级镜像名。

| 目录 | 镜像 | 在 compose 里的服务 |
|---|---|---|
| `security_gateway/` | `datasetlikee2e/policy-gateway:1` | `gateway`：唯一策略执行点 + 蓝队 API + NDR 镜像源 |
| `ndr/` | `datasetlikee2e/ndr:1` | `ndr`：蓝队的观测与处置平台，规则转发给网关 |
| `transparent_proxy/` | `datasetlikee2e/transparent-proxy:1` | 黑盒 `egress`（共享出口）、白盒入口 `wb_security_gateway` |
| `runner/` | `datasetlikee2e/runner:1` | 流量运行器、复测客户端、白盒 agent（python + requests + pytest） |

各 case 的 compose 这样引用，不再复制源码：

```yaml
  gateway:
    build:
      context: ../../../components/security_gateway
    image: datasetlikee2e/policy-gateway:1
```

`build.context` 是相对 compose 文件本身的路径，所以同一份源码在六道题里都构建成同一个 tag；BuildKit 会命中缓存，只有源码变了才真正重编。

## 改组件的流程

1. 只改这里的源码。
2. 重建：`make components`，或在任意一道题的 `cases/<CASE>/blackbox/` 下 `docker compose up -d --build`。
3. **回归标定受影响的 case**。镜像变了不等于行为等价，尤其改网关的数据面时，要重跑 `generic_env.py --calibrate` 的那几道题。

组件是全题共用，一处失误会同时影响所有 case，所以改完必须标定，不能只看编译通过。

## 各 case 的差异只有环境变量

网关：

| 变量 | 作用 |
|---|---|
| `GATEWAY_UPSTREAM_HOST` / `GATEWAY_UPSTREAM_PORT` | 上游业务服务，默认 `target:80` |
| `GATEWAY_NDR_URL` / `GATEWAY_NDR_INGEST_TOKEN` | 旁路镜像的目标 |
| `GATEWAY_ADMIN_TOKEN` / `GATEWAY_S5_TOKEN` / `GATEWAY_S6_TOKEN` | 评测器、S5 只读、S6 读写 |
| `GATEWAY_HEADER_BRIEF_CHARS` / `GATEWAY_BODY_BRIEF_CHARS` | 观测视图的截断长度，不影响规则匹配 |
| `GATEWAY_MAX_HEADER_BYTES` / `GATEWAY_MAX_BODY_BYTES` / `GATEWAY_HEADER_TIMEOUT` | 缓冲上限 |

NDR：

| 变量 | 作用 |
|---|---|
| `GATEWAY_MGMT_URL` / `NDR_GATEWAY_TOKEN` | 规则下发给网关的地址与凭据 |
| `NDR_INGEST_TOKEN` / `NDR_BLUE_TOKEN` / `NDR_RULE_TOKEN` / `NDR_ADMIN_TOKEN` | 四类凭据 |

透明代理：

| 变量 | 作用 |
|---|---|
| `UPSTREAM_HOST` / `UPSTREAM_PORT` | 转发目标 |
| `PROXY_ROLE` / `LISTEN_PORT` / `LOG_REQUESTS` | 角色标识、监听端口、是否记录请求行 |

## 分发时的注意

单个 case 目录不再是自包含的：拷到别处要么连 `components/` 一起带上并保持 `cases/<CASE>/blackbox/` 的相对位置，要么预先导入这三个镜像后再 `docker compose up`（不要加 `--build`）。
