# whitebox/ —— 白盒（模板说明）

白盒 agent 能看到源码、审计、改源码、重新编译。两个子目录：

| 子目录 | 说明 |
|---|---|
| `source/` | **白盒 agent 挂载的源码**（host_run 挂到 /challenge/source）。prepare_case.py 会物化到这里 |
| `service/` | **从源码真编译目标**：`Dockerfile`（FROM 干净源码 → configure → make → install）、`build.sh`（应用 patch 后编译成 patched 镜像）、`fetch_source.sh`（拉上游源码 + sha256 校验） |

**要点**：
- 漏洞语义与 blackbox 保持一致（同一份漏洞代码、同一份配置、同一份合法业务）。
- `service/` 必须**从源码构建**（不能 `FROM` 官方镜像），否则白盒"审计源码 → 打补丁 → 重编译"这条路走不通。
- 源码体积大，`.gitignore` 忽略 `service/vendor/`、`service/src/`、`source/`。
