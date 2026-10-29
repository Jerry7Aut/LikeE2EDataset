# runner — 红队 / 流量运行器 / 正常客户端 / 白盒复测客户端 / 白盒 Agent
# 共用的轻量镜像。
#
# 公用镜像 `datasetlikee2e/runner:1`：所有 case 的流量运行器、复测客户端与
# 白盒 agent 共用这一份，compose 只引用镜像，不复制源码。
#
# 职责差异靠「挂载什么、跑什么命令」区分，不靠镜像区分：
#   * 黑盒 red_agent   只挂 submission/red_team，能发 HTTP；
#   * 黑盒 traffic_runner 挂 traffic/ + business_tests/，跑参考 PoC 与 pytest；
#   * 白盒 wb_runner    挂 traffic/ + business_tests/ + submission/whitebox；
#   * 白盒 wb_agent     挂源码（只读）+ submission/whitebox，供源码审计工具循环使用。
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN pip install \
        "requests>=2.31,<3" \
        "pytest>=8,<9"

WORKDIR /work

CMD ["python", "-c", "print('runner image ready')"]
