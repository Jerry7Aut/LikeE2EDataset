#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""透明 TCP 转发器（公用镜像 `datasetlikee2e/transparent-proxy:1`）

同一个实现服务两个角色，所有 case 共用这一份：

    黑盒 shared_egress     共享出口（唯一入口之前的透明转发）
    白盒 security_gateway  环境入口（只记录、不拦截）

改这个文件等于改所有 case：改完重建镜像，再挑受影响的 case 重新标定。

为什么必须是「透明转发 + 原始字节送达上游」：

  1. 黑盒要求红队 / 秘密重放 / 正常业务三类流量的**真实源 IP 完全一致**，
     以消除「用容器 IP 区分红队」这一身份捷径；裸 TCP 转发天然满足，
     且对客户端就是「一个普通 HTTP 服务端」，无需任何客户端配合。
  2. 白盒曾经用 nginx 做入口，结果发现两个致命问题：
       * nginx 会在自己这一层对含 `..` 的 URI 返回 400，
         `.%2e` 穿越请求根本到不了 Apache —— 白盒复测会把「仍可利用」
         误判成「已修复」（假阴性）；
       * nginx 会把客户端的半关闭（`shutdown(SHUT_WR)`）判为 499。
     本仓库的黑盒/白盒复测客户端都使用裸 socket 半关闭语义。
  3. 本组件**不持有任何规则、不做匹配、不做处置、不改写任何 Header**。
     它只在日志里记录请求行，作为「请求确实经过该入口」的归属证据。

半关闭处理：读到 EOF 时只能 `write_eof()`，不能 `close()`。
客户端发完请求会 `shutdown(SHUT_WR)`，直接 close 会拆掉整条上游连接，
表现为客户端收到 0 字节。
"""
from __future__ import annotations

import asyncio
import os
import sys

LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "80"))
UPSTREAM_HOST = os.environ.get("UPSTREAM_HOST", "gateway")
UPSTREAM_PORT = int(os.environ.get("UPSTREAM_PORT", "80"))
CONNECT_TIMEOUT = float(os.environ.get("CONNECT_TIMEOUT", "10"))
IDLE_TIMEOUT = float(os.environ.get("IDLE_TIMEOUT", "120"))
LOG_REQUESTS = os.environ.get("LOG_REQUESTS", "1") == "1"
ROLE = os.environ.get("PROXY_ROLE", "transparent-proxy")


def log(msg: str) -> None:
    print(f"[{ROLE}] {msg}", flush=True)


def _request_line(data: bytes) -> str:
    line = data.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    return line.decode("iso-8859-1", "replace")[:300]


async def _pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                on_first=None) -> None:
    first = True
    try:
        while True:
            data = await asyncio.wait_for(reader.read(65536), timeout=IDLE_TIMEOUT)
            if not data:
                break
            if first:
                first = False
                if on_first is not None:
                    on_first(data)
            writer.write(data)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionError, asyncio.IncompleteReadError):
        pass
    except Exception:  # noqa: BLE001 - 单连接异常不应让入口退出
        pass
    finally:
        # 只半关闭：客户端会先 shutdown(SHUT_WR)，close() 会拆掉上游连接
        try:
            if writer.can_write_eof():
                writer.write_eof()
            else:
                writer.close()
        except Exception:  # noqa: BLE001
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass


async def handle(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
    peer = client_writer.get_extra_info("peername")
    try:
        up_reader, up_writer = await asyncio.wait_for(
            asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT), timeout=CONNECT_TIMEOUT)
    except Exception as exc:  # noqa: BLE001
        log(f"upstream {UPSTREAM_HOST}:{UPSTREAM_PORT} unreachable for {peer}: {exc}")
        try:
            client_writer.close()
        except Exception:  # noqa: BLE001
            pass
        return

    def _on_first(data: bytes) -> None:
        if LOG_REQUESTS:
            # 只记录请求行原文；不解析、不改写、不据此做任何决策
            log(f"{peer[0]}:{peer[1]} -> {_request_line(data)}")

    await asyncio.gather(
        _pump(client_reader, up_writer, on_first=_on_first),
        _pump(up_reader, client_writer),
    )
    for w in (up_writer, client_writer):
        try:
            w.close()
        except Exception:  # noqa: BLE001
            pass


async def main() -> None:
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    log(f"listening {LISTEN_HOST}:{LISTEN_PORT} -> {UPSTREAM_HOST}:{UPSTREAM_PORT} "
        f"(transparent, no rules, no rewriting)")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
