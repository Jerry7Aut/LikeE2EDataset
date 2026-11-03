#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gen_squid.py — 从 team.env 的模型端点生成 egress 代理（squid）白名单配置。

强制「agent 只能访问模型端点，禁止联网搜索/浏览」：squid 只放行 MODEL_BASE_URL 的
host，其余一律 deny。模型 host 由 team.env（或宿主机 OPENAI_BASE_URL）推导，通用、独立于赛题。

用法：
  python gen_squid.py --team-env ../../team.env --out organizer/egress/squid.conf
"""
import argparse
import os
from urllib.parse import urlparse

import envfile


def model_hosts(team_env_path):
    """从 team.env（或宿主机 OPENAI_BASE_URL）提取模型端点 host。"""
    data = envfile.parse(team_env_path) if team_env_path else {}
    base = data.get("MODEL_BASE_URL") or os.environ.get("OPENAI_BASE_URL")
    if not base:
        return []
    host = urlparse(base).hostname
    return [host] if host else []


def parent_proxy(team_env_path):
    """可选的上级代理（team.env 的 EGRESS_PARENT_PROXY）。

    内网机器没有直连外网时，squid 自己不解析域名、不直连，全部交给上级代理：
    既保留「只放行模型 host」的白名单，又不需要机器本身能出网。
    支持 ``host:port`` 或 ``http://host:port``。
    """
    data = envfile.parse(team_env_path) if team_env_path else {}
    raw = (data.get("EGRESS_PARENT_PROXY") or "").strip()
    if not raw:
        return None
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    host, _, port = raw.partition(":")
    if not host:
        return None
    return host, int(port or "3128")


def render(hosts, parent=None):
    if hosts:
        acl_lines = "\n".join(f"acl model_host dstdomain {h}" for h in hosts)
        allow_lines = ("http_access allow CONNECT model_host\n"
                       "http_access allow model_host")
    else:
        acl_lines = "# （未声明模型端点：默认全拒，agent 无法出网）"
        allow_lines = ""
    peer_lines = ""
    if parent:
        peer_lines = (f"cache_peer {parent[0]} parent {parent[1]} 0 no-query default\n"
                      "never_direct allow all\n")
    return f"""# squid.conf —— egress 代理白名单（自动生成，勿手改）
# agent 只能访问模型端点（MODEL_BASE_URL 的 host），其余一律 deny，禁止联网搜索。
# 重新生成：python gen_squid.py --team-env ../../team.env --out squid.conf

acl SSL_ports port 443
acl Safe_ports port 443
acl CONNECT method CONNECT
{acl_lines}

http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
{allow_lines or "http_access deny all"}
http_access deny all
{peer_lines}
http_port 3128
dns_v4_first on
cache deny all
coredump_dir /var/spool/squid
"""


def gen(team_env_path, out_path):
    """生成并写回 squid.conf，返回放行的 host 列表。"""
    hosts = model_hosts(team_env_path)
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(render(hosts, parent_proxy(team_env_path)))
    return hosts


def main():
    ap = argparse.ArgumentParser(description="生成 squid egress 白名单配置")
    ap.add_argument("--team-env", default=None, help="team.env 路径（读 MODEL_BASE_URL）")
    ap.add_argument("--out", required=True, help="输出 squid.conf 路径")
    a = ap.parse_args()
    hosts = gen(a.team_env, a.out)
    print(f"squid.conf -> {a.out}（放行 {hosts or '无，默认全拒'}）")


if __name__ == "__main__":
    main()
