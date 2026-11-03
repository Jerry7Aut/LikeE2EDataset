#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""host_run.py — 宿主侧驱动（通用，独立于赛题）：生成 task.json → 跑 agent 容器 → 收产物。

这是「agent 标准接口落地」的宿主侧：把 agent 容器跑起来、让它现场产出 /submission/ 下的
交付物。判分走各赛题 evaluator/generic_env.py（真编译+重放），本模块只负责
「跑 agent、收产物」，不判分。一套环境用于所有赛题，赛题差异只来自 --case-dir。

配置两文件（谁维护什么）：
  team.env —— 被测方维护一个：模型端点 / agent 选择 / 队伍身份（MODEL_* / AGENT / CUSTOM_ENTRYPOINT / TEAM_ID）
  case.env —— 赛题维护一个：网络拓扑 + agent 网络策略（网络名 / EGRESS_PROXY / NO_PROXY）
本模块读这两个文件，不再硬编码任何网络名；黑盒攻击者 join 的网由 case.env 决定。
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import envfile
import gen_task

AGENT_DIR = os.path.dirname(os.path.abspath(__file__))       # datasetLikeE2e/agent/
DATASET_DIR = os.path.dirname(AGENT_DIR)                     # datasetLikeE2e/
IMAGE = "datasetlikee2e/agent:v1"
DEFAULT_CASE = os.path.join(DATASET_DIR, "samples", "CVE-2025-24928")
DEFAULT_TEAM_ENV = os.path.join(DATASET_DIR, "team.env")


def _run(cmd, **kw):
    print("+", " ".join(cmd))
    return subprocess.run(cmd, **kw)


def run_agent(case_dir, mode, role, agent=None, custom_entrypoint=None,
              submission_dir=None, log_file=None, image=IMAGE, timeout=1800,
              build=False, team_env_path=None, case_env_path=None, phase=None) -> int:
    """跑一个 agent 容器产出交付物，返回退出码（0=正常，非 0=该阶段记 0 分）。

    phase 仅对黑盒防御者有意义：同一个 defender 角色分两段会话，
    s5 看 NDR 流量交告警、s6 读告警部署规则。
    """
    case = os.path.abspath(case_dir)
    spec_path = os.path.join(case, "agent_task.json")
    if not os.path.exists(spec_path):
        raise SystemExit(f"缺赛题任务规格：{spec_path}")

    # —— 配置：team.env（被测方）+ case.env（赛题拓扑）——
    team_env = envfile.parse(team_env_path or DEFAULT_TEAM_ENV)
    case_env = envfile.parse(case_env_path or os.path.join(case, "case.env"))

    agent = agent or team_env.get("AGENT") or "codex"
    submission_dir = os.path.abspath(submission_dir or os.path.join(case, "submission"))
    os.makedirs(submission_dir, exist_ok=True)

    # 模型端点：team.env MODEL_* → 容器 OPENAI_*（宿主机 OPENAI_* 兜底，兼容旧用法）
    model = {
        "OPENAI_BASE_URL": team_env.get("MODEL_BASE_URL") or os.environ.get("OPENAI_BASE_URL"),
        "OPENAI_API_KEY": team_env.get("MODEL_API_KEY") or os.environ.get("OPENAI_API_KEY"),
        "OPENAI_MODEL": team_env.get("MODEL_NAME") or os.environ.get("OPENAI_MODEL"),
    }
    # codex 侧行为开关（可选）：推理强度 / 联网搜索。缺省由 entrypoint 兜底
    # （high / disabled，理由见 entrypoint.codex.sh 的注释）；这里只在被测方
    # 显式声明时透传，用来覆盖默认值。
    for container_key, team_key in (("CODEX_REASONING_EFFORT", "MODEL_REASONING_EFFORT"),
                                    ("CODEX_WEB_SEARCH", "MODEL_WEB_SEARCH")):
        v = team_env.get(team_key)
        if v:
            model[container_key] = v

    # 网络：由 case.env 决定（不再硬编码 organizer_client_net）
    agent_net = case_env.get("AGENT_NETWORK")
    egress_proxy = case_env.get("EGRESS_PROXY")
    no_proxy = case_env.get("NO_PROXY")
    blue_api = case_env.get("BLUE_API")
    ndr_api = case_env.get("NDR_API")
    networks = [agent_net] if agent_net else []
    if role == "attacker":
        # 白盒/黑盒攻击者都 join 业务网：白盒也要能打到目标做「复现验证 + 失败重试」
        # （任务语义 = 复现，agent 应迭代到真正触发，而不是盲投一次就交）
        biz_net = case_env.get("BLACKBOX_ATTACKER_NETWORK") or case_env.get("CLIENT_NETWORK")
        if biz_net:
            networks.append(biz_net)
    elif (mode, role) == ("blackbox", "defender"):
        mgmt_net = case_env.get("BLACKBOX_DEFENDER_NETWORK") or case_env.get("MANAGEMENT_NETWORK")
        if mgmt_net:
            networks.append(mgmt_net)

    # 1. 生成 task.json（临时文件，供挂载）
    task = gen_task.build(gen_task.load_spec(spec_path), mode, role, timeout, phase=phase)
    tmp = tempfile.mkdtemp(prefix="agent_task_")
    task_path = os.path.join(tmp, "task.json")
    with open(task_path, "w", encoding="utf-8") as f:
        json.dump(task, f, ensure_ascii=False, indent=2)

    # 2. 选 entrypoint：预置（codex/qwencode）或做题方自研（custom）
    if agent == "custom":
        ep = custom_entrypoint or os.path.join(AGENT_DIR, "entrypoint.codex.sh")
    else:
        ep = os.path.join(AGENT_DIR, f"entrypoint.{agent}.sh")

    # 3. 构建镜像（context = agent/，Dockerfile 的 COPY 相对此目录）
    if build:
        r = _run(["docker", "build", "-t", image,
                  "-f", os.path.join(AGENT_DIR, "Dockerfile"), AGENT_DIR])
        if r.returncode != 0:
            raise SystemExit("agent 镜像构建失败")

    # 4. 组装 docker run（每个 agent 独立容器，输出留在容器内 /submission/，
    #    跑完后宿主 docker cp 回 submission/，不共享挂载 → agent 之间互看不到产物）
    import uuid
    tag = f"{mode}-{role}" + (f"-{phase}" if phase else "")
    container = f"agent-{tag}-{uuid.uuid4().hex[:8]}"
    cmd = ["docker", "create", "--name", container,
           "-v", f"{ep}:/challenge/agent/entrypoint.sh:ro",
           "-v", f"{task_path}:/challenge/task.json:ro"]
    # prompt.py 也从宿主机挂载（覆盖镜像内副本）：改提示词无需重建 agent 镜像
    prompt_py = os.path.join(AGENT_DIR, "prompt.py")
    if os.path.isfile(prompt_py):
        cmd += ["-v", f"{prompt_py}:/opt/agent/prompt.py:ro"]
    if mode == "whitebox":
        cmd += ["-v", f"{os.path.join(case, 'whitebox', 'source')}:/challenge/source:ro"]
    if role == "defender" and log_file:
        cmd += ["-v", f"{os.path.abspath(log_file)}:/challenge/logs/app.log:ro"]

    for k, v in model.items():
        if v:
            cmd += ["-e", f"{k}={v}"]

    # 蓝队部署接口（黑盒防御者读日志 + 部署防御用；由 case.env 提供）
    if blue_api:
        cmd += ["-e", f"BLUE_API={blue_api}"]
    if ndr_api:
        cmd += ["-e", f"NDR_API={ndr_api}"]

    # 出网管控：agent 只能经 egress 代理访问模型；内网目标直连（NO_PROXY）
    if egress_proxy:
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            cmd += ["-e", f"{k}={egress_proxy}"]
    if no_proxy:
        for k in ("NO_PROXY", "no_proxy"):
            cmd += ["-e", f"{k}={no_proxy}"]

    # 老版本 Docker（20.10 等）不允许 docker run 同时带多个 --network，
    # 但允许先 create 再逐条 network connect。新版本两种写法都支持。
    if networks:
        cmd += ["--network", networks[0]]

    cmd += [image,
            "--mode", mode, "--role", role,
            "--task", "/challenge/task.json", "--output", "/submission/",
            "--timeout", str(timeout)]

    r = _run(cmd)
    if r.returncode == 0:
        for n in networks[1:]:
            c = _run(["docker", "network", "connect", n, container])
            if c.returncode != 0:
                print(f"[host_run] 连接网络 {n} 失败，agent 可能访问不到目标")
        r = _run(["docker", "start", "-a", container])

    # 5. 把容器内产出 copy 回宿主 submission/（容器无共享挂载，产物留在容器层）
    os.makedirs(submission_dir, exist_ok=True)
    cp = _run(["docker", "cp", f"{container}:/submission/.", submission_dir])
    if cp.returncode != 0:
        # cp 失败（如 WSL2 宿主挂载抖动）：保留容器不删，产物可人工 docker cp 抢救
        print(f"[host_run] 警告：docker cp 失败，容器 {container} 已保留（可手动 docker cp 抢救产物）。"
              f"agent 退出码 {r.returncode}")
    else:
        _run(["docker", "rm", "-f", container])

    print(f"\n[host_run] {mode}/{role} agent 退出码 = {r.returncode}（0=正常，非 0=该阶段记 0）")
    for root, _, files in os.walk(submission_dir):
        for fn in files:
            print("  -", os.path.join(root, fn))
    return r.returncode


def main():
    ap = argparse.ArgumentParser(description="跑一个 agent 容器产出交付物（通用）")
    ap.add_argument("--case-dir", default=DEFAULT_CASE,
                    help="赛题目录（含 agent_task.json 与 whitebox/source）")
    ap.add_argument("--mode", required=True, choices=["whitebox", "blackbox"])
    ap.add_argument("--role", required=True, choices=["attacker", "defender"])
    ap.add_argument("--agent", default=None, choices=["codex", "qwencode", "custom"],
                    help="agent 类型（缺省读 team.env 的 AGENT）")
    ap.add_argument("--custom-entrypoint", default=None)
    ap.add_argument("--submission-dir", default=None, help="缺省 = <case-dir>/submission")
    ap.add_argument("--log-file", default=None, help="黑盒防御者：宿主上的应用日志路径")
    ap.add_argument("--image", default=IMAGE)
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--build", action="store_true", help="先 docker build agent 镜像")
    ap.add_argument("--team-env", default=None, help="被测方 team.env（缺省 datasetLikeE2e/team.env）")
    ap.add_argument("--case-env", default=None, help="赛题 case.env（缺省 <case>/case.env）")
    a = ap.parse_args()

    rc = run_agent(a.case_dir, a.mode, a.role, agent=a.agent,
                   custom_entrypoint=a.custom_entrypoint,
                   submission_dir=a.submission_dir, log_file=a.log_file,
                   image=a.image, timeout=a.timeout, build=a.build,
                   team_env_path=a.team_env, case_env_path=a.case_env)
    sys.exit(rc)


if __name__ == "__main__":
    main()
