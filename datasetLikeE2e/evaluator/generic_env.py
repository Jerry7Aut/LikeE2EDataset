#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""generic_env.py — 通用评测引擎（配置驱动，出题人不写代码）

读赛题根的 case.json，实现共享 evaluate.py 的 Environment 8 个方法。支持：
  * 判据类型：flag（nonce oracle，http 重放找 nonce）/ crash（攻击链命令，返回码=崩溃）
  * 业务回归：pytest / http 请求列表
  * 补丁真编译：case.json 声明的 shell 命令（{patch} 占位符替换为补丁绝对路径）

出题人只需提供：环境（blackbox/ + whitebox/ + ground_truth/）+ case.json +
agent_task.json + case.env，不再写任何 Python。

用法（run.py 内部调用，也可直接跑）：
  python evaluator/generic_env.py --case-dir <case> --run-agent
  python evaluator/generic_env.py --case-dir <case> --calibrate
"""
import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
import urllib.request

DATASET_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # datasetLikeE2e/
sys.path.insert(0, os.path.join(DATASET_DIR, "evaluator"))
sys.path.insert(0, os.path.join(DATASET_DIR, "agent"))

from evaluate import Environment, run_whitebox, run_blackbox, run_all       # noqa: E402
from retry import InfrastructureError                                       # noqa: E402
from oracle import Oracle                                                   # noqa: E402
import s5_judge                                                             # noqa: E402
import envfile                                                              # noqa: E402
import gen_squid                                                            # noqa: E402
import host_run                                                             # noqa: E402


def load_config(case_dir):
    """读 case.json，返回带默认值的 dict。"""
    p = os.path.join(case_dir, "case.json")
    if not os.path.isfile(p):
        raise SystemExit(f"缺赛题配置：{p}（配置驱动评测器，出题人只写 case.json，不写代码）")
    with open(p, encoding="utf-8") as f:
        cfg = json.load(f)
    if not cfg.get("case_id"):
        raise SystemExit("case.json 缺 case_id")
    return cfg


def find_bash():
    cands = [shutil.which("bash"),
             r"C:\Program Files\Git\bin\bash.exe",
             r"C:\Program Files\Git\usr\bin\bash.exe",
             r"C:\Program Files (x86)\Git\bin\bash.exe"]
    for b in cands:
        if b and os.path.isfile(b):
            try:
                r = subprocess.run([b, "-c", "set -o pipefail && echo ok"],
                                   capture_output=True, text=True, timeout=15)
                if r.returncode == 0 and "ok" in r.stdout:
                    return b
            except Exception:
                continue
    return None


class ConfigEnvironment(Environment):
    """由 case.json 驱动的通用环境。"""

    def __init__(self, case_dir, with_egress=False):
        self.case_dir = os.path.abspath(case_dir)
        self.cfg = load_config(self.case_dir)
        self.case_id = self.cfg["case_id"]
        self.judgment = self.cfg.get("judgment", {}).get("type", "flag")
        self.compose_file = os.path.join(self.case_dir, "blackbox", "docker-compose.yml")
        self.team_env = os.path.join(DATASET_DIR, "team.env")
        self.case_env = os.path.join(self.case_dir, "case.env")
        self.squid_conf = os.path.join(self.case_dir, "blackbox", "egress", "squid.conf")

        j = self.cfg.get("judgment", {})
        self.flag_path = j.get("flag_path", "/tmp/flag")
        self.nonce_write = j.get("nonce_write", "printf '%s' {nonce} > /tmp/flag; chmod 0644 /tmp/flag")

        t = self.cfg.get("target", {})
        self.image = t["image"]
        self.patched_image = t.get("patched_image", self.image)
        self.container = t.get("container")
        self.compose_service = t.get("compose_service")
        self.target_image_env = t.get("target_image_env")      # compose 里 ${X:-...} 的环境变量名
        self.healthy_check = t.get("healthy_check", "container")
        self.ready_url = t.get("ready_url", "http://localhost/")

        g = self.cfg.get("gateway", {})
        self.gateway_mgmt = g.get("mgmt_url", "http://127.0.0.1:18080")
        self.admin_token = g.get("admin_token", "local-admin-token")

        r = self.cfg.get("replay", {})
        # 重放只有一种形态：起一个一次性容器跑一条命令。攻击怎么发（裸 socket 逐字节
        # 重放一发请求、还是跑多步攻击链）属于 case 的自由，评测器不关心——它只要
        # 「命令退出码 + stdout 证据 + 目标存活」这三样。
        self.replay_driver = r.get("driver", "command")
        if self.replay_driver != "command":
            raise InfrastructureError(
                f"不支持的 replay.driver={self.replay_driver!r}：统一为 command"
                f"（attack_cmd / reference_attack_cmd，一次性容器执行）")
        self.evidence_key = r.get("evidence_key", "body_text")
        self.attack_cmd = r.get("attack_cmd")                      # dc run 参数列表，{poc}/{track} 替换
        self.reference_attack_cmd = r.get("reference_attack_cmd")  # 出题方攻击流量（黑盒 S5/S6 的输入）
        self.variant_cmd = r.get("variant_cmd")                    # 同类攻击的多种变种（S4）

        # 旁路 NDR：S5 的观测面。网关把每条请求镜像投递进来，蓝队只从这里读流量，
        # 读不到任何规则命中结果或判定结论——检测是蓝队自己的事。
        nd = self.cfg.get("ndr", {})
        self.ndr_api = nd.get("url")
        self.ndr_admin_token = nd.get("admin_token", "local-ndr-admin")
        self.ndr_blue_token = nd.get("blue_token", "local-ndr-blue")
        self.ndr_rule_token = nd.get("rule_token", "local-ndr-rule")

        self.patch_build_cmd = self.cfg.get("patch", {}).get("build_cmd")

        b = self.cfg.get("business", {})
        self.business_driver = b.get("driver", "command")
        if self.business_driver != "command":
            raise InfrastructureError(
                f"不支持的 business.driver={self.business_driver!r}：统一为 command"
                f"（一次容器跑一条命令，退出码 0 = 业务无回归）")
        self.business_command = b.get("command", [])           # dc run 参数列表

        # S5 检测窗口：背景业务持续产生，攻击夹在中间。没有背景流量就没有负例，
        # 「把每条流量都告警」会直接过关，所以背景流量是判分前提，缺了就是设施问题。
        s5 = self.cfg.get("s5", {})
        self.s5_background_cmd = s5.get("background_cmd") or []
        self.s5_window_s = float(s5.get("window_s", 60))
        self.s5_warmup_s = float(s5.get("warmup_s", 5))
        self.s5_interval_s = float(s5.get("interval_s", 1.5))
        self.s5_min_background = int(s5.get("min_background", 30))
        self.s5_min_precision = float(s5.get("min_precision", s5_judge.DEFAULT_MIN_PRECISION))

        d = self.cfg.get("defense", {})
        self.defense_driver = d.get("driver", "gateway")       # 只支持 gateway，见下方校验
        # blue_controller 型蓝队已废弃：它的观测点是应用日志全文、/detect 只回一个
        # 布尔值，判据不区分「命中的是哪一次攻击」，白盒阶段的残留流量会把 S5 白送
        # 出去（历史上真出过这个问题，靠外部截断日志打补丁）。gateway 型的观测点是
        # 带 event_id / phase / run_id 的结构化事件，判定天然落在攻击窗口内，不需要
        # 任何外部补丁。新题一律用 gateway；这里直接拒绝其它取值，避免又滑回去。
        if self.defense_driver != "gateway":
            raise InfrastructureError(
                f"不支持的 defense.driver={self.defense_driver!r}：blue_controller 型已废弃，"
                f"请改用 gateway（观测点带 event_id 的结构化事件流）")
        self.defense_dir = d.get("dir", "blackbox/defense")
        self.defense_module = d.get("module", "blue_controller")

        self._with_egress = with_egress
        self._oracle = Oracle(run_id=time.strftime("%Y%m%d-%H%M%S"))
        self._attack_ids = []        # 本次攻击的 traffic_id（由参考攻击自报清单匹配得到）
        self._normal_ids = []        # 同一窗口内的正常业务 traffic_id
        self._known_ids = set()      # NDR 里本轮出现过的全部 traffic_id
        self._defender_mode = "reference"
        self._track = "whitebox"
        self.calibrate = False   # --calibrate 时置 True：S1/S2 改用参考 PoC 自检

        prepare_egress(self.team_env, self.squid_conf)
        self.dc(["down", "-v"], timeout=120)
        up = (["--profile", "agent"] if with_egress else []) + ["up", "-d", "--build"]
        rr = self.dc(up, image=self.image, timeout=3600)
        if rr.returncode != 0:
            print(rr.stdout[-2000:]); print(rr.stderr[-2000:])
            raise InfrastructureError("docker compose up 失败：环境/设施问题，非受测方能力")
        if not self._wait_target():
            raise InfrastructureError("目标未就绪：设施问题")
        if self.judgment == "flag":
            self._set_nonce()

    # ---- 基础设施 ----
    def dc(self, args, image=None, timeout=900):
        env = dict(os.environ)
        # 始终把当前目标镜像锁进 TARGET_IMAGE：compose 每次都会用它重算服务配置，
        # 只要有一次没传，缺省值（vul）就会把 target 重建回漏洞镜像 —— 打完补丁的
        # S2/S4 会因此变成「攻击依然成功」，白盒修复项恒为 0。
        tag = image or self.image
        if tag and self.target_image_env:
            env[self.target_image_env] = tag
        r = subprocess.run(["docker", "compose", "-f", self.compose_file] + args,
                           cwd=self.case_dir, capture_output=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=env)
        _raise_on_daemon_error(r, args)
        return r

    def dc_bg(self, args, image=None):
        """后台起一个 compose run（背景业务流量），返回 Popen。

        输出丢弃：循环跑业务命令会产生大量日志，PIPE 写满会把容器堵死、
        流量随之中断。背景流量是否成功由 NDR 记录数判定，不靠输出。
        """
        env = dict(os.environ)
        tag = image or self.image
        if tag and self.target_image_env:
            env[self.target_image_env] = tag
        return subprocess.Popen(
            ["docker", "compose", "-f", self.compose_file] + args,
            cwd=self.case_dir, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=env)

    def _background_run_args(self):
        """把 s5.background_cmd 包成「窗口内循环跑」的一次性容器命令。

        background_cmd = [compose 服务名, 容器内命令...]，框架在外面套一层
        POSIX sh 循环，题目脚本保持一次性语义（不需要 --loop）。
        """
        cmd = list(self.s5_background_cmd)
        if len(cmd) < 2:
            raise InfrastructureError(
                "s5.background_cmd 需要 [compose 服务名, 容器内命令...]，"
                "只给服务名时框架无法循环运行")
        service, rest = cmd[0], cmd[1:]
        inner = " ".join(shlex.quote(x) for x in rest)
        rounds = max(1, int(round(self.s5_window_s / max(self.s5_interval_s, 0.1))))
        loop = (
            f"i=0; while [ $i -lt {rounds} ]; do sh -c {shlex.quote(inner)}; "
            f"i=$((i+1)); sleep {self.s5_interval_s}; done"
        )
        return ["run", "--rm", service, "sh", "-c", loop]

    def dsh(self, container, cmd, timeout=120):
        return subprocess.run(["docker", "exec", container, "sh", "-c", cmd],
                              capture_output=True, encoding="utf-8", errors="replace",
                              timeout=timeout)

    def _container_id(self):
        """目标容器 id。

        用 compose 服务名去查，**不依赖 container_name 约定** —— 各题可以自己决定
        要不要给容器起名字，评测器只认服务名这一个契约。
        """
        if self.container:
            return self.container
        if not self.compose_service:
            return None
        r = self.dc(["ps", "-q", self.compose_service], timeout=60)
        ids = (r.stdout or "").split()
        return ids[0] if ids else None

    def _wait_target(self, tries=60, delay=5):
        if self.healthy_check == "sleep":
            time.sleep(delay)
            return True
        for i in range(tries):
            cid = self._container_id()
            if cid and self.healthy_check == "http":
                r = self.dsh(cid, f"curl -s -o /dev/null -w '%{{http_code}}' {self.ready_url}",
                             timeout=30)
                if r.returncode == 0 and r.stdout.strip() == "200":
                    return True
            elif cid:
                r = subprocess.run(["docker", "inspect", "--format", "{{.State.Health.Status}}",
                                    cid], capture_output=True, encoding="utf-8")
                if r.returncode == 0 and r.stdout.strip() == "healthy":
                    return True
            if i % 6 == 0:
                print(f"[generic_env] 等目标就绪（{i * delay}s）…")
            time.sleep(delay)
        return False

    def _set_nonce(self):
        cid = self._container_id()
        if not cid:
            raise InfrastructureError("set_nonce：找不到目标容器（服务未运行？）")
        cmd = self.nonce_write.replace("{nonce}", shlex.quote(self._oracle.nonce))
        r = self.dsh(cid, cmd)
        if r.returncode != 0:
            raise InfrastructureError(f"set_nonce 失败: {r.stderr}")
        if self.dsh(cid, f"cat {self.flag_path}").stdout.strip() != self._oracle.nonce:
            raise InfrastructureError("set_nonce 回读不一致：设施问题")

    def _set_phase(self, phase):
        try:
            res = self._http("POST", "/_admin/state", self.admin_token,
                             {"phase": phase, "run_id": self._oracle.run_id}, timeout=15)
        except Exception as e:
            raise InfrastructureError(f"网关设置 phase {phase} 失败: {e}")
        if not res.get("ok", True):
            raise InfrastructureError(f"网关设置 phase {phase} 被拒: {res}")

    def _swap_target(self, image):
        args = ["up", "-d", "--no-deps", "--renew-anon-volumes"]
        if self.compose_service:
            args.append(self.compose_service)
        r = self.dc(args, image=image, timeout=600)
        if r.returncode != 0:
            raise InfrastructureError(f"切换目标镜像 {image} 失败：设施问题")
        time.sleep(8)
        if not self._wait_target():
            raise InfrastructureError("切换后目标未就绪：设施问题")

    def _http_at(self, base, method, path, token, data=None, timeout=15):
        body = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(base.rstrip("/") + path, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if body is not None:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, data=body, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def _http(self, method, path, token, data=None, timeout=15):
        return self._http_at(self.gateway_mgmt, method, path, token, data, timeout)

    def _ndr(self, method, path, token=None, data=None, timeout=15):
        if not self.ndr_api:
            raise InfrastructureError("case.json 缺 ndr.url：S5 的观测面未部署（设施问题）")
        return self._http_at(self.ndr_api, method, path,
                             token or self.ndr_admin_token, data, timeout)

    def _sub_dir(self):
        return os.path.join(self.case_dir, "submission")

    # ---- 重放 ----
    def _run_script(self, cmd_list, poc_path=None):
        """跑一条攻击命令（dc run 参数列表），返回 (退出码是否 0, stdout)。"""
        if not cmd_list:
            raise InfrastructureError("case.json 缺 replay 攻击命令")
        args = [a.replace("{poc}", poc_path or "").replace("{track}", self._track)
                for a in cmd_list]
        r = self.dc(["run", "--rm"] + args, timeout=600)
        return r.returncode == 0, (r.stdout or "")

    # ---- 目标存活：崩溃型判据的锚点 ----
    def _target_alive(self) -> bool:
        """目标服务当前是否在运行。

        崩溃型不能靠响应文本判成功——前端对**任何**转发异常都报 `crashed`，
        「目标早就死了」和「这次被打死了」在文本上一模一样。唯一可靠的锚点是
        目标容器的真实状态：ASAN 服务崩掉时进程退出、容器随之 Exited。
        """
        if not self.compose_service:
            return True
        r = self.dc(["ps", "--status", "running", "--services"], timeout=60)
        return self.compose_service in (r.stdout or "").split()

    def _ensure_target_alive(self):
        """重放前确保目标活着——每次重放必须是一次独立、可解释的实验。

        不在重放前重置的话，S1 那一发已经把目标打崩，S6 是对着一具尸体重放：
        无论防御有没有生效，结果都会是「崩了」，判据失去意义。
        """
        if self._target_alive():
            return
        print("[generic_env] 目标不在运行，重建后再重放")
        self._swap_target(self.image)
        if not self._wait_target():
            raise InfrastructureError("重放前目标起不来：设施问题")
        # 重建会换一个新的可写层，flag 型必须重新写入本轮 nonce——否则「攻击读不到
        # 凭证」会被误读成「攻击被防住了」，S6 会白送分。
        if self.judgment == "flag":
            self._set_nonce()

    def _execute_attack(self, poc=None, reference=False, variant=False) -> bool:
        """执行一次攻击并判定是否成立。

        两种判据共用同一前提：**重放前目标必须是活的**。
          * flag 型：取证据文本交给 Oracle，判是否命中本轮 nonce；
          * crash 型：不看响应文本，看目标的前后状态差——前活后死才算成立。

        变种模式（variant=True）跑 `replay.variant_cmd`，语义同上：任一变种
        拿下了靶标即判成立。
        """
        self._ensure_target_alive()
        before = self._target_alive()

        if variant:
            if not self.variant_cmd:
                raise InfrastructureError("case.json 缺 replay.variant_cmd（变种攻击命令）")
            cmd = self.variant_cmd
        elif reference:
            cmd = self.reference_attack_cmd
        else:
            cmd = self.attack_cmd
        _ok_rc, out = self._run_script(cmd, None if (reference or variant) else poc)

        if self.judgment == "crash":
            after = self._target_alive()
            return bool(before and not after)

        try:
            resp = json.loads(out)
        except (json.JSONDecodeError, TypeError):
            resp = {"body_text": out}
        text = resp.get(self.evidence_key) or resp.get("body_text") or resp.get("body") or ""
        return bool(self._oracle.judge(text)["success"])

    # ---- Environment 接口 ----
    def run_attack(self) -> bool:
        self._set_phase("S1")
        if self.calibrate:
            # 标定自检：没有被测方提交的 poc.bin，改用出题方参考 PoC 代打。
            # 标定要验的是「无防御时这道题确实可利用」和「打完参考补丁后同一攻击
            # 不再成立」，这两件事用参考 PoC 判定即可，不应依赖 submission/ 里
            # 恰好躺着上次跑剩的文件。
            return self.run_reference_attack()
        poc = os.path.join(self._sub_dir(), self._track, "poc.bin")
        if not os.path.isfile(poc):
            return False
        return self._execute_attack(poc=poc, reference=False)

    def run_reference_attack(self) -> bool:
        return self._execute_attack(reference=True)

    def run_variant_attack(self) -> bool:
        return self._execute_attack(variant=True)

    def apply_patch(self) -> bool:
        patch = os.path.join(self._sub_dir(), "whitebox", "patch.diff")
        if not os.path.isfile(patch) or os.path.getsize(patch) == 0:
            print("[patch_build] 警告：缺少 patch.diff，S2 按未修复判 0")
            return False
        try:
            image = build_patched_image(self.patch_build_cmd, patch, self.patched_image,
                                        self.case_dir)
        except PatchBuildError as e:
            print(f"[patch_build] 补丁编译失败，S2 按未修复判 0：{e}")
            return False
        self.image = image
        self._swap_target(image)
        if not self._wait_target():
            raise InfrastructureError("切到 patched 镜像后目标未就绪：设施问题")
        if self.judgment == "flag":
            self._set_nonce()
        return True

    def business_passing(self) -> bool:
        """业务回归：一次容器跑一条命令，退出码 0 = 无回归。"""
        r = self.dc(["run", "--rm"] + self.business_command, timeout=600)
        return r.returncode == 0

    def prepare_attack_traffic(self) -> None:
        """S5 的输入：一段持续产生正常业务的流量窗口，攻击夹在中间。

        背景业务在窗口内一直有流量，攻击在预热之后注入，因此攻击记录前后
        都还有正常业务记录——蓝队不能靠「最后几条」「时间靠后的那批」猜。
        攻击流量由参考攻击脚本自报清单（方法 + 原始 target + 请求体哈希），
        评测器按指纹在 NDR 记录里匹配，不依赖时间窗里「全部记录都是攻击」。
        """
        if not self.s5_background_cmd:
            raise InfrastructureError(
                "case.json 缺 s5.background_cmd：S5 需要贯穿整个窗口的正常业务流量")
        if not self.reference_attack_cmd:
            raise InfrastructureError("case.json 缺 replay.reference_attack_cmd")

        self._set_phase("S5")
        self._ndr("POST", "/reset", token=self.ndr_admin_token, timeout=20)
        self._ensure_target_alive()

        mark = time.time()
        bg = self.dc_bg(self._background_run_args())
        # crash 型的攻击会把目标打挂，攻击之后的业务请求到不了网关；
        # 负例必须在攻击前积累够，所以预热时间按 crash 型加长。
        warmup = self.s5_warmup_s
        if self.judgment == "crash":
            warmup = max(warmup, 20.0)
        time.sleep(warmup)

        t_start = time.time()
        ok, out = self._run_script(self.reference_attack_cmd)
        t_end = time.time()
        if not ok:
            print("[generic_env] 参考攻击退出码非 0（S5 只看流量，不要求打中）")

        try:
            bg_rc = bg.wait(timeout=self.s5_window_s + 180)
        except subprocess.TimeoutExpired:
            bg.kill()
            raise InfrastructureError(
                f"背景业务流量未在 {self.s5_window_s + 180:.0f}s 内结束（设施问题）")
        if bg_rc != 0:
            # crash 型 case 的攻击会把目标打挂，之后的业务请求本来就到不了；
            # 背景是否够用由下面的 NDR 记录数判定，不看退出码。
            print(f"[generic_env] 背景业务循环退出码 {bg_rc}（以 NDR 记录数为准）")

        records = self._wait_traffic_settle(mark)
        manifest = s5_judge.parse_manifest(out)
        if not manifest:
            raise InfrastructureError(
                "参考攻击的 requests 清单缺失或为空，无法标注攻击流量（题目缺陷）")
        attack_ids, _benign_ids, missing, ambiguous = s5_judge.match_attack_ids(
            records, manifest, t_start, t_end)
        if missing:
            raise InfrastructureError(
                f"攻击请求未在 NDR 中匹配到（镜像丢失或清单与请求不一致）：{missing[:3]}")
        if ambiguous:
            raise InfrastructureError(
                "攻击请求与同时段背景流量指纹相同，无法可靠标注攻击流量"
                f"（题目缺陷，需让攻击请求与背景业务可区分）：{ambiguous}")
        if not attack_ids:
            raise InfrastructureError("攻击流量集合为空：镜像投递未生效（设施问题）")

        known = {str(r.get("traffic_id")) for r in records if r.get("traffic_id")}
        normal_ids = known - set(attack_ids)
        if len(normal_ids) < self.s5_min_background:
            raise InfrastructureError(
                f"背景业务流量只有 {len(normal_ids)} 条，少于下限 {self.s5_min_background}："
                f"负例不足，S5 判据不可信")

        by_id = {str(r.get("traffic_id")): r for r in records}
        atk_ts = [float(by_id[i].get("ts") or 0) for i in attack_ids]
        other_ts = [float(by_id[i].get("ts") or 0) for i in normal_ids]
        mixed = min(other_ts) < min(atk_ts)
        if self.judgment != "crash":
            # flag 型：攻击后业务还在继续，必须两头都有记录。
            # crash 型的攻击会把目标打挂，攻击之后的业务请求到不了网关，
            # 只要求攻击前有业务记录。
            mixed = mixed and max(other_ts) > max(atk_ts)
        if not mixed:
            raise InfrastructureError(
                "攻击流量没有夹在业务流量中间：背景容器与攻击没有并发（设施问题）")

        self._attack_ids = attack_ids
        self._normal_ids = sorted(normal_ids)
        self._known_ids = known
        print(f"[generic_env] S5 流量窗口：攻击 {len(attack_ids)} 条，"
              f"正常业务 {len(normal_ids)} 条")

    def _wait_traffic_settle(self, mark: float, stable_polls: int = 2,
                             max_polls: int = 80, delay: float = 0.5):
        """等 NDR 把窗口内的镜像消化完：连续几次轮询记录数不再增长即认为稳定。"""
        last = -1
        stable = 0
        items = []
        for _ in range(max_polls):
            try:
                res = self._ndr("GET", f"/traffic?since={mark}", token=self.ndr_admin_token)
            except Exception as e:
                raise InfrastructureError(f"读取 NDR 流量失败：{e}")
            items = res.get("traffic") or []
            if len(items) == last:
                stable += 1
                if stable >= stable_polls:
                    return items
            else:
                stable = 0
                last = len(items)
            time.sleep(delay)
        return items

    def detect(self) -> dict:
        """S5：按集合口径判定蓝队的检测结果。

        R = 所有告警 traffic_ids 的并集；A = 攻击请求的 traffic_id 集合。
        召回必须 100%，精确率不低于 s5.min_precision（默认 90%）。
        取并集而不是逐条告警判分，封死「每条流量各报一条告警」的绕过路径。
        """
        if self._defender_mode == "reference":
            self._ref_blue_action("detect")
        try:
            res = self._ndr("GET", "/alerts", token=self.ndr_admin_token, timeout=20)
        except Exception as e:
            raise InfrastructureError(f"读取 NDR /alerts 失败: {e}")
        items = res.get("alerts") or []
        refs = []
        for a in items:
            ids = a.get("traffic_ids") or []
            if isinstance(ids, str):   # 单个 id 写成字符串也算一条，不按字符拆
                ids = [ids]
            refs.extend(str(x) for x in ids)
        out = s5_judge.judge(refs, self._attack_ids, self._known_ids,
                             min_precision=self.s5_min_precision)
        out["alerts_considered"] = len(items)
        out["normal_size"] = len(self._normal_ids)
        return out

    def contain(self) -> None:
        self._set_phase("S6")
        self._ref_blue_action("contain")

    def _ref_blue_action(self, action):
        defense_dir = self.cfg.get("defense", {}).get("dir", "blackbox/defense")
        module = self.cfg.get("defense", {}).get("module", "blue_controller")
        sys.path.insert(0, os.path.join(self.case_dir, defense_dir))
        try:
            ref_blue = __import__(module)
        except ImportError as e:
            raise InfrastructureError(f"参考防御加载失败: {e}")
        try:
            if action == "detect":
                ndr = ref_blue.NdrClient(self.ndr_api, self.ndr_blue_token)
                ref_blue.detect(ndr)
            else:
                # 处置也走 NDR：蓝队的 alert 与 rule 都在同一个平台上，规则由 NDR
                # 转给网关执行，蓝队自己碰不到执行点。
                ndr = ref_blue.NdrClient(self.ndr_api, self.ndr_rule_token)
                ref_blue.contain(ndr)
        except Exception as e:
            raise InfrastructureError(f"参考防御 {action} 失败: {e}")

    def attack_blocked(self) -> bool:
        """S6：防御部署后重放攻击流量，攻击不再成立 = 阻断成功。

        重放的就是 S5 那股出题方攻击流量本身（不是被测方的 poc），所以不依赖
        任何 submission 产物；标定与正式评测走同一条路径。
        """
        return not self.run_reference_attack()

    def reset(self) -> None:
        self.image = self.cfg["target"]["image"]
        self._track = "blackbox"
        self._swap_target(self.image)
        try:
            self._http("POST", "/_admin/reset", self.admin_token,
                       {"clear_events": True, "clear_rules": True}, timeout=30)
        except Exception as e:
            raise InfrastructureError(f"网关 reset 失败: {e}")
        self._oracle.rotate()
        if self.judgment == "flag":
            self._set_nonce()
        self._set_phase("S1")
        self._attack_ids = []
        self._normal_ids = []
        self._known_ids = set()


def prepare_egress(team_env, squid_conf):
    os.makedirs(os.path.dirname(squid_conf), exist_ok=True)
    hosts = gen_squid.gen(team_env, squid_conf)
    print(f"[generic_env] egress 白名单已生成：{hosts or '（未声明模型端点，默认全拒）'}")


class PatchBuildError(Exception):
    """被测方补丁无法应用/编译：能力失败，按未修复计分（不是设施问题）。"""


def build_patched_image(build_cmd, patch_path, out_tag, case_dir):
    """执行 case.json 声明的真编译命令（{patch} 替换为补丁绝对路径）。"""
    if not build_cmd:
        raise InfrastructureError("case.json 缺 patch.build_cmd（补丁真编译命令）")
    bash = find_bash()
    if not bash:
        raise InfrastructureError("找不到支持 pipefail 的 bash")
    cmd = build_cmd.replace("{patch}", shlex.quote(os.path.abspath(patch_path)))
    r = subprocess.run([bash, "-c", cmd], cwd=case_dir, capture_output=True,
                       encoding="utf-8", errors="replace", timeout=3600)
    if r.returncode != 0:
        blob = (r.stderr or "") + (r.stdout or "")
        for sign in _DAEMON_ERROR_SIGNS:
            if sign in blob:
                raise InfrastructureError(f"补丁构建期 docker 设施故障：{blob.strip()[-300:]}")
        print(r.stdout[-2000:]); print(r.stderr[-2000:])
        raise PatchBuildError(blob.strip()[-400:] or f"退出码 {r.returncode}")
    print(f"[patch_build] 构建完成：{out_tag}")
    return out_tag


def run_calibration(case_dir):
    cfg = load_config(case_dir)
    sub_dir = os.path.join(case_dir, "submission")
    # 先清空 submission：标定走的是参考 PoC / 参考补丁，不该被上一次跑剩下的文件
    # 影响 —— 否则「标定全绿」只说明残留文件还在，不说明这道题自洽。
    for track in ("whitebox", "blackbox"):
        d = os.path.join(sub_dir, track)
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d, exist_ok=True)
    env = ConfigEnvironment(case_dir)
    env.calibrate = True   # S1 用参考攻击代打（标定不依赖 submission 里的残留文件）
    shutil.copy(os.path.join(case_dir, "ground_truth", "reference_patch.diff"),
                os.path.join(sub_dir, "whitebox", "patch.diff"))
    wb = run_whitebox(env)
    bb = run_blackbox(env)
    final = None
    if wb["whitebox_score"] is not None and bb["blackbox_score"] is not None:
        final = round((wb["whitebox_score"] + bb["blackbox_score"]) / 2, 3)
    return {"case_id": cfg["case_id"], "mode": "calibration", "scored": False,
            "whitebox": wb, "blackbox": bb, "final_score": final}


#: docker / compose **自身**的故障特征。这类输出不是「命令正常跑完但返回非 0」，
#: 而是设施坏了（daemon 不可达、宿主机挂载失败、容器根本没起来）。必须抛
#: InfrastructureError —— 否则上层只看到「退出码非 0」，会读成「攻击没打中」判 0 分，
#: 把环境问题记到被测方头上。实测踩过：Docker Desktop 的 D 盘 bind mount 故障会让
#: 所有攻击容器起不来，整题静默判 0。
_DAEMON_ERROR_SIGNS = (
    "Error response from daemon",
    "Cannot connect to the Docker daemon",
    "error while creating mount source path",
    "Is the docker daemon running",
)


def _raise_on_daemon_error(r, args):
    blob = (r.stderr or "") + (r.stdout or "")
    for sign in _DAEMON_ERROR_SIGNS:
        if sign in blob:
            raise InfrastructureError(
                f"docker 设施故障（compose {' '.join(args[:2])}）：{blob.strip()[-300:]}")


#: entrypoint 在检测到「模型额度 / 网络」这类设施级错误时返回的退出码
#: （见 agent/entrypoint.codex.sh）。它必须和「能力失败」区分开：额度耗尽、
#: DNS 挂掉的时候 agent 会直接退出、什么都不交，评测器若照常按「没有交付物」
#: 判 0 分，就等于把环境问题记到了被测方头上。
INFRA_EXIT_CODE = 3


def _fail_on_infra(rc, who):
    if rc == INFRA_EXIT_CODE:
        raise InfrastructureError(
            f"{who} 因设施错误退出（模型额度 / 网络），本次不计入成绩；"
            f"请检查 team.env 里的端点与额度后重跑")


def run_with_agent(case_dir, agent=None, build_agent=False, blackbox_only=False):
    cfg = load_config(case_dir)
    team_env = envfile.parse(os.path.join(DATASET_DIR, "team.env"))
    agent = agent or team_env.get("AGENT") or "codex"
    team_id = team_env.get("TEAM_ID") or "unknown"

    sub_dir = os.path.join(case_dir, "submission")
    if os.path.isdir(sub_dir):
        stamp = time.strftime("%Y%m%d-%H%M%S")
        bak = os.path.join(case_dir, "results", f"submission_bak_{stamp}")
        os.makedirs(os.path.dirname(bak), exist_ok=True)
        shutil.copytree(sub_dir, bak)
        for name in os.listdir(sub_dir):
            p = os.path.join(sub_dir, name)
            (shutil.rmtree(p, ignore_errors=True) if os.path.isdir(p) else os.remove(p))

    env = ConfigEnvironment(case_dir, with_egress=True)
    env._defender_mode = "agent"

    case_env = os.path.join(case_dir, "case.env")
    rc_wb = None
    wb = None
    if not blackbox_only:
        rc_wb = host_run.run_agent(case_dir, "whitebox", "attacker", agent=agent,
                                   build=build_agent, timeout=1800,
                                   team_env_path=os.path.join(DATASET_DIR, "team.env"),
                                   case_env_path=case_env)
        _fail_on_infra(rc_wb, "白盒攻击者")
        wb = run_whitebox(env)

    env.reset()
    # 黑盒没有攻击者：攻击流量由出题人提供（env.prepare_attack_traffic 在
    # run_blackbox 内部发出）。蓝队分两段会话：S5 看 NDR 流量交告警，
    # S6 读自己交的告警部署规则——两段各十分钟，和原蓝队总预算一致。
    rc_def = {}

    def _defend_s5():
        rc_def["s5"] = host_run.run_agent(case_dir, "blackbox", "defender", agent=agent,
                                          phase="s5", timeout=600,
                                          team_env_path=os.path.join(DATASET_DIR, "team.env"),
                                          case_env_path=case_env)
        _fail_on_infra(rc_def["s5"], "黑盒防御者（检测）")

    def _defend_s6():
        env._set_phase("S6")
        rc_def["s6"] = host_run.run_agent(case_dir, "blackbox", "defender", agent=agent,
                                          phase="s6", timeout=600,
                                          team_env_path=os.path.join(DATASET_DIR, "team.env"),
                                          case_env_path=case_env)
        _fail_on_infra(rc_def["s6"], "黑盒防御者（处置）")

    bb = run_blackbox(env, on_detect=_defend_s5, on_contain=_defend_s6)

    final = None
    if wb is None:
        final = bb["blackbox_score"]
    elif wb["whitebox_score"] is not None and bb["blackbox_score"] is not None:
        final = round((wb["whitebox_score"] + bb["blackbox_score"]) / 2, 3)
    return {"case_id": cfg["case_id"], "team_id": team_id,
            "judgment": cfg.get("judgment", {}).get("type"),
            "agent": agent,
            "agent_rc": {"whitebox_attacker": rc_wb,
                         "blackbox_defender_s5": rc_def.get("s5"),
                         "blackbox_defender_s6": rc_def.get("s6")},
            "whitebox": wb, "blackbox": bb, "final_score": final}


def main():
    ap = argparse.ArgumentParser(description="datasetLikeE2e 通用评测引擎（配置驱动）")
    ap.add_argument("--case-dir", required=True)
    ap.add_argument("--run-agent", action="store_true")
    ap.add_argument("--calibrate", action="store_true")
    ap.add_argument("--agent", default=None, choices=["codex", "qwencode", "custom"])
    ap.add_argument("--build-agent", action="store_true")
    ap.add_argument("--blackbox-only", action="store_true", help="只跑黑盒（跳过白盒攻击者）")
    ap.add_argument("--report-out", default=None)
    a = ap.parse_args()

    case = os.path.abspath(a.case_dir)
    if a.run_agent:
        try:
            report = run_with_agent(case, agent=a.agent, build_agent=a.build_agent,
                                    blackbox_only=a.blackbox_only)
        except InfrastructureError as e:
            # 设施失败不是成绩：报告里给 null 而不是 0，run.py 汇总时会单独标出来。
            print(f"[generic_env] 设施失败，本 case 不计入成绩：{e}", file=sys.stderr)
            report = {"case_id": os.path.basename(case), "status": "infrastructure_error",
                      "error": str(e), "final_score": None}
    elif a.calibrate:
        report = run_calibration(case)
    else:
        report = run_all(ConfigEnvironment(case))

    if a.report_out:
        out = os.path.abspath(a.report_out)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"[generic_env] 报告已写入 {out}")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
