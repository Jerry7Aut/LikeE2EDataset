#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ndr.py — 旁路 NDR（网络检测与响应）组件

部署位置：gateway_net（接收网关投递的流量镜像）+ mgmt_net（蓝队访问）。
**不串联在数据面**：NDR 自己挂了不能影响攻击流量与业务流量，否则 S5 的输入就没了。

它做三件事：
  1. 接收网关镜像过来的原始请求，落成带 id 的流量记录（traffic）；
  2. 给蓝队提供两种读取方式——解析后的视图（列表）与原始字节（详情）；
  3. 接收蓝队提交的告警（alert），供评测器回读判分。

为什么检测面放在这里而不是网关上：S5 要考的是「拿到网络层观测数据能不能认出攻击」。
网关本身是策略执行点，它的事件带规则命中结果等执行侧信息；NDR 只给流量，
不含任何判定结论。

接口
----
  POST /ingest            网关投递流量镜像（ingest token）
  GET  /traffic           流量列表，支持 since / run_id / limit（blue token）
  GET  /traffic/<id>      单条流量详情，含原始请求（blue token，raw=1 取原始字节）
  POST /alerts            蓝队提交告警（blue token；单个对象、对象数组或 {"alerts": [...]} 均可）
  GET  /alerts            读告警（blue / rule / admin token）
  POST /submissions       蓝队提交分阶段结果（blue token；阶段=攻击链节点，候选按名次）
  GET  /submissions       读最近一次分阶段提交（blue / rule / admin token）
  GET  /rules             读已部署规则（rule token，转发到网关）
  POST /rules             蓝队部署处置规则（rule token；NDR 转给网关执行）
  DELETE /rules/<id>      撤销规则（rule token；转发到网关）
  POST /reset             清空流量与告警（admin token）
  GET  /_health           健康检查（免认证）

令牌：`NDR_INGEST_TOKEN`（网关用）、`NDR_BLUE_TOKEN`（蓝队检测用）、
`NDR_RULE_TOKEN`（蓝队处置用）、`NDR_ADMIN_TOKEN`（评测器用）。

处置面为什么也在 NDR：蓝队的观测与处置是同一个平台上的两个动作，规则由 NDR
下发到网关执行（`GATEWAY_MGMT_URL` + `NDR_GATEWAY_TOKEN`）。蓝队自己碰不到
执行点，既不会看到规则命中结果，也不能绕过 NDR 直接改策略。
"""
from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

LISTEN_HOST = os.environ.get("NDR_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("NDR_PORT", "8080"))
INGEST_TOKEN = os.environ.get("NDR_INGEST_TOKEN", "local-ndr-ingest")
BLUE_TOKEN = os.environ.get("NDR_BLUE_TOKEN", "local-ndr-blue")
RULE_TOKEN = os.environ.get("NDR_RULE_TOKEN", "local-ndr-rule")
ADMIN_TOKEN = os.environ.get("NDR_ADMIN_TOKEN", "local-ndr-admin")
MAX_RECORDS = int(os.environ.get("NDR_MAX_RECORDS", "2000"))

# 执行点：规则由 NDR 转交网关下发。蓝队只与 NDR 交互，拿不到执行点的凭据。
GATEWAY_URL = os.environ.get("GATEWAY_MGMT_URL", "").rstrip("/")
GATEWAY_TOKEN = os.environ.get("NDR_GATEWAY_TOKEN", "")


def _gateway(method: str, path: str, payload: Any = None) -> Dict[str, Any]:
    """把规则操作转给网关执行。网关不可达时如实报错，不假装部署成功。"""
    if not GATEWAY_URL:
        return {"ok": False, "status": None, "data": {"error": "gateway not configured on ndr"}}
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(GATEWAY_URL + path, method=method, data=data)
    req.add_header("Authorization", f"Bearer {GATEWAY_TOKEN}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return {"ok": True, "status": r.status, "data": json.loads(r.read().decode("utf-8"))}
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except ValueError:
            parsed = {"raw": body}
        return {"ok": False, "status": exc.code, "data": parsed}
    except (urllib.error.URLError, OSError) as exc:
        return {"ok": False, "status": None, "data": {"error": str(exc)}}


def _now() -> float:
    return time.time()


class Store:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seq = 0
        self._alert_seq = 0
        self._traffic: List[Dict[str, Any]] = []
        self._alerts: List[Dict[str, Any]] = []
        self._submissions: List[Dict[str, Any]] = []

    def add_traffic(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            item = {
                "traffic_id": f"t-{self._seq:06d}",
                "ts": float(rec.get("ts") or _now()),
                "ingested_at": _now(),
                "run_id": rec.get("run_id"),
                "phase": rec.get("phase"),
                "src_ip": rec.get("src_ip"),
                "src_port": rec.get("src_port"),
                "method": rec.get("method"),
                "target": rec.get("target"),
                "path": rec.get("path"),
                "http_version": rec.get("http_version"),
                "headers": rec.get("headers") or {},
                "body_text": (rec.get("body_text") or "")[:16384],
                # 请求体指纹：出题方用它把「攻击请求」和「正常业务」分开标注，
                # 蓝队看到的是一串哈希，不构成额外线索。
                "body_sha256": rec.get("body_sha256") or "",
                "body_len": int(rec.get("body_len") or 0),
                "raw_request_b64": rec.get("raw_request_b64") or "",
            }
            self._traffic.append(item)
            if len(self._traffic) > MAX_RECORDS:
                self._traffic = self._traffic[-MAX_RECORDS:]
            return item

    def list_traffic(self, since: Optional[float], run_id: Optional[str],
                     limit: Optional[int]) -> List[Dict[str, Any]]:
        with self._lock:
            out = []
            for t in self._traffic:
                if since is not None and t["ts"] < since:
                    continue
                if run_id and t.get("run_id") != run_id:
                    continue
                brief = {k: v for k, v in t.items() if k != "raw_request_b64"}
                brief["raw_len"] = len(base64.b64decode(t["raw_request_b64"])) if t["raw_request_b64"] else 0
                out.append(brief)
            if limit:
                out = out[-int(limit):]
            return out

    def get_traffic(self, traffic_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for t in self._traffic:
                if t["traffic_id"] == traffic_id:
                    return dict(t)
            return None

    def add_alert(self, alert: Dict[str, Any], actor: str) -> Dict[str, Any]:
        with self._lock:
            self._alert_seq += 1
            rec = {
                "alert_id": f"a-{self._alert_seq:04d}",
                "ts": _now(),
                "submitted_by": actor,
                "asset": alert.get("asset"),
                "behavior": alert.get("behavior"),
                "traffic_ids": alert.get("traffic_ids") or alert.get("event_ids") or [],
                "severity": alert.get("severity", "high"),
                "evidence": alert.get("evidence"),
                "raw": alert,
            }
            self._alerts.append(rec)
            return dict(rec)

    def list_alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [dict(a) for a in self._alerts]

    def add_submission(self, submission: Dict[str, Any], actor: str) -> Dict[str, Any]:
        """分阶段提交：阶段=攻击链节点，候选按名次排列。

        只做结构校验、原样存档；怎么判分是评测器的事，NDR 不给结论。
        同一轮允许多次提交，以最后一次为准（与告警的并集语义不同——链条有顺序，
        不能跨次拼接）。
        """
        slots = []
        for i, st in enumerate(submission.get("stages") or []):
            if not isinstance(st, dict):
                continue
            cands = st.get("candidates")
            if isinstance(cands, str):
                cands = [cands]
            cands = [str(c).strip() for c in (cands or []) if str(c).strip()]
            slots.append({
                "step": st.get("step", i + 1),
                "candidates": cands,
                "note": st.get("note"),
                "log_evidence": st.get("log_evidence"),
                "result": st.get("result"),
            })
        with self._lock:
            rec = {
                "submission_id": f"s-{len(self._submissions) + 1:04d}",
                "ts": _now(),
                "submitted_by": actor,
                "stages": slots,
                "stage_count": len(slots),
                "candidate_count": sum(len(s["candidates"]) for s in slots),
            }
            self._submissions.append(rec)
            return dict(rec)

    def get_submission(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            return dict(self._submissions[-1]) if self._submissions else None

    def reset(self) -> None:
        with self._lock:
            self._traffic = []
            self._alerts = []
            self._submissions = []
            self._seq = 0
            self._alert_seq = 0

    def counts(self) -> Dict[str, int]:
        with self._lock:
            return {"traffic": len(self._traffic), "alerts": len(self._alerts),
                    "submissions": len(self._submissions)}


STORE = Store()


def alerts_from_submission(sub: Dict[str, Any]) -> List[Dict[str, Any]]:
    """把分阶段提交映射成「告警视图」，供 S6 处置阶段沿用告警接口。

    S6 的语义是「读自己在 S5 交的结论，据此部署规则」；提交从并集改成阶段后，
    这里把每个阶段投影成一条告警（traffic_ids = 该阶段候选），蓝队与参考防御
    都不需要换接口。投影只在没有真实告警时发生，不改变 S5 的判分数据源。
    """
    out = []
    for i, st in enumerate(sub.get("stages") or []):
        out.append({
            "alert_id": f"sa-{i + 1:04d}",
            "ts": sub.get("ts"),
            "submitted_by": sub.get("submitted_by"),
            "asset": None,
            "behavior": st.get("note"),
            "traffic_ids": list(st.get("candidates") or []),
            "severity": "high",
            "evidence": st.get("log_evidence"),
            "derived_from": "submission",
            "raw": st,
        })
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "ndr/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 静默：NDR 自己的访问日志不是判分依据
        pass

    def handle_one_request(self) -> None:
        """单条请求的兜底：处理异常时回 500 JSON，而不是直接断开连接。

        参考防御会逐条拉取 /traffic/<id>?raw=1；只要某一条触发异常就断连，
        蓝队侧的 detect 会整体失败（Remote end closed），S5 被误判成设施错误。
        """
        try:
            super().handle_one_request()
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            try:
                self._send(500, {"error": f"internal error: {exc}"})
            except Exception:
                pass

    # ---- helpers ----
    def _send(self, code: int, obj: Any) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> Dict[str, Any]:
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _token(self) -> str:
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.lower().startswith("bearer ") else ""

    def _scope(self) -> Optional[str]:
        tok = self._token()
        if tok == ADMIN_TOKEN:
            return "admin"
        if tok == RULE_TOKEN:
            return "rule"
        if tok == BLUE_TOKEN:
            return "blue"
        if tok == INGEST_TOKEN:
            return "ingest"
        return None

    # ---- routes ----
    def do_GET(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        if u.path == "/_health":
            self._send(200, {"ok": True, **STORE.counts()})
            return
        scope = self._scope()
        if scope not in ("blue", "rule", "admin"):
            self._send(401, {"error": "missing or invalid token"})
            return

        if u.path == "/traffic":
            q = parse_qs(u.query)
            since = float(q["since"][0]) if "since" in q else None
            run_id = q.get("run_id", [None])[0]
            limit = int(q["limit"][0]) if "limit" in q else None
            items = STORE.list_traffic(since, run_id, limit)
            self._send(200, {"count": len(items), "traffic": items})
            return

        if u.path.startswith("/traffic/"):
            tid = u.path[len("/traffic/"):]
            rec = STORE.get_traffic(tid)
            if rec is None:
                self._send(404, {"error": "not found", "traffic_id": tid})
                return
            want_raw = parse_qs(u.query).get("raw", ["0"])[0] in ("1", "true", "yes")
            out = dict(rec)
            if want_raw and out.get("raw_request_b64"):
                out["raw_request"] = base64.b64decode(out["raw_request_b64"]).decode("utf-8", "replace")
            out.pop("raw_request_b64", None)
            self._send(200, out)
            return

        if u.path == "/alerts":
            items = STORE.list_alerts()
            if not items:
                sub = STORE.get_submission()
                if sub:
                    items = alerts_from_submission(sub)
            self._send(200, {"count": len(items), "alerts": items})
            return

        if u.path == "/submissions":
            sub = STORE.get_submission()
            self._send(200, {"submission": sub})
            return

        if u.path == "/rules":
            res = _gateway("GET", "/rules")
            self._send(res["status"] or 502, res["data"])
            return

        self._send(404, {"error": "not found", "path": u.path})

    def do_POST(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        scope = self._scope()

        if u.path == "/ingest":
            if scope not in ("ingest", "admin"):
                self._send(401, {"error": "missing or invalid ingest token"})
                return
            data = self._body()
            if not data.get("path") and not data.get("target"):
                self._send(400, {"error": "traffic requires path or target"})
                return
            item = STORE.add_traffic(data)
            self._send(201, {"created": True, "traffic_id": item["traffic_id"]})
            return

        if u.path == "/alerts":
            if scope not in ("blue", "admin"):
                self._send(401, {"error": "missing or invalid token"})
                return
            data = self._body()
            # 兼容三种提交形态：单个对象、对象数组、{"alerts": [...]} 包装。
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and isinstance(data.get("alerts"), list):
                items = data["alerts"]
            else:
                items = [data]
            created = []
            for alert in items:
                if not isinstance(alert, dict):
                    continue
                # 旧版参考防御用单数字段 traffic_id / event_id，这里统一成复数。
                if not alert.get("traffic_ids") and alert.get("traffic_id") is not None:
                    tid = alert.get("traffic_id")
                    alert["traffic_ids"] = tid if isinstance(tid, list) else [tid]
                if not alert.get("event_ids") and alert.get("event_id") is not None:
                    eid = alert.get("event_id")
                    alert["event_ids"] = eid if isinstance(eid, list) else [eid]
                if not alert.get("traffic_ids") and not alert.get("event_ids") and not alert.get("asset"):
                    continue
                created.append(STORE.add_alert(alert, actor=scope))
            if not created:
                self._send(400, {"error": "alert requires traffic_ids or asset"})
                return
            self._send(201, {"created": True, "count": len(created),
                             "alert": created[0]})
            return

        if u.path == "/submissions":
            if scope not in ("blue", "admin"):
                self._send(401, {"error": "missing or invalid token"})
                return
            data = self._body()
            stages = data.get("stages") if isinstance(data, dict) else None
            if not isinstance(stages, list) or not stages:
                self._send(400, {"error": "submission requires non-empty stages list"})
                return
            rec = STORE.add_submission(data, actor=scope)
            self._send(201, {"created": True, "submission_id": rec["submission_id"],
                             "stage_count": rec["stage_count"],
                             "candidate_count": rec["candidate_count"]})
            return

        if u.path == "/rules":
            if scope not in ("rule", "admin"):
                self._send(403, {"error": "rule token required to deploy policy"})
                return
            data = self._body()
            # 兼容单个规则、规则数组和 {"rules": [...]} 包装（参考防御常见写法）。
            if isinstance(data, list):
                items = data
            elif isinstance(data, dict) and isinstance(data.get("rules"), list):
                items = data["rules"]
            else:
                items = [data]
            results = []
            for rule in items:
                if not isinstance(rule, dict):
                    continue
                if not rule.get("match") or not rule.get("action"):
                    continue
                results.append(_gateway("POST", "/rules", rule))
            if not results:
                self._send(400, {"error": "rule requires match and action"})
                return
            last = results[-1]
            self._send(last["status"] or 502,
                       {"created": len(results),
                        "result": last["data"]})
            return

        if u.path == "/reset":
            if scope != "admin":
                self._send(403, {"error": "admin token required"})
                return
            STORE.reset()
            self._send(200, {"reset": True})
            return

        self._send(404, {"error": "not found", "path": u.path})

    def do_DELETE(self) -> None:  # noqa: N802
        u = urlparse(self.path)
        scope = self._scope()
        if scope not in ("rule", "admin"):
            self._send(403, {"error": "rule token required"})
            return
        if u.path.startswith("/rules/"):
            rid = u.path[len("/rules/"):]
            res = _gateway("DELETE", f"/rules/{rid}")
            self._send(res["status"] or 502, res["data"])
            return
        self._send(404, {"error": "not found", "path": u.path})


def main() -> None:
    srv = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"[ndr] listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
