"""Minimal A2A v1.0-style JSON-RPC server over HTTP.

JGD remains the domain agent: this adapter accepts a goal, starts a JGD run,
and exposes the task/artifacts. Streaming uses SSE; push notifications are
declared unsupported in the card.
"""
from __future__ import annotations

import json
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from jgd.service import JgdService

VERSION = "0.4.0"
_RUN_RE = re.compile(r"^[0-9A-Za-z._-]+$")
_ART_RE = re.compile(r"^[0-9A-Za-z._-]+$")

SKILLS = [
    {
        "id": "deserialization-audit",
        "name": "Deserialization audit",
        "description": "Run JGD static known-chain/bridge analysis on a JAR directory.",
        "tags": ["java", "deserialization", "gadget-chain"],
        "examples": ["Audit /opt/app/lib for Java deserialization chains"],
    },
    {
        "id": "chain-verification",
        "name": "Targeted chain verification",
        "description": "Targeted dynamic verification is available only with a configured sandbox/JDK.",
        "tags": ["dynamic-analysis", "sandbox"],
    },
    {
        "id": "poc-reproduction",
        "name": "PoC reproduction",
        "description": "Benign PoC reproduction in the isolated VM; requires allowHost=true and an explicit bridge class.",
        "tags": ["poc", "vm-sandbox"],
    },
]


def agent_card(base_url: str, token: str | None = None) -> dict:
    card = {
        "name": "JGD Deserialization Analyzer",
        "description": "Domain-autonomous Java deserialization gadget-chain analysis. Dynamic probes and deterministic PoCs are sandbox-gated; the preferred boundary is the dedicated Linux VM.",
        "version": VERSION,
        "supportedInterfaces": [
            {
                "url": base_url,
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            }
        ],
        "capabilities": {"streaming": True, "pushNotifications": False},
        "defaultInputModes": ["application/json", "text/plain"],
        "defaultOutputModes": [
            "application/json",
            "application/sarif+json",
            "text/markdown",
        ],
        "skills": SKILLS,
    }
    if token:
        card["securitySchemes"] = {"bearer": {"type": "http", "scheme": "bearer"}}
        card["security"] = [{"bearer": []}]
    return card


def _json_response(handler, obj, code=200) -> None:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _rpc_error(handler, req_id, code, message) -> None:
    _json_response(
        handler,
        {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}},
    )


def _auth_ok(handler, token: str | None) -> bool:
    if not token:
        return True
    return handler.headers.get("Authorization", "") == f"Bearer {token}"


def _extract_goal(params: dict) -> tuple[str, str, str, bool, str, bool]:
    message = params.get("message") or {}
    context_id = message.get("contextId") or ""
    parts = message.get("parts") or []
    for part in parts:
        data = part.get("data")
        if isinstance(data, dict) and data.get("target"):
            return (
                str(data["target"]),
                str(data.get("profile", "standard")),
                context_id,
                bool(data.get("dynamic", False)),
                str(data.get("sandbox", "docker")),
                bool(data.get("allowHost", False)),
            )
        text = part.get("text")
        if isinstance(text, str):
            try:
                data = json.loads(text)
            except Exception:
                continue
            if isinstance(data, dict) and data.get("target"):
                return (
                    str(data["target"]),
                    str(data.get("profile", "standard")),
                    context_id,
                    bool(data.get("dynamic", False)),
                    str(data.get("sandbox", "docker")),
                    bool(data.get("allowHost", False)),
                )
    raise ValueError("message must contain a data part with target")


def _extract_poc(params: dict) -> dict | None:
    """Return a PoC request if the message carries a bridge class."""
    message = params.get("message") or {}
    context_id = message.get("contextId") or ""
    parts = message.get("parts") or []
    data = None
    for part in parts:
        candidate = part.get("data")
        if not isinstance(candidate, dict):
            text = part.get("text")
            if isinstance(text, str):
                try:
                    candidate = json.loads(text)
                except Exception:
                    candidate = None
        if isinstance(candidate, dict) and candidate.get("bridge"):
            data = candidate
            break
    if data is None:
        return None
    if not data.get("target"):
        raise ValueError("PoC request must contain target")
    return {
        "target": str(data["target"]),
        "bridge": str(data["bridge"]),
        "trigger": str(data.get("trigger", "hash")),
        "tail": data.get("tail"),
        "jdk11": bool(data.get("jdk11", False)),
        "ecj": data.get("ecj"),
        "allow_host": bool(data.get("allowHost", False)),
        "context_id": context_id,
    }


def _make_handler(service: JgdService, base_url: str, token: str | None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            print(f"jgd a2a: {fmt % args}", file=sys.stderr)

        def _require_auth(self) -> bool:
            if _auth_ok(self, token):
                return True
            _json_response(self, {"error": "unauthorized"}, 401)
            return False

        def _card(self) -> dict:
            host = self.server.server_address[0]
            port = self.server.server_port
            return agent_card(f"http://{host}:{port}/a2a", token)

        def do_GET(self):
            path = urlparse(self.path).path
            if path in ("/.well-known/agent-card.json", "/agent-card.json"):
                _json_response(self, self._card())
                return
            if path == "/health":
                _json_response(self, {"ok": True})
                return
            m = re.match(r"^/artifacts/([^/]+)/([^/]+)$", path)
            if m:
                if not self._require_auth():
                    return
                run_id, name = m.group(1), m.group(2)
                if not _RUN_RE.match(run_id) or not _ART_RE.match(name):
                    _json_response(self, {"error": "bad artifact path"}, 400)
                    return
                artifact = service.home / "runs" / run_id / name
                if not artifact.is_file():
                    _json_response(self, {"error": "not found"}, 404)
                    return
                data = artifact.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            _json_response(self, {"error": "not found"}, 404)

        def do_POST(self):
            if not self._require_auth():
                return
            length = int(self.headers.get("Content-Length", "0"))
            try:
                req = json.loads(self.rfile.read(length) or b"{}")
            except Exception as exc:
                _rpc_error(self, None, -32700, f"parse error: {exc}")
                return
            req_id = req.get("id")
            method = req.get("method")
            params = req.get("params") or {}
            try:
                if method == "SendMessage":
                    poc = _extract_poc(params)
                    if poc is not None:
                        run_id = service.start_poc(
                            poc["target"],
                            poc["bridge"],
                            trigger=poc["trigger"],
                            tail=poc["tail"],
                            jdk11=poc["jdk11"],
                            ecj=poc["ecj"],
                            allow_host=poc["allow_host"],
                            context_id=poc["context_id"],
                        )
                    else:
                        target, profile, context_id, dynamic, sandbox, allow_host = _extract_goal(params)
                        run_id = service.start_audit(
                            target, profile, context_id=context_id,
                            dynamic=dynamic, sandbox=sandbox, allow_host=allow_host,
                        )
                    if not (params.get("configuration") or {}).get("returnImmediately", False):
                        service.wait(run_id, timeout=float((params.get("configuration") or {}).get("timeout", 600)))
                    _json_response(self, {"jsonrpc": "2.0", "id": req_id, "result": service.get_task(run_id)})
                    return
                if method == "SendStreamingMessage":
                    target, profile, context_id, dynamic, sandbox, allow_host = _extract_goal(params)
                    run_id = service.start_audit(
                        target, profile, context_id=context_id,
                        dynamic=dynamic, sandbox=sandbox, allow_host=allow_host,
                    )
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(b"data: " + json.dumps({"task": service.get_task(run_id)}, ensure_ascii=False).encode() + b"\n\n")
                    self.wfile.flush()
                    while True:
                        task = service.poll(run_id)
                        if task.state in ("TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED"):
                            self.wfile.write(b"data: " + json.dumps({"statusUpdate": service.get_task(run_id)["status"]}, ensure_ascii=False).encode() + b"\n\n")
                            self.wfile.flush()
                            break
                        time.sleep(0.2)
                    return
                if method == "GetTask":
                    task = service.get_task(params["id"])
                    _json_response(self, {"jsonrpc": "2.0", "id": req_id, "result": task})
                    return
                if method == "ListTasks":
                    tasks = service.list_tasks()
                    _json_response(self, {"jsonrpc": "2.0", "id": req_id, "result": {
                        "tasks": tasks, "nextPageToken": "", "pageSize": len(tasks), "totalSize": len(tasks)
                    }})
                    return
                if method == "CancelTask":
                    service.cancel(params["id"])
                    _json_response(self, {"jsonrpc": "2.0", "id": req_id, "result": service.get_task(params["id"])})
                    return
                if method == "GetExtendedAgentCard":
                    _json_response(self, {"jsonrpc": "2.0", "id": req_id, "result": self._card()})
                    return
                _rpc_error(self, req_id, -32601, f"method not found: {method}")
            except KeyError as exc:
                _rpc_error(self, req_id, -32602, f"missing parameter: {exc}")
            except Exception as exc:
                _rpc_error(self, req_id, -32603, str(exc))

    return Handler


def create_server(
    host: str = "127.0.0.1",
    port: int = 8080,
    home: Path | str | None = None,
    token: str | None = None,
) -> ThreadingHTTPServer:
    service = JgdService(home=home)
    base_url = f"http://{host}:{port}/a2a"
    handler = _make_handler(service, base_url, token)
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.jgd_service = service  # type: ignore[attr-defined]
    return server


def serve(host: str = "127.0.0.1", port: int = 8080, home: Path | str | None = None, token: str | None = None) -> int:
    server = create_server(host, port, home, token)
    print(f"jgd a2a: http://{host}:{server.server_port} (card: /.well-known/agent-card.json)", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
