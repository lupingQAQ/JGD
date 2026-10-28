"""Minimal MCP stdio server for JGD.

The MCP surface is a control plane: a model starts an audit, polls it, and
reads findings. The JGD mining loop remains inside JGD.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from jgd.service import JgdService

TOOL_VERSION = "0.3.0"

TOOLS = [
    {
        "name": "jgd_audit",
        "description": "Start a JGD static audit of a JAR directory. Returns runId and, by default, the completed run summary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Local JAR directory"},
                "profile": {"enum": ["known", "standard", "deep", "full"], "default": "standard"},
                "dynamic": {"type": "boolean", "default": False},
                "sandbox": {"enum": ["docker", "wsl2", "host"], "default": "docker"},
                "allowHost": {"type": "boolean", "default": False},
                "ecj": {"type": "string", "description": "ECJ jar for automatic PoC tails"},
                "wait": {"type": "boolean", "default": True},
                "timeout": {"type": "number", "default": 600},
            },
            "required": ["target"],
        },
    },
    {
        "name": "jgd_poc",
        "description": "Build and verify one deserialization PoC. Executes target code; use only inside the isolated VM.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Local JAR directory"},
                "bridge": {"type": "string", "description": "Bridge class name"},
                "trigger": {"enum": ["hash", "hash-build", "equals", "tostring"], "default": "hash"},
                "tail": {"type": "string"},
                "jdk11": {"type": "boolean", "default": False},
                "ecj": {"type": "string"},
                "allowHost": {"type": "boolean", "default": False},
                "wait": {"type": "boolean", "default": True},
                "timeout": {"type": "number", "default": 600},
            },
            "required": ["target", "bridge", "allowHost"],
        },
    },
    {
        "name": "jgd_get_run",
        "description": "Read a JGD run status and report artifact.",
        "inputSchema": {
            "type": "object",
            "properties": {"runId": {"type": "string"}},
            "required": ["runId"],
        },
    },
    {
        "name": "jgd_list_findings",
        "description": "List findings for a completed JGD run.",
        "inputSchema": {
            "type": "object",
            "properties": {"runId": {"type": "string"}},
            "required": ["runId"],
        },
    },
    {
        "name": "jgd_cancel",
        "description": "Cancel a running JGD audit.",
        "inputSchema": {
            "type": "object",
            "properties": {"runId": {"type": "string"}},
            "required": ["runId"],
        },
    },
]


def _text(value) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}]}


def _handle(msg: dict, service: JgdService):
    method = msg.get("method")
    params = msg.get("params") or {}
    if method == "initialize":
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "jgd", "version": TOOL_VERSION},
        }
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "resources/list":
        return {"resources": []}
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "jgd_audit":
            target = args.get("target")
            if not target:
                return _text({"error": "target is required"})
            run_id = service.start_audit(
                target,
                args.get("profile", "standard"),
                dynamic=bool(args.get("dynamic", False)),
                sandbox=str(args.get("sandbox", "docker")),
                allow_host=bool(args.get("allowHost", False)),
                ecj=args.get("ecj"),
            )
            if args.get("wait", True):
                service.wait(run_id, timeout=float(args.get("timeout", 600)))
            return _text(service.get_task(run_id))
        if name == "jgd_poc":
            target = args.get("target")
            bridge = args.get("bridge")
            if not target or not bridge:
                return _text({"error": "target and bridge are required"})
            try:
                run_id = service.start_poc(
                    target,
                    bridge,
                    trigger=args.get("trigger", "hash"),
                    tail=args.get("tail"),
                    jdk11=bool(args.get("jdk11", False)),
                    ecj=args.get("ecj"),
                    allow_host=bool(args.get("allowHost", False)),
                )
            except PermissionError as exc:
                return _text({"error": str(exc)})
            if args.get("wait", True):
                service.wait(run_id, timeout=float(args.get("timeout", 600)))
            return _text(service.get_task(run_id))
        if name == "jgd_get_run":
            return _text(service.get_task(args["runId"]))
        if name == "jgd_list_findings":
            return _text(service.read_findings(args["runId"]))
        if name == "jgd_cancel":
            service.cancel(args["runId"])
            return _text(service.get_task(args["runId"]))
        return _text({"error": f"unknown tool: {name}"})
    return None


def serve(home: Path | str | None = None, stdin=None, stdout=None) -> int:
    service = JgdService(home=home)
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except Exception as exc:
            print(f"jgd mcp: bad JSON: {exc}", file=sys.stderr)
            continue
        if "id" not in msg:
            _handle(msg, service)
            continue
        try:
            result = _handle(msg, service)
            response = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
        except Exception as exc:
            response = {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {"code": -32603, "message": str(exc)},
            }
        stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
