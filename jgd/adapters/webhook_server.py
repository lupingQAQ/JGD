"""Nexus/CI webhook receiver for JGD.

The receiver is deliberately narrow:

* bind to loopback by default;
* require a Bearer token or an HMAC-SHA256 signature;
* only download URLs under an explicitly configured Nexus base URL, or read
  files under an explicitly configured local root;
* only accept ``.jar`` artifacts;
* hand the artifact to the normal JGD service/policy path.

It does not expose arbitrary command execution.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from jgd.service import JgdService

_MAX_ARTIFACT_BYTES = 512 * 1024 * 1024


@dataclass(frozen=True)
class WebhookConfig:
    home: Path
    work_dir: Path
    token: str | None = None
    secret: str | None = None
    nexus_base_url: str | None = None
    nexus_token: str | None = None
    local_root: Path | None = None
    profile: str = "standard"
    fail_on: str = "high"
    dynamic: bool = False
    sandbox: str = "docker"
    allow_host: bool = False
    wait: bool = False
    wait_timeout: float = 600.0


def _json_response(handler: BaseHTTPRequestHandler, obj: dict, status: int = 200) -> None:
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _token_ok(handler: BaseHTTPRequestHandler, token: str | None) -> bool:
    if not token:
        return True
    expected = f"Bearer {token}"
    return hmac.compare_digest(handler.headers.get("Authorization", ""), expected)


def _signature_ok(handler: BaseHTTPRequestHandler, secret: str | None, body: bytes) -> bool:
    if not secret:
        return True
    supplied = (
        handler.headers.get("X-Nexus-Webhook-Signature")
        or handler.headers.get("X-Hub-Signature-256")
        or ""
    )
    if supplied.startswith("sha256="):
        supplied = supplied[7:]
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(supplied.lower(), expected.lower())


def _under_base(url: str, base: str | None) -> bool:
    if not base:
        return False
    target = urllib.parse.urlsplit(url)
    root = urllib.parse.urlsplit(base)
    if target.scheme not in ("http", "https") or target.scheme != root.scheme:
        return False
    if target.netloc != root.netloc:
        return False
    base_path = root.path.rstrip("/") + "/"
    return target.path == root.path.rstrip("/") or target.path.startswith(base_path)


def extract_artifact_url(payload: dict) -> str | None:
    """Extract a Nexus asset download URL from common webhook shapes."""
    asset = payload.get("asset") if isinstance(payload.get("asset"), dict) else {}
    for container in (asset, payload):
        for key in ("downloadUrl", "downloadURL", "url"):
            value = container.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def extract_artifact_path(payload: dict) -> str | None:
    asset = payload.get("asset") if isinstance(payload.get("asset"), dict) else {}
    for container in (asset, payload):
        for key in ("path", "blobRef", "name"):
            value = container.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _is_jar(name: str) -> bool:
    return urllib.parse.urlsplit(name).path.lower().endswith(".jar")


def _download(
    url: str,
    base: str | None,
    dest: Path,
    nexus_token: str | None = None,
) -> Path:
    if not _under_base(url, base):
        raise ValueError("artifact URL is outside the configured Nexus base URL")
    headers = {"User-Agent": "jgd-webhook/0.4"}
    if nexus_token:
        headers["Authorization"] = f"Bearer {nexus_token}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as response:  # noqa: S310 - allowlisted
        final_url = response.geturl()
        if not _under_base(final_url, base):
            raise ValueError("redirect left the configured Nexus base URL")
        length = int(response.headers.get("Content-Length") or 0)
        if length > _MAX_ARTIFACT_BYTES:
            raise ValueError("artifact exceeds size limit")
        dest.parent.mkdir(parents=True, exist_ok=True)
        total = 0
        with dest.open("wb") as fh:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_ARTIFACT_BYTES:
                    raise ValueError("artifact exceeds size limit")
                fh.write(chunk)
    return dest


def _resolve_artifact(payload: dict, config: WebhookConfig) -> Path | None:
    url = extract_artifact_url(payload)
    name = url or extract_artifact_path(payload) or ""
    if not _is_jar(name):
        return None
    if url:
        target_dir = config.work_dir / f"event-{uuid.uuid4().hex[:12]}"
        target_dir.mkdir(parents=True, exist_ok=True)
        dest = target_dir / (Path(urllib.parse.urlsplit(url).path).name or "artifact.jar")
        return _download(url, config.nexus_base_url, dest, config.nexus_token)
    raw_path = extract_artifact_path(payload)
    if not raw_path or not config.local_root:
        raise ValueError("artifact has no downloadUrl and no local_root is configured")
    candidate = (config.local_root / raw_path).resolve()
    root = config.local_root.resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("artifact path escapes local_root") from exc
    if not candidate.is_file():
        raise ValueError("artifact path does not exist")
    target_dir = config.work_dir / f"event-{uuid.uuid4().hex[:12]}"
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / candidate.name
    dest.write_bytes(candidate.read_bytes())
    return dest


def _make_handler(service: JgdService, config: WebhookConfig):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):
            print(f"jgd webhook: {fmt % args}", file=sys.stderr)

        def _authorized(self, body: bytes) -> bool:
            if not (_token_ok(self, config.token) and _signature_ok(self, config.secret, body)):
                _json_response(self, {"error": "unauthorized"}, 401)
                return False
            return True

        def do_GET(self):
            if urllib.parse.urlsplit(self.path).path != "/health":
                _json_response(self, {"error": "not found"}, 404)
                return
            _json_response(self, {"ok": True, "service": "jgd-webhook"})

        def do_POST(self):
            if urllib.parse.urlsplit(self.path).path not in ("/webhooks/nexus", "/webhooks/ci"):
                _json_response(self, {"error": "not found"}, 404)
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 4 * 1024 * 1024:
                _json_response(self, {"error": "invalid body size"}, 413)
                return
            body = self.rfile.read(length)
            if not self._authorized(body):
                return
            try:
                payload = json.loads(body or b"{}")
                if not isinstance(payload, dict):
                    raise ValueError("webhook body must be an object")
                artifact = _resolve_artifact(payload, config)
                if artifact is None:
                    _json_response(self, {"status": "ignored", "reason": "not a .jar"}, 202)
                    return
                target_dir = artifact.parent
                run_id = service.start_audit(
                    target_dir,
                    config.profile,
                    dynamic=config.dynamic,
                    sandbox=config.sandbox,
                    allow_host=config.allow_host,
                    fail_on=config.fail_on,
                )
                if config.wait:
                    service.wait(run_id, timeout=config.wait_timeout)
                _json_response(
                    self,
                    {
                        "status": "accepted",
                        "taskId": run_id,
                        "event": str(payload.get("action", "")),
                        "artifact": artifact.name,
                    },
                    202,
                )
            except ValueError as exc:
                _json_response(self, {"error": str(exc)}, 422)
            except Exception as exc:
                _json_response(self, {"error": f"internal error: {exc}"}, 500)

    return Handler


def create_server(
    host: str = "127.0.0.1",
    port: int = 8090,
    *,
    home: Path | str | None = None,
    work_dir: Path | str | None = None,
    token: str | None = None,
    secret: str | None = None,
    nexus_base_url: str | None = None,
    nexus_token: str | None = None,
    local_root: Path | str | None = None,
    profile: str = "standard",
    fail_on: str = "high",
    dynamic: bool = False,
    sandbox: str = "docker",
    allow_host: bool = False,
    wait: bool = False,
    wait_timeout: float = 600.0,
) -> ThreadingHTTPServer:
    if not token and not secret:
        raise ValueError("webhook requires --token and/or --secret")
    home_path = Path(home) if home is not None else Path.cwd() / "runs"
    config = WebhookConfig(
        home=home_path,
        work_dir=Path(work_dir) if work_dir else home_path / "webhook-artifacts",
        token=token,
        secret=secret,
        nexus_base_url=nexus_base_url.rstrip("/") if nexus_base_url else None,
        nexus_token=nexus_token,
        local_root=Path(local_root) if local_root else None,
        profile=profile,
        fail_on=fail_on,
        dynamic=dynamic,
        sandbox=sandbox,
        allow_host=allow_host,
        wait=wait,
        wait_timeout=wait_timeout,
    )
    config.work_dir.mkdir(parents=True, exist_ok=True)
    service = JgdService(home=home_path)
    server = ThreadingHTTPServer((host, port), _make_handler(service, config))
    server.daemon_threads = True
    server.jgd_service = service  # type: ignore[attr-defined]
    server.jgd_config = config  # type: ignore[attr-defined]
    return server


def serve(
    host: str = "127.0.0.1",
    port: int = 8090,
    *,
    home: Path | str | None = None,
    work_dir: Path | str | None = None,
    token: str | None = None,
    secret: str | None = None,
    nexus_base_url: str | None = None,
    nexus_token: str | None = None,
    local_root: Path | str | None = None,
    profile: str = "standard",
    fail_on: str = "high",
    dynamic: bool = False,
    sandbox: str = "docker",
    allow_host: bool = False,
    wait: bool = False,
    wait_timeout: float = 600.0,
) -> int:
    server = create_server(
        host,
        port,
        home=home,
        work_dir=work_dir,
        token=token,
        secret=secret,
        nexus_base_url=nexus_base_url,
        nexus_token=nexus_token,
        local_root=local_root,
        profile=profile,
        fail_on=fail_on,
        dynamic=dynamic,
        sandbox=sandbox,
        allow_host=allow_host,
        wait=wait,
        wait_timeout=wait_timeout,
    )
    print(
        f"jgd webhook: http://{host}:{server.server_port} "
        "(POST /webhooks/nexus, GET /health)",
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
