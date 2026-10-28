"""Webhook receiver auth and Nexus URL allowlist contracts."""
import hashlib
import hmac
import json
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from jgd.adapters.webhook_server import (
    _under_base,
    create_server,
    extract_artifact_path,
    extract_artifact_url,
)


def test_extract_common_nexus_fields():
    payload = {
        "action": "CREATED",
        "asset": {
            "downloadUrl": "https://nexus.example/repository/maven/demo-1.0.jar",
            "path": "com/acme/demo-1.0.jar",
        },
    }
    assert extract_artifact_url(payload).endswith("demo-1.0.jar")
    assert extract_artifact_path(payload) == "com/acme/demo-1.0.jar"


def test_nexus_url_allowlist():
    base = "https://nexus.example/repository/maven-releases"
    assert _under_base(base + "/com/acme/demo.jar", base)
    assert not _under_base("https://evil.example/demo.jar", base)
    assert not _under_base("http://nexus.example/repository/maven-releases/x.jar", base)
    assert not _under_base("https://nexus.example/repository/other/x.jar", base)


def test_webhook_requires_auth_configuration(tmp_path: Path):
    with pytest.raises(ValueError):
        create_server(port=0, home=tmp_path / "home")


def _post(port: int, body: bytes, headers: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/webhooks/nexus",
        data=body,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_webhook_health_auth_and_ignore(tmp_path: Path):
    server = create_server(
        port=0,
        home=tmp_path / "home",
        token="test-token",
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urllib.request.urlopen(base + "/health", timeout=10) as response:
            assert json.loads(response.read().decode("utf-8"))["ok"] is True

        status, _ = _post(server.server_port, b"{}", {})
        assert status == 401

        status, body = _post(
            server.server_port,
            b"{}",
            {"Authorization": "Bearer test-token"},
        )
        assert status == 202
        assert body["status"] == "ignored"
    finally:
        server.shutdown()
        server.server_close()


def test_webhook_accepts_local_jar(tmp_path: Path):
    import zipfile

    root = tmp_path / "nexus"
    root.mkdir()
    with zipfile.ZipFile(root / "demo.jar", "w"):
        pass
    server = create_server(
        port=0,
        home=tmp_path / "home",
        token="test-token",
        local_root=root,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        body = json.dumps(
            {"action": "CREATED", "asset": {"path": "demo.jar"}}
        ).encode()
        status, response = _post(
            server.server_port,
            body,
            {"Authorization": "Bearer test-token"},
        )
        assert status == 202
        assert response["status"] == "accepted"
        assert response["taskId"]
    finally:
        server.shutdown()
        server.server_close()


def test_webhook_hmac_accepts_valid_signature(tmp_path: Path):
    secret = "hmac-secret"
    body = json.dumps({"action": "CREATED"}).encode("utf-8")
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    server = create_server(
        port=0,
        home=tmp_path / "home",
        secret=secret,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, response = _post(
            server.server_port,
            body,
            {"X-Nexus-Webhook-Signature": f"sha256={sig}"},
        )
        assert status == 202
        assert response["status"] == "ignored"
    finally:
        server.shutdown()
        server.server_close()
