"""A2A streaming and Bearer-auth checks."""
import json
import threading
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from jgd.adapters.a2a_server import create_server


def _empty_jar(target: Path) -> None:
    target.mkdir()
    with zipfile.ZipFile(target / "empty.jar", "w"):
        pass


def _send_stream(base: str, target: Path) -> str:
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendStreamingMessage",
        "params": {
            "message": {
                "role": "user",
                "messageId": "m1",
                "parts": [{"data": {"target": str(target), "profile": "known"}}],
            }
        },
    }
    req = urllib.request.Request(
        base + "/a2a",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as r:
        return r.read().decode("utf-8")


def test_a2a_streaming_contains_task_and_status(tmp_path: Path):
    target = tmp_path / "jars"
    _empty_jar(target)
    server = create_server(port=0, home=tmp_path / "home")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        payload = _send_stream(base, target)
        events = [json.loads(line[6:]) for line in payload.splitlines() if line.startswith("data: ")]
        assert any("task" in e for e in events)
        assert any("statusUpdate" in e for e in events)
    finally:
        server.shutdown()
        server.server_close()


def test_a2a_bearer_auth(tmp_path: Path):
    target = tmp_path / "jars"
    _empty_jar(target)
    server = create_server(port=0, home=tmp_path / "home", token="secret")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urllib.request.urlopen(base + "/.well-known/agent-card.json", timeout=10) as r:
            card = json.loads(r.read().decode())
        assert "securitySchemes" in card
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "GetTask",
            "params": {"id": "missing"},
        }
        req = urllib.request.Request(
            base + "/a2a",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)
        except urllib.error.HTTPError as exc:
            assert exc.code == 401
        else:
            raise AssertionError("expected 401 without bearer token")
    finally:
        server.shutdown()
        server.server_close()
