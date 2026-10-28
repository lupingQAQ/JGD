"""Plan 4: A2A card and SendMessage/GetTask over HTTP."""
import json
import threading
import urllib.request
import zipfile
from pathlib import Path

from jgd.adapters.a2a_server import create_server


def _empty_jar(target: Path) -> None:
    target.mkdir()
    with zipfile.ZipFile(target / "empty.jar", "w"):
        pass


def test_a2a_card_and_blocking_send(tmp_path: Path):
    target = tmp_path / "jars"
    _empty_jar(target)
    server = create_server(port=0, home=tmp_path / "home")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        with urllib.request.urlopen(base + "/.well-known/agent-card.json", timeout=10) as r:
            card = json.loads(r.read().decode("utf-8"))
        assert card["name"] == "JGD Deserialization Analyzer"
        assert card["skills"]
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "SendMessage",
            "params": {
                "message": {
                    "role": "user",
                    "messageId": "m1",
                    "parts": [
                        {
                            "data": {
                                "skillId": "deserialization-audit",
                                "target": str(target),
                                "profile": "known",
                            }
                        }
                    ],
                },
                "configuration": {"returnImmediately": False, "timeout": 120},
            },
        }
        req = urllib.request.Request(
            base + "/a2a",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=180) as r:
            response = json.loads(r.read().decode("utf-8"))
        task = response["result"]
        assert task["id"]
        assert task["status"]["state"] in ("TASK_STATE_COMPLETED", "TASK_STATE_FAILED")
        assert task["artifacts"]
    finally:
        server.shutdown()
        server.server_close()
