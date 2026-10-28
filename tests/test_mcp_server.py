"""Plan 4: MCP stdio contract."""
import json
import subprocess
import sys
import zipfile
from pathlib import Path


def test_mcp_initialize_list_and_audit(tmp_path: Path):
    target = tmp_path / "jars"
    target.mkdir()
    with zipfile.ZipFile(target / "empty.jar", "w"):
        pass
    home = tmp_path / "home"
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "jgd_audit",
                "arguments": {"target": str(target), "profile": "known", "wait": True},
            },
        },
    ]
    payload = "\n".join(json.dumps(r) for r in requests) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "jgd", "serve", "mcp", "--home", str(home)],
        input=payload,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [json.loads(x) for x in proc.stdout.splitlines() if x.strip()]
    assert len(lines) == 3, proc.stdout
    assert lines[0]["result"]["serverInfo"]["name"] == "jgd"
    names = {t["name"] for t in lines[1]["result"]["tools"]}
    assert {"jgd_audit", "jgd_poc", "jgd_get_run", "jgd_list_findings"} <= names
    task = json.loads(lines[2]["result"]["content"][0]["text"])
    assert task["id"]
    assert task["status"]["state"] in (
        "TASK_STATE_COMPLETED",
        "TASK_STATE_FAILED",
        "TASK_STATE_WORKING",
    )
