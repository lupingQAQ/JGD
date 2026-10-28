"""Small process-backed run service for MCP/A2A adapters.

JGD owns the audit; this service only starts the CLI in an isolated run
directory, tracks task state, and exposes results. Dynamic/sandboxed tools
remain behind the CLI policy.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass
class RunTask:
    run_id: str
    target: str
    profile: str
    state: str = "TASK_STATE_SUBMITTED"
    rc: int | None = None
    error: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    process: subprocess.Popen | None = field(default=None, repr=False)
    context_id: str = ""


class JgdService:
    def __init__(self, home: Path | str | None = None) -> None:
        self.home = Path(home) if home is not None else Path.cwd() / "runs"
        self.home.mkdir(parents=True, exist_ok=True)
        self._tasks: dict[str, RunTask] = {}
        self._lock = threading.Lock()

    def _new_id(self) -> str:
        return f"{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"

    def start_audit(
        self,
        target: Path | str,
        profile: str = "standard",
        *,
        context_id: str = "",
        dynamic: bool = False,
        sandbox: str = "docker",
        allow_host: bool = False,
        ecj: Path | str | None = None,
    ) -> str:
        target = Path(target).resolve()
        if not target.is_dir():
            raise FileNotFoundError(f"target is not a directory: {target}")
        run_id = self._new_id()
        run_dir = self.home / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            sys.executable,
            "-m",
            "jgd",
            "audit",
            "--target",
            str(target),
            "--profile",
            profile,
            "--format",
            "json,sarif,md",
            "--out",
            str(run_dir),
        ]
        if dynamic:
            cmd += ["--dynamic", "--sandbox", sandbox]
            if allow_host:
                cmd.append("--unsafe-host")
            if ecj:
                cmd += ["--ecj", str(Path(ecj))]
        env = dict(os.environ)
        env.setdefault("PYTHONPATH", str(PROJECT_ROOT))
        log = (run_dir / "process.log").open("w", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        task = RunTask(
            run_id=run_id,
            target=str(target),
            profile=profile,
            state="TASK_STATE_WORKING",
            process=proc,
            context_id=context_id or run_id,
        )
        with self._lock:
            self._tasks[run_id] = task
        return run_id

    def start_poc(
        self,
        target: Path | str,
        bridge: str,
        *,
        trigger: str = "hash",
        tail: str | None = None,
        jdk11: bool = False,
        ecj: Path | str | None = None,
        allow_host: bool = False,
        context_id: str = "",
    ) -> str:
        """Start a deterministic PoC build/verification task.

        ``allow_host`` is explicit because this executes target gadget code.
        The expected deployment is inside the isolated Linux VM.
        """
        if not allow_host:
            raise PermissionError(
                "PoC execution requires allowHost=true inside an isolated VM"
            )
        target = Path(target).resolve()
        if not target.is_dir():
            raise FileNotFoundError(f"target is not a directory: {target}")
        run_id = self._new_id()
        run_dir = self.home / "runs" / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        cmd = [
            sys.executable,
            "-m",
            "jgd",
            "poc",
            "--target",
            str(target),
            "--bridge",
            bridge,
            "--trigger",
            trigger,
            "--out",
            str(run_dir),
            "--unsafe-host",
        ]
        if tail:
            cmd += ["--tail", tail]
        if jdk11:
            cmd.append("--jdk11")
        if ecj:
            cmd += ["--ecj", str(Path(ecj))]
        env = dict(os.environ)
        env.setdefault("PYTHONPATH", str(PROJECT_ROOT))
        log = (run_dir / "process.log").open("w", encoding="utf-8")
        proc = subprocess.Popen(
            cmd,
            cwd=str(PROJECT_ROOT),
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        task = RunTask(
            run_id=run_id,
            target=str(target),
            profile="poc",
            state="TASK_STATE_WORKING",
            process=proc,
            context_id=context_id or run_id,
        )
        with self._lock:
            self._tasks[run_id] = task
        return run_id

    def wait(self, run_id: str, timeout: float | None = None) -> RunTask:
        task = self._get(run_id)
        proc = task.process
        if proc is not None:
            try:
                task.rc = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                task.state = "TASK_STATE_WORKING"
                return task
            task.process = None
            task.finished_at = time.time()
            task.state = (
                "TASK_STATE_COMPLETED"
                if task.rc in (0, 10, 20)
                else "TASK_STATE_FAILED"
            )
            if task.rc not in (0, 10, 20):
                task.error = f"jgd exited {task.rc}; see process.log"
        return task

    def poll(self, run_id: str) -> RunTask:
        """Non-blocking refresh for GetTask."""
        task = self._get(run_id)
        if task.process is None:
            return task
        try:
            rc = task.process.wait(timeout=0.01)
        except subprocess.TimeoutExpired:
            return task
        task.rc = rc
        task.process = None
        task.finished_at = time.time()
        task.state = "TASK_STATE_COMPLETED" if rc in (0, 10, 20) else "TASK_STATE_FAILED"
        if rc not in (0, 10, 20):
            task.error = f"jgd exited {rc}; see process.log"
        return task

    def cancel(self, run_id: str) -> RunTask:
        task = self._get(run_id)
        if task.process is not None:
            task.process.terminate()
            try:
                task.rc = task.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                task.process.kill()
                task.rc = task.process.wait()
            task.process = None
            task.finished_at = time.time()
            task.state = "TASK_STATE_CANCELED"
        return task

    def _get(self, run_id: str) -> RunTask:
        with self._lock:
            task = self._tasks.get(run_id)
        if task is None:
            raise KeyError(run_id)
        return task

    def get_task(self, run_id: str) -> dict:
        task = self.poll(run_id)
        result = self.read_run(run_id)
        artifacts = []
        if result:
            artifacts.append(
                {
                    "artifactId": f"{run_id}-report",
                    "name": "report.json",
                    "parts": [{"data": result, "mediaType": "application/json"}],
                }
            )
        return {
            "id": run_id,
            "contextId": task.context_id,
            "status": {
                "state": task.state,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "message": task.error or "",
            },
            "artifacts": artifacts,
            "metadata": {
                "target": task.target,
                "profile": task.profile,
                "rc": task.rc,
            },
        }

    def read_run(self, run_id: str) -> dict | None:
        run_dir = self.home / "runs" / run_id
        for name in ("run.json", "poc_result.json"):
            path = run_dir / name
            if not path.exists():
                continue
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return None
        return None

    def read_findings(self, run_id: str) -> list[dict]:
        path = self.home / "runs" / run_id / "findings.json"
        if not path.exists():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def list_tasks(self) -> list[dict]:
        with self._lock:
            ids = list(self._tasks)
        return [self.get_task(i) for i in ids]
