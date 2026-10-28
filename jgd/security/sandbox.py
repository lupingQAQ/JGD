"""Sandbox contract for executing untrusted target code.

Plan 2 provides the boundary; dynamic tooling must go through it. HostSandbox
exists only for trusted fixtures/tests and requires an explicit opt-in.
"""
from __future__ import annotations

import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Protocol


class SandboxError(RuntimeError):
    """Raised when a sandbox is unavailable or policy denies execution."""


@dataclass(frozen=True)
class SandboxLimits:
    memory_mb: int = 2048
    cpus: float = 2.0
    pids: int = 256
    timeout_s: int = 120
    network: bool = False


@dataclass
class SandboxResult:
    rc: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    duration_s: float = 0.0
    command: list[str] = field(default_factory=list)


class Sandbox(Protocol):
    name: str

    def run(
        self,
        argv: list[str],
        *,
        mounts: dict[Path, tuple[Path, bool]] | None = None,
        env: dict[str, str] | None = None,
        limits: SandboxLimits = SandboxLimits(),
        workdir: Path | None = None,
    ) -> SandboxResult:
        ...


def _posix(path: Path | str) -> str:
    s = str(path).replace("\\", "/")
    return s if s.startswith("/") else "/" + s.lstrip("/")


class HostSandbox:
    """Unsafe host execution; only for trusted fixtures and tests."""

    name = "host"

    def __init__(self, allow_host: bool = False) -> None:
        self.allow_host = allow_host

    def run(
        self,
        argv: list[str],
        *,
        mounts: dict[Path, tuple[Path, bool]] | None = None,
        env: dict[str, str] | None = None,
        limits: SandboxLimits = SandboxLimits(),
        workdir: Path | None = None,
    ) -> SandboxResult:
        if not self.allow_host:
            raise SandboxError(
                "host sandbox requires allow_host=True; use Docker/WSL2 for untrusted targets"
            )
        t0 = time.perf_counter()
        try:
            p = subprocess.run(
                argv,
                cwd=str(workdir) if workdir else None,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=limits.timeout_s,
            )
            return SandboxResult(
                rc=p.returncode,
                stdout=p.stdout or "",
                stderr=p.stderr or "",
                duration_s=round(time.perf_counter() - t0, 3),
                command=list(argv),
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(
                rc=-1,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr="TIMEOUT",
                timed_out=True,
                duration_s=round(time.perf_counter() - t0, 3),
                command=list(argv),
            )


class DockerSandbox:
    name = "docker"

    def __init__(self, image: str = "jgd-sandbox:latest", docker: str = "docker") -> None:
        self.image = image
        self.docker = docker

    def command(
        self,
        argv: list[str],
        *,
        mounts: dict[Path, tuple[Path, bool]] | None = None,
        env: dict[str, str] | None = None,
        limits: SandboxLimits = SandboxLimits(),
        workdir: Path | None = None,
    ) -> list[str]:
        cmd = [
            self.docker,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--user",
            "65532:65532",
            "--cap-drop=ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(limits.pids),
            "--memory",
            f"{limits.memory_mb}m",
            "--cpus",
            str(limits.cpus),
        ]
        for host, (container, readonly) in (mounts or {}).items():
            suffix = ":ro" if readonly else ""
            cmd += ["-v", f"{host}:{_posix(container)}{suffix}"]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        if workdir is not None:
            cmd += ["-w", _posix(workdir)]
        cmd += [self.image, *argv]
        return cmd

    def run(
        self,
        argv: list[str],
        *,
        mounts: dict[Path, tuple[Path, bool]] | None = None,
        env: dict[str, str] | None = None,
        limits: SandboxLimits = SandboxLimits(),
        workdir: Path | None = None,
    ) -> SandboxResult:
        if shutil.which(self.docker) is None:
            raise SandboxError(f"docker not found: {self.docker}")
        cmd = self.command(argv, mounts=mounts, env=env, limits=limits, workdir=workdir)
        t0 = time.perf_counter()
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=limits.timeout_s,
            )
            return SandboxResult(
                rc=p.returncode,
                stdout=p.stdout or "",
                stderr=p.stderr or "",
                duration_s=round(time.perf_counter() - t0, 3),
                command=cmd,
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(
                rc=-1,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr="TIMEOUT",
                timed_out=True,
                duration_s=round(time.perf_counter() - t0, 3),
                command=cmd,
            )


class WslSandbox:
    name = "wsl2"

    def __init__(self, distro: str = "Ubuntu") -> None:
        self.distro = distro

    def command(self, argv: list[str], *, workdir: Path | None = None) -> list[str]:
        script = shlex.join(argv)
        if workdir is not None:
            script = f"cd {shlex.quote(_posix(workdir))} && {script}"
        return ["wsl.exe", "-d", self.distro, "--", "bash", "-lc", script]

    def run(
        self,
        argv: list[str],
        *,
        mounts: dict[Path, tuple[Path, bool]] | None = None,
        env: dict[str, str] | None = None,
        limits: SandboxLimits = SandboxLimits(),
        workdir: Path | None = None,
    ) -> SandboxResult:
        if shutil.which("wsl.exe") is None and shutil.which("wsl") is None:
            raise SandboxError("wsl not found")
        cmd = self.command(argv, workdir=workdir)
        t0 = time.perf_counter()
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=limits.timeout_s,
                env=env,
            )
            return SandboxResult(
                rc=p.returncode,
                stdout=p.stdout or "",
                stderr=p.stderr or "",
                duration_s=round(time.perf_counter() - t0, 3),
                command=cmd,
            )
        except subprocess.TimeoutExpired as exc:
            return SandboxResult(
                rc=-1,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr="TIMEOUT",
                timed_out=True,
                duration_s=round(time.perf_counter() - t0, 3),
                command=cmd,
            )


def get_sandbox(kind: str, *, allow_host: bool = False, image: str = "jgd-sandbox:latest") -> Sandbox:
    if kind == "host":
        if not allow_host:
            raise SandboxError("host sandbox requires allow_host=True")
        return HostSandbox(allow_host=True)
    if kind == "docker":
        return DockerSandbox(image=image)
    if kind == "wsl2":
        return WslSandbox()
    raise SandboxError(f"unknown sandbox: {kind}")


def wsl_path(path: Path | str) -> str:
    """Translate a Windows drive path to a WSL /mnt/<drive>/... path."""
    raw = str(path)
    if raw.startswith("/"):
        return raw
    p = PureWindowsPath(raw)
    drive = p.drive.rstrip(":")
    if not drive:
        raise SandboxError(f"cannot translate non-absolute path to WSL: {raw}")
    parts = [part for part in p.parts[1:]]
    return "/mnt/" + drive.lower() + "/" + "/".join(parts)
