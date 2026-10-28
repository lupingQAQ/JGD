"""Plan 2: sandbox contract and command construction."""
import sys
from pathlib import Path, PurePosixPath

import pytest

from jgd.security.sandbox import (
    DockerSandbox,
    HostSandbox,
    SandboxError,
    SandboxLimits,
    WslSandbox,
    get_sandbox,
    wsl_path,
)


def test_host_sandbox_requires_explicit_opt_in():
    with pytest.raises(SandboxError, match="allow_host"):
        HostSandbox().run([sys.executable, "-c", "print('no')"], limits=SandboxLimits(timeout_s=10))


def test_get_sandbox_host_requires_allow_host():
    with pytest.raises(SandboxError):
        get_sandbox("host", allow_host=False)


def test_host_sandbox_runs_when_allowed(tmp_path: Path):
    sb = HostSandbox(allow_host=True)
    r = sb.run(
        [sys.executable, "-c", "print('sandbox-ok')"],
        limits=SandboxLimits(timeout_s=20),
        workdir=tmp_path,
    )
    assert r.rc == 0
    assert "sandbox-ok" in r.stdout
    assert r.timed_out is False


def test_docker_command_has_security_flags(tmp_path: Path):
    sb = DockerSandbox(image="jgd-sandbox:test")
    cmd = sb.command(
        ["java", "-version"],
        mounts={tmp_path: (PurePosixPath("/target"), True)},
        limits=SandboxLimits(memory_mb=512, cpus=1, pids=64, timeout_s=30),
        workdir=Path("/work"),
    )
    joined = " ".join(cmd)
    assert "docker" in joined
    assert "--network=none" in joined
    assert "--read-only" in joined
    assert "--cap-drop=ALL" in joined
    assert "no-new-privileges" in joined
    assert str(tmp_path) in joined and "/target:ro" in joined
    assert "512m" in joined


def test_wsl_path_translation():
    assert wsl_path("D:\\work\\x") == "/mnt/d/work/x"
    assert wsl_path("/mnt/d/already") == "/mnt/d/already"


def test_wsl_command_quotes_spaces(tmp_path: Path):
    sb = WslSandbox("Ubuntu")
    cmd = sb.command(["java", "-cp", "/mnt/d/a b/x.jar", "Main"], workdir="/mnt/d/a b")
    assert cmd[:4] == ["wsl.exe", "-d", "Ubuntu", "--"]
    assert "/mnt/d/a b" in cmd[-1]
    assert "'/mnt/d/a b/x.jar'" in cmd[-1] or "/mnt/d/a b/x.jar" in cmd[-1]
