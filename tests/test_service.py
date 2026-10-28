"""Plan 3: process-backed run service."""
import zipfile
from pathlib import Path

from jgd.service import JgdService


def _empty_jar(target: Path) -> None:
    target.mkdir()
    with zipfile.ZipFile(target / "empty.jar", "w"):
        pass


def test_service_runs_static_audit(tmp_path: Path):
    target = tmp_path / "jars"
    _empty_jar(target)
    svc = JgdService(home=tmp_path / "home")
    run_id = svc.start_audit(target, "known")
    task = svc.wait(run_id, timeout=120)
    assert task.state == "TASK_STATE_COMPLETED", task.error
    run = svc.read_run(run_id)
    assert run and run["schemaVersion"] == "jgd.run/v1"
    assert isinstance(svc.read_findings(run_id), list)
    task_view = svc.get_task(run_id)
    assert task_view["id"] == run_id
    assert task_view["artifacts"]


def test_service_rejects_missing_target(tmp_path: Path):
    svc = JgdService(home=tmp_path / "home")
    try:
        svc.start_audit(tmp_path / "nope", "known")
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError")


def test_service_rejects_poc_without_host_opt_in(tmp_path: Path):
    target = tmp_path / "jars"
    _empty_jar(target)
    svc = JgdService(home=tmp_path / "home")
    try:
        svc.start_poc(target, "java.util.ArrayList", allow_host=False)
    except PermissionError:
        pass
    else:
        raise AssertionError("expected PermissionError")


def test_service_dynamic_host_on_trusted_fixture(tmp_path: Path):
    from jgd.dynamic import JvmToolchain

    if not JvmToolchain.discover().available:
        return
    target = Path(__file__).parent / "fixtures"
    svc = JgdService(home=tmp_path / "home")
    run_id = svc.start_audit(
        target,
        "standard",
        dynamic=True,
        sandbox="host",
        allow_host=True,
    )
    task = svc.wait(run_id, timeout=180)
    assert task.state == "TASK_STATE_COMPLETED", task.error
    run = svc.read_run(run_id)
    assert run["coverage"]["dynamic"] >= 1

