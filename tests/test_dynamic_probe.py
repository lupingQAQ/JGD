"""Plan 2: a tiny trusted-fixture JVM probe through the sandbox."""
import io
import zipfile
from pathlib import Path

import pytest

from jgd.cli import _dynamic_classpath
from jgd.dynamic import DynamicProbe, JvmToolchain
from jgd.security.sandbox import HostSandbox, SandboxLimits


def test_dynamic_classpath_extracts_nested_spring_boot_jars(tmp_path: Path):
    target = tmp_path / "jars"
    target.mkdir()
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("demo/Bridge.class", b"not-a-real-class")
    outer = target / "app.jar"
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("BOOT-INF/lib/inner.jar", inner.getvalue())
        z.writestr("BOOT-INF/classes/demo/App.class", b"not-a-real-class")
    cp = _dynamic_classpath(
        target,
        {"jar_path": str(outer), "origin": "BOOT-INF/lib/inner.jar"},
        tmp_path / "out",
    )
    names = [p.name for p in cp]
    assert "app.jar" in names
    assert any(p.parent.name == "classpath" and p.suffix == ".jar" for p in cp)
    assert any(p.name == "classes" and p.is_dir() for p in cp)
    assert (tmp_path / "out" / "dynamic" / "classpath" / "classes" / "demo" / "App.class").exists()


def test_toolchain_can_run_java():
    tc = JvmToolchain.discover()
    if not tc.available:
        pytest.skip("JDK not available")
    r = tc.run_java(["-version"], SandboxLimits(timeout_s=20))
    assert r.rc == 0
    assert "version" in (r.stdout + r.stderr).lower()


def test_probe_hashmap_class_in_host_sandbox(tmp_path: Path):
    tc = JvmToolchain.discover()
    if not tc.available:
        pytest.skip("JDK not available")
    probe = DynamicProbe(tc, HostSandbox(allow_host=True))
    r = probe.probe_class(
        "java.util.ArrayList",
        tmp_path,
        SandboxLimits(timeout_s=60),
        mode="HASHMAP",
    )
    assert r.verdict in ("DESER_OK", "DESER_EX"), r
    assert r.rc == 0


def test_probe_many_uses_one_batch_jvm(tmp_path: Path):
    tc = JvmToolchain.discover()
    if not tc.available:
        pytest.skip("JDK not available")
    probe = DynamicProbe(tc, HostSandbox(allow_host=True))
    results = probe.probe_many(
        ["java.util.ArrayList", "java.util.HashMap"],
        tmp_path,
        SandboxLimits(timeout_s=60),
        mode="HASHMAP",
    )
    assert len(results) == 2
    assert all(r.verdict == "DESER_OK" for r in results), results
    assert all(r.rc == 0 for r in results)


def test_probe_bundled_fixture_class(tmp_path: Path):
    tc = JvmToolchain.discover()
    if not tc.available:
        pytest.skip("JDK not available")
    fixture = Path(__file__).parent / "fixtures" / "commons-collections-3.2.1.jar"
    probe = DynamicProbe(tc, HostSandbox(allow_host=True))
    r = probe.probe_class(
        "org/apache/commons/collections/keyvalue/TiedMapEntry",
        tmp_path,
        SandboxLimits(timeout_s=60),
        mode="HASHMAP",
        classpath=[fixture],
    )
    assert not r.verdict.startswith("ERROR:java.lang.ClassNotFoundException"), r
    assert r.rc == 0
