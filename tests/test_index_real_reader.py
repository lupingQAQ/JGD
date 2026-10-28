"""Task 4: real bcdisasm-backed class reader."""
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest

from jgd.index.bytecode import BytecodeIndex
from jgd.index.reader import DisasmClassReader
from jgd.engine.bridge import scan_bridges
from jgd.engine.known import scan_known


def _compile(tmp_path: Path) -> Path:
    src = tmp_path / "A.java"
    src.write_text(
        "public class A extends B { Object f; public int hashCode(){ return f.hashCode(); } }\n"
        "class B {}\n",
        encoding="utf-8",
    )
    subprocess.run(["javac", "-d", str(tmp_path / "classes"), str(src)], check=True)
    jar = tmp_path / "a.jar"
    with zipfile.ZipFile(jar, "w") as z:
        for p in (tmp_path / "classes").rglob("*.class"):
            z.write(p, p.relative_to(tmp_path / "classes").as_posix())
    return jar


@pytest.mark.skipif(shutil.which("javac") is None, reason="javac not available")
def test_real_reader_extracts_invoke_and_field(tmp_path: Path):
    jar = _compile(tmp_path)
    target = tmp_path / "jars"
    target.mkdir()
    shutil.copy(jar, target / jar.name)
    idx = BytecodeIndex(tmp_path / "index.db", reader=DisasmClassReader())
    stats = idx.build(target)
    assert stats.classes >= 2
    assert stats.invokes >= 1
    assert stats.field_accesses >= 1
    row = idx._conn.execute(
        "SELECT callee_owner, callee_name FROM invokes WHERE callee_name='hashCode'"
    ).fetchone()
    assert row == ("java/lang/Object", "hashCode")
    idx.close()


def test_bundled_real_jar_is_indexed(tmp_path: Path):
    fixture_dir = Path(__file__).parent / "fixtures"
    idx = BytecodeIndex(tmp_path / "index.db", reader=DisasmClassReader())
    stats = idx.build(fixture_dir)
    assert stats.classes >= 5
    assert stats.invokes > 0
    assert stats.field_accesses > 0
    names = {r[0] for r in idx._conn.execute("SELECT name FROM classes")}
    assert (
        "org/apache/commons/collections/functors/InvokerTransformer" in names
    )
    idx.close()


def test_known_scan_on_bundled_fixture(tmp_path: Path):
    fixture_dir = Path(__file__).parent / "fixtures"
    idx = BytecodeIndex(tmp_path / "index.db", reader=DisasmClassReader())
    idx.build(fixture_dir)
    results = scan_known(idx)
    cc = next(r for r in results if r["chain"].startswith("CC1"))
    assert cc["present"] is True
    idx.close()


def test_bridge_scan_on_bundled_fixture(tmp_path: Path):
    fixture_dir = Path(__file__).parent / "fixtures"
    idx = BytecodeIndex(tmp_path / "index.db", reader=DisasmClassReader())
    idx.build(fixture_dir)
    bridges = scan_bridges(idx)
    assert any(b["cls"].endswith("TiedMapEntry") for b in bridges)
    idx.close()


def test_nested_fat_jar_is_indexed(tmp_path: Path):
    fixture = Path(__file__).parent / "fixtures" / "sample.jar"
    target = tmp_path / "jars"
    target.mkdir()
    outer = target / "fat.jar"
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("BOOT-INF/lib/sample.jar", fixture.read_bytes())
    idx = BytecodeIndex(tmp_path / "index.db", reader=DisasmClassReader())
    stats = idx.build(target)
    assert stats.classes >= 5
    names = {r[0] for r in idx._conn.execute("SELECT name FROM classes")}
    assert "org/apache/commons/collections/functors/InvokerTransformer" in names
    bridges = scan_bridges(idx)
    assert any(b["cls"].endswith("TiedMapEntry") for b in bridges)
    idx.close()

