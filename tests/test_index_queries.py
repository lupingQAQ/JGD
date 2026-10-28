"""Task 5: SQL recall for known chains and bridges."""
from pathlib import Path

import pytest

from jgd.index.bytecode import BytecodeIndex
from jgd.index.queries import bridge_rows, classes_present
from jgd.engine.bridge import BridgeScanError, scan_bridges
from tests.test_bytecode_index import FakeReader, _jar


def _index(tmp_path: Path) -> BytecodeIndex:
    target = tmp_path / "jars"
    target.mkdir()
    _jar(target / "a.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    idx.build(target)
    return idx


def test_classes_present_returns_all_jars(tmp_path: Path):
    target = tmp_path / "jars"
    target.mkdir()
    _jar(target / "a.jar")
    _jar(target / "b.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    idx.build(target)
    got = classes_present(idx, ["demo/A", "missing/C"])
    assert len(got["demo/A"]) == 2
    assert got["missing/C"] == []
    idx.close()


def test_bridge_rows_find_field_plus_invoke(tmp_path: Path):
    idx = _index(tmp_path)
    rows = bridge_rows(idx, {"hashCode"})
    assert rows and rows[0]["cls"] == "demo/A"
    assert rows[0]["field"] == "f"
    assert rows[0]["target"] == "java/lang/Object.hashCode()I"
    idx.close()


def test_jdk_only_class_is_present(tmp_path: Path):
    idx = _index(tmp_path)
    got = classes_present(idx, ["java/net/URL"])
    assert got["java/net/URL"] == ["JDK_BUILTIN"]
    idx.close()


def test_bridge_scan_reports_parse_failure(tmp_path: Path):
    idx = _index(tmp_path)
    try:
        with pytest.raises(BridgeScanError):
            scan_bridges(idx)
    finally:
        idx.close()
