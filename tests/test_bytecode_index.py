"""Task 3: one-pass bytecode index schema and fake-reader build path."""
from pathlib import Path
import zipfile

from jgd.index.bytecode import BytecodeIndex
from jgd.index.models import ClassMeta, FieldMeta, InstructionMeta, MethodMeta


class FakeReader:
    def iter_classes(self, jar):
        yield ClassMeta(
            name="demo/A",
            super="java/lang/Object",
            interfaces=[],
            access=0x0021,
            major=55,
            fields=[FieldMeta("f", "Ljava/lang/Object;", 0)],
            methods=[
                MethodMeta(
                    "hashCode",
                    "()I",
                    0x0001,
                    1,
                    [
                        InstructionMeta(
                            0,
                            "getfield",
                            "demo/A.f",
                            ("field", "demo/A", "f", "Ljava/lang/Object;"),
                        ),
                        InstructionMeta(
                            3,
                            "invokevirtual",
                            "java/lang/Object.hashCode",
                            ("method", "java/lang/Object", "hashCode", "()I"),
                        ),
                    ],
                )
            ],
        )


def _jar(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("demo/A.class", b"ignored")
    return path


def test_build_indexes_semantic_rows(tmp_path: Path):
    target = tmp_path / "jars"
    target.mkdir()
    _jar(target / "a.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    stats = idx.build(target)
    assert stats.jars == 1 and stats.classes == 1
    assert stats.methods == 1 and stats.fields == 1
    assert stats.invokes == 1 and stats.field_accesses == 1
    rows = idx._conn.execute("SELECT name, super FROM classes").fetchall()
    assert rows == [("demo/A", "java/lang/Object")]
    idx.close()


def test_rebuild_is_idempotent_and_changed_jar_replaces_rows(tmp_path: Path):
    target = tmp_path / "jars"
    target.mkdir()
    _jar(target / "a.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    idx.build(target)
    assert idx.build(target).jars == 0  # unchanged
    with zipfile.ZipFile(target / "a.jar", "a") as z:
        z.comment = b"changed"
    idx.build(target)
    assert idx._conn.execute("SELECT COUNT(*) FROM classes").fetchone()[0] == 1
    idx.close()


def test_duplicate_class_names_are_preserved(tmp_path: Path):
    target = tmp_path / "jars"
    target.mkdir()
    _jar(target / "a.jar")
    _jar(target / "b.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    idx.build(target)
    assert (
        idx._conn.execute("SELECT COUNT(*) FROM classes WHERE name='demo/A'").fetchone()[0]
        == 2
    )
    idx.close()


class BoomReader:
    def iter_classes(self, jar):
        raise RuntimeError("parser boom")


def test_failed_jar_rolls_back(tmp_path: Path):
    target = tmp_path / "jars"
    target.mkdir()
    _jar(target / "a.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=BoomReader())
    try:
        try:
            idx.build(target)
        except RuntimeError:
            pass
        assert idx._conn.execute("SELECT COUNT(*) FROM jars").fetchone()[0] == 0
    finally:
        idx.close()
