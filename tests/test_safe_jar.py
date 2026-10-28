"""Task 2: bounded, path-safe JAR reader."""
import zipfile
from pathlib import Path

import pytest

from jgd.security.archive import ArchiveError, ArchiveLimits, SafeJar


def _jar(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


def test_reads_normal_jar(tmp_path: Path):
    p = _jar(tmp_path / "ok.jar", {"a/B.class": b"CAFEBABE"})
    with SafeJar(p) as j:
        assert j.read("a/B.class") == b"CAFEBABE"
        assert j.class_entries() == ["a/B.class"]
        assert len(j.sha256()) == 64


def test_rejects_parent_traversal(tmp_path: Path):
    p = _jar(tmp_path / "evil.jar", {"../evil.class": b"x"})
    with pytest.raises(ArchiveError, match="path"):
        with SafeJar(p):
            pass


def test_rejects_absolute_path(tmp_path: Path):
    p = _jar(tmp_path / "abs.jar", {"/etc/passwd": b"x"})
    with pytest.raises(ArchiveError, match="path"):
        with SafeJar(p):
            pass


def test_rejects_symlink(tmp_path: Path):
    p = tmp_path / "link.jar"
    with zipfile.ZipFile(p, "w") as z:
        zi = zipfile.ZipInfo("link.class")
        zi.external_attr = 0o120777 << 16
        z.writestr(zi, b"x")
    with pytest.raises(ArchiveError, match="symlink"):
        with SafeJar(p):
            pass


def test_rejects_zip_bomb_ratio(tmp_path: Path):
    p = _jar(tmp_path / "bomb.jar", {"big.class": b"\0" * 2_000_000})
    limits = ArchiveLimits(max_entry_bytes=4_000_000, max_compression_ratio=10)
    with pytest.raises(ArchiveError, match="ratio"):
        with SafeJar(p, limits):
            pass


def test_accepts_high_ratio_resource_but_not_class(tmp_path: Path):
    p = _jar(
        tmp_path / "resources.jar",
        {"a/B.class": b"CAFEBABE", "org/eclipse/part14.rsc": b"\0" * 2_000_000},
    )
    limits = ArchiveLimits(max_entry_bytes=4_000_000, max_compression_ratio=10)
    with SafeJar(p, limits) as j:
        assert j.class_entries() == ["a/B.class"]


def test_multi_release_entries_are_not_base_classes(tmp_path: Path):
    p = _jar(
        tmp_path / "mr.jar",
        {
            "a/B.class": b"base",
            "META-INF/versions/17/a/B.class": b"v17",
        },
    )
    with SafeJar(p) as j:
        assert j.class_entries() == ["a/B.class"]
