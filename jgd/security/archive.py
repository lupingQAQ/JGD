"""Bounded JAR/ZIP reader for untrusted target archives.

Nothing in this module extracts to disk or imports target classes. It only
validates archive metadata and reads individual entries on demand.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path


class ArchiveError(ValueError):
    """Raised when an archive violates a safety limit or path rule."""


@dataclass(frozen=True)
class ArchiveLimits:
    max_entries: int = 200_000
    max_entry_bytes: int = 64_000_000
    max_total_bytes: int = 2_000_000_000
    max_compression_ratio: int = 100
    max_name_len: int = 512


_ABS_WINDOWS = re.compile(r"^[A-Za-z]:")


class SafeJar:
    """A read-only, validated view of a JAR/ZIP file."""

    def __init__(self, path: Path | str, limits: ArchiveLimits = ArchiveLimits()) -> None:
        self.path = Path(path)
        self.limits = limits
        self._zip: zipfile.ZipFile | None = None
        self._infos: dict[str, zipfile.ZipInfo] = {}
        self._names: list[str] = []
        self._data: bytes | None = None

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        name: str = "<memory>",
        limits: ArchiveLimits = ArchiveLimits(),
    ) -> "SafeJar":
        obj = cls(name, limits)
        obj._data = data
        return obj

    def __enter__(self) -> "SafeJar":
        if self._data is not None:
            try:
                self._zip = zipfile.ZipFile(io.BytesIO(self._data))
            except (zipfile.BadZipFile, OSError) as exc:
                raise ArchiveError(f"bad nested archive {self.path}: {exc}") from exc
        else:
            if not self.path.is_file():
                raise ArchiveError(f"archive not found: {self.path}")
            try:
                self._zip = zipfile.ZipFile(self.path)
            except (zipfile.BadZipFile, OSError) as exc:
                raise ArchiveError(f"bad archive {self.path}: {exc}") from exc
        try:
            self._validate()
        except Exception:
            self._zip.close()
            self._zip = None
            raise
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._zip is not None:
            self._zip.close()
            self._zip = None

    def _validate(self) -> None:
        assert self._zip is not None
        infos = self._zip.infolist()
        if len(infos) > self.limits.max_entries:
            raise ArchiveError(f"too many entries: {len(infos)} > {self.limits.max_entries}")

        total = 0
        for info in infos:
            name = info.filename
            self._validate_name(name)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ArchiveError(f"symlink entry rejected: {name!r}")
            if info.is_dir():
                continue
            if info.file_size > self.limits.max_entry_bytes:
                raise ArchiveError(
                    f"entry too large: {name!r} {info.file_size} > {self.limits.max_entry_bytes}"
                )
            total += info.file_size
            if total > self.limits.max_total_bytes:
                raise ArchiveError(
                    f"archive expands beyond {self.limits.max_total_bytes} bytes"
                )
            if info.compress_size > 0 and name.endswith(".class"):
                ratio = info.file_size / info.compress_size
                if ratio > self.limits.max_compression_ratio:
                    raise ArchiveError(
                        f"compression ratio too high for {name!r}: {ratio:.1f}"
                    )
            self._infos[name] = info
            self._names.append(name)

    def _validate_name(self, name: str) -> None:
        if not name or "\x00" in name or "\\" in name:
            raise ArchiveError(f"unsafe path: {name!r}")
        if len(name) > self.limits.max_name_len:
            raise ArchiveError(f"path too long: {len(name)} > {self.limits.max_name_len}")
        if name.startswith("/") or _ABS_WINDOWS.match(name):
            raise ArchiveError(f"absolute path rejected: {name!r}")
        parts = [p for p in name.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise ArchiveError(f"path traversal rejected: {name!r}")

    @property
    def names(self) -> list[str]:
        return list(self._names)

    def namelist(self) -> list[str]:
        return list(self._names)

    def read(self, name: str, max_bytes: int | None = None) -> bytes:
        if self._zip is None:
            raise ArchiveError("SafeJar must be used as a context manager")
        info = self._infos.get(name)
        if info is None:
            raise KeyError(name)
        limit = self.limits.max_entry_bytes if max_bytes is None else min(
            max_bytes, self.limits.max_entry_bytes
        )
        with self._zip.open(info) as fh:
            data = fh.read(limit + 1)
        if len(data) > limit:
            raise ArchiveError(f"entry exceeds read limit: {name!r}")
        return data

    def class_entries(self) -> list[str]:
        out = []
        for name in self._names:
            if not name.endswith(".class"):
                continue
            if name.startswith("META-INF/versions/"):
                continue
            base = name.rsplit("/", 1)[-1]
            if base in ("module-info.class", "package-info.class"):
                continue
            out.append(name)
        return sorted(out)

    def jar_entries(self) -> list[str]:
        return sorted(n for n in self._names if n.endswith(".jar"))

    def sha256(self) -> str:
        if self._data is not None:
            return hashlib.sha256(self._data).hexdigest()
        h = hashlib.sha256()
        with self.path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
