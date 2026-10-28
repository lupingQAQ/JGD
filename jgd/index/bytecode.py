"""One-pass, content-addressed bytecode index.

The index is a derived cache: it can always be rebuilt from the target JARs.
Raw class bytes remain the source of truth.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from jgd.index.models import ClassMeta, ClassReader, IndexStats
from jgd.index.schema import DDL, INDEX_VERSION
from jgd.security.archive import SafeJar


class BytecodeIndex:
    def __init__(self, db_path: Path | str, reader: ClassReader | None = None) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.reader = reader
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(DDL)
        cols = {
            row[1]
            for row in self._conn.execute("PRAGMA table_info(classes)").fetchall()
        }
        if "origin" not in cols:
            self._conn.execute(
                "ALTER TABLE classes ADD COLUMN origin TEXT NOT NULL DEFAULT ''"
            )
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('index_version', ?)",
            (INDEX_VERSION,),
        )
        self._conn.commit()

    def __enter__(self) -> "BytecodeIndex":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def _reader(self) -> ClassReader:
        if self.reader is None:
            from jgd.index.reader import DisasmClassReader

            self.reader = DisasmClassReader()
        return self.reader

    def build(self, target: Path | str, force: bool = False) -> IndexStats:
        try:
            return self._build_impl(target, force)
        except Exception:
            self._conn.rollback()
            raise

    def _build_impl(self, target: Path | str, force: bool = False) -> IndexStats:
        target = Path(target)
        if not target.is_dir():
            raise NotADirectoryError(f"target is not a directory: {target}")

        t0 = time.monotonic()
        jars = 0
        classes = 0
        methods = 0
        fields = 0
        invokes = 0
        field_accesses = 0
        reader = self._reader()

        for jar_path in sorted(target.glob("*.jar")):
            stat = jar_path.stat()
            with SafeJar(jar_path) as jar:
                sha = jar.sha256()
                row = self._conn.execute(
                    "SELECT id, sha256 FROM jars WHERE path=?", (str(jar_path),)
                ).fetchone()
                if row is not None and row[1] == sha and not force:
                    continue
                if row is not None:
                    self._conn.execute("DELETE FROM jars WHERE id=?", (row[0],))

                cur = self._conn.execute(
                    "INSERT INTO jars(sha256, path, size, mtime_ns) VALUES(?,?,?,?)",
                    (sha, str(jar_path), stat.st_size, stat.st_mtime_ns),
                )
                jar_id = cur.lastrowid
                jars += 1

                for cm in reader.iter_classes(jar):
                    class_id = self._insert_class(jar_id, cm)
                    classes += 1
                    for fm in cm.fields:
                        self._conn.execute(
                            "INSERT INTO fields(class_id, name, desc, access, transient) "
                            "VALUES(?,?,?,?,?)",
                            (
                                class_id,
                                fm.name,
                                fm.desc,
                                fm.access,
                                int(bool(fm.access & 0x0080)),
                            ),
                        )
                        fields += 1
                    for mm in cm.methods:
                        mcur = self._conn.execute(
                            "INSERT INTO methods(class_id, name, desc, access, code_size) "
                            "VALUES(?,?,?,?,?)",
                            (class_id, mm.name, mm.desc, mm.access, mm.code_size),
                        )
                        method_id = mcur.lastrowid
                        methods += 1
                        for ins in mm.instructions:
                            if ins.opcode in ("ldc", "ldc_w") and ins.text.startswith('"'):
                                self._conn.execute(
                                    "INSERT INTO strings(method_id, value) VALUES(?,?)",
                                    (method_id, ins.text.strip('"')),
                                )
                            if not ins.resolved:
                                continue
                            kind = ins.resolved[0]
                            if kind == "method":
                                self._conn.execute(
                                    "INSERT INTO invokes(caller_method_id, callee_owner, "
                                    "callee_name, callee_desc, opcode, line) "
                                    "VALUES(?,?,?,?,?,NULL)",
                                    (
                                        method_id,
                                        ins.resolved[1],
                                        ins.resolved[2],
                                        ins.resolved[3],
                                        ins.opcode,
                                    ),
                                )
                                invokes += 1
                            elif kind == "field":
                                access_kind = (
                                    "write"
                                    if ins.opcode in ("putfield", "putstatic")
                                    else "read"
                                )
                                self._conn.execute(
                                    "INSERT INTO field_access(method_id, owner, name, desc, "
                                    "kind, opcode, line) VALUES(?,?,?,?,?,?,NULL)",
                                    (
                                        method_id,
                                        ins.resolved[1],
                                        ins.resolved[2],
                                        ins.resolved[3],
                                        access_kind,
                                        ins.opcode,
                                    ),
                                )
                                field_accesses += 1

                self._conn.commit()

        return IndexStats(
            jars=jars,
            classes=classes,
            methods=methods,
            fields=fields,
            invokes=invokes,
            field_accesses=field_accesses,
            duration_s=round(time.monotonic() - t0, 3),
        )

    def _insert_class(self, jar_id: int, cm: ClassMeta) -> int:
        cur = self._conn.execute(
            "INSERT INTO classes(jar_id, name, super, access, major, interfaces_json, origin) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                jar_id,
                cm.name,
                cm.super,
                cm.access,
                cm.major,
                json.dumps(cm.interfaces, ensure_ascii=False),
                cm.origin,
            ),
        )
        return cur.lastrowid
