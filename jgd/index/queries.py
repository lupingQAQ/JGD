"""SQL queries over the derived bytecode index.

These functions only recall candidates. Exact operand-stack checks remain in
``bridge_fix`` and are applied to the narrowed candidate set by the engine.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from jgd.index.bytecode import BytecodeIndex

DEFAULT_TRIGGERS = {"toString", "hashCode", "equals", "compare", "compareTo"}
_JDK_PREFIXES = ("java/", "javax/", "jdk/", "sun/", "com/sun/")
_NOT_JDK_INTERNAL = (
    "com/sun/syndication/",
    "com/sun/xml/",
    "com/sun/mail/",
    "com/sun/activation/",
    "com/sun/jersey/",
    "com/sun/istack/",
    "com/sun/grizzly/",
    "com/sun/star/",
)


def jars_with_class(index: BytecodeIndex, class_name: str) -> list[str]:
    rows = index._conn.execute(
        "SELECT DISTINCT j.path FROM classes c JOIN jars j ON j.id=c.jar_id "
        "WHERE c.name=? ORDER BY j.path",
        (class_name,),
    ).fetchall()
    return [r[0] for r in rows]


def classes_present(index: BytecodeIndex, names: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name in names:
        paths = jars_with_class(index, name)
        if (
            not paths
            and name.startswith(_JDK_PREFIXES)
            and not name.startswith(_NOT_JDK_INTERNAL)
        ):
            paths = ["JDK_BUILTIN"]
        out[name] = paths
    return out


def bridge_rows(
    index: BytecodeIndex, triggers: set[str] | None = None
) -> list[dict]:
    names = sorted(triggers or DEFAULT_TRIGGERS)
    if not names:
        return []
    placeholders = ",".join("?" * len(names))
    sql = f"""
        SELECT c.name AS cls, j.path AS jar_path, j.sha256 AS jar_sha256,
               m.name AS trigger, fa.name AS field, fa.desc AS field_desc,
               i.callee_owner, i.callee_name, i.callee_desc, c.origin
        FROM methods m
        JOIN classes c ON c.id=m.class_id
        JOIN jars j ON j.id=c.jar_id
        JOIN field_access fa
          ON fa.method_id=m.id AND fa.owner=c.name AND fa.kind='read'
        JOIN invokes i ON i.caller_method_id=m.id
        WHERE m.name IN ({placeholders})
        ORDER BY c.name, m.name, fa.name, i.callee_owner, i.callee_name, i.callee_desc
    """
    rows = index._conn.execute(sql, names).fetchall()
    out = []
    for r in rows:
        target = f"{r[6]}.{r[7]}{r[8]}"
        out.append(
            {
                "cls": r[0],
                "jar_path": r[1],
                "jar_sha256": r[2],
                "trigger": r[3],
                "field": r[4],
                "field_desc": r[5],
                "target": target,
                "via": "recv",
                "origin": r[9] or "",
            }
        )
    return out


def load_chains(db_path: Path | str | None = None) -> list[dict]:
    """Load chain metadata from a built DB, or fall back to the module corpus."""
    from jgd.verification import known_chains

    if db_path is None:
        return list(known_chains.KNOWN_CHAINS)
    path = Path(db_path)
    if not path.exists():
        raise FileNotFoundError(f"known-chain DB not found: {path}")
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    try:
        chains = []
        for r in conn.execute("SELECT * FROM chains ORDER BY family, name"):
            gates = [
                (g["jar_pattern"], known_chains._V_VERDICT_MAP.get(g["verdict"]), g["reason"])
                for g in conn.execute(
                    "SELECT * FROM gates WHERE chain_id=? ORDER BY gate_order", (r["id"],)
                )
            ]
            chains.append(
                {
                    "name": r["name"],
                    "classes": json.loads(r["signatures"]),
                    "gates": gates,
                    "family": r["family"],
                }
            )
        return chains
    finally:
        conn.close()
