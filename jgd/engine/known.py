"""Known-chain four-state scan backed by the bytecode index."""
from __future__ import annotations

from pathlib import Path

from jgd.index.bytecode import BytecodeIndex
from jgd.index.queries import classes_present, load_chains
from jgd.verification import known_chains


def scan_known(index: BytecodeIndex, db_path: Path | str | None = None) -> list[dict]:
    chains = load_chains(db_path)
    jars = [
        Path(row[0]).name
        for row in index._conn.execute("SELECT path FROM jars ORDER BY path")
    ]
    names = sorted({s for c in chains for s in c.get("classes", [])})
    present_map = classes_present(index, names)

    results = []
    for chain in chains:
        missing = [s for s in chain.get("classes", []) if not present_map.get(s)]
        present = not missing
        results.append(
            {
                "chain": chain["name"],
                "present": present,
                "missing": missing,
                "version": (
                    known_chains.version_verdict(jars, chain.get("gates", []))
                    if present
                    else "N/A"
                ),
                "assemble": "not-run" if present else "N/A",
                "state": "PRESENT" if present else "ABSENT",
            }
        )
    return results
