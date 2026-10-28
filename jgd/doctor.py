"""Environment preflight for JGD."""
from __future__ import annotations

import json
import platform
import shutil
import sqlite3
import sys
from pathlib import Path


def run_doctor(home: Path | None = None, target: Path | None = None) -> dict:
    base = Path(home) if home is not None else Path.cwd()
    db = base / "data" / "known_chains.db"
    out = {
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "home": str(base),
        "jdk": shutil.which("java"),
        "db": str(db),
        "db_exists": db.exists(),
        "platform": sys.platform,
    }
    if target is not None:
        out["target"] = str(target)
        out["target_exists"] = Path(target).is_dir()
    return out


def doctor_json(home: Path | None = None) -> str:
    return json.dumps(run_doctor(home), ensure_ascii=True, indent=2)
