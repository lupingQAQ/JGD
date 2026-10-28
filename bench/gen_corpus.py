#!/usr/bin/env python3
"""Generate a synthetic JAR corpus for index benchmarks.

The fixture JAR is copied N times. Paths differ, so the index keeps per-JAR
rows; this measures repeated archive I/O and query reuse, not unique classes.
"""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--count", type=int, default=828)
    ap.add_argument(
        "--fixture",
        default=str(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample.jar"),
    )
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()

    out = Path(args.out)
    fixture = Path(args.fixture)
    if not fixture.is_file():
        raise SystemExit(f"fixture not found: {fixture}")
    out.mkdir(parents=True, exist_ok=True)
    if any(out.glob("*.jar")) and not args.force:
        raise SystemExit(f"output already contains JARs: {out} (use --force)")
    for i in range(args.count):
        shutil.copyfile(fixture, out / f"jar_{i:04d}.jar")
    print(f"{args.count} jars -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
