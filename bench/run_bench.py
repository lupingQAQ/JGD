#!/usr/bin/env python3
"""Benchmark old per-chain JAR opens vs the cached bytecode index.

The gate is warm-query speed: build the index once, then measure repeated
known-chain queries. Cold build cost is reported separately.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from jgd.engine.known import scan_known  # noqa: E402
from jgd.index.bytecode import BytecodeIndex  # noqa: E402
from jgd.index.reader import DisasmClassReader  # noqa: E402
from jgd.verification import known_chains  # noqa: E402


def _old(corpus: Path) -> float:
    t0 = time.perf_counter()
    known_chains.audit(corpus)
    return time.perf_counter() - t0


def _new(corpus: Path, tmp: Path) -> tuple[float, float, float]:
    idx = BytecodeIndex(tmp / "index.db", reader=DisasmClassReader())
    try:
        tracemalloc.start()
        t0 = time.perf_counter()
        idx.build(corpus)
        cold = time.perf_counter() - t0
        t1 = time.perf_counter()
        scan_known(idx)
        warm = time.perf_counter() - t1
        peak = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
        tracemalloc.stop()
        return cold, warm, peak
    finally:
        idx.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--repeat", type=int, default=2)
    ap.add_argument("--out", default="bench.json")
    ap.add_argument("--allow-slow", action="store_true")
    args = ap.parse_args()

    corpus = Path(args.corpus)
    jars = sorted(corpus.glob("*.jar"))
    if not jars:
        raise SystemExit(f"no JARs in {corpus}")

    old_times, cold_times, warm_times, peaks = [], [], [], []
    tmp = Path(tempfile.mkdtemp(prefix="jgd-bench-"))
    try:
        for _ in range(args.repeat):
            old_times.append(_old(corpus))
            cold, warm, peak = _new(corpus, tmp)
            cold_times.append(cold)
            warm_times.append(warm)
            peaks.append(peak)
            # fresh index for each repeat so cold/warm are comparable
            (tmp / "index.db").unlink(missing_ok=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    old_s = min(old_times)
    cold_s = min(cold_times)
    warm_s = min(warm_times)
    speedup = old_s / warm_s if warm_s else 0.0
    result = {
        "corpus": str(corpus),
        "jars": len(jars),
        "repeat": args.repeat,
        "old_s": round(old_s, 4),
        "cold_s": round(cold_s, 4),
        "warm_s": round(warm_s, 4),
        "warm_speedup": round(speedup, 2),
        "peak_python_mb": round(max(peaks) if peaks else 0.0, 2),
    }
    Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))

    if len(jars) >= 828 and speedup < 5.0 and not args.allow_slow:
        print(
            f"FAIL: warm speedup {speedup:.2f}x < 5x on {len(jars)} jars; "
            "attach bench.json and do not claim the optimization",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
