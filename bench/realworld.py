#!/usr/bin/env python3
"""Real-world validation harness.

Runs the hardened JGD CLI against an authorized corpus, records wall time,
coverage, known-chain hits, dynamic probes, and report artifacts. Use only
with corpora you are authorized to test.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--profile", default="standard")
    ap.add_argument("--dynamic", action="store_true")
    ap.add_argument("--sandbox", default="docker")
    ap.add_argument("--allow-host", action="store_true")
    ap.add_argument("--run-out", default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    corpus = Path(args.corpus).resolve()
    if not corpus.is_dir():
        raise SystemExit(f"corpus not found: {corpus}")
    run_dir = Path(args.run_out) if args.run_out else Path(tempfile.mkdtemp(prefix="jgd-realworld-"))
    cmd = [
        sys.executable,
        "-m",
        "jgd",
        "audit",
        "--target",
        str(corpus),
        "--profile",
        args.profile,
        "--format",
        "json,sarif,md",
        "--out",
        str(run_dir),
    ]
    if args.dynamic:
        cmd += ["--dynamic", "--sandbox", args.sandbox]
        if args.allow_host:
            cmd.append("--unsafe-host")

    t0 = time.perf_counter()
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True, encoding="utf-8", errors="replace")
    duration = time.perf_counter() - t0
    run_path = run_dir / "run.json"
    run = json.loads(run_path.read_text(encoding="utf-8")) if run_path.exists() else {}
    findings = run.get("findings", [])
    known = [
        f for f in findings
        if f.get("verdict") == "PRESENT"
    ]
    dynamic = [f for f in findings if str(f.get("id", "")).startswith("JGD-D")]
    summary = {
        "corpus": str(corpus),
        "profile": args.profile,
        "dynamic": args.dynamic,
        "sandbox": args.sandbox if args.dynamic else None,
        "exit": proc.returncode,
        "duration_s": round(duration, 3),
        "run_dir": str(run_dir),
        "coverage": run.get("coverage", {}),
        "findings": len(findings),
        "known_present": len(known),
        "known_chains": [f["entry"]["class"] for f in known],
        "dynamic_findings": len(dynamic),
        "dynamic_verdicts": {f["verdict"]: sum(1 for x in dynamic if x["verdict"] == f["verdict"]) for f in dynamic},
        "errors": run.get("errors", []),
        "sarif": str(run_dir / "report.sarif"),
        "markdown": str(run_dir / "report.md"),
    }
    text = json.dumps(summary, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)
    return 0 if proc.returncode in (0, 10, 20) else 1


if __name__ == "__main__":
    raise SystemExit(main())
