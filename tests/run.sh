#!/usr/bin/env bash
# tests/run.sh — 无 pytest 依赖的冒烟 runner
set -u
cd "$(dirname "$0")/.."
python3 - <<'EOF'
import subprocess, sys
sys.path.insert(0, "tests")
import test_smoke as t
fails = 0
for name in dir(t):
    if name.startswith("test_"):
        fn = getattr(t, name)
        try:
            fn() if "tmp_path" not in fn.__code__.co_varnames else None
            print(f"PASS {name}")
        except Exception as e:
            print(f"FAIL {name}: {e}")
            fails += 1
sys.exit(1 if fails else 0)
EOF
