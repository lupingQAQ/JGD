"""JGD — JavaGadgetDigger.

Autonomous agent that takes any JAR directory and produces known-chain
verdicts, novel gadget chains, and weaponized (benign-demo) PoCs.

Package layout:
    jgd.mining         static analysis, graph building, chain pairing, evolution
    jgd.verification   adversarial LLM auditing, known-chain verdicts, conductor
    jgd.poc            weaponized PoC generation
    jgd.infra          LLM client, RAG store, scoping, profiling, matrix probes
    jgd.cli            product entry point (python -m jgd.cli / audit_target.py)
    jgd.tui            interactive chain-tree TUI
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

#: Repository root — the directory containing jgd/, config/, examples/, tests/.
#: All runtime artifacts (data/, pocs/, audit_report/, state JSONs) anchor here,
#: so behavior is identical no matter which subpackage a module lives in.
#:
#: Resolution order:
#:   1. JGD_ROOT env var (tests / relocated workspaces)
#:   2. frozen single-binary build -> directory of the executable, so
#:      artifacts persist next to the binary instead of the onefile temp
#:      extraction dir (jgd/__main__ provisions config/ + examples/ there)
#:   3. source checkout -> parent of the jgd/ package
_env_root = os.environ.get("JGD_ROOT")
if _env_root:
    PROJECT_ROOT = Path(_env_root).resolve()
elif getattr(sys, "frozen", False):
    PROJECT_ROOT = Path(sys.executable).resolve().parent
else:
    PROJECT_ROOT = Path(__file__).resolve().parent.parent

__all__ = ["PROJECT_ROOT"]
