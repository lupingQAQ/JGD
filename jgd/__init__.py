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

from pathlib import Path

#: Repository root — the directory containing jgd/, config/, examples/, tests/.
#: All runtime artifacts (data/, pocs/, audit_report/, state JSONs) anchor here,
#: so behavior is identical no matter which subpackage a module lives in.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

__all__ = ["PROJECT_ROOT"]
