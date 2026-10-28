#!/usr/bin/env python3
"""Thin compatibility wrapper — real implementation lives in jgd.cli."""
import sys

from jgd.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["audit", *sys.argv[1:]]))
