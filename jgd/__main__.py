#!/usr/bin/env python3
"""jgd unified entry — `python -m jgd` in source, single executable when frozen.

Dispatch modes:
  jgd [--target DIR --name N [--full]]   audit CLI (jgd.cli)
  jgd --tui [--lang en|zh] [--data F]    interactive chain-tree TUI (jgd.tui)
  jgd [-u] -m <module> [args...]         run a pipeline stage module — this is
                                         how jgd.cli spawns stages through
                                         sys.executable, so the frozen binary
                                         keeps the multi-stage architecture.
"""
from __future__ import annotations

import os
import runpy
import shutil
import sys
from pathlib import Path

# python-compatible interpreter flags (jgd.cli spawns `sys.executable -u -m …`)
_PY_FLAGS = {"-u", "-B", "-E", "-s", "-S", "-O", "-OO", "-I", "-v", "-b", "-q"}


def _enable_windows_vt() -> None:
    """Best-effort ANSI escape support for the TUI on classic Windows console."""
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if k32.GetConsoleMode(handle, ctypes.byref(mode)):
            k32.SetConsoleMode(handle, mode.value | 0x0004)  # VT_PROCESSING
    except Exception:
        pass


def _prepare_frozen_root() -> None:
    """Onefile build: anchor PROJECT_ROOT next to the executable and
    materialize bundled config/ + examples/ templates there on first run."""
    exe_dir = Path(sys.executable).resolve().parent
    mei = getattr(sys, "_MEIPASS", None)
    if mei:
        for name in ("config", "examples"):
            src, dst = Path(mei) / name, exe_dir / name
            if src.is_dir() and not dst.exists():
                try:
                    shutil.copytree(src, dst)
                except OSError:
                    pass
    try:
        (exe_dir / "data").mkdir(exist_ok=True)
        os.environ.setdefault("JGD_ROOT", str(exe_dir))
    except OSError:
        # read-only location (e.g. Program Files): degrade to the bundle temp
        # dir so the tool still runs, at the cost of non-persistent artifacts
        if mei:
            os.environ.setdefault("JGD_ROOT", str(mei))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    if getattr(sys, "frozen", False):
        _prepare_frozen_root()
    _enable_windows_vt()

    while argv and argv[0] in _PY_FLAGS:
        flag = argv.pop(0)
        if flag == "-X" and argv:  # -X takes an option argument
            argv.pop(0)

    if argv and argv[0] == "-m":
        if len(argv) < 2:
            print("jgd: -m requires a module name", file=sys.stderr)
            return 2
        module, rest = argv[1], argv[2:]
        sys.argv = [module] + rest
        runpy.run_module(module, run_name="__main__", alter_sys=True)
        return 0

    if argv and argv[0] == "--tui":
        from jgd.tui import main as tui_main
        sys.argv = ["tui.py"] + argv[1:]
        return tui_main() or 0

    from jgd.cli import main as cli_main
    sys.argv = ["audit_target.py"] + argv
    return cli_main() or 0


if __name__ == "__main__":
    raise SystemExit(main())
