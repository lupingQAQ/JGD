#!/usr/bin/env python3
"""JGD chain-tree TUI — interactive visualization of discovered deserialization chains.

Usage:
  python3 tui.py [--lang en|zh] [--data examples/chains.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).parent

# ─── ANSI escape codes ───────────────────────────────────────────────────────
R = "\033[0m"       # Reset
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GRN = "\033[92m"
YLW = "\033[93m"
BLU = "\033[94m"
MAG = "\033[95m"
CYN = "\033[96m"
WHT = "\033[97m"

# ─── UI strings ──────────────────────────────────────────────────────────────
STR = {
    "en": {
        "title": "JGD",
        "subtitle": "Solving the Last Mile of Deserialization Vulnerability Discovery",
        "chains": "Discovered Chains",
        "tier": "Tier",
        "bridge": "Bridge",
        "carrier": "Carrier",
        "tail": "Tail",
        "jdk": "JDK",
        "status": "Status",
        "fired": "✅ RCE_CLOSED",
        "pending": "⏳ PENDING",
        "depth": "Depth",
        "classes": "Classes",
        "conditions": "Conditions",
        "back": "[q] Quit  [↑↓] Navigate  [Enter] Detail  [t] Language",
        "select": "Select a chain to view details",
        "entry": "Entry Point",
        "dispatch": "Dispatch",
        "sink": "Sink",
        "filter": "Filter",
        "all": "All",
        "t1": "T1 (Novel Entry)",
        "t2": "T2 (New Carrier)",
        "t3": "T3 (Variant)",
    },
    "zh": {
        "title": "JGD",
        "subtitle": "解决反序列化漏洞挖掘的最后一公里",
        "chains": "已发现链",
        "tier": "级别",
        "bridge": "桥接类",
        "carrier": "载体",
        "tail": "尾部",
        "jdk": "JDK",
        "status": "状态",
        "fired": "✅ RCE已闭环",
        "pending": "⏳ 待验证",
        "depth": "深度",
        "classes": "类",
        "conditions": "利用条件",
        "back": "[q] 退出  [↑↓] 导航  [Enter] 详情  [t] 语言",
        "select": "选择链查看详情",
        "entry": "入口",
        "dispatch": "分派",
        "sink": "Sink",
        "filter": "筛选",
        "all": "全部",
        "t1": "T1 (新入口)",
        "t2": "T2 (新载体)",
        "t3": "T3 (变体)",
    },
}


def load_chains(path: Path) -> list[dict]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return []


def bar(width: int, ch: str = "─") -> str:
    return ch * width


def tree_node(prefix: str, label: str, color: str = "", last: bool = False) -> str:
    connector = "└─" if last else "├─"
    return f"  {DIM}{prefix}{connector}{R} {color}{label}{R}"


def render_chain(c: dict, lang: str = "en", idx: int = 0, sel: bool = False) -> list[str]:
    s = STR[lang]
    lines = []
    cursor = "▶ " if sel else "  "
    tier_colors = {"T1": MAG, "T2": CYN, "T3": YLW}
    tc = tier_colors.get(c.get("tier", "T3"), WHT)
    status_color = GRN if c.get("rce_closed") else YLW
    status_text = s["fired"] if c.get("rce_closed") else s["pending"]
    lines.append(f"{cursor}{tc}{BOLD}[{c.get('tier','?')}]{R} "
                 f"{BOLD}{c.get('id','?')}{R} "
                 f"{status_color}{status_text}{R}")
    lines.append(f"    {DIM}JDK {c.get('jdk','?')}{R} "
                 f"{DIM}Carrier: {c.get('carrier','?')}{R} "
                 f"{DIM}Tail: {c.get('tail','?')}{R}")
    # Chain hops
    for i, hop in enumerate(c.get("hops", [])):
        last = i == len(c.get("hops", [])) - 1
        hop_color = GRN if i == 0 else (RED if "TemplatesImpl" in hop or "defineClass" in hop else CYN)
        lines.append(tree_node("", f"{hop}", hop_color, last))
    return lines


def render_detail(c: dict, lang: str = "en") -> list[str]:
    s = STR[lang]
    lines = []
    lines.append(f"  {BOLD}{MAG}{'='*60}{R}")
    lines.append(f"  {BOLD}{c.get('id','?')}{R}  {BOLD}[{c.get('tier','?')}]{R}")
    lines.append(f"  {MAG}{'='*60}{R}")
    lines.append(f"")
    lines.append(f"  {BOLD}{s['bridge']}:{R} {c.get('bridge_class','?')}")
    lines.append(f"  {BOLD}{s['carrier']}:{R} {c.get('carrier','?')}")
    lines.append(f"  {BOLD}{s['tail']}:{R}    {c.get('tail','?')}")
    lines.append(f"  {BOLD}{s['jdk']}:{R}     {c.get('jdk','?')}")
    lines.append(f"  {BOLD}{s['status']}:{R}   "
                 f"{'✅' if c.get('rce_closed') else '⏳'}"
                 f"{'RCE_DEMO_FIRED' if c.get('rce_closed') else 'PENDING'}")
    lines.append(f"")
    lines.append(f"  {BOLD}{s['entry']}:{R}")
    lines.append(f"    {GRN}→{R} {c.get('entry','?')}")
    lines.append(f"")
    lines.append(f"  {BOLD}{s['dispatch']}:{R}")
    for hop in c.get("hops", []):
        lines.append(f"    {CYN}→{R} {hop}")
    lines.append(f"")
    lines.append(f"  {BOLD}{s['sink']}:{R}")
    lines.append(f"    {RED}→{R} {c.get('sink','TemplatesImpl.defineClass → static block')}")
    lines.append(f"")
    lines.append(f"  {BOLD}{s['conditions']}:{R}")
    for cond in c.get("conditions", []):
        lines.append(f"    {YLW}•{R} {cond}")
    lines.append(f"")
    lines.append(f"  {DIM}{s['back']}{R}")
    return lines


def main() -> int:
    lang = "en"
    data_path = HERE / "examples" / "chains.json"
    chains = load_chains(data_path)
    if not chains:
        print("No chain data found at examples/chains.json")
        return 1

    selected = 0
    detail_mode = False

    print(f"\033[2J\033[H")  # clear screen
    while True:
        s = STR[lang]
        print(f"\033[H", end="")  # cursor to top
        # Header
        print(f"  {BOLD}{CYN}╔{'═'*58}╗{R}")
        print(f"  {BOLD}{CYN}║{R}  {BOLD}{MAG}⚡ {s['title']}{R}{'':<{58-len(s['title'])-4}}{BOLD}{CYN}║{R}")
        print(f"  {BOLD}{CYN}║{R}  {DIM}{s['subtitle']}{'':<{58-len(s['subtitle'])}}{BOLD}{CYN}║{R}")
        print(f"  {BOLD}{CYN}╚{'═'*58}╝{R}")
        print(f"")

        if detail_mode and 0 <= selected < len(chains):
            for ln in render_detail(chains[selected], lang):
                print(ln)
        else:
            print(f"  {BOLD}{GRN}{s['chains']} ({len(chains)}){R}")
            print(f"  {DIM}{bar(58)}{R}")
            for i, c in enumerate(chains):
                for ln in render_chain(c, lang, i, i == selected):
                    print(ln)
                if i < len(chains) - 1:
                    print(f"  {DIM}│{R}")
            print(f"")
            print(f"  {DIM}{s['back']}{R}")

        # Input
        try:
            import termios
            import tty
            fd = sys.stdin.fileno()
            old = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                ch = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except (ImportError, OSError):
            ch = input().strip()[:1] or "q"

        if ch in ("q", "Q", "\x03"):
            print(f"\033[2J\033[H")
            break
        elif ch in ("t", "T"):
            lang = "zh" if lang == "en" else "en"
        elif ch in ("j", "\x1b[B"):  # down
            if detail_mode:
                detail_mode = False
            else:
                selected = min(selected + 1, len(chains) - 1)
        elif ch in ("k", "\x1b[A"):  # up
            if detail_mode:
                detail_mode = False
            else:
                selected = max(selected - 1, 0)
        elif ch in ("\r", "\n"):  # enter
            detail_mode = not detail_mode
        elif ch in ("h", "\x1b"):  # escape / back
            detail_mode = False

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
