"""Profiler — 每管线节点的 wall/CPU/peakRSS 采样 。

用法: python3 profiler.py <label> <cmd...>
输出: profile_<label>.json {label, wall_s, cpu_s, peak_rss_mb, cmd}
采样: /proc/<pid>/stat (utime+stime) + /proc/<pid>/status VmRSS, 0.5s 间隔,
     含子进程 (pgid) 的聚合 — java 子进程计入对应 stage。
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from jgd import PROJECT_ROOT

HERE = PROJECT_ROOT


def _proc_cpu(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().split()
        return (int(parts[13]) + int(parts[14])) / os.sysconf("SC_CLK_TCK")
    except Exception:
        return 0.0


def _proc_rss(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status") as f:
            for ln in f:
                if ln.startswith("VmRSS:"):
                    return int(ln.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0


def _tree_pids(root: int) -> list[int]:
    out = [root]
    try:
        for d in os.listdir("/proc"):
            if not d.isdigit():
                continue
            try:
                with open(f"/proc/{d}/stat") as f:
                    ppid = int(f.read().split()[3])
            except Exception:
                continue
            if ppid == root:
                out += _tree_pids(int(d))
    except Exception:
        pass
    return out


def run_profiled(label: str, cmd: list[str], timeout: int = 3000) -> dict:
    t0 = time.time()
    p = subprocess.Popen(cmd, cwd=HERE, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    cpu = 0.0
    peak = 0.0
    while p.poll() is None:
        pids = _tree_pids(p.pid)
        cpu = max(cpu, sum(_proc_cpu(pid) for pid in pids))
        peak = max(peak, sum(_proc_rss(pid) for pid in pids))
        time.sleep(0.5)
        if time.time() - t0 > timeout:
            p.kill()
            break
    wall = time.time() - t0
    prof = {"label": label, "wall_s": round(wall, 1),
            "cpu_s": round(cpu, 1), "peak_rss_mb": round(peak, 1),
            "cmd": " ".join(cmd[:6])}
    (HERE / f"profile_{label}.json").write_text(
        json.dumps(prof, ensure_ascii=False), encoding="utf-8")
    print(f"[prof] {label}: wall={wall:.1f}s cpu={cpu:.1f}s "
          f"peakRSS={peak:.1f}MB rc={p.returncode}", flush=True)
    return prof


if __name__ == "__main__":
    run_profiled(sys.argv[1], sys.argv[2:])
