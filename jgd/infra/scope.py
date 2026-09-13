"""scope.py — R51(D3): 语料分域工具。

任何跨运行产物(状态/审计/POC目录)经 scoped(name) 获取语料专属路径;
语料指纹变更时旧文件自动归档(加 .<fp8> 后缀), 不污染新语料。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from jgd import PROJECT_ROOT

DATA = PROJECT_ROOT / "data"
DATA.mkdir(exist_ok=True)


def corpus_fp() -> str:
    import hashlib
    t = os.environ.get("JGD_TARGET")
    if not t:
        return "default"
    h = hashlib.sha256()
    from pathlib import Path as P
    for j in sorted(P(t).glob("*.jar")):
        h.update(j.name.encode())
        h.update(str(j.stat().st_size).encode())
    return h.hexdigest()[:8]


def scoped(name: str) -> Path:
    """返回 <name 去后缀>.<fp8><原后缀>; 旧指纹文件留在原地不影响。"""
    fp = corpus_fp()
    p = Path(name)
    return p.with_name(f"{p.stem}.{fp}{p.suffix}")


def scoped_dir(name: str) -> Path:
    return Path(name) / corpus_fp()
