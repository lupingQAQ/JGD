"""scope.py — (D3): 语料分域工具。

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


_FP_CACHE: dict[str, str] = {}


def _fp16() -> str:
    """16 位语料指纹(jar 名+大小+mtime), 全项目唯一实现。

    mtime 参与: 同名同大小替换 jar(如热修版)也能触发指纹变更与状态归档;
    JGD_TARGET 未设时为常量 default(研究模式)。
    """
    import hashlib
    t = os.environ.get("JGD_TARGET")
    key = t or ""
    if key in _FP_CACHE:
        return _FP_CACHE[key]
    if not t:
        _FP_CACHE[key] = "default"
        return "default"
    h = hashlib.sha256()
    from pathlib import Path as P
    for j in sorted(P(t).glob("*.jar")):
        st = j.stat()
        h.update(j.name.encode())
        h.update(str(st.st_size).encode())
        h.update(str(st.st_mtime).encode())
    v = h.hexdigest()[:16]
    _FP_CACHE[key] = v
    return v


def corpus_fp() -> str:
    """8 位语料指纹 — 文件分域后缀用"""
    return _fp16()[:8]


def scoped(name: str) -> Path:
    """返回 <name 去后缀>.<fp8><原后缀>; 旧指纹文件留在原地不影响。"""
    fp = corpus_fp()
    p = Path(name)
    return p.with_name(f"{p.stem}.{fp}{p.suffix}")


def scoped_dir(name: str) -> Path:
    return Path(name) / corpus_fp()
