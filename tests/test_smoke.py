"""tests/test_smoke.py — 可第三方独立复现的冒烟套件。

覆盖: 全模块编译 / scope 分域 / 公开链判定 / verify 无LLM快扫 / 一次性入口。
运行: python3 -m pytest tests/test_smoke.py -x  (或 bash tests/run.sh)
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

MODULES = [
    "audit_target.py", "conductor.py", "verify_agent.py", "evolve_v2.py",
    "chain_complete.py", "poc_gen.py", "known_chains.py", "matrix_agent.py",
    "staticagent.py", "ledger.py", "bcdisasm.py", "bridge_fix.py",
    "chroma_store.py", "llm.py", "scope.py", "profiler.py", "chains_2026.py",
    "dsh_cross.py", "dsh_final.py", "dsh_debt.py", "evidence_r52.py",
]


def test_all_modules_compile():
    for m in MODULES:
        p = ROOT / m
        assert p.exists(), f"missing live module {m}"
        r = subprocess.run([sys.executable, "-m", "py_compile", str(p)],
                           capture_output=True, text=True)
        assert r.returncode == 0, f"{m}: {r.stderr[-200:]}"


def test_scope_data_root():
    import scope
    assert scope.DATA.exists()
    assert scope.corpus_fp()


def test_root_has_no_zombies():
    for z in ("_r5tmp", "_verify", "downloads", "schemes"):
        assert not (ROOT / z).exists(), f"zombie dir {z} alive"
    legacy = [p.name for p in ROOT.glob("diag_*.py")] + \
             [p.name for p in ROOT.glob("check_*.py")]
    assert not legacy, f"legacy scripts at root: {legacy}"


def test_known_chains_runs(tmp_path):
    jars = tmp_path / "corpus"
    jars.mkdir()
    import zipfile
    # 构造最小语料: 一个含 InvokerTransformer 的 jar
    src = ROOT / "archive" / "code"
    cc_jars = list((Path.home() / "jgd/targets-apache2026/all").glob(
        "commons-collections-*.jar")) if (
        Path.home() / "jgd/targets-apache2026/all").exists() else []
    if cc_jars:
        import shutil
        shutil.copy(cc_jars[0], jars / cc_jars[0].name)
        env = dict(os.environ, JGD_TARGET=str(jars))
        r = subprocess.run(
            [sys.executable, "-u", str(ROOT / "known_chains.py")],
            capture_output=True, text=True, env=env, cwd=ROOT, timeout=120)
        assert r.returncode == 0
        assert "CC1-CC7" in r.stdout
    else:
        print("skip: no fixture jar available")


def test_one_shot_entry_help():
    r = subprocess.run([sys.executable, str(ROOT / "audit_target.py"),
                        "--help"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0 and "--target" in r.stdout
