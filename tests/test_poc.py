"""Deterministic PoC entry point: source contracts and CLI safety."""
from pathlib import Path

from jgd.cli import main as cli_main
from jgd.poc import poc_gen


def test_poc_builder_source_contract():
    src = poc_gen.BUILD_TAIL
    assert "hmz:" in src
    assert "put_no_hash" in src
    assert "java.util.HashMap$Node" in src
    # CC3 tail must use the real getMethod -> invoke -> exec sequence.
    assert '"getMethod"' in src
    assert '"invoke"' in src
    assert 'java.lang.reflect.Array.newInstance' in src


def test_poc_requires_unsafe_host(tmp_path: Path):
    target = tmp_path / "jars"
    target.mkdir()
    (target / "x.jar").write_bytes(b"")
    rc = cli_main(["poc", "--target", str(target), "--bridge", "x.Y"])
    assert rc == 30


def test_run_chain_writes_result(tmp_path: Path, monkeypatch):
    target = tmp_path / "jars"
    target.mkdir()
    (target / "x.jar").write_bytes(b"")
    ecj = tmp_path / "ecj.jar"
    ecj.write_bytes(b"stub")
    out = tmp_path / "out"
    monkeypatch.setattr(
        poc_gen, "select_tail", lambda _target: [{"lib": "cc3", "present": True}]
    )
    monkeypatch.setattr(
        poc_gen,
        "build_and_verify",
        lambda chain, mode, bridge, jdk11, tails: {
            "chain": chain,
            "status": "RCE_DEMO_FIRED",
            "fired_at_deser": True,
        },
    )
    result = poc_gen.run_chain(
        target, "com.example.Bridge", trigger="hash", out=out, ecj=ecj
    )
    assert result["status"] == "RCE_DEMO_FIRED"
    assert result["trigger"] == "hash"
    assert result["target"] == str(target.resolve())
    assert (out / "poc_result.json").exists()
