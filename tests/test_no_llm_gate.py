"""The production conductor must not contain an LLM acceptance gate."""
from pathlib import Path

from jgd.poc import poc_gen
from jgd.verification import conductor


def test_conductor_has_no_llm_acceptance_gate():
    src = Path(conductor.__file__).read_text(encoding="utf-8")
    assert "_ds_acceptance" not in src
    assert "accepted" not in src.lower()


def test_poc_has_no_llm_acceptance_gate():
    src = Path(poc_gen.__file__).read_text(encoding="utf-8")
    assert "ds_verify" not in src
    assert "accepted" not in src.lower()
