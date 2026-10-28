"""Plan 2: PoC/LLM/sandbox policy gates."""
from dataclasses import replace

import pytest

from jgd.config import Policy
from jgd.security.policy import PolicyEngine, PolicyError, Scope


def test_local_scope_can_use_poc_when_enabled():
    eng = PolicyEngine(
        Policy(),
        Scope(authorized_targets={"fp"}, tenant="local", grants={"jgd.poc"}),
    )
    eng.authorize_poc("fp", "local")


def test_remote_without_grant_is_denied():
    eng = PolicyEngine(
        Policy(),
        Scope(authorized_targets={"fp"}, tenant="remote", grants=set()),
    )
    with pytest.raises(PolicyError, match="jgd.poc"):
        eng.authorize_poc("fp", "remote")


def test_out_of_scope_is_denied():
    eng = PolicyEngine(
        Policy(),
        Scope(authorized_targets={"fp"}, grants={"jgd.poc"}),
    )
    with pytest.raises(PolicyError, match="scope"):
        eng.authorize_poc("other")


def test_poc_disabled_is_denied():
    eng = PolicyEngine(
        replace(Policy(), poc=False),
        Scope(authorized_targets={"fp"}, grants={"jgd.poc"}),
    )
    with pytest.raises(PolicyError, match="disabled"):
        eng.authorize_poc("fp")


def test_llm_off_is_denied():
    eng = PolicyEngine(replace(Policy(), llm="off"))
    with pytest.raises(PolicyError):
        eng.authorize_llm()
