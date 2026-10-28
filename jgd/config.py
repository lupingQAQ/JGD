"""JGD runtime configuration.

No import-time filesystem writes: all runtime paths come from ``JgdConfig``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

Profile = Literal["known", "standard", "deep", "full"]
SandboxKind = Literal["docker", "wsl2", "host"]
LlmMode = Literal["on", "local", "cloud", "off"]
RedactMode = Literal["none", "package", "class", "full"]
FailOn = Literal["critical", "high", "medium", "low", "none"]

_PROFILES = {"known", "standard", "deep", "full"}
_SANDBOXES = {"docker", "wsl2", "host"}
_LLM_MODES = {"on", "local", "cloud", "off"}
_REDACT_MODES = {"none", "package", "class", "full"}
_FAIL_ON = {"critical", "high", "medium", "low", "none"}


def _choice(value: str, allowed: set[str], name: str) -> str:
    if value not in allowed:
        raise ValueError(f"invalid {name}: {value!r}; expected one of {sorted(allowed)}")
    return value


@dataclass(frozen=True)
class Policy:
    """Run policy. PoC and LLM are on by default; LLM is advisory only."""

    sandbox: SandboxKind = "docker"
    allow_host: bool = False
    offline: bool = False
    llm: LlmMode = "on"
    poc: bool = True
    allow_cloud_llm: bool = False
    redact: RedactMode = "package"
    fail_on: FailOn = "high"

    def __post_init__(self) -> None:
        _choice(self.sandbox, _SANDBOXES, "sandbox")
        _choice(self.llm, _LLM_MODES, "llm")
        _choice(self.redact, _REDACT_MODES, "redact")
        _choice(self.fail_on, _FAIL_ON, "fail_on")


@dataclass(frozen=True)
class Budget:
    wall_s: int = 1800
    jvm_s: int = 1200
    llm_tokens: int = 200_000
    jobs: int = 8

    def __post_init__(self) -> None:
        if self.wall_s <= 0 or self.jvm_s < 0 or self.llm_tokens < 0:
            raise ValueError("budget values must be non-negative (wall_s > 0)")
        if self.jobs <= 0:
            raise ValueError("jobs must be > 0")


@dataclass(frozen=True)
class JgdConfig:
    home: Path
    target: Path
    profile: Profile = "standard"
    policy: Policy = field(default_factory=Policy)
    budget: Budget = field(default_factory=Budget)

    def __post_init__(self) -> None:
        _choice(self.profile, _PROFILES, "profile")
        object.__setattr__(self, "home", Path(self.home))
        object.__setattr__(self, "target", Path(self.target))
