"""Plan 2 policy gate for sandbox, PoC, and LLM egress."""
from __future__ import annotations

from dataclasses import dataclass, field

from jgd.config import Policy
from jgd.security.sandbox import Sandbox, get_sandbox


class PolicyError(PermissionError):
    """Raised when a run asks for a capability it is not authorized to use."""


@dataclass(frozen=True)
class Scope:
    authorized_targets: set[str] = field(default_factory=set)
    tenant: str = "local"
    grants: set[str] = field(default_factory=set)


class PolicyEngine:
    def __init__(self, policy: Policy, scope: Scope | None = None) -> None:
        self.policy = policy
        self.scope = scope or Scope()

    def sandbox(self) -> Sandbox:
        return get_sandbox(
            self.policy.sandbox,
            allow_host=self.policy.allow_host,
        )

    def authorize_poc(self, target_fingerprint: str, tenant: str | None = None) -> None:
        if not self.policy.poc:
            raise PolicyError("PoC is disabled by policy")
        if target_fingerprint not in self.scope.authorized_targets:
            raise PolicyError("target is not in the authorized scope")
        if tenant is not None and tenant != self.scope.tenant:
            raise PolicyError("tenant mismatch")
        if "jgd.poc" not in self.scope.grants:
            raise PolicyError("caller lacks jgd.poc grant")

    def authorize_llm(self) -> None:
        if self.policy.llm == "off":
            raise PolicyError("LLM is disabled by policy")
