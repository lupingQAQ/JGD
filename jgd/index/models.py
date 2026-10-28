"""Typed inputs produced by class readers and consumed by the index."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Protocol


@dataclass(frozen=True)
class FieldMeta:
    name: str
    desc: str
    access: int = 0


@dataclass(frozen=True)
class InstructionMeta:
    offset: int
    opcode: str
    text: str = ""
    resolved: tuple | None = None


@dataclass(frozen=True)
class MethodMeta:
    name: str
    desc: str
    access: int = 0
    code_size: int = 0
    instructions: list[InstructionMeta] = field(default_factory=list)


@dataclass(frozen=True)
class ClassMeta:
    name: str
    super: str = ""
    interfaces: list[str] = field(default_factory=list)
    access: int = 0
    major: int = 0
    fields: list[FieldMeta] = field(default_factory=list)
    methods: list[MethodMeta] = field(default_factory=list)
    origin: str = ""


class ClassReader(Protocol):
    def iter_classes(self, jar) -> Iterable[ClassMeta]:
        """Yield classes from an open SafeJar."""


@dataclass(frozen=True)
class IndexStats:
    jars: int = 0
    classes: int = 0
    methods: int = 0
    fields: int = 0
    invokes: int = 0
    field_accesses: int = 0
    duration_s: float = 0.0
