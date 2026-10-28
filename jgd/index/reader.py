"""Class reader backed by the existing pure-Python ``bcdisasm`` parser."""
from __future__ import annotations

from typing import Iterable

from jgd.index.models import ClassMeta, FieldMeta, InstructionMeta, MethodMeta
from jgd.mining import bcdisasm
from jgd.security.archive import SafeJar


class DisasmClassReader:
    """Read classes from a validated SafeJar without extracting or executing them."""

    def __init__(self, max_nested_depth: int = 2) -> None:
        self.max_nested_depth = max_nested_depth

    def iter_classes(
        self, jar: SafeJar, _depth: int = 0, _origin: str = ""
    ) -> Iterable[ClassMeta]:
        for entry in jar.class_entries():
            data = jar.read(entry)
            cf = bcdisasm.ClassFile(data)
            fields = [
                FieldMeta(name=f["name"], desc=f["desc"], access=f["access"])
                for f in cf.fields
            ]
            methods = []
            for m in cf.methods:
                code = m.get("code")
                code_size = len(code["code"]) if code else 0
                instructions = [
                    InstructionMeta(offset=off, opcode=name, text=text, resolved=res)
                    for off, name, text, res in cf.disasm(m)
                ] if code else []
                methods.append(
                    MethodMeta(
                        name=m["name"],
                        desc=m["desc"],
                        access=m["access"],
                        code_size=code_size,
                        instructions=instructions,
                    )
                )
            yield ClassMeta(
                name=cf.this,
                super=cf.super,
                interfaces=list(cf.ifcs),
                access=cf.access,
                major=cf.major,
                fields=fields,
                methods=methods,
                origin=_origin,
            )

        # Spring Boot / WAR layouts nest dependency JARs. Index one or two
        # levels deep so the outer fat JAR is not silently half-scanned.
        if _depth >= self.max_nested_depth:
            return
        for nested in jar.jar_entries():
            data = jar.read(nested)
            nested_origin = f"{_origin}!{nested}" if _origin else nested
            with SafeJar.from_bytes(
                data, name=f"{jar.path}!/{nested}", limits=jar.limits
            ) as inner:
                yield from self.iter_classes(inner, _depth + 1, nested_origin)
