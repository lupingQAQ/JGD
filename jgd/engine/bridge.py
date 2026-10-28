"""Bridge scan: SQL recall over the index, exact check on candidates only."""
from __future__ import annotations

from jgd.index.bytecode import BytecodeIndex
from jgd.index.queries import bridge_rows
from jgd.mining import bcdisasm
from jgd.mining.bridge_fix import field_bridges_from_classfile
from jgd.security.archive import SafeJar


class BridgeScanError(RuntimeError):
    """Raised when a recalled bridge candidate cannot be parsed exactly."""


def _read_class_bytes(jar_path: str, origin: str, class_name: str) -> bytes:
    if not origin:
        with SafeJar(jar_path) as jar:
            return jar.read(class_name + ".class")
    parts = origin.split("!")
    with SafeJar(jar_path) as jar:
        data = jar.read(parts[0])
    for part in parts[1:]:
        with SafeJar.from_bytes(data) as inner:
            data = inner.read(part)
    with SafeJar.from_bytes(data) as inner:
        return inner.read(class_name + ".class")


def scan_bridges(
    index: BytecodeIndex, triggers: set[str] | None = None
) -> list[dict]:
    candidates = bridge_rows(index, triggers)
    cache: dict[tuple[str, str, str], list[dict]] = {}
    seen: set[tuple] = set()
    out: list[dict] = []

    for cand in candidates:
        key = (cand["jar_path"], cand.get("origin", ""), cand["cls"])
        if key not in cache:
            try:
                data = _read_class_bytes(
                    cand["jar_path"], cand.get("origin", ""), cand["cls"]
                )
                cache[key] = field_bridges_from_classfile(bcdisasm.ClassFile(data))
            except Exception as exc:
                raise BridgeScanError(
                    f"failed to parse bridge candidate {cand['cls']} "
                    f"in {cand['jar_path']} (origin={cand.get('origin', '')}): {exc}"
                ) from exc
        for detail in cache[key]:
            dedupe = (
                cand["cls"],
                detail.get("trigger"),
                detail.get("field"),
                detail.get("target"),
                detail.get("via"),
            )
            if dedupe in seen:
                continue
            seen.add(dedupe)
            out.append(
                {
                    **cand,
                    "trigger": detail.get("trigger", cand["trigger"]),
                    "field": detail.get("field", cand["field"]),
                    "field_desc": detail.get("field_desc", cand["field_desc"]),
                    "target": detail.get("target", cand["target"]),
                    "via": detail.get("via", cand["via"]),
                    "map_key": detail.get("map_key"),
                    "map_iface": detail.get("map_iface"),
                }
            )
    return out
