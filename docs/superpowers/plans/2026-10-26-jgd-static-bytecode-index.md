# JGD Static Bytecode Index & Safe Scanner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a one-pass SQLite bytecode index and use it to run known-chain and bridge scans over large JAR corpora without reopening JARs, with JSON/SARIF output, explicit exit codes, and a benchmark that proves the speedup.

**Architecture:** Keep the existing JGD domain algorithms. Add a derived, content-addressed bytecode index (`jgd/index`) as a cache, not a second source of truth. Parse each JAR once with `bcdisasm`, materialize semantic facts (classes, methods, fields, invokes, field accesses, strings), and answer known-chain/bridge queries with SQL. Exact operand-stack checks remain procedural (`bridge_fix`) on the narrowed candidate set.

**Tech Stack:** Python 3.10+, SQLite (WAL), existing `bcdisasm`/`staticagent`/`bridge_fix`/`known_chains`, pytest, `jsonschema`, SARIF 2.1.0, Docker/WSL2 only for later plans.

**Spec:** `docs/superpowers/specs/2026-10-26-jgd-autonomous-agent-hardening-design.md`

## Program Roadmap

This spec is intentionally split into executable, independently testable plans:

1. **Plan 1 (this): Static bytecode index + safe scanner + benchmark.** No target code execution.
2. **Plan 2: Sandbox + dynamic verification + PoC policy.** Docker/WSL2, SafeJar integration, policy engine.
3. **Plan 3: Agent runtime.** Run/Task state machine, tool registry, planner, verifier, terminator, SQLite store, LLM advisory (no gatekeeping).
4. **Plan 4: Interfaces.** Full CLI/SDK, MCP, A2A v1.0 Agent Card + task lifecycle + streaming + auth, SARIF.
5. **Plan 5: Performance + real-world validation.** Resident JVM pool, incremental graph, commercial-product authorized corpus, disclosure workflow.

Do not start Plan 2 until Plan 1's benchmark and security tests pass.

## Bytecode DB Decision

**Adopt** a relational bytecode index; **do not** use a vector DB or a generic graph DB in this plan.

- Store semantic facts only: class/method/field metadata, invoke edges, field accesses, string constants, supertypes. Do not store every instruction byte.
- Raw `.class` bytes remain the source of truth; the index is rebuildable from target JARs and a `index_version`.
- Use SQL for candidate generation (bridge candidates, class presence, receiver narrowing). Keep the operand-stack symbolic executor for exact checks.
- Incremental by JAR `sha256`: unchanged JARs are skipped; changed JARs delete/insert their rows.
- Benchmark gate: on the 828-JAR corpus, indexed queries must be **≥5× faster** than the current per-chain/per-class JAR opens. If not, report why and fall back to an in-memory index for small corpora.
- Vector search is **not** useful for exact bytecode semantics; do not use Chroma/RAG as the index.

## Global Constraints

- Python `>=3.10`; `pyproject.toml` is the single packaging source; remove duplicate `setup.py` entry points.
- SQLite only for this plan; no Postgres, no DuckDB dependency.
- **No target code execution in Plan 1.** `Class.forName`, constructors, `readObject`, and PoC are out of scope; they belong to Plan 2.
- No global `JGD_TARGET` or import-time `data/` side effects in new code. All paths come from `JgdConfig`.
- Every run gets `runs/<runId>/`; no shared `audit_report/` or `data/` writes.
- JSON outputs use `jgd.findings/v1` and `jgd.run/v1`; SARIF is 2.1.0.
- Exit codes: `0` no finding, `10` finding, `20` partial, `30` failure, `40` policy denied.
- PoC and LLM defaults are recorded as `poc=true`, `llm=on` but are not exercised in Plan 1; no LLM gate code exists.
- Tests must not require network, author home directories, or a running Docker daemon.
- Keep MIT license headers and upstream attribution.

## Review Focus

1. **Duplicate class names across JARs** must produce multiple index rows and deterministic candidate ordering, not last-writer-wins.
2. **Multi-release JARs** (`META-INF/versions/<n>/...`) must not be confused with base classes; index semantics are explicit.
3. **Malicious archives** (zip bomb, `../`, absolute names, symlinks, huge entries) must be rejected before parsing, with bounded memory/time.
4. **Missing 155-chain DB** must produce an explicit `db_version`/error or auto-build, never a silent 14-chain fallback presented as full coverage.
5. **Machine contract**: identical target/profile produces identical JSON findings; exit codes and SARIF validate; no logging-only failures.

---

### Task 1: Config, contracts, and defaults

**Files:**
- Create: `jgd/config.py`
- Create: `jgd/contracts/__init__.py`
- Create: `jgd/contracts/models.py`
- Test: `tests/test_config_defaults.py`

**Interfaces:**
- Produces:
  - `Policy(sandbox: str = "docker", offline: bool = False, llm: str = "on", poc: bool = True, allow_cloud_llm: bool = False, redact: str = "package", fail_on: str = "high")`
  - `Budget(wall_s: int = 1800, jvm_s: int = 1200, llm_tokens: int = 200_000, jobs: int = 8)`
  - `JgdConfig(home: Path, target: Path, profile: str = "standard", policy: Policy = Policy(), budget: Budget = Budget())`
  - `RunGoal(target: Path, profile: str, policy: Policy, budget: Budget)`
  - `Finding(id: str, category: str, verdict: str, severity: str, confidence: float, entry: dict, bridge: dict, sink: dict, evidence: list[dict], remediation: dict)`
  - `RunResult(schema_version: str, run_id: str, tool: dict, target: dict, status: str, findings: list[Finding], coverage: dict, errors: list[dict])`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config_defaults.py
from pathlib import Path
import pytest
from jgd.config import Budget, JgdConfig, Policy


def test_defaults_match_spec(tmp_path: Path):
    p = Policy()
    assert p.sandbox == "docker"
    assert p.offline is False
    assert p.llm == "on"
    assert p.poc is True
    assert p.allow_cloud_llm is False
    assert p.fail_on == "high"
    assert Budget().jobs == 8
    cfg = JgdConfig(home=tmp_path / "home", target=tmp_path / "jars")
    assert cfg.profile == "standard"
    assert cfg.policy.poc is True


def test_profile_is_validated(tmp_path: Path):
    with pytest.raises(ValueError, match="profile"):
        JgdConfig(home=tmp_path, target=tmp_path, profile="bogus")


def test_finding_roundtrip():
    from jgd.contracts.models import Finding, RunResult
    f = Finding(
        id="JGD-1", category="java-deserialization", verdict="CHAIN_CONFIRMED",
        severity="high", confidence=0.9, entry={"class": "A"},
        bridge={"class": "B"}, sink={"class": "C"}, evidence=[], remediation={},
    )
    r = RunResult(
        schema_version="jgd.run/v1", run_id="01J", tool={"name": "jgd"},
        target={"root": "/tmp"}, status="completed", findings=[f],
        coverage={"jars": 1}, errors=[],
    )
    data = r.to_dict()
    assert data["findings"][0]["verdict"] == "CHAIN_CONFIRMED"
    assert data["schemaVersion"] == "jgd.run/v1"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_config_defaults.py -v`  
Expected: FAIL with `ModuleNotFoundError: No module named 'jgd.config'`

- [ ] **Step 3: Implement `jgd/config.py` and `jgd/contracts/models.py`**

`JgdConfig.__post_init__` validates `profile in {"known","standard","deep","full"}` and raises `ValueError("invalid profile: ...")`. Use frozen dataclasses; `Policy`/`Budget` as default factories, never mutable defaults. `RunResult.to_dict()` returns camelCase keys (`schemaVersion`, `runId`, `findings`) and calls `Finding.to_dict()`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_config_defaults.py -v`  
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add jgd/config.py jgd/contracts tests/test_config_defaults.py
git commit -m "feat: add hardened config and run contracts"
```

---

### Task 2: SafeJar archive reader

**Files:**
- Create: `jgd/security/__init__.py`
- Create: `jgd/security/archive.py`
- Test: `tests/test_safe_jar.py`

**Interfaces:**
- Produces:
  - `ArchiveLimits(max_entries: int = 200_000, max_entry_bytes: int = 64_000_000, max_total_bytes: int = 2_000_000_000, max_compression_ratio: int = 100, max_name_len: int = 512)`
  - `SafeJar(path: Path, limits: ArchiveLimits = ArchiveLimits())`
  - `SafeJar.__enter__() -> SafeJar`
  - `SafeJar.namelist() -> list[str]`
  - `SafeJar.read(name: str, max_bytes: int | None = None) -> bytes`
  - `SafeJar.class_entries() -> list[str]`
  - `SafeJar.sha256() -> str`
  - `ArchiveError(Exception)`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_safe_jar.py
import zipfile
from pathlib import Path
import pytest
from jgd.security.archive import ArchiveError, ArchiveLimits, SafeJar


def _jar(path: Path, entries: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return path


def test_reads_normal_jar(tmp_path: Path):
    p = _jar(tmp_path / "ok.jar", {"a/B.class": b"CAFEBABE"})
    with SafeJar(p) as j:
        assert j.read("a/B.class") == b"CAFEBABE"
        assert j.class_entries() == ["a/B.class"]
        assert len(j.sha256()) == 64


def test_rejects_parent_traversal(tmp_path: Path):
    p = _jar(tmp_path / "evil.jar", {"../evil.class": b"x"})
    with pytest.raises(ArchiveError, match="path"):
        with SafeJar(p):
            pass


def test_rejects_absolute_path(tmp_path: Path):
    p = _jar(tmp_path / "abs.jar", {"/etc/passwd": b"x"})
    with pytest.raises(ArchiveError, match="path"):
        with SafeJar(p):
            pass


def test_rejects_symlink(tmp_path: Path):
    p = tmp_path / "link.jar"
    with zipfile.ZipFile(p, "w") as z:
        zi = zipfile.ZipInfo("link.class")
        zi.external_attr = (0o120777 << 16)
        z.writestr(zi, b"x")
    with pytest.raises(ArchiveError, match="symlink"):
        with SafeJar(p):
            pass


def test_rejects_zip_bomb_ratio(tmp_path: Path):
    p = _jar(tmp_path / "bomb.jar", {"big.class": b"\0" * 2_000_000})
    limits = ArchiveLimits(max_entry_bytes=4_000_000, max_compression_ratio=10)
    with pytest.raises(ArchiveError, match="ratio"):
        with SafeJar(p, limits):
            pass


def test_multi_release_entries_are_not_base_classes(tmp_path: Path):
    p = _jar(tmp_path / "mr.jar", {
        "a/B.class": b"base",
        "META-INF/versions/17/a/B.class": b"v17",
    })
    with SafeJar(p) as j:
        assert j.class_entries() == ["a/B.class"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_safe_jar.py -v`  
Expected: FAIL with `ModuleNotFoundError: No module named 'jgd.security'`

- [ ] **Step 3: Implement `SafeJar`**

Validate every `ZipInfo` before exposing entries: reject names that are absolute, contain `..` segments, contain `\` or NUL, or exceed `max_name_len`; reject symlinks via `(external_attr >> 16) & 0o170000 == 0o120000`; reject entries over `max_entry_bytes`, total over `max_total_bytes`, or ratio over `max_compression_ratio` when `compress_size > 0`. `class_entries()` returns entries ending `.class`, excluding `META-INF/versions/`, `module-info.class`, and `package-info.class`. Never call `extractall()`. `sha256()` hashes the file bytes in 1 MiB chunks.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_safe_jar.py -v`  
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add jgd/security tests/test_safe_jar.py
git commit -m "feat: add bounded SafeJar reader"
```

---

### Task 3: Bytecode index schema + fake-reader build path

**Files:**
- Create: `jgd/index/__init__.py`
- Create: `jgd/index/models.py`
- Create: `jgd/index/schema.py`
- Create: `jgd/index/bytecode.py`
- Test: `tests/test_bytecode_index.py`
- Create: `tests/__init__.py`

**Interfaces:**
- Produces:
  - `FieldMeta(name: str, desc: str, access: int)`
  - `InstructionMeta(offset: int, opcode: str, text: str, resolved: tuple | None)`
  - `MethodMeta(name: str, desc: str, access: int, code_size: int, instructions: list[InstructionMeta])`
  - `ClassMeta(name: str, super: str, interfaces: list[str], access: int, major: int, fields: list[FieldMeta], methods: list[MethodMeta])`
  - `ClassReader` protocol: `iter_classes(jar: SafeJar) -> Iterator[ClassMeta]`
  - `IndexStats(jars: int, classes: int, methods: int, fields: int, invokes: int, field_accesses: int, duration_s: float)`
  - `BytecodeIndex(db_path: Path, reader: ClassReader | None = None)`
  - `BytecodeIndex.build(target: Path, force: bool = False) -> IndexStats`
  - `BytecodeIndex.close() -> None`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_bytecode_index.py
from pathlib import Path
import zipfile
import pytest
from jgd.index.bytecode import BytecodeIndex
from jgd.index.models import ClassMeta, FieldMeta, InstructionMeta, MethodMeta


class FakeReader:
    def iter_classes(self, jar):
        yield ClassMeta(
            name="demo/A", super="java/lang/Object", interfaces=[], access=0x0021,
            major=55,
            fields=[FieldMeta("f", "Ljava/lang/Object;", 0)],
            methods=[MethodMeta(
                "hashCode", "()I", 0x0001, 1,
                [InstructionMeta(0, "getfield", "demo/A.f", ("field", "demo/A", "f", "Ljava/lang/Object;")),
                 InstructionMeta(3, "invokevirtual", "java/lang/Object.hashCode", ("method", "java/lang/Object", "hashCode", "()I"))],
            )],
        )


def _jar(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("demo/A.class", b"ignored")
    return path


def test_build_indexes_semantic_rows(tmp_path: Path):
    target = tmp_path / "jars"; target.mkdir()
    _jar(target / "a.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    stats = idx.build(target)
    assert stats.jars == 1 and stats.classes == 1
    assert stats.methods == 1 and stats.fields == 1
    assert stats.invokes == 1 and stats.field_accesses == 1
    rows = idx._conn.execute("SELECT name, super FROM classes").fetchall()
    assert rows == [("demo/A", "java/lang/Object")]
    idx.close()


def test_rebuild_is_idempotent_and_changed_jar_replaces_rows(tmp_path: Path):
    target = tmp_path / "jars"; target.mkdir()
    _jar(target / "a.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    idx.build(target)
    assert idx.build(target).jars == 0  # unchanged
    with zipfile.ZipFile(target / "a.jar", "a") as z:
        z.comment = b"changed"
    idx.build(target)
    assert idx._conn.execute("SELECT COUNT(*) FROM classes").fetchone()[0] == 1
    idx.close()


def test_duplicate_class_names_are_preserved(tmp_path: Path):
    target = tmp_path / "jars"; target.mkdir()
    _jar(target / "a.jar"); _jar(target / "b.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    idx.build(target)
    assert idx._conn.execute("SELECT COUNT(*) FROM classes WHERE name='demo/A'").fetchone()[0] == 2
    idx.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_bytecode_index.py -v`  
Expected: FAIL with `ModuleNotFoundError: No module named 'jgd.index'`

- [ ] **Step 3: Implement `jgd/index/schema.py` and `jgd/index/bytecode.py`**

Create the SQLite schema with `meta`, `jars`, `classes`, `methods`, `fields`, `invokes`, `field_access`, `strings` tables and indexes on `classes(name)`, `methods(class_id)`, `invokes(callee_owner, callee_name)`, `field_access(method_id)`. Store `index_version` in `meta`. Use `PRAGMA journal_mode=WAL`, `foreign_keys=ON`, `synchronous=NORMAL`. `build()` enumerates `*.jar` sorted, computes `SafeJar.sha256()`, skips rows already present unless `force=True`, and writes each JAR in one transaction. Map `ClassMeta` to rows; for each instruction whose `resolved[0]` is `"method"` insert `invokes`; `"field"` insert `field_access` with `kind` derived from opcode (`get*` → `read`, `put*` → `write`). `IndexStats` counts rows inserted.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_bytecode_index.py -v`  
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add jgd/index tests/test_bytecode_index.py tests/__init__.py
git commit -m "feat: add one-pass bytecode index schema"
```

---

### Task 4: Real `bcdisasm` class reader

**Files:**
- Create: `jgd/index/reader.py`
- Test: `tests/test_index_real_reader.py`

**Interfaces:**
- Consumes: `BytecodeIndex`, `ClassMeta`, `MethodMeta`, `FieldMeta`, `InstructionMeta` from Task 3; `jgd.mining.bcdisasm.ClassFile`.
- Produces: `DisasmClassReader.iter_classes(jar: SafeJar) -> Iterator[ClassMeta]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_index_real_reader.py
import shutil, subprocess, zipfile
from pathlib import Path
import pytest
from jgd.index.bytecode import BytecodeIndex
from jgd.index.reader import DisasmClassReader

pytestmark = pytest.mark.skipif(shutil.which("javac") is None, reason="javac not available")


def _compile(tmp_path: Path) -> Path:
    src = tmp_path / "A.java"
    src.write_text(
        "public class A extends B { Object f; public int hashCode(){ return f.hashCode(); } }\n"
        "class B {}\n", encoding="utf-8")
    subprocess.run(["javac", "-d", str(tmp_path / "classes"), str(src)], check=True)
    jar = tmp_path / "a.jar"
    with zipfile.ZipFile(jar, "w") as z:
        for p in (tmp_path / "classes").rglob("*.class"):
            z.write(p, p.relative_to(tmp_path / "classes").as_posix())
    return jar


def test_real_reader_extracts_invoke_and_field(tmp_path: Path):
    jar = _compile(tmp_path)
    target = tmp_path / "jars"; target.mkdir()
    shutil.copy(jar, target / jar.name)
    idx = BytecodeIndex(tmp_path / "index.db", reader=DisasmClassReader())
    stats = idx.build(target)
    assert stats.classes >= 2
    assert stats.invokes >= 1
    assert stats.field_accesses >= 1
    row = idx._conn.execute(
        "SELECT callee_owner, callee_name FROM invokes WHERE callee_name='hashCode'"
    ).fetchone()
    assert row == ("java/lang/Object", "hashCode")
    idx.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_index_real_reader.py -v`  
Expected: FAIL with `ModuleNotFoundError: No module named 'jgd.index.reader'` (or skip if no `javac`; run in CI image with JDK 17).

- [ ] **Step 3: Implement `DisasmClassReader`**

For each `jar.class_entries()`, read bytes via `SafeJar.read`, construct `bcdisasm.ClassFile(data)`, and map `cf.this`, `cf.super`, `cf.ifcs`, `cf.access`, `cf.major`, `cf.fields`, `cf.methods`. For each method, `instructions = [InstructionMeta(off, name, text, res) for off, name, text, res in cf.disasm(m)]`; `code_size = len(m["code"]["code"]) if m["code"] else 0`. Skip `module-info`/`package-info` in `SafeJar.class_entries()` already. Do not catch `ClassFile` parse errors silently; return a `ClassMeta` failure marker? For now, let parse errors propagate as `IndexError` with jar/entry context; Task 7 adds error ledger.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_index_real_reader.py -v`  
Expected: PASS (1 passed, or 1 skipped without javac)

- [ ] **Step 5: Commit**

```bash
git add jgd/index/reader.py tests/test_index_real_reader.py
git commit -m "feat: add bcdisasm-backed index reader"
```

---

### Task 5: Known-chain and bridge queries over the index

**Files:**
- Create: `jgd/index/queries.py`
- Create: `jgd/engine/__init__.py`
- Create: `jgd/engine/known.py`
- Create: `jgd/engine/bridge.py`
- Test: `tests/test_index_queries.py`

**Interfaces:**
- Produces:
  - `jars_with_class(index: BytecodeIndex, class_name: str) -> list[str]`
  - `classes_present(index: BytecodeIndex, names: list[str]) -> dict[str, list[str]]`
  - `bridge_rows(index: BytecodeIndex, triggers: set[str]) -> list[dict]`
  - `scan_known(index: BytecodeIndex, db_path: Path | None = None) -> list[dict]`
  - `scan_bridges(index: BytecodeIndex, triggers: set[str] | None = None) -> list[dict]`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_index_queries.py
from pathlib import Path
from jgd.index.bytecode import BytecodeIndex
from jgd.index.queries import classes_present, jars_with_class, bridge_rows
from tests.test_bytecode_index import FakeReader, _jar


def _index(tmp_path: Path) -> BytecodeIndex:
    target = tmp_path / "jars"; target.mkdir()
    _jar(target / "a.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    idx.build(target)
    return idx


def test_classes_present_returns_all_jars(tmp_path: Path):
    target = tmp_path / "jars"; target.mkdir()
    _jar(target / "a.jar"); _jar(target / "b.jar")
    idx = BytecodeIndex(tmp_path / "index.db", reader=FakeReader())
    idx.build(target)
    got = classes_present(idx, ["demo/A", "missing/C"])
    assert len(got["demo/A"]) == 2
    assert got["missing/C"] == []
    idx.close()


def test_bridge_rows_find_field_plus_invoke(tmp_path: Path):
    idx = _index(tmp_path)
    rows = bridge_rows(idx, {"hashCode"})
    assert rows and rows[0]["cls"] == "demo/A"
    assert rows[0]["field"] == "f"
    assert rows[0]["target"] == "java/lang/Object.hashCode()I"
    idx.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_index_queries.py -v`  
Expected: FAIL with `ModuleNotFoundError: No module named 'jgd.index.queries'`

- [ ] **Step 3: Implement queries and engine wrappers**

`jars_with_class` runs `SELECT DISTINCT jar_sha256 FROM classes WHERE name=? ORDER BY jar_sha256`. `classes_present` maps each name to `jars_with_class`. `bridge_rows` runs a join on `methods` (trigger names), `classes`, `field_access` (`kind='read'`, `owner=classes.name`), and `invokes` (`caller_method_id=methods.id`), returning `cls`, `jar_sha256`, `trigger`, `field`, `field_desc`, `target` (`owner.name + desc`), and `via="recv"`. `scan_known` loads `KNOWN_CHAINS` from `jgd.verification.known_chains` (or DB via `_load_db_chains`), calls `classes_present` once for all signatures, and applies the existing `version_verdict` logic without reopening JARs. `scan_bridges` calls `bridge_rows` and then runs `bridge_fix.field_bridges` only for candidate classes (resolve JAR path from `jars` table), returning only exact matches.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_index_queries.py -v`  
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add jgd/index/queries.py jgd/engine tests/test_index_queries.py
git commit -m "feat: query known chains and bridges from bytecode index"
```

---

### Task 6: CLI contract, JSON/SARIF, doctor, and DB build

**Files:**
- Modify: `jgd/cli.py` (replace `main` with subcommands; keep `audit_target.py` compatibility)
- Modify: `jgd/__main__.py` (dispatch `audit`/`index`/`db`/`doctor`/`version`)
- Modify: `jgd/verification/build_chain_db.py` (accept `db_path: Path | None = None`; remove hardcoded `/mnt/f/...`)
- Create: `jgd/adapters/__init__.py`
- Create: `jgd/adapters/sarif.py`
- Create: `jgd/doctor.py`
- Test: `tests/test_cli_contract.py`

**Interfaces:**
- Produces:
  - `main(argv: list[str] | None = None) -> int`
  - `to_sarif(findings: list[Finding], tool_version: str) -> dict`
  - `run_doctor(home: Path) -> dict`
  - CLI:
    - `jgd audit --target DIR [--profile known|standard] [--format json,sarif,md] [--out DIR] [--no-poc] [--no-llm]`
    - `jgd index build --target DIR [--db PATH]`
    - `jgd db build [--out PATH]`
    - `jgd doctor`
    - `jgd version`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_contract.py
import json, subprocess, sys
from pathlib import Path
from jgd.adapters.sarif import to_sarif


def test_audit_json_and_exit_code(tmp_path: Path):
    target = tmp_path / "jars"; target.mkdir()
    import zipfile
    with zipfile.ZipFile(target / "empty.jar", "w"):
        pass
    out = tmp_path / "out"
    r = subprocess.run([sys.executable, "-m", "jgd", "audit", "--target", str(target),
                        "--profile", "known", "--format", "json", "--out", str(out)],
                       capture_output=True, text=True)
    assert r.returncode in (0, 10, 20), r.stderr
    data = json.loads((out / "run.json").read_text(encoding="utf-8"))
    assert data["schemaVersion"] == "jgd.run/v1"
    assert isinstance(data["findings"], list)


def test_audit_is_deterministic(tmp_path: Path):
    target = tmp_path / "jars"; target.mkdir()
    import zipfile
    with zipfile.ZipFile(target / "empty.jar", "w"):
        pass
    outs = []
    for name in ("a", "b"):
        out = tmp_path / name
        r = subprocess.run([sys.executable, "-m", "jgd", "audit", "--target", str(target),
                            "--profile", "known", "--format", "json", "--out", str(out)],
                           capture_output=True, text=True)
        assert r.returncode in (0, 10, 20), r.stderr
        data = json.loads((out / "run.json").read_text(encoding="utf-8"))
        outs.append(sorted(json.dumps(f, sort_keys=True) for f in data["findings"]))
    assert outs[0] == outs[1]


def test_bad_target_returns_30(tmp_path: Path):
    r = subprocess.run([sys.executable, "-m", "jgd", "audit", "--target", str(tmp_path / "nope")],
                       capture_output=True, text=True)
    assert r.returncode == 30


def test_doctor_reports_paths(tmp_path: Path):
    r = subprocess.run([sys.executable, "-m", "jgd", "doctor"], capture_output=True, text=True)
    assert r.returncode == 0
    data = json.loads(r.stdout)
    assert "python" in data and "sqlite" in data and "home" in data


def test_sarif_minimum_shape():
    from jgd.contracts.models import Finding
    f = Finding(id="JGD-1", category="java-deserialization", verdict="CHAIN_CONFIRMED",
                severity="high", confidence=0.9, entry={"class": "A"}, bridge={},
                sink={}, evidence=[], remediation={})
    sarif = to_sarif([f], "0.2.0")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["ruleId"] == "jgd/java-deserialization/A"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_contract.py -v`  
Expected: FAIL (argparse rejects `audit`; `jgd.adapters.sarif` missing)

- [ ] **Step 3: Implement CLI, SARIF, doctor, DB path**

`jgd/cli.py` uses `argparse` subparsers; `audit` builds `JgdConfig`, creates `runs/<runId>/`, builds the index, runs `scan_known`/`scan_bridges`, writes `run.json` (`RunResult`), `findings.json`, `report.sarif`, `report.md`, and returns `10` if findings exceed `--fail-on`, else `0`; `30` for invalid target/parse error; `40` for policy denial. `jgd db build` calls `build_chain_db.build(db_path=out)` and prints `db_version`/count; `build_chain_db.build` accepts `db_path` and uses `sqlite3.connect` on it. `run_doctor` returns JSON with Python version, SQLite version, writable home, target existence (only when `--target` given), JDK presence (optional), and DB presence. `to_sarif` maps `ruleId="jgd/<category>/<entry.class>"`, `level` from severity, `message.text=verdict`, and `logicalLocations` with class/method.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli_contract.py -v`  
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add jgd/cli.py jgd/__main__.py jgd/doctor.py jgd/adapters jgd/verification/build_chain_db.py tests/test_cli_contract.py
git commit -m "feat: add JSON/SARIF CLI contract and doctor"
```

---

### Task 7: Benchmark, missing-DB behavior, security tests, docs

**Files:**
- Create: `bench/gen_corpus.py`
- Create: `bench/run_bench.py`
- Create: `tests/test_missing_db.py`
- Create: `tests/test_security_static.py`
- Modify: `README.md`, `SECURITY.md`
- Create: `docs/THREAT-MODEL.md`

**Interfaces:**
- Produces:
  - `bench/run_bench.py --corpus DIR --repeat N --out bench.json`
  - `tests` prove indexed known-chain scan is ≥5× faster on 828 JARs, or record the actual ratio with a clear failure message.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_missing_db.py
from pathlib import Path
from jgd.verification import known_chains


def test_missing_db_is_explicit(tmp_path: Path):
    result = known_chains.audit(tmp_path)
    assert result  # fallback results still exist
    assert known_chains.db_status() in ("missing", "fallback", "loaded")
```

```python
# tests/test_security_static.py
import zipfile
from pathlib import Path
import pytest
from jgd.security.archive import ArchiveError, SafeJar


def test_zip_bomb_rejected_before_parse(tmp_path: Path):
    p = tmp_path / "bomb.jar"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a/B.class", b"\0" * 5_000_000)
    with pytest.raises(ArchiveError):
        with SafeJar(p):
            pass
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_missing_db.py tests/test_security_static.py -v`  
Expected: FAIL (`db_status` missing; benchmark files missing)

- [ ] **Step 3: Implement benchmark and explicit DB status**

`known_chains.db_status()` returns `loaded` if `data/known_chains.db` exists and has chains, `fallback` if using `KNOWN_CHAINS_FALLBACK`, `missing` if neither. `jgd audit` writes `coverage.db_status` and `coverage.db_version`. `bench/gen_corpus.py` copies a small real JAR (or generates empty JARs with duplicate class names) into `--count` files; `bench/run_bench.py` measures (a) old `known_chains.audit` and (b) new `BytecodeIndex` + `scan_known`/`scan_bridges`, writes `{corpus, count, old_s, new_s, speedup, peak_rss}` and fails if `speedup < 5.0` on `count >= 828` unless `--allow-slow` is passed. `README` Quick Start must show `jgd db build`, `jgd audit --format json`, and `jgd doctor`; `SECURITY.md` links `docs/THREAT-MODEL.md`; the threat model lists untrusted JAR, zip bomb, path traversal, duplicate classes, DB fallback, and "Plan 1 does not execute target code".

- [ ] **Step 4: Run tests and benchmark**

Run: `python -m pytest tests/test_missing_db.py tests/test_security_static.py -v`  
Expected: PASS (2 passed)  
Run: `python bench/run_bench.py --corpus <real-828-jar-corpus> --repeat 2 --out bench.json`  
Expected: `speedup >= 5.0`; if not, attach `bench.json` and do not claim the optimization.

- [ ] **Step 5: Commit**

```bash
git add bench tests/test_missing_db.py tests/test_security_static.py README.md SECURITY.md docs/THREAT-MODEL.md
git commit -m "feat: benchmark bytecode index and document static threat model"
```

---

## Self-Review

- **Spec coverage:** Plan 1 covers WP0 packaging/CLI/doctor/DB, WP1 static archive safety/classpath (partial), and WP5 bytecode index/benchmark. Dynamic sandbox, PoC policy, A2A/MCP, agent runtime, and real-world commercial validation are explicitly deferred to Plans 2–5.
- **Placeholder scan:** No placeholders; every task has a concrete test, command, signature, and commit.
- **Type consistency:** `SafeJar`, `ClassMeta`, `BytecodeIndex`, `scan_known`, `scan_bridges`, `to_sarif`, and `RunResult` names are defined once and reused consistently.
- **Review Focus mapping:** duplicate classes → Task 3; multi-release → Task 2; malicious archives → Task 2/7; missing DB → Task 7; machine contract → Task 6.
- **Proportion:** The plan specifies interfaces and tests, not full implementations; algorithm bodies remain for the implementer.

## Execution Handoff

After Plan 1 passes, write and execute Plan 2 (sandbox/dynamic) before any target code execution. Plan 5 is where authorized commercial-product corpora are tested; do not use unlicensed third-party artifacts.
