# JGD Threat Model — Plan 1 (Static Bytecode Index)

**Status:** 2026-10-26. This model covers the Plan 1 static scanner. Dynamic
JVM probes, PoC execution, A2A/MCP, and multi-tenancy are covered by Plans 2–5.

## Scope and trust boundaries

| Component | Trust |
|---|---|
| Host Python process | Trusted code; must not load or execute target classes in Plan 1 |
| Target JAR/ZIP | **Untrusted** bytes and archive metadata |
| `SafeJar` | Boundary validator; rejects unsafe paths/limits before parsing |
| `bcdisasm` | Parser for untrusted bytes; must be bounded and exception-safe |
| SQLite index | Derived cache; rebuildable from target; not a trust anchor |
| Known-chain DB | First-party data; `db_status`/`db_chains` must be explicit |
| LLM provider | Untrusted output; advisory only; no verdict/termination authority |

## Adversaries and failure modes

1. **Malicious JAR with a static initializer or gadget payload.**
   - Plan 1 never calls `Class.forName`, constructors, `readObject`, or a JVM.
   - Test: `tests/test_index_real_reader.py` parses classes only; no target
     execution path exists in the CLI.
2. **Zip bomb / decompression exhaustion.**
   - `SafeJar` limits entries, per-entry bytes, total bytes, compression ratio.
   - Test: `tests/test_safe_jar.py::test_rejects_zip_bomb_ratio`,
     `tests/test_security_static.py::test_zip_bomb_rejected_before_parse`.
3. **Path traversal / absolute paths / symlinks.**
   - `SafeJar` rejects `..`, absolute names, backslashes, NUL, and symlink modes.
   - Test: `tests/test_safe_jar.py` traversal/absolute/symlink cases.
4. **Duplicate class names across JARs.**
   - Index keeps per-JAR rows; no last-writer-wins. `classes_present` returns
     all origins.
   - Test: `tests/test_bytecode_index.py::test_duplicate_class_names_are_preserved`,
     `tests/test_index_queries.py::test_classes_present_returns_all_jars`.
5. **Multi-release JAR confusion.**
   - `META-INF/versions/**` entries are not treated as base classes.
   - Test: `tests/test_safe_jar.py::test_multi_release_entries_are_not_base_classes`.
6. **Missing/stale known-chain DB presented as full coverage.**
   - `db_status` returns `missing`/`loaded`; `jgd audit` builds/uses a DB and
     records `db_status`/`db_chains` in coverage. A fallback is explicit.
   - Test: `tests/test_missing_db.py`.
7. **Parser crash / malformed class.**
   - Parser exceptions fail the run with `E_INDEX` and exit 30; they are not
     silently converted to “absent” findings. (Plan 1 currently fails the run;
     the agent runtime in Plan 3 adds per-class error rows.)
8. **Determinism / audit integrity.**
   - Findings are sorted by stable IDs; same target/profile produces the same
     findings (runId/timestamps excluded).
   - Test: `tests/test_cli_contract.py::test_audit_is_deterministic`.

## Runtime and CI/CD additions (2026-10-28)

- **Dynamic probes** go through `jgd/security/sandbox.py`. `HostSandbox`
  requires `allow_host=True`; tests use it only with the bundled Apache
  Commons fixture. The production boundary is an isolated Linux VM; Docker
  and WSL2 remain optional adapters.
- **MCP** is stdio-only and inherits the local trust boundary; `jgd_audit`
  and `jgd_poc` start JGD tasks, not arbitrary commands. `jgd_poc` rejects
  `allowHost=false`.
- **A2A** exposes a card and JSON-RPC `SendMessage`/`GetTask`/`CancelTask`;
  Bearer auth is enabled when `--token` is set. PoC requests require the same
  explicit host opt-in; push notifications are declared unsupported.
- **PoC**: `jgd poc` is wired to the deterministic `poc_gen` verifier.
  `audit --dynamic --sandbox host --unsafe-host --ecj` can close up to three
  `DESER_OK` candidates; only `fired_at_deser=true` becomes
  `CHAIN_CONFIRMED`. The old LLM acceptance gate is gone.

- **CI/CD gates**: the GitHub Action runs with read-only contents and a
  separate SARIF upload permission; the gate uses stable exit codes and a
  deterministic `gate.json`. Optional `--baseline` turns legacy findings
  into non-blocking context while retaining them in the report.
- **Nexus webhook**: token and/or HMAC authentication is mandatory;
  downloads are restricted to `--nexus-base-url` (scheme/host/path prefix),
  local paths to `--local-root`, and only `.jar` artifacts with a 512 MB
  limit are accepted. The receiver delegates to the normal JGD policy path;
  it never executes an arbitrary command from the event.

## Out of scope for Plan 1–4

- Full commercial-product validation without an authorized corpus.
- Full commercial-product validation without an authorized corpus.
- Multi-tenant A2A authorization beyond the optional shared Bearer token.
- LLM prompt injection hardening beyond the advisory-only boundary.

## Residual risks

- `bcdisasm` is a parser written in Python; malformed class files may still
  trigger unexpected exceptions or high CPU. Plan 2 moves parsing into a
  bounded subprocess/container and adds fuzzing.
- SQLite index files are derived and can be large; Plan 5 adds retention and
  compaction policy.
- The current `known_chains` module still has legacy import-time side effects
  (`scope.DATA`); the agent runtime in Plan 3 removes them.
