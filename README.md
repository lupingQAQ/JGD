# ⚡ JGD

### JavaGadgetDigger — Solving the Last Mile of Deserialization Vulnerability Discovery

[![Version](https://img.shields.io/badge/version-0.3.0-blue)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-11%20%7C%2017-orange?logo=java&logoColor=white)](https://openjdk.org)

🌐 **[中文版](README.zh-CN.md)**

---

## What is JGD?

An **autonomous agent** that takes any JAR directory and produces:
1. **Known public chains** — four-state determination (PRESENT / VERSION / ASSEMBLE / FIRE)
2. **Novel unpublished chains** — discovered via static + dynamic analysis with adversarial LLM auditing
3. **Weaponized PoCs** — serialized payloads with RCE closure demo (benign marker file)

All decisions are internalized: `JARs in → chains out`, zero intermediate user input.

```
┌─────────────────────────────────────────────────────────────────┐
│  Input: any JAR directory          Output: chains + PoCs        │
│                                                                 │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   │
│  │  Known   │──▶│  Bridge  │──▶│  Chain   │──▶│   PoC    │   │
│  │  Chains  │   │  Discovery│  │  Pairing │   │  Weapon  │   │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘   │
│       │               │               │               │          │
│   signature       bytecode         dynamic         benign      │
│   + version       + CHA graph      + contract      payload     │
│   gates           + dispatch       synthesis       + fire      │
│                   edges            + 5 carriers    test       │
└─────────────────────────────────────────────────────────────────┘
```

## 🆕 Discovered Novel Chains (20 total, all PoC FIRED)

### T1 — Novel Entry (ds confirmed: absent from all public corpora)

| Chain | Bridge Class | Carrier | JDK | Status |
|-------|-------------|---------|-----|--------|
| **objlongpair-hashmap** | `org.apache.activemq.artemis.api.core.ObjLongPair` | HashMap rehash | 17+ | ✅ RCE_CLOSED |

```
HashMap.readObject() → rehash → hash(key)
  → ObjLongPair.hashCode() → Objects.hash(first, second)
    → Arrays.hashCode() → first.hashCode()     [Object field — isInstance always true]
      → EqualsBean.hashCode() → beanHashCode()
        → ObjectBean.toString() → ToStringBean.toString()
          → Templates.getOutputProperties() → TemplatesImpl.newTransformer()
            → TemplatesImpl.defineClass() → payload static block → RCE
```

> **Novelty**: Entry-side confirmed T1 by adversarial audit — absent from ysoserial,
> GadgetInspector, and all public CVE writeups. Orthogonal to all known ROME entry
> paradigms (direct ROME key / BAVE / HotSwappableTargetSource / XString).

### T2 — New Bridge Classes (ds confirmed CONFIRM, novel=True)

#### Vavr family (7 chains, ds T2 novel=True)

| Chain | Bridge Class | Carrier | JDK |
|-------|-------------|---------|-----|
| **tuple1-8-hashmap** | `io.vavr.Tuple1`…`Tuple8` | HashMap rehash | 11 |
| **either$left-hashmap** | `io.vavr.control.Either$Left` | HashMap rehash | 11 |
| **either$right-hashmap** | `io.vavr.control.Either$Right` | HashMap rehash | 11 |
| **option$some-hashmap** | `io.vavr.control.Option$Some` | HashMap rehash | 11 |
| **validation$valid-hashmap** | `io.vavr.control.Validation$Valid` | HashMap rehash | 11 |
| **validation$invalid-hashmap** | `io.vavr.control.Validation$Invalid` | HashMap rehash | 11 |
| **hasharraymappedtrie$leafsingleton** | `io.vavr.HashArrayMappedTrie$LeafSingleton` | HashMap rehash | 11 |

```
HashMap.readObject → HashMap.hash → Tuple3.hashCode
  → Tuple.hash → Objects.hashCode → _1.hashCode()       [Object field, attacker-controlled]
    → EqualsBean.hashCode → beanHashCode → ObjectBean.toString
      → ToStringBean.toString → Templates.getOutputProperties
        → TemplatesImpl.newTransformer → defineClass → RCE
```

#### Spring AOP family (6 chains, ds T2/T3 novel=True)

| Chain | Bridge Class | Carrier | JDK |
|-------|-------------|---------|-----|
| **composablepointcut-hashmap** | `ComposablePointcut` | HashMap rehash | 11 |
| **methodmatchers$unionmethodmatcher** | `MethodMatchers$UnionMethodMatcher` | HashMap rehash | 11 |
| **methodmatchers$intersectionmethodmatcher** | `MethodMatchers$IntersectionMethodMatcher` | HashMap rehash | 11 |
| **singletontargetsource-bave** | `SingletonTargetSource` | BAVE toString | 11 |
| **hotswappabletargetsource-bave** | `HotSwappableTargetSource` | BAVE toString | 11 |
| **defaultintroductionadvisor-bave** | `DefaultIntroductionAdvisor` | BAVE toString | 11 |

#### Guava family (3 chains, ds T2 novel=True)

| Chain | Bridge Class | Carrier | JDK |
|-------|-------------|---------|-----|
| **functions$formapwithdefault** | `com.google.common.base.Functions$ForMapWithDefault` | HashMap rehash | 11 |
| **predicates$isequaltopredicate** | `com.google.common.base.Predicates$IsEqualToPredicate` | HashMap rehash | 11 |
| **present** | `com.google.common.base.Present` | HashMap rehash | 11 |

#### Other libraries

| Chain | Bridge Class | Library | Carrier | JDK |
|-------|-------------|---------|---------|-----|
| **mutableobj-bave** | `cn.hutool.core.lang.mutable.MutableObj` | hutool-core | BAVE | ≤11 |
| **antlr4-pair-bave** | `org.antlr.v4.runtime.misc.Pair` | antlr4-runtime | BAVE | ≤11 |
| **clojure-proxy-hashmap** | `clojure.inspector.proxy$…AbstractTableModel$ff19274a` | clojure | HashMap | 11 |
| **jacksoninject$value-bave** | `JacksonInject$Value` | jackson-annotations | BAVE | 11 |
| **objectidgenerator$idkey-bave** | `ObjectIdGenerator$IdKey` | jackson-databind | BAVE | 11 |
| **tolerantmap-hashmap** | `org.snakeyaml.engine.v2.common.TolerantMap` | snakeyaml | HashMap | 11 |
| **scala-objectref-bave** | `scala.runtime.ObjectRef` | scala-library | BAVE | 11 |

### T3 — Variants

| Chain | Bridge Class | Library | Notes |
|-------|-------------|---------|-------|
| **ewah-hashmap** | `EWAHCompressedBitmap` | JavaEWAH (Lucene/ES) | Shallow dispatch |
| **federation*-hashmap** | `FederationConfiguration` etc. (4) | Artemis | Config class family |

<details>
<summary>📊 Full dispatch stacks (click to expand)</summary>

**ObjLongPair (T1, JDK 17):**
```
HashMap.put → HashMap.hash
  → ObjLongPair.hashCode(ObjLongPair.java:55)
    → Objects.hash → Arrays.hashCode
      → EqualsBean.hashCode → EqualsBean.beanHashCode
        → ObjectBean.toString → ToStringBean.toString → Method.invoke
          → TemplatesImpl.defineClass → payload static block
```

**MutableObj (T2, JDK 11):**
```
BAVE.readObject → val.toString()
  → MutableObj.toString → value.toString()
    → ObjectBean.toString → ToStringBean.toString
      → Templates.getOutputProperties → newTransformer → defineClass → RCE
```
</details>

## 🚀 Quick Start

### Hardened static scanner (bytecode index, Plan 1)

```bash
# 1) Build the known-chain DB (current builder: 115 chains / 168 version gates)
python -m jgd db build

# 2) Static audit: one-pass bytecode index + JSON/SARIF report
python -m jgd audit --target /path/to/jars --profile standard \
  --format json,sarif,md --out runs/demo

# 3) Environment preflight
python -m jgd doctor
```

The scanner does **not execute target code**. Dynamic probes and PoC closure
run only through an explicit sandbox boundary; the current preferred boundary
is the dedicated Linux VM (`docs/VM-SANDBOX.md`). PoC and LLM advisory default
on in policy; LLM output is advisory and cannot own a terminal verdict.

### Sandboxed dynamic probes

```bash
# Inside the isolated Linux VM (host sandbox = the VM, not Windows)
python -m jgd audit --target /opt/app/lib --profile standard \
  --dynamic --sandbox host --unsafe-host --format json,sarif,md --out runs/app

# Optional container/WSL2 routes (requires Docker or a rebooted WSL2)
python -m jgd audit --target tests/fixtures --profile standard \
  --dynamic --sandbox docker --format json --out runs/lab
```

Dynamic probes batch classes that share a target classpath into one JVM, so
the per-bridge JVM startup cost is paid once per classpath batch. Spring Boot
`BOOT-INF/lib` JARs and `BOOT-INF/classes` are extracted under the run for
dynamic loading; the probe classpath is the whole target, not only the bridge
JAR.

### Deterministic PoC

```bash
# Must run inside the isolated VM; --unsafe-host is mandatory
python -m jgd poc --target /opt/app/lib \
  --bridge cn.hutool.core.bean.DynaBean \
  --trigger hash --ecj /path/to/ecj.jar \
  --out runs/poc --unsafe-host
```

See [`docs/POC.md`](docs/POC.md) for the verified Hutool DynaBean + CC3
deserialization closure and the Honest scope caveat.

### MCP and A2A

```bash
# MCP stdio (tools: jgd_audit, jgd_poc, jgd_get_run, jgd_list_findings, jgd_cancel)
python -m jgd serve mcp

# A2A v1.0-style JSON-RPC + SSE + agent card
python -m jgd serve a2a --host 127.0.0.1 --port 8080
# card: http://127.0.0.1:8080/.well-known/agent-card.json
```

A2A sets Bearer auth when `--token` is provided. The full JGD mining loop
remains inside JGD; the adapters only start/inspect tasks.

### Legacy research CLI (still available)

```bash
# Install optional RAG dependency (Python 3.10+, JDK 11 & 17 for dynamic stages)
pip install chromadb  # optional, for RAG persistence

# Point at any JAR directory
python3 audit_target.py --target /path/to/jars --name "your-product"
```

### TUI Mode (interactive visualization)

```bash
python3 tui.py                    # English
python3 tui.py --lang zh          # 中文
```

### Key Bindings (TUI)

| Key | Action |
|-----|--------|
| `↑` `↓` / `j` `k` | Navigate chains |
| `Enter` | Toggle detail view |
| `t` | Switch language (EN/CN) |
| `q` | Quit |

## 📁 Project Structure

```
jgd/
├── audit_target.py          # Product CLI entry point
├── tui.py                   # Interactive TUI
├── jgd/            # Core agent modules (25)
│   ├── verify_agent.py      # Bridge discovery + ds adversarial audit (incremental checkpoint)
│   ├── chain_complete.py    # Chain pairing + exhaustion proof (per-item evidence save)
│   ├── poc_gen.py           # Weaponized PoC generation (heq/jackson/map-dispatch tails)
│   ├── known_chains.py      # Public chain determination (SQLite-backed)
│   ├── build_chain_db.py    # Chain DB builder (current: 115 chains / 168 gates)
│   ├── novel_chains.py      # Novel chain auto-tiering (GLM propose + DS verify)
│   ├── matrix_agent.py      # Multi-JDK probe orchestration
│   ├── bcdisasm.py          # Pure-Python bytecode disassembler
│   ├── bridge_fix.py        # Operand-stack symbolic execution
│   ├── chroma_store.py      # RAG with corpus-scoped collections
│   ├── llm.py               # Dual-model (GLM × DeepSeek)
│   ├── scope.py             # Corpus fingerprint isolation
│   ├── profiler.py          # Node-level performance profiling
│   ├── conductor.py         # Acceptance-gated terminal verdict
│   └── ...
├── examples/
│   ├── chains.json          # All discovered chains (machine-readable)
│   └── chains.md            # Human-readable chain catalog
├── tests/
│   └── test_smoke.py        # Third-party reproducible test suite
├── ARCHITECTURE.md          # 25-module graph + design decisions
├── CHANGELOG.md             # Design decision history (R6-R52)
├── SECURITY.md              # Authorized-use policy + disclosure
├── CONTRIBUTING.md          # Five development principles
└── LICENSE                  # MIT
```

## 🔬 How It Works

### 1. Public Chain Determination (guaranteed)
- **SQLite database** with per-chain: family, source, CVE, trigger method, sink type, JDK range, conditions, jar version gates. The current builder emits **115 chains / 168 gates**; `jgd db build` writes it and `jgd audit` reports `db_status`/`db_chains` explicitly.
- Class signature matching (jar-scoped) + JDK internal class detection
- Version gates with per-jar multi-version verdicts (APPLICABLE / BLOCKED / UNVERIFIED per jar)
- Dynamic assembly + fire verification using target's own JARs

### 2. Novel Chain Discovery (domain-exhaustive)
- **Static**: Operand-stack symbolic execution detects receiver-bridges + argument-bridges + Map-dispatch bridges (`via=mapget`)
- **Graph**: Real-time corpus-fingerprinted call graph + CHA dispatch edges + JDK builtin sink seeds
- **Dynamic**: Batch-parallel JVM probes (5 carriers × field-contract synthesis × multi-JDK)
- **Observability**: Marker reachability + exception stack frames + marker caller-stack + MAPDISPATCH signals
- **Incremental checkpoint**: verify/chain/poc all support resume-on-same-fingerprint
- **Adaptive scaling**: dynamic probes and ds audits scale with INTERESTING candidate count

### 3. Adversarial Auditing
- **Finder ≠ Verifier**: GLM selects candidates, DeepSeek audits independently
- **Deterministic verifier/terminator**: terminal verdicts are owned by evidence, coverage, budget, and policy; LLM output is advisory only. The old LLM acceptance gate is removed.
- **"Claims ≠ Evidence" standard**: Every fix requires measurement evidence

### 4. Weaponized PoC Generation
- Chains auto-derived from mining artifacts (`derive_chains`)
- Field-type-aware bridge assembly (`make_bridge` with Object/interface-Proxy/Map-injection)
- Tail candidates: ROME (toString/hashCode), Jackson (POJONode), CC3, heq (equals carrier)
- Complete loop until RCE closure or candidate exhaustion
- Benign payload: writes `/tmp` marker file only

### 5. Novel Chain Auto-Tiering (default pipeline stage 5)
- RCE_DEMO_FIRED chains with non-known-family bridges are automatically tiered
- GLM proposes tier (T1/T2/T3) + novelty rationale → DeepSeek cross-verifies (can reject/downgrade)
- Anti-forgery guard: tier results only trusted when the stage ran successfully in current run

## 🧪 Real-world validation

`bench/realworld.py` runs the hardened CLI against an authorized corpus and
records coverage, known-chain hits, dynamic probes, and artifacts.

Lab corpus (Tomcat/Commons deps, 30 JARs, 2026-10-26):

| Mode | Duration | Classes | Bridges | Known chains | Dynamic probes |
|---|---|---|---|---|---|
| static standard | 11.9s | 3389 | 492 | 25 | 0 |
| + dynamic host (trusted lab) | 18.2s | 3389 | 492 | 25 | 10 (6 DESER_OK, 4 NOT_SERIALIZABLE) |

Commercial-product testing requires an authorized corpus; do not point this at
third-party products without permission. Dynamic probes confirm class
load/serialization round-trip, not a full gadget chain; full chain pairing is
the next hardening step.

Recent high-star open-source products (static only, 2026-10-27; no target code
executed):

| Product | JARs | Classes | Bridges | Known chains | Time |
|---|---:|---:|---:|---:|---:|
| Nacos 3.2.4 | 15 | 78,393 | 15,169 | 55 | 786s |
| SkyWalking 11.0.0 | 283 | 65,346 | 16,794 | 38 | 400s |
| Jenkins 2.587 | 77 | 29,339 | 4,535 | 47 | 145s |
| RocketMQ 5.5.1 | 160 | 31,126 | 3,575 | 43 | 108s |
| Hutool 5.8.48 | 1 | 1,663 | 172 | 25 | 7.9s |

Details, sources, and caveats: [`docs/REAL-WORLD-VALIDATION.md`](docs/REAL-WORLD-VALIDATION.md)
and [`bench/results/`](bench/results/). Known-chain presence is not
exploitability; bridge candidates need dynamic/contract verification.

Dynamic probes inside the Linux VM (2026-10-28):

| Product | Time | Probes | Result |
|---|---:|---:|---|
| Hutool 5.8.48 | 23.8s | 10 | 4 `DESER_OK`, incl. `cn/hutool/core/bean/DynaBean` |
| RocketMQ 5.5.1 | 166.6s | 10 | 8 `NOT_SERIALIZABLE`, 2 dependency errors |
| Jenkins 2.587 | 166.7s | 10 | 6 `NOT_SERIALIZABLE`, 4 NPE |
| Nacos 3.2.4 | 835.9s | 10 | 10 `NOT_SERIALIZABLE` (shaded ASM) |
| SkyWalking 11.0.0 | 549.3s cold / 217.6s warm | 10 | 10 `DESER_OK` (bundled Nacos API classes), no PoC closure |

`DESER_OK` is a carrier round-trip, not chain closure. VM setup: [`docs/VM-SANDBOX.md`](docs/VM-SANDBOX.md). Auto-PoC on the Hutool + CC3 lab classpath closed in 43.1s with `coverage.poc=2`; see [`docs/POC.md`](docs/POC.md).

## ⚡ Performance

| Metric | Value |
|--------|-------|
| Static index warm query (828 synthetic JARs) | **0.04s vs 2.29s old = 57×** (this host, 2026-10-26) |
| Static index cold build (828 synthetic JARs) | 17.98s one-time (5-class fixture; real corpora will differ) |
| Full pipeline (31 jars) | ~90s end-to-end (research baseline, not the hardened scanner) |
| Pair throughput | 1500+ pairs / 9 min (batch + 4 workers, research baseline) |
| PoC generation (3 chains) | 20.3s (2.7× speedup with parallel, research baseline) |
| Memory per JVM | ≤ 256 MB (-Xmx256m, 28% headroom, research baseline) |
| OOM count across full corpus | 0 (research baseline) |

The 828-JAR number is a **warm-query** measurement on a synthetic corpus of
five-class JARs; it proves the archive-I/O/query path, not end-to-end chain
mining. Cold build is reported separately and must be measured on the real
commercial corpus in Plan 5.


## 🛡️ Honest Capability Boundaries

| Claim | Status |
|-------|--------|
| Public chains: guaranteed detection | Yes — mechanical (finite signature set) |
| Novel chains: domain-exhaustive | Yes — within declared scope (ledger-verifiable) |
| Novel chains: universally exhaustive | No — undecidable (Rice's theorem) |
| PoC: always complete output | Yes — tail candidate loop until RCE closure |
| Carrier families: all classic triggers | Yes — toString/hashCode/equals/compare/compareTo |

## 📖 Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — 25-module graph, design decisions
- [CHANGELOG.md](CHANGELOG.md) — 47-round evolution history (R6-R52)
- [examples/chains.md](examples/chains.md) — Human-readable chain catalog
- [SECURITY.md](SECURITY.md) — Authorized-use policy, responsible disclosure
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — Plan 1 static threat model
- [docs/superpowers/specs/2026-10-26-jgd-autonomous-agent-hardening-design.md](docs/superpowers/specs/2026-10-26-jgd-autonomous-agent-hardening-design.md) — hardening spec
- [docs/superpowers/plans/2026-10-26-jgd-static-bytecode-index.md](docs/superpowers/plans/2026-10-26-jgd-static-bytecode-index.md) — Plan 1

## ⚠️ Disclaimer

For **lawful security research, education, and authorized penetration testing only**.
All PoC payloads write a benign marker file (`/tmp/jgd_poc_fired`) — no destructive action.

## 📄 License

[MIT](LICENSE) — Copyright (c) 2026 JGD Contributors
