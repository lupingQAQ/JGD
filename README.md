# ⚡ JGD

### JavaGadgetDigger — Solving the Last Mile of Deserialization Vulnerability Discovery

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

### CLI Mode (batch audit)

```bash
# Install dependencies (Python 3.10+, JDK 11 & 17, ECJ compiler)
pip install chromadb  # optional, for RAG persistence

# Point at any JAR directory and get chains + PoCs
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
│   ├── known_chains.py      # Public chain four-state determination (155-chain SQLite)
│   ├── build_chain_db.py    # Chain database builder (155 chains, 168 version gates)
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
- **155-chain SQLite database** with per-chain: family, source, CVE, trigger method, sink type, JDK range, conditions, jar version gates
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
- **DSH acceptance gate**: Terminal verdicts rejected until DS acceptance passes
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

## ⚡ Performance

| Metric | Value |
|--------|-------|
| Full pipeline (31 jars) | ~90s end-to-end |
| Pair throughput | 1500+ pairs / 9 min (batch + 4 workers) |
| PoC generation (3 chains) | 20.3s (2.7× speedup with parallel) |
| Memory per JVM | ≤ 256 MB (-Xmx256m, 28% headroom) |
| OOM count across full corpus | 0 |

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

## ⚠️ Disclaimer

For **lawful security research, education, and authorized penetration testing only**.
All PoC payloads write a benign marker file (`/tmp/jgd_poc_fired`) — no destructive action.

## 📄 License

[MIT](LICENSE) — Copyright (c) 2026 JGD Contributors
