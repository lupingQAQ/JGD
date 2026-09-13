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
│                   edges            + 3 carriers    test       │
└─────────────────────────────────────────────────────────────────┘
```

## 🆕 Discovered Novel Chains

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

### T2 — New Carriers (ds confirmed CONFIRM)

| Chain | Bridge Class | Library | Carrier | JDK | Status |
|-------|-------------|---------|---------|-----|--------|
| **mutableobj-bave** | `cn.hutool.core.lang.mutable.MutableObj` | hutool-core | BAVE toString | ≤11 | ✅ RCE_CLOSED |
| **antlr4-pair-bave** | `org.antlr.v4.runtime.misc.Pair` | antlr4-runtime | BAVE toString | ≤11 | ✅ RCE_CLOSED |
| **federationconfiguration-hashmap** | `FederationConfiguration` | Artemis | HashMap rehash | 17+ | ✅ RCE_CLOSED |
| **federationaddresspolicy** | `FederationAddressPolicyConfiguration` | Artemis | HashMap rehash | 17+ | ✅ RCE_CLOSED |
| **federationqueuepolicy** | `FederationQueuePolicyConfiguration` | Artemis | HashMap rehash | 17+ | ✅ RCE_CLOSED |
| **broadcastgroupconfiguration** | `BroadcastGroupConfiguration` | Artemis | HashMap rehash | 17+ | ✅ RCE_CLOSED |

### T3 — Variants

| Chain | Bridge Class | Library | Notes |
|-------|-------------|---------|-------|
| **ewah-hashmap** | `EWAHCompressedBitmap` | JavaEWAH (Lucene/ES) | Shallow dispatch, limited value |

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
│   ├── verify_agent.py      # Bridge discovery + ds adversarial audit
│   ├── chain_complete.py    # Chain pairing + exhaustion proof
│   ├── poc_gen.py           # Weaponized PoC generation
│   ├── known_chains.py      # Public chain four-state determination
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
- Class signature matching against curated corpus
- Version gates (e.g., CC 3.2.2 blocks functors, CC4 4.6 NotSerializable, BAVE JDK17 narrows val to String)
- Dynamic assembly + fire verification using target's own JARs

### 2. Novel Chain Discovery (domain-exhaustive)
- **Static**: Operand-stack symbolic execution detects receiver-bridges + argument-bridges
- **Graph**: Real-time corpus-fingerprinted call graph + CHA dispatch edges
- **Dynamic**: Batch-parallel JVM probes (3 carriers × field-contract synthesis × multi-JDK)
- **Observability**: Marker reachability + exception stack frames + marker caller-stack capture

### 3. Adversarial Auditing
- **Finder ≠ Verifier**: GLM selects candidates, DeepSeek audits independently
- **DSH acceptance gate**: Terminal verdicts rejected until DS acceptance passes
- **"Claims ≠ Evidence" standard**: Every fix requires measurement evidence

### 4. Weaponized PoC Generation
- Chains auto-derived from mining artifacts (`derive_chains`)
- Field-type-aware bridge assembly (`make_bridge` with Object/interface-Proxy)
- Tail candidate loop until RCE closure (`R42 completeness cycle`)
- Benign payload: writes `/tmp` marker file only

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
| Public chains: guaranteed detection | ✅ Mechanical (finite signature set) |
| Novel chains: domain-exhaustive | ✅ Within declared scope (ledger-verifiable) |
| Novel chains: universally exhaustive | ❌ Undecidable (Rice's theorem) |
| PoC: always complete output | ✅ Tail candidate loop until RCE closure |

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
