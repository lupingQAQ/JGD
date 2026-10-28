# Real-World Open-Source Product Validation — 2026-10-27

This run uses the hardened static scanner on recent, high-star open-source Java
products. Static scans do **not** execute target code. Dynamic probes were later
run inside a dedicated VirtualBox Ubuntu VM (`docs/VM-SANDBOX.md`); no target
code executed on Windows.

## Corpus

| Product | Release | GitHub stars | Last push | JARs | License |
|---|---|---:|---|---:|---|
| Nacos | 3.2.4 | 33,484 | 2026-10-26 | 15 | Apache-2.0 |
| SkyWalking | 11.0.0 | 24,973 | 2026-10-26 | 283 | Apache-2.0 |
| Jenkins | 2.587 | 26,693 | 2026-10-26 | 77 | MIT |
| RocketMQ | 5.5.1 | 22,644 | 2026-10-26 | 160 | Apache-2.0 |
| Hutool | 5.8.48 | 30,235 | 2026-10-21 | 1 | MPL-2.0 |

Sources and checksums are recorded in `bench/results/README.md`.

## Results (static, profile=standard)

| Product | Duration | Classes | Methods | Bridge candidates | Known chains present | Findings |
|---|---:|---:|---:|---:|---:|---:|
| Nacos 3.2.4 | 786s | 78,393 | 991,110 | 15,169 | 55 | 15,224 |
| SkyWalking 11.0.0 | 400s | 65,346 | 747,454 | 16,794 | 38 | 16,832 |
| Jenkins 2.587 | 145s | 29,339 | 221,416 | 4,535 | 47 | 4,582 |
| RocketMQ 5.5.1 | 108s | 31,126 | 312,384 | 3,575 | 43 | 3,618 |
| Hutool 5.8.48 | 7.9s | 1,663 | 16,763 | 172 | 25 | 197 |

All runs completed with **0 errors**. Nacos is slower because its fat JAR
contains nested Spring Boot dependency JARs; nested indexing is now supported.

## Notable observations

- **Nacos**: `AspectJWeaver1-SimpleCache-file`, CommonsCollections 1–7,
  CommonsBeanutils, BAVE/`HashMap` carriers, JDK7u21, URLDNS, JRMP, etc. are
  present in the classpath. This is classpath-level chain presence, not a
  confirmed exploit on a running Nacos.
- **Jenkins**: 47 known-chain signatures present, including
  CommonsBeanutils1/2 and CommonsCollections families; 4,535 bridge candidates.
- **RocketMQ**: 43 known-chain signatures present, including CC/CB families;
  3,575 bridge candidates.
- **SkyWalking**: Jackson `POJONode`/`TemplatesImpl`/`JdbcRowSetImpl`,
  FreeMarker, and 16,794 bridge candidates; Kubernetes/Fabric8 and Kafka
  packages dominate candidates.
- **Hutool**: 128 bridge candidates in `cn/hutool/core`. The most interesting
  static candidate is `cn/hutool/core/bean/DynaBean` with an `Object` field
  `bean` and `toString`/`hashCode`/`equals` forwarding. This is **not** a
  confirmed chain; it needs dynamic/contract verification.

## Dynamic probes inside the Linux VM (2026-10-28)

The dedicated VirtualBox Ubuntu 22.04 VM (`docs/VM-SANDBOX.md`) ran dynamic
probes against three products. No target code executed on Windows.

| Product | Duration | Bridges | Dynamic probes | Verdicts |
|---|---:|---:|---:|---|
| Hutool 5.8.48 | 23.8s | 172 | 10 | 4 `DESER_OK` (incl. `cn/hutool/core/bean/DynaBean`), 3 `NOT_SERIALIZABLE`, 3 instantiation errors |
| RocketMQ 5.5.1 | 166.6s | 3,575 | 10 | 8 `NOT_SERIALIZABLE`, 2 `NoClassDefFoundError` |
| Jenkins 2.587 | 166.7s | 4,535 | 10 | 6 `NOT_SERIALIZABLE`, 4 `NullPointerException` |
| Nacos 3.2.4 | 835.9s | 15,169 | 10 | 10 `NOT_SERIALIZABLE` (shaded ASM `ConstantDynamic`), 0 dynamic errors |
| SkyWalking 11.0.0 | 549.3s cold / 217.6s warm | 16,794 | 10 | 10 `DESER_OK` (bundled Nacos API classes); auto-PoC with the Jackson tail did not close |

`DESER_OK` is a carrier round-trip, not chain closure or RCE. The strongest
follow-up candidate was Hutool `DynaBean` (`Object bean` field with
toString/hashCode/equals forwarding).

### PoC closure (Hutool DynaBean + CC3)

A deterministic PoC is now verified inside the VM:

- `hmz:` HashMap carrier inserts a `HashMap$Node` reflectively, so the bridge
  is not triggered during build or `ObjectOutputStream.writeObject`;
- `HashMap.readObject()` rehashes the key, invokes `DynaBean.hashCode()`,
  forwards to `bean.hashCode()`, and reaches the CC3
  `TiedMapEntry`/`LazyMap`/`TemplatesImpl` tail;
- result: `RCE_DEMO_FIRED`, `fired_at_build=false`, `fired_at_deser=true` on
  JDK 17;
- classpath: `hutool-all-5.8.48.jar` + `commons-collections-3.2.1.jar`;
- effect: marker file only; payload 1,271 bytes;
- automatic audit path: 43.1s end-to-end, `coverage.poc=2`, two
  `CHAIN_CONFIRMED` findings (`bench/results/2026-10-28-hutool-auto-poc.json`).

This is a Hutool bridge plus a common tail library, not a single-JAR Hutool
zero-day. Jenkins 2.587 bundles CC 3.2.2, whose serialization guard blocks
`InvokerTransformer` by default, so the same construction is correctly not
claimed on Jenkins. Details: `docs/POC.md`.

## What this does and does not prove

**Proves**

- The index scales to 283-JAR / 65k-class / 747k-method products.
- Nested Spring Boot JARs are indexed, not silently skipped.
- Known-chain signature presence and bridge recall work on recent real code.
- Static scans complete without target execution or host contamination.

**Does not prove**

- That any listed chain is reachable in the product's runtime configuration.
- That a bridge candidate is serializable, triggerable, or RCE-capable.
- That a product is vulnerable; JEP-290 filters, classloader isolation,
  runtime JDK, and business entry points are not modeled here.
- Any commercial-product claim. Commercial validation requires an authorized
  corpus and the sandbox after reboot.

## Reproduction

```bash
python bench/realworld.py --corpus /path/to/nacos \
  --profile standard --out bench/results/2026-10-27-nacos-3.2.4.json

# dynamic/PoC: run inside the Linux VM (host sandbox = VM boundary)
python bench/realworld.py --corpus <authorized-corpus> \
  --profile standard --dynamic --sandbox host \
  --out bench/results/<product>.json
```

The raw result JSON files contain coverage, known-chain names, bridge counts,
errors, and report paths. Reports are SARIF/Markdown under each run directory.
