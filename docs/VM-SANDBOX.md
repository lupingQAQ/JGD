# Linux VM Sandbox (2026-10-28)

Use an isolated Linux VM for dynamic probes and PoC reproduction. The VM is the
security boundary: `--sandbox host` means the guest, never the Windows host.

Recommended baseline:

- Ubuntu 22.04 or newer, 4 vCPU, 4 GB RAM, 20 GB disk
- OpenJDK 17 (`javac` included), Python 3.10+
- NAT networking only; no bridged adapter and no host shared folders
- Copy sources/corpora over SSH or a read-only transfer channel
- Take a VM snapshot before running an untrusted corpus; revert afterward

## Reproduce

```bash
# Inside the guest
sudo apt-get update
sudo apt-get install -y openjdk-17-jdk-headless python3 python3-venv git unzip

# Copy the project/corpus, then:
python3 -m jgd audit --target /path/to/jars --profile standard \
  --dynamic --sandbox host --unsafe-host --format json --out /path/to/run
```

For PoC generation, pass a compiler jar explicitly:

```bash
python3 -m jgd poc --target /path/to/jars \
  --bridge cn.hutool.core.bean.DynaBean \
  --trigger hash --ecj /path/to/ecj.jar \
  --out /path/to/poc-run --unsafe-host
```

## Dynamic results

The 2026-10-28 validation ran inside a dedicated Ubuntu 22.04 VM with JDK 17:

| Product | Duration | Bridges | Dynamic probes | Verdicts |
|---|---:|---:|---:|---|
| Hutool 5.8.48 | 23.8s | 172 | 10 | 4 `DESER_OK` (incl. `cn/hutool/core/bean/DynaBean`), 3 `NOT_SERIALIZABLE`, 3 instantiation errors |
| RocketMQ 5.5.1 | 166.6s | 3,575 | 10 | 8 `NOT_SERIALIZABLE`, 2 `NoClassDefFoundError` |
| Jenkins 2.587 | 166.7s | 4,535 | 10 | 6 `NOT_SERIALIZABLE`, 4 `NullPointerException` |
| Nacos 3.2.4 | 835.9s | 15,169 | 10 | 10 `NOT_SERIALIZABLE` (shaded ASM) |
| SkyWalking 11.0.0 | 549.3s cold / 217.6s warm | 16,794 | 10 | 10 `DESER_OK` (bundled Nacos API), no PoC closure |

`DESER_OK` means the class/object survived the HashMap carrier round-trip; it
is **not** a gadget chain or RCE proof. `DynaBean` is the most interesting
static/dynamic candidate.

## JVM batch pool

Dynamic probes that share a target classpath compile `DynProbeBatch` once and
exercise the classes in one JVM (`DynamicProbe.probe_many`). Finding IDs and
per-class verdicts are unchanged; individual probes remain the fallback if a
batch fails to compile or run.

The probe classpath is the **whole target**, not just the bridge JAR. For
Spring Boot fat JARs, `BOOT-INF/lib/*.jar` and `BOOT-INF/classes` are safely
extracted under the run directory so `Class.forName` can resolve the bridge and
its dependencies; top-level JARs are still included.

## PoC closure

The Hutool DynaBean chain was closed with the deferred `hmz:` HashMap carrier.
Result: `RCE_DEMO_FIRED`, `fired_at_build=false`, `fired_at_deser=true` on
JDK 17. The automatic `audit --dynamic --ecj ...` path also closed in 43.1s
with `coverage.poc=2`. Details and scope caveats: `docs/POC.md`.

## Security notes

- NAT only; no bridged network.
- No host folder sharing; copy corpora over SSH.
- Snapshot before untrusted corpora and revert afterward.
- Do not use `--sandbox host` on the workstation for third-party JARs.
