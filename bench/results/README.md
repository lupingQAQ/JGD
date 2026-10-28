# Real-World Scan Results — 2026-10-27 / 2026-10-28

The `2026-10-27-*` files are **static** scans. No target class was loaded or
executed. Results are JSON summaries produced by `bench/realworld.py`; raw
SARIF/Markdown reports live in the temporary run directories named inside each
JSON file.

The `2026-10-28-*-dynamic.json` files were produced inside the VirtualBox
Ubuntu 22.04 VM (`../../docs/VM-SANDBOX.md`) with JDK 17. The
`2026-10-28-hutool-dynabean-poc.json` file records the deterministic
deserialization closure for the Hutool DynaBean + Commons Collections 3.2.1
lab classpath; see `../../docs/POC.md`.

## Sources

| File | Product | Release URL | License |
|---|---|---|---|
| `2026-10-27-nacos-3.2.4.json` | Nacos 3.2.4 | https://github.com/alibaba/nacos/releases/tag/3.2.4 | Apache-2.0 |
| `2026-10-27-skywalking-11.0.0.json` | Apache SkyWalking 11.0.0 | https://dlcdn.apache.org/skywalking/11.0.0/apache-skywalking-apm-11.0.0-bin.tar.gz | Apache-2.0 |
| `2026-10-27-jenkins-2.587.json` | Jenkins 2.587 | https://github.com/jenkinsci/jenkins/releases/tag/jenkins-2.587 | MIT |
| `2026-10-27-rocketmq-5.5.1.json` | Apache RocketMQ 5.5.1 | https://dlcdn.apache.org/rocketmq/5.5.1/rocketmq-all-5.5.1-bin-release.zip | Apache-2.0 |
| `2026-10-27-hutool-5.8.48.json` | Hutool 5.8.48 | https://repo1.maven.org/maven2/cn/hutool/hutool-all/5.8.48/hutool-all-5.8.48.jar | MPL-2.0 |
| `2026-10-28-hutool-dynabean-poc.json` | Hutool DynaBean + CC 3.2.1 lab classpath | local fixture | Apache-2.0 / MPL-2.0 |
| `2026-10-28-hutool-auto-poc.json` | Hutool + CC3 audit→dynamic→PoC | local fixture | Apache-2.0 / MPL-2.0 |
| `2026-10-28-hutool-5.8.48-dynamic.json` | Hutool 5.8.48 dynamic | same artifact | MPL-2.0 |
| `2026-10-28-jenkins-dynamic.json` | Jenkins 2.587 dynamic | same artifact | MIT |
| `2026-10-28-rocketmq-dynamic.json` | RocketMQ 5.5.1 dynamic | same artifact | Apache-2.0 |
| `2026-10-28-nacos-3.2.4-dynamic.json` | Nacos 3.2.4 dynamic | same artifact | Apache-2.0 |
| `2026-10-28-skywalking-11.0.0-dynamic.json` | SkyWalking 11.0.0 dynamic (cold + warm) | same artifact | Apache-2.0 |

GitHub stars and last-push timestamps were read on 2026-10-27:
Nacos 33,484 / SkyWalking 24,973 / Jenkins 26,693 / RocketMQ 22,644 /
Hutool 30,235.

## Method

1. Download the official distribution or Maven artifact.
2. Extract JARs into an isolated corpus directory:
   - Nacos: server fat JAR + plugins;
   - SkyWalking: `oap-libs/*.jar`;
   - Jenkins: `WEB-INF/lib/*.jar`;
   - RocketMQ: `lib/*.jar`;
   - Hutool: the single `hutool-all` JAR.
3. Run `bench/realworld.py --profile standard` (static SafeJar + SQLite index +
   known-chain/bridge queries). No `--dynamic`, no target execution.
4. Store the summary JSON here; keep downloaded artifacts outside git.

## Caveats

- Known-chain **presence** is not exploitability.
- Bridge candidates are static recall only; they need dynamic/contract
  verification.
- Runtime JDK, JEP-290 filters, classloader isolation, and the product's
  deserialization entry points are not modeled by this static pass.
- Nested Spring Boot JARs are indexed recursively (depth 2); this is why Nacos
  class counts are high.
