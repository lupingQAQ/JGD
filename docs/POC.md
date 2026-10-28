# Deterministic PoC and chain closure (2026-10-28)

JGD now has a first-class, deterministic PoC entry point:

```bash
jgd poc --target /path/to/jars \
  --bridge cn.hutool.core.bean.DynaBean \
  --trigger hash \
  --ecj /path/to/ecj.jar \
  --out /path/to/poc-run \
  --unsafe-host
```

`--unsafe-host` is mandatory because the command compiles and executes target
gadget code. Run it inside the isolated Linux VM (`docs/VM-SANDBOX.md`), not on
the Windows host.

`jgd audit --dynamic --sandbox host --unsafe-host --ecj <jar>` also attempts
closure automatically for up to three `DESER_OK` dynamic candidates, adding
`JGD-P*` findings only when `fired_at_deser=true`. The end-to-end Hutool + CC3
run completed in 43.1s with `coverage.poc=2` and two `CHAIN_CONFIRMED`
findings; see `bench/results/2026-10-28-hutool-auto-poc.json`.

## What was fixed

The legacy `jgd/poc/poc_gen.py` had two correctness bugs:

1. CC3 `ChainedTransformer` was constructed with a `Serializable[]` signature;
   the real constructor is `Transformer[]`. It now allocates the exact
   `Transformer[]` type and uses the standard
   `getMethod → invoke → exec` transformer sequence.
2. A normal `HashMap.put(bridge, ...)` fires the bridge during **payload
   construction/serialization**, so it proves a build-time effect, not a
   deserialization chain. The new `hmz:` carrier inserts a `HashMap$Node` into
   the map table reflectively, so no `hashCode()` runs until
   `HashMap.readObject()` rehashes the key.

The `hmz:` carrier still requires the target JVM to allow reflective access to
`java.util` in this benign local harness; JGD adds:
`--add-opens java.base/java.util=ALL-UNNAMED` to the PoC JVM only.

## Verified chain (benign marker)

| Field | Value |
|---|---|
| Bridge | `cn.hutool.core.bean.DynaBean` |
| Trigger | `hashCode()` → `bean.hashCode()` |
| Tail | Commons Collections 3.2.1 `TiedMapEntry`/`LazyMap` → `InvokerTransformer` → `TemplatesImpl` |
| Carrier | `HashMap` with reflective table insertion (`hmz:`) |
| JDK | 17.0.20.1 |
| Result | `RCE_DEMO_FIRED`, `fired_at_build=false`, `fired_at_deser=true` |
| Effect | `TemplatesImpl` static initializer writes a marker file only |
| Classpath | `hutool-all-5.8.48.jar` + `commons-collections-3.2.1.jar` |
| Payload | `1271` bytes, SHA-256 `d3423c076259e9349f4326ffa173b1c4e8353c30a0582b43f73afa5e6980a515` |

Evidence: `bench/results/2026-10-28-hutool-dynabean-poc.json`.

**Scope caveat:** Hutool standalone does not bundle Commons Collections. This
is a real Hutool bridge combined with a common tail library; it is not a
single-JAR Hutool zero-day. Jenkins 2.587 bundles Commons Collections 3.2.2,
but that version rejects `InvokerTransformer` serialization unless the target
sets `org.apache.commons.collections.enableUnsafeSerialization=true`, so the
same chain is correctly reported as blocked by default on that corpus.

## MCP

The MCP control plane exposes `jgd_poc` with the same fields plus
`allowHost`. `allowHost=false` is rejected; the service never silently runs
target code on the control host.

## Determinism

The verifier owns the verdict. An LLM may describe or prioritize candidates,
but cannot mark a chain closed. `RCE_DEMO_FIRED` requires the marker to appear
during `ObjectInputStream.readObject()`, not merely during payload building.
