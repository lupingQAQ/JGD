# JGD — Discovered Chain Catalog

> All chains below were discovered by the autonomous mining pipeline and verified
> through adversarial LLM auditing. Full dispatch stacks included.

## T1 — Novel Entry (Entry-side novelty confirmed by adversarial audit)

### objlongpair-hashmap (JDK 17+, Artemis)

**Full dispatch stack:**
```
HashMap.put → HashMap.hash
  → org.apache.activemq.artemis.api.core.ObjLongPair.hashCode(ObjLongPair.java:55)
    → java.util.Objects.hash → Arrays.hashCode
      → EqualsBean.hashCode → EqualsBean.beanHashCode
        → ObjectBean.toString → ToStringBean.toString → Method.invoke
          → TemplatesImpl.defineClass → payload static block → RCE
```

**Conditions:**
- Any deserialization vulnerability (prerequisite)
- Artemis on classpath (broker or client ≥ 2.44)
- ROME on classpath (or any Object-field dispatch receiver)
- JDK ≥ 17 (class file version 61)

**Novelty:** Entry-side confirmed T1 — absent from ysoserial/GadgetInspector/all public
CVE writeups. Orthogonal to known ROME entry paradigms.

---

## T2 — New Carriers

### mutableobj-bave (JDK ≤11, hutool)

```
BAVE.readObject → val.toString()
  → cn.hutool.core.lang.mutable.MutableObj.toString
    → value.toString()  [Object field]
      → ObjectBean.toString → ToStringBean.toString
        → Templates.getOutputProperties → TemplatesImpl.newTransformer
          → defineClass → payload static block → RCE
```

### antlr4-pair-bave (JDK ≤11, antlr4-runtime)

```
BAVE.readObject → val.toString()
  → org.antlr.v4.runtime.misc.Pair.toString
    → String.format → a/b.toString()  [both Object fields]
      → ObjectBean.toString → ToStringBean.toString
        → Templates.getOutputProperties → newTransformer → defineClass → RCE
```

### federationconfiguration-hashmap (JDK 17+, Artemis)

```
HashMap.readObject → rehash
  → FederationConfiguration.hashCode → Object field forwarding
    → EqualsBean.beanHashCode → ObjectBean.toString
      → TemplatesImpl.defineClass → RCE
```

### federationaddresspolicy-hashmap (JDK 17+, Artemis)

```
HashMap.readObject → rehash
  → FederationAddressPolicyConfiguration.hashCode → Object field
    → EqualsBean.beanHashCode → ObjectBean.toString → defineClass → RCE
```

### federationqueuepolicy-hashmap (JDK 17+, Artemis)

```
HashMap.readObject → rehash
  → FederationQueuePolicyConfiguration.hashCode → Object field
    → EqualsBean.beanHashCode → ObjectBean.toString → defineClass → RCE
```

### broadcastgroupconfiguration-hashmap (JDK 17+, Artemis)

```
HashMap.readObject → rehash
  → BroadcastGroupConfiguration.hashCode → Object field
    → EqualsBean.beanHashCode → ObjectBean.toString → defineClass → RCE
```

---

## T3 — Variants

### ewah-hashmap (JDK ≤11, JavaEWAH / Lucene ecosystem)

```
HashMap.readObject → rehash
  → EWAHCompressedBitmap.hashCode
    → rlw.getRunningBit() / buffer.getWord(i)  [shallow dispatch]
```

Limited value: dispatch targets are primitive getters, no second-level object dispatch.

---

## Exploitation Formula

```
Any deserialization vulnerability (prerequisite)
  + Target JDK matches carrier (BAVE→≤11, HashMap→by bridge class version)
  + Bridge library on classpath (see per-chain table)
  + Tail library on classpath (ROME or equivalent)
  ────────────────────────────
  = Command Execution (demonstrated via benign marker file)
```
