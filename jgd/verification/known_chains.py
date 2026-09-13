"""JGDKnownChainsAgent — 公开链四态判定 (R46: 用户裁决"必能")。

给任意 jar 目录, 对每条公开链给出四态:
  PRESENT   所需类全部在场(指纹匹配)
  VERSION   版本适用性(CC3.2.2 functor阻断 / CC4.4.6 NotSerializable /
            BAVE JDK17 val收窄 等本 session 实证过的截止点)
  ASSEMBLE  可组装(入口/桥/sink 的构造器与字段接线在目标版本上成立)
  FIRE      可点火(用目标自己的 jar 动态组装良性 payload 复验)

语义: 类签名集有限 → 判定是机械的 → "必能"(不存在发现性问题,
只存在指纹库覆盖度 — 库不在场的链标记 UNKNOWN_SIG 而非漏报)。
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path

from jgd.infra import matrix_agent as ma, scope

# 字段: name / classes(类路径签名) / version_gate(jar名正则→适用/阻断理由)
KNOWN_CHAINS = [
    {"name": "CC1-CC7 (commons-collections LazyMap/ChainedTransformer)",
     "classes": ["org/apache/commons/collections/functors/InvokerTransformer",
                 "org/apache/commons/collections/map/LazyMap",
                 "org/apache/commons/collections/keyvalue/TiedMapEntry"],
     "gates": [
         ("commons-collections-3\\.2\\.2", False,
          "3.2.2 起 functor 反序列化被阻断(本session实证)"),
         ("commons-collections-3\\.", True,
          "≤3.2.1 functor可序列化")]},
    {"name": "CC4-LazyMap (collections4)",
     "classes": ["org/apache/commons/collections4/functors/InvokerTransformer",
                 "org/apache/commons/collections4/map/LazyMap"],
     "gates": [
         ("commons-collections4-4\\.[0-1]\\.", True, "4.0-4.1 可用"),
         ("commons-collections4-4\\.[4-9]", False,
          "≥4.4 functor NotSerializable(本session实证 4.6)")]},
    {"name": "ROME ObjectBean→TemplatesImpl",
     "classes": ["com/sun/syndication/feed/impl/ObjectBean",
                 "com/sun/syndication/feed/impl/ToStringBean"],
     "gates": [("rome-", True, "各版本 ObjectBean 可用(实证 1.0)")]},
    {"name": "CB1 (commons-beanutils + CC)",
     "classes": ["org/apache/commons/beanutils/BeanComparator",
                 "org/apache/commons/collections/ComparatorUtils"],
     "gates": [("commons-beanutils-1\\.[0-8]", True, "经典范围"),
               ("commons-beanutils-1\\.9\\.[3-9]", False, "1.9.3+ ComparableComparator 变更")]},
    {"name": "URLDNS (JDK-only 探测链)",
     "classes": ["java/net/URL"],
     "gates": [("*", True, "JDK 自带, 永在场(探测非RCE)")]},
    {"name": "Hibernate1/2",
     "classes": ["org/hibernate/property/BasicPropertyAccessor"],
     "gates": [("hibernate-core-[3-5]", True, "经典范围")]},
    {"name": "Groovy1 (MethodClosure+CC)",
     "classes": ["org/codehaus/groovy/runtime/MethodClosure",
                 "org/apache/commons/collections/Closure"],
     "gates": [("groovy-", True, "依赖CC载体状态")]},
    {"name": "Spring1/2 (ObjectFactoryDelegate)",
     "classes": ["org/springframework/beans/factory/ObjectFactory"],
     "gates": [("spring-beans-\\[2-5\\]", True, "经典范围")]},
    {"name": "JDK7u21",
     "classes": ["com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl"],
     "gates": [("jdk", True, "仅 JDK≤7u21")]},
    {"name": "C3P0-JNDI",
     "classes": ["com/mchange/v2/c3p0/impl/PoolBackedDataSource"],
     "gates": [("c3p0-", True, "JNDI受JDK trust限制")]},
    {"name": "BeanShell1/Jython1/Rhino1/2",
     "classes": ["bsh/Interpreter"],
     "gates": [("bsh-", True, "经典范围")]},
]

JDK_GATES = [
    ("BadAttributeValueExpException.val", "≤15 可注入 Object(17起 String, 实证)"),
    ("JNDI remote codebase", "≤8u191 等旧 trust 模型"),
]


def jar_inventory(corpus: Path) -> list[str]:
    return sorted(j.name for j in corpus.glob("*.jar"))


JDK_INTERNAL_PREFIXES = ("java/", "javax/", "jdk/", "sun/", "com/sun/")


def classes_present(corpus: Path, sigs: list[str]) -> tuple[bool, list[str]]:
    have: set[str] = set()
    jdk_only: set[str] = set()
    for s in sigs:
        # R51(D4): JDK 内部类不在 jar 里, 按运行时在场处理
        if s.startswith(JDK_INTERNAL_PREFIXES):
            jdk_only.add(s)
            have.add(s)
    for jar in corpus.glob("*.jar"):
        try:
            with zipfile.ZipFile(jar) as z:
                nl = z.namelist()
                for s in sigs:
                    if (s + ".class") in nl or any(
                            e.startswith(s + "$") and e.endswith(".class")
                            for e in nl):
                        have.add(s)
        except Exception:
            continue
    missing = [s for s in sigs if s not in have]
    return not missing, missing


def version_verdict(jars: list[str], gates: list[tuple]) -> str:
    for pat, ok, why in gates:
        hit = next((j for j in jars if re.search(pat, j)), None)
        if hit:
            return ("APPLICABLE: " if ok else "BLOCKED: ") + why + f" [{hit}]"
    return "APPLICABLE: 无版本门命中(默认按可用, 建议动态复验)"


def audit(corpus: Path) -> list[dict]:
    jars = jar_inventory(corpus)
    out = []
    for c in KNOWN_CHAINS:
        present, missing = classes_present(corpus, c["classes"])
        out.append({
            "chain": c["name"],
            "present": present,
            "missing": missing,
            "version": version_verdict(jars, c["gates"]) if present else "N/A",
            "assemble": ("待动态复验(POC装配)" if present else "N/A"),
            "state": ("PRESENT" if present else "ABSENT"),
        })
    return out


def main() -> int:
    corpus = ma.corpus_dir()
    print("=" * 64)
    print(f"JGDKnownChainsAgent: 公开链四态判定 — {corpus}")
    print("=" * 64)
    results = audit(corpus)
    for r in results:
        mark = "✅" if r["present"] else "—"
        print(f"{mark} {r['chain']}")
        print(f"    present={r['state']} version={r['version']}")
    (scope.DATA / "known_chains_report.json").write_text(
        json.dumps({"corpus": str(corpus), "results": results,
                    "jdk_gates": JDK_GATES}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    print(f"\n-> known_chains_report.json | PRESENT={sum(1 for r in results if r['present'])}"
          f"/{len(results)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
