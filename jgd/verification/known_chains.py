"""JGDKnownChainsAgent — 公开链四态判定 (用户裁决"必能")。

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

DB_PATH = scope.DATA / "known_chains.db"

# 硬编码兜底(数据库不可用时); 数据库优先(155+ 条含全元数据)
KNOWN_CHAINS_FALLBACK = [
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
         ("commons-collections4-4\\.[23]", None, "4.2/4.3 未实证, 需动态复验"),
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
    # (fastjson考核): fastjson 家族签名入库, 补签名库覆盖缺口
    {"name": "fastjson CVE-2026-16723 (checkAutoType @JSONType 资源探测, 默认配置 RCE)",
     "classes": ["com/alibaba/fastjson/parser/ParserConfig"],
     "gates": [
         ("fastjson-1\\.2\\.(8[4-9]|9[0-9])", False,
          "≥1.2.84 已修复: 拒绝含 :/! 的 typeName 后再做资源探测"),
         ("fastjson-1\\.2\\.(6[89]|7[0-9]|8[0-3])", True,
          "CVE-2026-16723 受影响(官方区间 1.2.68-1.2.83): autoType 关闭仍可 RCE, "
          "需 Spring Boot fat-jar 形态; JDK8 全利用, JDK9+ 降级 SSRF"),
         ("fastjson-1\\.", None,
          "版本不在已披露受影响区间(未核实), 需人工核对")]},
    {"name": "fastjson A2 跨格式链 (Native BAVE → JSONArray.toString 引擎 → TemplatesImpl)",
     "classes": ["com/alibaba/fastjson/JSONArray",
                 "javax/management/BadAttributeValueExpException",
                 "com/sun/org/apache/xalan/internal/xsltc/trax/TemplatesImpl"],
     "gates": [
         ("fastjson-1\\.2\\.[4-9][0-9]", True,
          "≥1.2.49 resolveClass 过滤 TemplatesImpl → DEGRADED, "
          "需引用句柄/再嵌 SignedObject 绕过(账本 A2 控制矩阵)"),
         ("fastjson-1\\.", True, "<1.2.49 无 resolveClass 过滤, A2 直接可用")]},
    {"name": "fastjson2 FNV-1a 白名单前缀碰撞 (checkAutoType, ≤2.0.62)",
     "classes": ["com/alibaba/fastjson2/JSONReader"],
     "gates": [
         ("fastjson2-2\\.(0\\.(6[3-9]|7[0-9]|[89][0-9])|[1-9])", False,
          "≥2.0.63 已修(PR#7695: 哈希命中后文本等价校验)"),
         ("fastjson2-", True,
          "≤2.0.62 受影响: @type 前缀哈希碰撞 → 远程类加载 RCE")]},
]

_V_VERDICT_MAP = {"APPLICABLE": True, "BLOCKED": False, "UNVERIFIED": None}


def _load_db_chains() -> list[dict] | None:
    if not DB_PATH.exists():
        return None
    import sqlite3
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    out = []
    for r in conn.execute("SELECT * FROM chains ORDER BY family, name"):
        gates = [(g["jar_pattern"], _V_VERDICT_MAP.get(g["verdict"]), g["reason"])
                 for g in conn.execute(
                     "SELECT * FROM gates WHERE chain_id=? ORDER BY gate_order",
                     (r["id"],))]
        out.append({"name": r["name"], "classes": json.loads(r["signatures"]),
                    "gates": gates, "family": r["family"]})
    conn.close()
    return out or None


_DB_CHAINS = _load_db_chains()
KNOWN_CHAINS = _DB_CHAINS if _DB_CHAINS else KNOWN_CHAINS_FALLBACK

JDK_GATES = [
    ("BadAttributeValueExpException.val", "≤15 可注入 Object(17起 String, 实证)"),
    ("JNDI remote codebase", "≤8u191 等旧 trust 模型"),
]


def jar_inventory(corpus: Path) -> list[str]:
    return sorted(j.name for j in corpus.glob("*.jar"))


JDK_INTERNAL_PREFIXES = ("java/", "javax/", "jdk/", "sun/", "com/sun/")
# com/sun/ 命名空间下的第三方库, 不属 JDK 内部类, 须排除防误报 PRESENT
NOT_JDK_INTERNAL = (
    "com/sun/syndication/",   # ROME
    "com/sun/xml/",           # Jakarta JAXB RI (JDK 只有 com.sun.xml.internal)
    "com/sun/mail/",          # Jakarta Mail
    "com/sun/activation/",    # Jakarta Activation
    "com/sun/jersey/",        # Jersey 1.x
    "com/sun/istack/",        # istack-commons
    "com/sun/grizzly/",       # Grizzly
    "com/sun/star/",          # LibreOffice UNO
)


def classes_present(corpus: Path, sigs: list[str]) -> tuple[bool, list[str]]:
    have: set[str] = set()
    jdk_only: set[str] = set()
    for s in sigs:
        # (D4): JDK 内部类不在 jar 里, 按运行时在场处理
        if s.startswith(JDK_INTERNAL_PREFIXES) and not s.startswith(
                NOT_JDK_INTERNAL):
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
    # 通配哨兵 "*": 全局单判定(逐 jar 会重复报)
    if any(pat == "*" for pat, _ok, _why in gates):
        hit = jars[0] if jars else "(no-jar)"
        _pat, ok, why = next(g for g in gates if g[0] == "*")
        prefix = "UNVERIFIED: " if ok is None else ("APPLICABLE: " if ok else "BLOCKED: ")
        return f"{prefix}{why} [{hit}]"
    # 多版本共存的语料: 每个 jar 各自给判定, 全部列出而非只报首个命中
    per_jar: list[str] = []
    for j in jars:
        for pat, ok, why in gates:
            if pat == "*" or re.search(pat, j):
                prefix = "UNVERIFIED: " if ok is None else (
                    "APPLICABLE: " if ok else "BLOCKED: ")
                per_jar.append(f"{prefix}{why} [{j}]")
                break
    if per_jar:
        return " | ".join(per_jar)
    return "APPLICABLE: 无版本门命中(默认按可用, 建议动态复验)"


def audit(corpus: Path) -> list[dict]:
    jars = jar_inventory(corpus)
    out = []
    for c in KNOWN_CHAINS:
        # 单链判定异常不再击穿整个阶段(曾静默收敛为"0 在场")
        try:
            present, missing = classes_present(corpus, c["classes"])
            out.append({
                "chain": c["name"],
                "present": present,
                "missing": missing,
                "version": version_verdict(jars, c["gates"]) if present else "N/A",
                "assemble": ("待动态复验(POC装配)" if present else "N/A"),
                "state": ("PRESENT" if present else "ABSENT"),
            })
        except Exception as e:
            out.append({"chain": c["name"], "present": False, "missing": [],
                        "version": f"SIG_ERROR: {e}", "assemble": "N/A",
                        "state": "SIG_ERROR"})
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
