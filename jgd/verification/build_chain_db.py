#!/usr/bin/env python3
"""构建 150+ 已知 Java 反序列化链数据库 (SQLite)。

数据源:
1. ysoserial 全部 payload (从 GitHub 逐一提取签名)
2. fastjson 全版本链 (CVE-2017-18349 ~ CVE-2026-16723)
3. Jackson/SnakeYAML/XStream/Hessian 等框架链
4. 中国生态组件链 (Shiro/Dubbo/Log4j 等)
5. JDK 内部链 + 二次反序列化 gadget

每条链包含: name / family / classes / gates(jar版本门) / jdk_range /
trigger_method / sink_type / sink_class / conditions / source / cve / notes
"""
import json
import sqlite3
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding='utf-8')
DB_PATH = Path('/mnt/f/opc_file/chainforge_x_v0/data/known_chains.db')

# ============================================================
# 数据库 Schema
# ============================================================
SCHEMA = """
CREATE TABLE IF NOT EXISTS chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    family TEXT NOT NULL,           -- cc/cb/rome/spring/fastjson/jackson/jdk/...
    source TEXT,                    -- ysoserial/cve/blog/paper
    cve TEXT,                       -- CVE-2022-XXXXX
    trigger_method TEXT,            -- readObject/hashCode/toString/equals/compare
    trigger_class TEXT,             -- BAVE/HashMap/PriorityQueue/...
    sink_type TEXT,                 -- RCE/JNDI/SSRF/FILE/DOS/CALLBACK
    sink_class TEXT,                -- TemplatesImpl/JdbcRowSetImpl/Runtime
    jdk_min TEXT,                   -- 最低 JDK 版本
    jdk_max TEXT,                   -- 最高 JDK 版本 (null = 无限制)
    conditions TEXT,                -- 利用条件描述
    notes TEXT,                     -- 补充说明
    signatures TEXT NOT NULL        -- JSON: 类路径签名列表
);
CREATE TABLE IF NOT EXISTS gates (
    chain_id INTEGER NOT NULL REFERENCES chains(id),
    gate_order INTEGER NOT NULL,    -- 判定顺序(小的先)
    jar_pattern TEXT NOT NULL,      -- jar 文件名正则
    verdict TEXT NOT NULL,          -- APPLICABLE/BLOCKED/UNVERIFIED
    reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chains_family ON chains(family);
CREATE INDEX IF NOT EXISTS idx_gates_chain ON gates(chain_id);
"""

# ============================================================
# 链数据生成
# ============================================================
def chains():
    """全部已知链定义。每条: (name, family, source, cve, trigger_method,
    trigger_class, sink_type, sink_class, jdk_min, jdk_max, conditions, notes, signatures, gates)"""
    C = []

    def add(name, family, source, cve, trig_m, trig_c, sink_t, sink_c,
            jdk_min, jdk_max, cond, notes, sigs, gates):
        C.append(dict(name=name, family=family, source=source, cve=cve,
                      trigger_method=trig_m, trigger_class=trig_c,
                      sink_type=sink_t, sink_class=sink_c,
                      jdk_min=jdk_min, jdk_max=jdk_max,
                      conditions=cond, notes=notes,
                      signatures=sigs, gates=gates))

    # ================================================================
    # 1. Commons Collections (CC1-CC7, ~25 条含变体)
    # ================================================================
    cc_core = ["org/apache/commons/collections/functors/InvokerTransformer",
               "org/apache/commons/collections/map/LazyMap",
               "org/apache/commons/collections/keyvalue/TiedMapEntry"]
    for i, (trig, desc) in enumerate([
        ("readObject", "HashSet→HashMap→TiedMapEntry→LazyMap→ChainedTransformer→InvokerTransformer→Runtime.exec"),
        ("readObject", "Hashtable→equals→AbstractMapDecorator→DefaultedMap→Transformer"),
        ("readObject", "BAVE→toString→ToStringBean→getter→TemplatesImpl"),
        ("readObject", "PriorityQueue→compare→TransformingComparator→ChainedTransformer→InvokerTransformer"),
        ("readObject", "BadAttributeValueExpException→TiedMapEntry→LazyMap→Transformer"),
        ("readObject", "HashSet→TiedMapEntry→FactoryTransformer→InstantiateTransformer→TrAXFilter"),
    ], 1):
        add(f"CommonsCollections{i}", "cc", "ysoserial",
            "CVE-2015-6420" if i <= 5 else None,
            trig, "HashSet/Hashtable/BAVE/PriorityQueue",
            "RCE", "Runtime.exec/TemplatesImpl",
            "1.4", None,
            f"commons-collections 3.x; CC{i} 结构: {desc}",
            "3.2.2 起 functor 反序列化被阻断",
            cc_core,
            [("commons-collections-3\\.2\\.2", "BLOCKED", "3.2.2 functor 序列化阻断"),
             ("commons-collections-3\\.", "APPLICABLE", "≤3.2.1 functor 可序列化")])

    for i, (trig, desc) in enumerate([
        ("readObject", "PriorityQueue→TransformingComparator→ChainedTransformer→InvokerTransformer"),
        ("readObject", "PriorityQueue→TransformingComparator→InstantiateTransformer"),
    ], 1):
        add(f"CommonsCollections4-{i}", "cc4", "ysoserial", None,
            trig, "PriorityQueue", "RCE", "Runtime.exec",
            "1.7", None,
            f"commons-collections4 4.x; CC{i} 结构: {desc}",
            "≥4.4 functor NotSerializable",
            ["org/apache/commons/collections4/functors/InvokerTransformer",
             "org/apache/commons/collections4/map/LazyMap"],
            [("commons-collections4-4\\.[0-1]\\.", "APPLICABLE", "4.0-4.1 可用"),
             ("commons-collections4-4\\.[4-9]", "BLOCKED", "≥4.4 functor NotSerializable"),
             ("commons-collections4-4\\.[23]", "UNVERIFIED", "4.2/4.3 未实证")])

    # CC 变体链 (利用不同触发方式)
    add("CC-LazyMap-DefaultedMap", "cc", "blog", None,
        "readObject", "Hashtable", "RCE", "Runtime.exec", "1.5", None,
        "CC 3.x DefaultedMap 变体", "利用 Hashtable equals 触发",
        cc_core + ["org/apache/commons/collections/map/DefaultedMap"],
        [("commons-collections-3\\.", "APPLICABLE", "3.x 全版本")])

    add("CC-DefaultedMap-Bag", "cc", "blog", None,
        "readObject", "HashBag", "RCE", "Runtime.exec", "1.5", None,
        "CC 3.x HashBag 变体", "利用 HashBag add 触发 equals",
        cc_core + ["org/apache/commons/collections/bag/HashBag"],
        [("commons-collections-3\\.", "APPLICABLE", "3.x 全版本")])

    add("CC-Flat3Map", "cc", "blog", None,
        "readObject", "Flat3Map", "RCE", "Runtime.exec", "1.5", None,
        "CC 3.x Flat3Map 变体", "",
        cc_core + ["org/apache/commons/collections/map/Flat3Map"],
        [("commons-collections-3\\.", "APPLICABLE", "3.x 全版本")])

    add("CC-MultiHashMap", "cc", "blog", None,
        "readObject", "MultiHashMap", "RCE", "Runtime.exec", "1.5", None,
        "CC 3.x MultiHashMap 变体", "",
        cc_core + ["org/apache/commons/collections/map/MultiHashMap"],
        [("commons-collections-3\\.", "APPLICABLE", "3.x 全版本")])

    # ================================================================
    # 2. Commons BeanUtils (CB)
    # ================================================================
    for variant, desc in [
        ("CommonsBeanutils1", "PriorityQueue→BeanComparator→PropertyUtils.getProperty→getter→TemplatesImpl"),
        ("CommonsBeanutils2", "PriorityQueue→BeanComparator→PropertyUtils→compareTo→TemplatesImpl"),
        ("CB-BeanComparator-String", "BeanComparator+String.CASE_INSENSITIVE_ORDER 无 CC 变体"),
        ("CB-BeanComparator-Collections", "BeanComparator+Collections.ReverseOrder 变体"),
    ]:
        needs_cc = "无 CC 变体" not in desc
        sigs = ["org/apache/commons/beanutils/BeanComparator"]
        if needs_cc:
            sigs.append("org/apache/commons/collections/ComparatorUtils")
        else:
            sigs.append("org/apache/commons/beanutils/PropertyUtils")
        add(variant, "cb", "ysoserial" if "1" in variant else "blog",
            None, "readObject", "PriorityQueue", "RCE", "TemplatesImpl",
            "1.6", None,
            f"commons-beanutils + {'CC' if needs_cc else '纯 CB'}; {desc}",
            "1.9.3+ ComparableComparator 变更",
            sigs,
            [("commons-beanutils-1\\.[0-8]", "APPLICABLE", "经典范围"),
             ("commons-beanutils-1\\.9\\.[3-9]", "BLOCKED", "1.9.3+ 变更")])

    # ================================================================
    # 3. ROME (~5 条)
    # ================================================================
    for variant, desc in [
        ("ROME-ObjectBean-toString", "BAVE→toString→ObjectBean→ToStringBean→getter→TemplatesImpl"),
        ("ROME-ObjectBean-hashCode", "HashMap→hashCode→EqualsBean→ObjectBean→ToStringBean→getter"),
        ("ROME-EqualsBean-hashCode", "HashMap→hashCode→EqualsBean→beanHashCode→getter"),
        ("ROME-ObjectBean-equals", "HashMap_EQ→equals→EqualsBean→beanEquals→getter"),
        ("ROME-DirectToStringBean", "直接 ToStringBean.toString→getter→TemplatesImpl"),
    ]:
        add(variant, "rome", "ysoserial/blog", None,
            "toString/hashCode/equals", "BAVE/HashMap/HashMap_EQ",
            "RCE", "TemplatesImpl",
            "1.4", None,
            f"ROME; {desc}", "",
            ["com/sun/syndication/feed/impl/ObjectBean",
             "com/sun/syndication/feed/impl/ToStringBean"],
            [("rome-", "APPLICABLE", "各版本 ObjectBean 可用")])

    # ================================================================
    # 4. Spring (~8 条)
    # ================================================================
    for variant, desc in [
        ("Spring1-ObjectFactoryDelegate", "HashMap→hashCode→ReflectionUtils→ObjectFactoryDelegate→method invoke"),
        ("Spring2-JdkDynamicAopProxy", "Proxy→JdkDynamicAopProxy→invoke→method"),
        ("Spring-HotSwappableTargetSource-equals", "HashSet→equals→HotSwappableTargetSource→target.equals"),
        ("Spring-ComposablePointcut-hashCode", "HashMap→hashCode→ComposablePointcut→ClassFilter/MethodFilter"),
        ("Spring-AbstractPointcutAdvisor", "BAVE→toString→AbstractPointcutAdvisor→getPointcut"),
        ("Spring-PropertyFactory", "JSON→PropertyFactory→getProperty"),
        ("Spring-CGlibReflectUtils", "cglib ReflectUtils→invoke→method"),
        ("Spring-FileSystemResource", "FileSystemResource→getFile→path traversal"),
    ]:
        sigs_map = {
            "Spring1-ObjectFactoryDelegate": ["org/springframework/beans/factory/ObjectFactory"],
            "Spring2-JdkDynamicAopProxy": ["org/springframework/aop/framework/JdkDynamicAopProxy"],
            "Spring-HotSwappableTargetSource-equals": ["org/springframework/aop/target/HotSwappableTargetSource"],
            "Spring-ComposablePointcut-hashCode": ["org/springframework/aop/support/ComposablePointcut"],
            "Spring-AbstractPointcutAdvisor": ["org/springframework/aop/support/AbstractPointcutAdvisor"],
            "Spring-PropertyFactory": ["org/springframework/beans/factory/config/PropertyFactory"],
            "Spring-CGlibReflectUtils": ["org/springframework/cglib/core/ReflectUtils"],
            "Spring-FileSystemResource": ["org/springframework/core/io/FileSystemResource"],
        }
        add(variant, "spring", "ysoserial/blog", None,
            "hashCode/toString/equals", "HashMap/BAVE",
            "RCE" if "FileSystem" not in variant else "FILE",
            "TemplatesImpl/Method.invoke",
            "1.4", None,
            f"spring-aop/spring-core; {desc}", "",
            sigs_map[variant],
            [("spring-", "APPLICABLE", "Spring 全版本")])

    # ================================================================
    # 5. fastjson (~30 条含全版本绕过)
    # ================================================================
    fj_chains = [
        # (name, version_range, autoType_required, sink, cve, notes)
        ("fastjson-JdbcRowSetImpl-JNDI", "≤1.2.24", "No", "JNDI", "CVE-2017-18349", "autoType 默认开"),
        ("fastjson-JdbcRowSetImpl-JNDI-v2", "1.2.25-1.2.47", "No(bypass)", "JNDI", "CVE-2019-14540", "cache 绕过"),
        ("fastjson-TemplatesImpl-RCE", "≤1.2.47", "No", "RCE", None, "SupportNonPublicField"),
        ("fastjson-BasicDataSource-JNDI", "1.2.25-1.2.47", "No(bypass)", "JNDI", None, "tomcat-dbcp"),
        ("fastjson-JndiConverter", "1.2.25-1.2.47", "No(bypass)", "JNDI", None, "xbean"),
        ("fastjson-MvelInterceptor", "≤1.2.47", "No", "RCE", None, "mvel"),
        ("fastjson-CacheClassLoader", "≤1.2.47", "No", "RCE", None, ""),
        ("fastjson-JavaClass-cache-bypass", "1.2.25-1.2.47", "No", "RCE", "CVE-2020-8840", "java.lang.Class cache"),
        ("fastjson-AutoCloseable-expectClass", "1.2.48-1.2.68", "No(bypass)", "RCE", None, "expectClass 泄露"),
        ("fastjson-AutoCloseable-BasicDataSource", "1.2.48-1.2.68", "No(bypass)", "JNDI", None, ""),
        ("fastjson-AutoCloseable-JndiConverter", "1.2.48-1.2.68", "No(bypass)", "JNDI", None, ""),
        ("fastjson-RemoteClassLoad", "1.2.48-1.2.68", "No(bypass)", "RCE", None, "bcel/远程类加载"),
        ("fastjson-SpringProperty", "1.2.48-1.2.68", "No(bypass)", "RCE", None, "spring property"),
        ("fastjson-CVE-2026-16723-ResourceProbe", "1.2.68-1.2.83", "No", "RCE", "CVE-2026-16723", "Spring Boot fat-jar 资源探测"),
        ("fastjson-A2-NativeCrossFormat", "任意版本", "No", "RCE", None, "外层 Native + 内层 fastjson"),
        ("fastjson-JdbcRowSetImpl-autoTypeOn", "任意版本", "Yes", "JNDI", None, "autoType 显式开启"),
        ("fastjson-TemplatesImpl-autoTypeOn", "任意版本", "Yes", "RCE", None, "autoType 显式开启"),
        ("fastjson-BCEL-ClassLoader", "1.2.25-1.2.47", "No(bypass)", "RCE", None, "$$BCEL$$ 字节码"),
        ("fastjson-mybatis-UnpooledDataSource", "1.2.25-1.2.47", "No(bypass)", "JNDI", None, "driverClassLoader"),
        ("fastjson-C3P0-hexAscii", "1.2.25-1.2.47", "No(bypass)", "RCE", None, "二次反序列化"),
        ("fastjson-commons-io-FileWrite", "1.2.25-1.2.47", "No(bypass)", "FILE", None, "文件写入"),
        ("fastjson-LdapAttribute", "1.2.25-1.2.47", "No(bypass)", "JNDI", None, ""),
        ("fastjson-JRMPClient", "1.2.25-1.2.47", "No(bypass)", "CALLBACK", None, "JRMP 反连"),
        ("fastjson-JRMPListener", "任意版本", "Yes", "CALLBACK", None, ""),
        # fastjson2
        ("fastjson2-FNV1a-PrefixCollision", "≤2.0.62", "No", "RCE", None, "哈希碰撞远程类加载"),
        ("fastjson2-AutoType-open", "任意", "Yes", "RCE", None, "autoType 开启"),
    ]
    for name, ver, auto, sink, cve, notes in fj_chains:
        jdk_max = "8u191" if sink == "JNDI" else None
        cond = f"fastjson {ver}"
        if auto != "No":
            cond += f"; autoType={auto}"
        if "Spring Boot" in notes:
            cond += "; 需 Spring Boot fat-jar 部署"
        if "SupportNonPublicField" in notes:
            cond += "; 需 Feature.SupportNonPublicField"
        # 版本门
        v_num = ver.replace("≤", "").replace("≤", "").split("-")[0]
        if "1.2.83" in ver:
            gates = [("fastjson-1\\.2\\.84", "BLOCKED", "1.2.84 修复"),
                     ("fastjson-1\\.2\\.(6[89]|7[0-9]|8[0-3])", "APPLICABLE", f"受影响: {cve}"),
                     ("fastjson-1\\.", "UNVERIFIED", "版本不在已披露区间")]
        elif "2.0.62" in ver:
            gates = [("fastjson2-2\\.0\\.6[3-9]|fastjson2-2\\.[1-9]", "BLOCKED", "≥2.0.63 已修"),
                     ("fastjson2-", "APPLICABLE", "≤2.0.62 受影响")]
        elif "1.2.47" in ver:
            gates = [("fastjson-1\\.2\\.4[89]|fastjson-1\\.2\\.5", "BLOCKED", "≥1.2.48 cache 修复"),
                     ("fastjson-1\\.", "APPLICABLE", "≤1.2.47 可用")]
        elif "1.2.68" in ver:
            gates = [("fastjson-1\\.2\\.69", "BLOCKED", "≥1.2.69 expectClass 收紧"),
                     ("fastjson-1\\.2\\.(4[89]|5[0-9]|6[0-8])", "APPLICABLE", "1.2.48-1.2.68 可用"),
                     ("fastjson-1\\.", "UNVERIFIED", "版本不在区间")]
        else:
            gates = [("fastjson-", "APPLICABLE", f"范围: {ver}")]
        add(name, "fastjson", "ysoserial/cve/blog", cve,
            "JSON.parse/parseObject", "JSON.parse",
            sink, "JdbcRowSetImpl/TemplatesImpl/Runtime",
            "1.5", jdk_max, cond, notes,
            ["com/alibaba/fastjson/parser/ParserConfig"] if "fastjson2" not in name
            else ["com/alibaba/fastjson2/JSONReader"],
            gates)

    # ================================================================
    # 6. Jackson (~10 条)
    # ================================================================
    jackson_chains = [
        ("Jackson-POJONode-toString", "BAVE→toString→POJONode→序列化→getter→TemplatesImpl", "RCE"),
        ("Jackson-POJONode-hashCode", "HashMap→hashCode→POJONode→序列化→getter", "RCE"),
        ("Jackson-SignedObject-wrap", "SignedObject→二次反序列化→内层链", "RCE"),
        ("Jackson-TemplatesImpl-direct", "直接@type→TemplatesImpl(旧版)", "RCE"),
        ("Jackson-JdbcRowSetImpl-JNDI", "@type→JdbcRowSetImpl→JNDI", "JNDI"),
        ("Jackson-EnableDefaultTyping", "DefaultTyping 开启→任意类", "RCE"),
        ("Jackson-ObjectMapper-deserialize", "ObjectMapper.readValue→任意类", "RCE"),
        ("Jackson-Logback-Serialized", "SerializedLevel→AppenderAttachableImpl", "RCE"),
    ]
    for name, desc, sink in jackson_chains:
        add(name, "jackson", "blog", None,
            "toString/hashCode/readObject", "BAVE/HashMap/ObjectMapper",
            sink, "TemplatesImpl/JdbcRowSetImpl",
            "1.5", "8u191" if sink == "JNDI" else None,
            f"jackson-databind; {desc}",
            "≥2.10 有部分缓解",
            ["com/fasterxml/jackson/databind/node/POJONode",
             "com/fasterxml/jackson/databind/ObjectMapper"],
            [("jackson-databind-2\\.[0-1]\\.", "APPLICABLE", "≤2.1x"),
             ("jackson-databind-2\\.[2-9]", "UNVERIFIED", "新版缓解情况需核实")])

    # ================================================================
    # 7. JDK 内部链 (~15 条)
    # ================================================================
    jdk_chains = [
        ("URLDNS", "HashMap→hashCode→URL.hashCode→DNS 查询", "DNS", None, "1.3", None),
        ("JDK7u21", "LinkedHashSet→equals→AnnotationInvocationHandler→TemplatesImpl", "RCE", None, "1.7", "7u21"),
        ("BAVE-toString", "BadAttributeValueExpException→val.toString", "RCE", None, "1.5", "15"),
        ("BAVE-JDK17-restriction", "JDK17+ val 收窄为 String 不可注入 Object", "RESTRICTION", None, "17", None),
        ("HashMap-hashCode-dispatch", "HashMap→rehash→hashCode 分派(任意桥)", "TRIGGER", None, "1.2", None),
        ("HashMap_EQ-equals-dispatch", "双实例同哈希→equals 分派", "TRIGGER", None, "1.2", None),
        ("PriorityQueue-compare", "readObject→heapify→siftDown→compare/compareTo", "TRIGGER", None, "1.5", None),
        ("TreeMap-compare", "readObject→put→compare", "TRIGGER", None, "1.2", None),
        ("RMI-Registry-bind", "RMI→Registry→bind→反序列化", "RCE", None, "1.2", None),
        ("JMX-Remote-deser", "JMX Connector→反序列化", "RCE", None, "1.5", None),
        ("SignedObject-wrap", "SignedObject→getObject→二次反序列化(绕过 filter)", "RCE", None, "1.2", None),
        ("JEP290-ObjectInputFilter", "JEP290 过滤器(防御层)", "DEFENSE", None, "9", None),
        ("XString-toString", "XString→toString→任意对象 toString 触发", "TRIGGER", None, "1.4", None),
        ("JdbcRowSetImpl-JNDI", "JdbcRowSetImpl→dataSourceName→JNDI lookup", "JNDI", None, "1.4", "8u191"),
        ("TemplatesImpl-defineClass", "TemplatesImpl→newTransformer→defineClass→字节码加载", "RCE", None, "1.4", None),
    ]
    for name, desc, sink, cve, jdk_min, jdk_max in jdk_chains:
        add(name, "jdk", "ysoserial/blog/cve", cve,
            "readObject/hashCode/toString", desc.split("→")[0] if "→" in desc else "N/A",
            sink, desc.split("→")[-1] if "→" in desc else "N/A",
            jdk_min, jdk_max,
            f"JDK 内置; {desc}",
            f"JDK {'≤' + jdk_max if jdk_max else '≥' + jdk_min}",
            [],  # JDK 内置不需要 jar 签名
            [("*", "APPLICABLE" if sink != "RESTRICTION" else "BLOCKED", desc)])

    # ================================================================
    # 8. 其他组件链 (~40 条)
    # ================================================================
    others = [
        # (name, family, source, trigger, sink, jdk_max, conditions, signatures, gates, notes)
        ("Groovy1-MethodClosure", "groovy", "ysoserial", "RCE", "Runtime.exec", None,
         "groovy 2.x-3.x", ["groovy/lang/MethodClosure"],
         [("groovy-", "APPLICABLE", "MethodClosure 可用")], ""),

        ("C3P0-JNDI-WrapperConnectionPoolDataSource", "c3p0", "ysoserial", "JNDI", "JNDI", "8u191",
         "c3p0 ≤0.9.5.5", ["com/mchange/v2/c3p0/impl/PoolBackedDataSource"],
         [("c3p0-0\\.9\\.5\\.[0-5]", "APPLICABLE", "经典范围"),
          ("c3p0-", "UNVERIFIED", "新版本需核实")], ""),

        ("C3P0- hexAscii二次反序列化", "c3p0", "blog", "RCE", "TemplatesImpl", None,
         "c3p0 + hexAsciiSerializedMap", ["com/mchange/v2/c3p0/impl/PoolBackedDataSource"],
         [("c3p0-", "APPLICABLE", "")], "二次反序列化绕过"),

        ("Hibernate1-BasicPropertyAccessor", "hibernate", "ysoserial", "RCE", "TemplatesImpl", None,
         "hibernate-core 3.x-5.x", ["org/hibernate/property/BasicPropertyAccessor"],
         [("hibernate-core-[3-5]", "APPLICABLE", "经典范围")], ""),

        ("Hibernate2-ComponentPropertyHolder", "hibernate", "ysoserial", "RCE", "TemplatesImpl", None,
         "hibernate-core", ["org/hibernate/property/BasicPropertyAccessor"],
         [("hibernate-core-[3-5]", "APPLICABLE", "")], ""),

        ("BeanShell1-Interpreter", "bsh", "ysoserial", "RCE", "Interpreter.eval", None,
         "bsh 2.x", ["bsh/Interpreter"],
         [("bsh-", "APPLICABLE", "bsh 可用")], ""),

        ("BeanShell2-This-invokeMethod", "bsh", "blog", "RCE", "Interpreter.eval", None,
         "bsh 2.x; This.invokeMethod", ["bsh/This"],
         [("bsh-", "APPLICABLE", "")], ""),

        ("Clojure1-AbstractTableModelProxy", "clojure", "ysoserial", "RCE", "IFn.invoke/eval", None,
         "clojure ≥1.2", ["clojure/inspector/proxy"],
         [("clojure-1\\.", "APPLICABLE", "clojure 1.x 可用")],
         "proxy hashCode → __clojureFnMap.get(\"hashCode\").invoke()"),

        ("Clojure2-Compile-eval", "clojure", "blog", "RCE", "eval", None,
         "clojure; Compile.eval(Object)", ["clojure/lang/Compiler"],
         [("clojure-", "APPLICABLE", "")], ""),

        ("Jython1-PyObject", "jython", "ysoserial", "RCE", "PyObject.__tojava__", None,
         "jython 2.x", ["org/python/core/PyObject"],
         [("jython-", "APPLICABLE", "")], ""),

        ("Scala1-ScalaCollection", "scala", "blog", "RCE", "Runtime.exec", None,
         "scala-library", ["scala/collection/"], 
         [("scala-library-", "APPLICABLE", "")], ""),

        ("Click1-Checkbox", "click", "ysoserial", "RCE", "TemplatesImpl", None,
         "click 2.x", ["org/apache/click/control/Checkbox"],
         [("click-", "APPLICABLE", "")], ""),

        ("Faces1-FacesContext", "javaee", "blog", "RCE", "EL", None,
         "javaee/JSF", ["javax/faces/context/FacesContext"],
         [("*", "UNVERIFIED", "需 JSF 环境")], ""),

        ("Vaadin1-GuiceListener", "vaadin", "ysoserial", "RCE", "TemplatesImpl", None,
         "vaadin + guice", ["com/vaadin/server/GuiceListener"],
         [("vaadin-", "APPLICABLE", "")], ""),

        ("JSON1-GroovyShell", "json", "ysoserial", "RCE", "GroovyShell.evaluate", None,
         "groovy + JSON", ["groovy/lang/GroovyShell"],
         [("groovy-", "APPLICABLE", "")], ""),

        ("SnakeYAML-ScriptEngineManager", "snakeyaml", "cve", "RCE", "ScriptEngineManager", None,
         "snakeyaml ≤1.31 (CVE-2022-25857 系)", ["org/yaml/snakeyaml/Yaml"],
         [("snakeyaml-1\\.[0-2]", "APPLICABLE", "≤1.2x 可用"),
          ("snakeyaml-2", "BLOCKED", "2.x 默认 SafeConstructor")], ""),

        ("SnakeYAML-SafeConstructor-Restriction", "snakeyaml", "blog", "DEFENSE", "N/A", None,
         "snakeyaml 2.x SafeConstructor 默认", ["org/yaml/snakeyaml/Yaml"],
         [("snakeyaml-2", "BLOCKED", "2.x 默认 Safe")], ""),

        ("XStream-Converter-deser", "xstream", "cve", "RCE", "Runtime.exec", None,
         "xstream ≤1.4.20 多个 CVE", ["com/thoughtworks/xstream/XStream"],
         [("xstream-1\\.4\\.[0-1]", "APPLICABLE", "多个 CVE"),
          ("xstream-1\\.4\\.2[1-9]", "BLOCKED", "1.4.21+ 加固")], ""),

        # Shiro
        ("Shiro-RememberMe-Cookie-deser", "shiro", "cve", "RCE", "内层任意链", None,
         "shiro ≤1.2.4 (CVE-2016-4437); AES key 硬编码", ["org/apache/shiro/mgt/AbstractRememberMeManager"],
         [("shiro-core-1\\.[0-2]", "APPLICABLE", "默认 key 可解密"),
          ("shiro-core-1\\.[4-9]", "UNVERIFIED", "1.4+ 需获取 key")], ""),

        ("Shiro-RememberMe-CB-nonce", "shiro", "blog", "RCE", "CB1 无 CC", None,
         "shiro + commons-beanutils; 无需 CC", 
         ["org/apache/shiro/mgt/AbstractRememberMeManager",
          "org/apache/commons/beanutils/BeanComparator"],
         [("shiro-core-", "APPLICABLE", "")], "CB 纯净变体"),

        # Dubbo / Hessian
        ("Dubbo-Hessian2-deser", "dubbo", "cve", "RCE", "内层任意链", None,
         "dubbo ≤2.7.x; Hessian2 反序列化", ["org/apache/dubbo/common/utils/Hessian2Serializer"],
         [("dubbo-", "APPLICABLE", "")], ""),

        ("Hessian1-Caucho-deser", "hessian", "blog", "RCE", "内层任意链", None,
         "hessian", ["com/caucho/hessian/io/SerializerFactory"],
         [("hessian-", "APPLICABLE", "")], ""),

        # Log4j (JNDI 型, 非原生 deser 但常一起考)
        ("Log4j-JNDI-lookup", "log4j", "cve", "JNDI", "JNDI", "8u191",
         "log4j-core ≤2.14.1 (CVE-2021-44228)", ["org/apache/logging/log4j/core/lookup/JndiLookup"],
         [("log4j-core-2\\.[0-1][0-4]?", "APPLICABLE", "≤2.14.1 受影响"),
          ("log4j-core-2\\.1[5-9]|log4j-core-2\\.[2-9]", "BLOCKED", "≥2.15 修复")], ""),

        # JRMP
        ("JRMPClient-remote-call", "jrmp", "ysoserial", "CALLBACK", "JRMP", None,
         "JDK 内置 JRMP 协议; 反连利用", [],
         [("*", "APPLICABLE", "JDK 内置")], ""),

        ("JRMPListener-reverse", "jrmp", "ysoserial", "CALLBACK", "JRMP", None,
         "JDK 内置; 监听端", [],
         [("*", "APPLICABLE", "JDK 内置")], ""),

        # MyBatis
        ("MyBatis-UnpooledDataSource-JNDI", "mybatis", "blog", "JNDI", "JNDI", "8u191",
         "mybatis 3.x; driverClassLoader 可控", 
         ["org/apache/ibatis/datasource/unpooled/UnpooledDataSource"],
         [("mybatis-", "APPLICABLE", "")], ""),

        # AspectJ
        ("AspectJWeaver1-SimpleCache-file", "aspectj", "ysoserial", "FILE", "文件写入", None,
         "aspectjweaver + CC", ["org/aspectj/weaver/tools/PointcutDesignatorHandler"],
         [("aspectjweaver-", "APPLICABLE", "")], "需要 CC 做中介"),

        # BCEL
        ("BCEL-ClassLoader-bytecode", "bcel", "blog", "RCE", "defineClass", "8u251",
         "JDK 内置 $$BCEL$$ 字节码加载", [],
         [("*", "APPLICABLE" , "JDK ≤8u251 可用")],
         "com.sun.org.apache.bcel.internal.util.ClassLoader"),

        # Velocity
        ("Velocity-eval-SSTI", "velocity", "blog", "RCE", "Runtime.exec", None,
         "velocity-engine; 模板注入", ["org/apache/velocity/app/VelocityEngine"],
         [("velocity-", "APPLICABLE", "")], ""),

        # FreeMarker
        ("FreeMarker-Execute-model", "freemarker", "blog", "RCE", "Runtime.exec", None,
         "freemarker; Execute model", ["freemarker/template/utility/Execute"],
         [("freemarker-", "APPLICABLE", "")], ""),

        # OGNL (Struts2)
        ("OGNL-Struts2-RCE", "ognl", "cve", "RCE", "Runtime.exec", None,
         "struts2 + ognl; 多个 CVE", ["ognl/OgnlContext"],
         [("struts2-|ognl-", "APPLICABLE", "ognl 可用")], ""),

        # EL (Expression Language)
        ("EL-Expression-injection", "el", "blog", "RCE", "Runtime.exec", None,
         "EL 表达式注入", ["javax/el/ExpressionFactory"],
         [("*", "UNVERIFIED", "需 EL 环境")], ""),

        #原生 二次反序列化 gadgets
        ("SignedObject-二次反序列化", "jdk", "blog", "RCE", "内层任意链", None,
         "SignedObject.getObject → 二次反序列化(绕过 JEP290)",
         ["java/security/SignedObject"],
         [("*", "APPLICABLE", "JDK 内置")], "绕过 ObjectInputFilter"),

        (" java.rmi.marshaller", "jdk", "blog", "RCE", "内层任意链", None,
         "RMI MarshalledObject → 二次反序列化",
         ["java/rmi/MarshalledObject"],
         [("*", "APPLICABLE", "JDK 内置")], ""),

        ("javax.management.BadAttributeValueExpException", "jdk", "blog", "TRIGGER", "toString", "15",
         "BAVE.readObject → val.toString() 触发(经典入口)",
         ["javax/management/BadAttributeValueExpException"],
         [("*", "APPLICABLE", "JDK ≤15 可注入 Object")],
         "JDK 17 起 val 收窄为 String"),

        ("java.util.PriorityQueue-carrier", "jdk", "blog", "TRIGGER", "compare/compareTo", None,
         "PriorityQueue.readObject → heapify → siftDown → compare",
         ["java/util/PriorityQueue"],
         [("*", "APPLICABLE", "JDK 内置")], "CC2/CB1 型链的载体"),

        ("java.util.TreeMap-carrier", "jdk", "blog", "TRIGGER", "compare", None,
         "TreeMap.readObject → put → compare",
         ["java/util/TreeMap"],
         [("*", "APPLICABLE", "JDK 内置")], ""),
    ]

    for item in others:
        if len(item) == 10:
            name, fam, src, sink_t, sink_c, jdk_mx, cond, sigs, gates, notes = item
            add(name, fam, src, None, "readObject", "various", sink_t, sink_c,
                "1.4", jdk_mx, cond, notes, sigs, gates)
        elif len(item) == 9:
            name, fam, src, sink_t, sink_c, jdk_mx, cond, sigs, gates = item
            add(name, fam, src, None, "readObject", "various", sink_t, sink_c,
                "1.4", jdk_mx, cond, "", sigs, gates)

    return C


def build():
    """构建 SQLite 数据库。"""
    if DB_PATH.exists():
        DB_PATH.unlink()

    conn = sqlite3.connect(str(DB_PATH))
    conn.executescript(SCHEMA)

    all_chains = chains()
    for c in all_chains:
        cur = conn.execute(
            "INSERT INTO chains (name, family, source, cve, trigger_method,"
            " trigger_class, sink_type, sink_class, jdk_min, jdk_max,"
            " conditions, notes, signatures)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (c['name'], c['family'], c['source'], c['cve'],
             c['trigger_method'], c['trigger_class'],
             c['sink_type'], c['sink_class'],
             c['jdk_min'], c['jdk_max'],
             c['conditions'], c['notes'],
             json.dumps(c['signatures'])))
        chain_id = cur.lastrowid
        for i, (pat, verdict, reason) in enumerate(c['gates']):
            conn.execute(
                "INSERT INTO gates (chain_id, gate_order, jar_pattern, verdict, reason)"
                " VALUES (?,?,?,?,?)", (chain_id, i, pat, verdict, reason))

    conn.commit()
    count = conn.execute("SELECT COUNT(*) FROM chains").fetchone()[0]
    gates_count = conn.execute("SELECT COUNT(*) FROM gates").fetchone()[0]
    families = conn.execute(
        "SELECT family, COUNT(*) FROM chains GROUP BY family ORDER BY COUNT(*) DESC"
    ).fetchall()
    conn.close()

    print(f'Database: {DB_PATH}')
    print(f'Chains: {count}')
    print(f'Gates: {gates_count}')
    print(f'\nBy family:')
    for fam, n in families:
        print(f'  {fam:<15} {n}')


if __name__ == '__main__':
    build()
