"""2023-2026 公开链知识库补齐（含 JDD/GadgetBuilder/Atredis/FLASH/JDK21+ 新链）。"""

import json

from jgd.infra import chroma_store

CHAINS_2026 = [
    # === JDD BlackHat Asia 2025 发现 ===
    {"name": "JDD-fastjson2-SofaChain", "year": 2025, "source": "JDD BH Asia 2025",
     "deps": ["fastjson2", "JDK"],
     "hops": [
         {"hop": "H1", "cls": "java.util.HashMap", "method": "readObject/put",
          "why": "反序列化时 HashMap.put 触发 hash(key)→key.hashCode"},
         {"hop": "H2", "cls": "com.alibaba.fastjson2.JSONObject", "method": "toString",
          "why": "JSONObject.toString→JSONWriter.write 序列化时调全部 getter"},
         {"hop": "H3", "cls": "com.alibaba.fastjson2.writer.FieldWriterObject", "method": "write",
          "why": "FieldWriterObject.write→Method.invoke 反射调用 getter"},
         {"hop": "H4", "cls": "ServerTableEntry", "method": "activate",
          "why": "activate()→Runtime.exec 直接命令执行"}],
     "novel": "仅依赖 JDK+fastjson2, 影响 Sofa/Solon 等框架"},

    # === Atredis LLM Chain Hunter 2026 ===
    {"name": "CB1-Shaded-JPMS-Bypass", "year": 2026, "source": "Atredis 2026.3",
     "deps": ["jakarta.servlet.jsp.jstl", "commons-beanutils"],
     "hops": [
         {"hop": "H1", "cls": "java.util.PriorityQueue", "method": "readObject",
          "why": "PriorityQueue.heapify→compare"},
         {"hop": "H2", "cls": "org.apache.commons.beanutils.BeanComparator", "method": "compare",
          "why": "compare→PropertyUtils.getProperty→getter"},
         {"hop": "H4", "cls": "org.eclipse.tags.shaded.org.apache.xalan.xsltc.trax.TemplatesImpl",
          "method": "getOutputProperties",
          "why": "shaded 版本的 TemplatesImpl 不受 JPMS 限制, JDK21 仍可 RCE"}],
     "novel": "利用 WildFly 自带的 shaded Xalan JAR 绕过 JPMS 模块封装, JDK21 验证可行"},

    {"name": "TreeBag-TransformingComparator-CB", "year": 2026, "source": "Atredis 2026.3",
     "deps": ["commons-collections4>=4.5", "commons-beanutils"],
     "hops": [
         {"hop": "H1", "cls": "org.apache.commons.collections4.bag.TreeBag", "method": "readObject",
          "why": "TreeBag 继承 AbstractMapBag, 反序列化时走 TreeMap.put→compare(替代被过滤的 PriorityQueue)"},
         {"hop": "H2", "cls": "org.apache.commons.collections4.comparators.TransformingComparator",
          "method": "compare",
          "why": "compare→transformer.transform (CC4 4.5+ InvokerTransformer 不可序列化了, 但 TransformingComparator 仍可)"},
         {"hop": "H3", "cls": "org.apache.commons.beanutils.BeanComparator", "method": "compare",
          "why": "ConstantTransformer 包裹 BeanComparator 在 TransformingComparator 内部"},
         {"hop": "H4", "cls": "TemplatesImpl(shaded)", "method": "getOutputProperties",
          "why": "getter 触发 shaded 版本字节码加载"}],
     "novel": "PriorityQueue 被反序列化过滤器阻止时的替代入口"},

    {"name": "AttributeComparator-toString-JNDI", "year": 2026, "source": "Atredis 2026.3",
     "deps": ["Payara/GlassFish"],
     "hops": [
         {"hop": "H1", "cls": "AttributeComparator", "method": "toString",
          "why": "替代 BadAttributeValueExpException (JDK18+ 已修复 BAVE 的 val 字段 toString 调用)"},
         {"hop": "H2", "cls": "InjectableJMSContext", "method": "",
          "why": "通过 InjectableJMSContext 到达 JNDI 查询的新路径"}],
     "novel": "BAVE 在 JDK18+ 失效后的替代 toString 触发器"},

    # === GadgetBuilder NordSec 2025 ===
    {"name": "CommonsCollections8", "year": 2025, "source": "GadgetBuilder/ysoserial newgadgets",
     "deps": ["commons-collections4"],
     "hops": [
         {"hop": "H1", "cls": "java.util.Hashtable", "method": "readObject",
          "why": "Hashtable.reconstitutionPut→equals"},
         {"hop": "H2", "cls": "TiedMapEntry(collections4)", "method": "hashCode",
          "why": "hashCode→getValue→map.get"},
         {"hop": "H3", "cls": "LazyMap(collections4)", "method": "get",
          "why": "get→factory.transform"}],
     "novel": "collections4 版本的 Hashtable 入口变体"},

    {"name": "CommonsBeanutils2-NoCC", "year": 2025, "source": "GadgetBuilder/ysoserial newgadgets",
     "deps": ["commons-beanutils (无 CC 依赖)"],
     "hops": [
         {"hop": "H1", "cls": "java.util.PriorityQueue", "method": "readObject",
          "why": "heapify→compare"},
         {"hop": "H2", "cls": "org.apache.commons.beanutils.BeanComparator", "method": "compare",
          "why": "compare→getProperty→getter (不需要 commons-collections)"}],
     "novel": "完全去掉 CC 依赖的 CB 链"},

    {"name": "Scala1", "year": 2025, "source": "GadgetBuilder/ysoserial newgadgets",
     "deps": ["scala-library"],
     "hops": [
         {"hop": "H1", "cls": "java.util.HashMap", "method": "readObject",
          "why": "HashMap.put→hash→hashCode"},
         {"hop": "H2", "cls": "scala.collection.immutable.HashMap$HashMap1", "method": "hashCode/proxy",
          "why": "Scala HashMap 的 hashCode 走代理触发 invoke"}],
     "novel": "Scala 集合类作为桥"},

    {"name": "SpringJTA", "year": 2025, "source": "GadgetBuilder/ysoserial newgadgets",
     "deps": ["spring-tx"],
     "hops": [
         {"hop": "H1", "cls": "java.util.HashSet", "method": "readObject",
          "why": "HashSet→HashMap.put→hashCode"},
         {"hop": "H2", "cls": "org.springframework.transaction.jta.JtaTransactionManager",
          "method": "hashCode/readObject",
          "why": "JTA 事务管理器的 hashCode 调 JNDI lookup"}],
     "novel": "Spring JTA 事务管理器 JNDI 注入"},

    # === JDK 21+ Post-TemplatesImpl ===
    {"name": "SignedObject-NestedDeser-Bypass", "year": 2024, "source": "JDK21 filter bypass research",
     "deps": ["JDK"],
     "hops": [
         {"hop": "H1", "cls": "java.util.HashMap", "method": "readObject",
          "why": "正常入口, 外层过滤器放行 HashMap"},
         {"hop": "H2", "cls": "java.security.SignedObject", "method": "getObject",
          "why": "getObject()内部创建新 ObjectInputStream 反序列化 content, 新流不继承外层 filter"},
         {"hop": "H3", "cls": "(任意已知链)", "method": "",
          "why": "内层流无过滤器, CC6/CB1 等完整链在内层执行"}],
     "novel": "JEP290 过滤器架构缺陷: 过滤器绑定在 OIS 实例而非数据流上"},

    {"name": "XalanJ-External-TemplatesImpl", "year": 2024, "source": "JDK21+ research",
     "deps": ["xalan:xalan:2.7.3"],
     "hops": [
         {"hop": "H4", "cls": "org.apache.xalan.xsltc.trax.TemplatesImpl", "method": "getOutputProperties",
          "why": "外部 Xalan-J 版本不受 JPMS 模块封装限制, 反射正常访问"}],
     "novel": "Maven Central 112,000+ 依赖方, JDK21 仍可 RCE"},

    {"name": "H2-JDBC-Init-CREATEALIAS", "year": 2024, "source": "CVE-2024-0692 SolarWinds",
     "deps": ["h2-database"],
     "hops": [
         {"hop": "H2", "cls": "JDBC URL", "method": "connect",
          "why": "JDBC URL 含 INIT 参数执行 SQL: CREATE ALIAS 加载 Java 代码"},
         {"hop": "H4", "cls": "CREATE ALIAS → System.exec", "method": "",
          "why": "H2 的 CREATE ALIAS 可以调用 Java 静态方法"}],
     "novel": "Post-TemplatesImpl 时代 JDBC 连接串作为 RCE sink"},

    {"name": "AspectJWeaver-SimpleCache-FileWrite", "year": 2024, "source": "CVE-2023-48178 Relution",
     "deps": ["aspectjweaver", "commons-collections4"],
     "hops": [
         {"hop": "H1", "cls": "java.util.HashSet", "method": "readObject",
          "why": "HashSet→HashMap.put→hashCode"},
         {"hop": "H2", "cls": "TiedMapEntry", "method": "hashCode",
          "why": "hashCode→getValue→map.get"},
         {"hop": "H3", "cls": "LazyMap(含 SimpleCache$StorableCachingMap)", "method": "put",
          "why": "StorableCachingMap.put→FileOutputStream.write 任意文件写入"}],
     "novel": "不依赖 TemplatesImpl 的文件写入链, JDK21 可用"},

    {"name": "c3p0-ReferenceIndirector-RemoteClassLoad", "year": 2025,
     "source": "MOGWAI LABS 2025",
     "deps": ["c3p0"],
     "hops": [
         {"hop": "H1", "cls": "PoolBackedDataSourceBase", "method": "readObject",
          "why": "反序列化时从 indirect form 恢复 connectionPoolDataSource 属性"},
         {"hop": "H4", "cls": "ReferenceIndirector$ReferenceSerialized", "method": "getObject",
          "why": "getObject→referenceToObject→URLClassLoader 从 classFactoryLocation 加载远程类"}],
     "novel": "JDK 8u191 修复了 JNDI 远程类加载但未修复 c3p0 的 indirectForm, 最新 Java 仍可利用"},

    # === FLASH USENIX 2025 ===
    {"name": "FLASH-ProxyDispatch-Bridge", "year": 2025, "source": "FLASH USENIX Sec 2025",
     "deps": ["JDK"],
     "hops": [
         {"hop": "H2", "cls": "(任意 InvocationHandler 实现)", "method": "invoke",
          "why": "FLASH 发现 4.8% 的调用点可触发动态代理, 将代理分发作为方法分派建模"}],
     "novel": "首次在反序列化中分析动态代理分发, 发现 90 条新链中大量依赖代理跳边"},

    # === Dormant Gadgets CCS 2025 ===
    {"name": "Dormant-Gadget-SupplyChain", "year": 2025, "source": "CCS 2025 Sleeping Giants",
     "deps": ["533 个依赖中的 53 个"],
     "hops": [
         {"hop": "ANY", "cls": "( dormant classes )", "method": "",
          "why": "三类修改模式(加 Serializable/加接口 Serializable/修改字段)可在 26% 的依赖中激活 gadget 链"}],
     "novel": "供应链攻击向量: 微量代码修改即可激活休眠 gadget"},
]


def ingest() -> int:
    db = chroma_store.VStore()
    docs = []
    for c in CHAINS_2026:
        docs.append({
            "id": f"chain2026:{c['name']}",
            "type": "known_chain_2026",
            "tags": [c["name"], str(c["year"]), "novel" if c.get("novel") else "variant"],
            "payload": c,
        })
    db.add(docs)
    print(f"[ingest] +{len(docs)} 条 2023-2026 链 -> chroma, 总量 {db.count()}")
    stats = db.stats()
    print(f"[stats] {stats}")
    for q in ("JPMS 绕过 shaded TemplatesImpl JDK21 RCE",
              "PriorityQueue 被过滤后的替代入口",
              "JEP290 过滤器绕过 嵌套反序列化",
              "不依赖 TemplatesImpl 的文件写入",
              "fastjson2 toString getter 反射调用"):
        print(f"\n[Q] {q}")
        for item in db.query(q, topk=3):
            if isinstance(item, tuple) and len(item) >= 2:
                dist, doc = item[0], item[1]
                did = doc.get('id', '?') if isinstance(doc, dict) else str(item[0])
                dtype = doc.get('type', '?') if isinstance(doc, dict) else '?'
            elif isinstance(item, dict):
                did = item.get('id', '?')
                dist = 0
                dtype = item.get('type', '?')
            else:
                continue
            print(f"   d={dist} {did[:70]} [{dtype}]")
    return len(docs)


if __name__ == "__main__":
    raise SystemExit(ingest())
