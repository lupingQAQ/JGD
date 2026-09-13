"""StaticAgent v0.1：真实 jar 的调用图构建（纯 Python 字节码解析）。

- 解析 class 文件常量池/方法/Code 属性，扫描 invoke* 调用点
- CHA-lite 分派：跨 jar 类层次闭包内同名同签名方法（多目标 → field_dispatch 动态边界）
- JDK 触发语义种子（隐式触发 hub / fastjson getter 引擎 / 反射 hub / JDK sink 模型）
- 已知局限（记入 provenance）：无 rt.jar（JDK 内部不可见）、无指针分析、J3 字段边未建
"""

from __future__ import annotations

import io
import sqlite3
import struct
import zipfile
from pathlib import Path

from ledger import Node, add_edge, add_node

# JDK 隐式触发 hub（知识图谱 §3.2 语义种子）
HUBS = {
    "HASH_HUB": ("hashCode", "()I"),
    "EQUALS_HUB": ("equals", "(Ljava/lang/Object;)Z"),
    "TOSTRING_HUB": ("toString", "()Ljava/lang/String;"),
}
CMP_NAMES = ("compare", "compareTo")
GETTER_PREFIX = ("get", "is", "with")

JDK_SINKS = [  # (owner, name, category)
    ("java.lang.Runtime", "exec", "RCE"),
    ("java.lang.ProcessBuilder", "start", "RCE"),
    ("javax.script.ScriptEngine", "eval", "RCE"),
    ("c.s.o.a.x.t.TemplatesImpl", "defineTransletClasses", "CLASS_LOAD"),
    ("java.net.URLClassLoader", "<init>", "CLASS_LOAD"),
    ("sun.misc.Unsafe", "defineClass", "CLASS_LOAD"),
    ("javax.naming.InitialContext", "lookup", "JNDI"),
    ("com.sun.rowset.JdbcRowSetImpl", "getDatabaseMetaData", "JNDI"),
    ("java.io.FileOutputStream", "<init>", "FILE_WRITE"),
    ("java.nio.file.Files", "write", "FILE_WRITE"),
]
JAR_SINKS = [  # (owner_suffix, name, category) —— 真实 jar 类
    ("XStream", "fromXML", "SECONDARY_DESER"),
    ("Yaml", "load", "SECONDARY_DESER"),
    ("ObjectMapper", "readValue", "SECONDARY_DESER"),
    ("GroovyShell", "evaluate", "RCE"),
    ("GroovyShell", "parse", "RCE"),
]
KNOWN_SERIAL_SUPERS = {  # JDK 侧可序列化祖先白名单（补无 rt.jar 的盲区）
    "java/lang/Exception", "java/lang/RuntimeException", "java/lang/Throwable",
    "java/util/HashMap", "java/util/Hashtable", "java/util/ArrayList", "java/util/LinkedList",
    "java/util/Date", "java/lang/Number",
}

_EVOLUTION_STATE = Path(__file__).parent / "evolution_state.json"
_ENGINE_SEEDS: list[dict] = []
if _EVOLUTION_STATE.exists():                     # 自进化补丁：EvolutionAgent 写入的增量
    try:
        import json as _json
        _st = _json.loads(_EVOLUTION_STATE.read_text(encoding="utf-8"))
        KNOWN_SERIAL_SUPERS |= set(_st.get("serial_extra", []))
        _ENGINE_SEEDS = _st.get("engine_seeds", [])
    except Exception:
        pass

OP_LEN = {}  # 标准 JVM 操作数长度表（不含 0xaa/0xab/0xc4 特例，单独处理）
for _op in list(range(0x00, 0x10)):  # nop,aconst...,bipush 等按表
    pass
_fixed = {0x10: 1, 0x11: 2, 0x12: 1, 0x13: 2, 0x14: 2, 0x15: 1, 0x16: 1, 0x17: 1, 0x18: 1,
          0x19: 1, 0x1a: 0, 0x1b: 0, 0x1c: 0, 0x1d: 0, 0x1e: 0, 0x1f: 0, 0x20: 1, 0x21: 1,
          0x22: 1, 0x23: 1, 0x24: 0, 0x25: 0, 0x26: 0, 0x27: 0, 0x28: 0, 0x29: 0, 0x2a: 0,
          0x2b: 0, 0x2c: 0, 0x2d: 0, 0x2e: 0, 0x2f: 0, 0x30: 0, 0x31: 0, 0x32: 0, 0x33: 0,
          0x34: 0, 0x35: 0, 0x36: 0, 0x37: 0, 0x38: 0, 0x39: 0, 0x3a: 0}
for _i in range(0x3b, 0x84): OP_LEN[_i] = 0
OP_LEN.update(_fixed)
OP_LEN.update({0x84: 2, 0x85: 0, 0x86: 0, 0x87: 0, 0x88: 0, 0x89: 0, 0x8a: 0, 0x8b: 0,
               0x8c: 0, 0x8d: 0, 0x8e: 0, 0x8f: 0, 0x90: 0, 0x91: 0, 0x92: 0, 0x93: 0,
               0x94: 0, 0x95: 0, 0x96: 0, 0x97: 0, 0x98: 0, 0x99: 2, 0x9a: 2, 0x9b: 2,
               0x9c: 2, 0x9d: 2, 0x9e: 2, 0x9f: 2, 0xa0: 2, 0xa1: 2, 0xa2: 2, 0xa3: 2,
               0xa4: 2, 0xa5: 3, 0xa6: 3, 0xa7: 2, 0xa8: 2, 0xa9: 2, 0xac: 0, 0xad: 0,
               0xae: 0, 0xaf: 0, 0xb0: 0, 0xb1: 0, 0xb2: 2, 0xb3: 2, 0xb4: 2, 0xb5: 2,
               0xb6: 2, 0xb7: 2, 0xb8: 2, 0xb9: 4, 0xba: 4, 0xbb: 2, 0xbc: 1, 0xbd: 2,
               0xbe: 0, 0xbf: 0, 0xc0: 1, 0xc1: 1, 0xc2: 0, 0xc3: 0, 0xc5: 3, 0xc6: 3,
               0xc7: 3})


def parse_class(data: bytes) -> dict:
    r = io.BytesIO(data)
    if struct.unpack(">I", r.read(4))[0] != 0xCAFEBABE:
        return {}
    r.read(4)                                    # minor+major
    n = struct.unpack(">H", r.read(2))[0]
    cp: list = [None] * n
    i = 1
    while i < n:
        tag = r.read(1)[0]
        if tag == 1:
            ln = struct.unpack(">H", r.read(2))[0]
            cp[i] = ("u", r.read(ln).decode("utf-8", "replace"))
        elif tag in (3, 4): r.read(4)
        elif tag in (5, 6): r.read(8); cp[i] = ("x", None); i += 1
        elif tag == 7: cp[i] = ("c", struct.unpack(">H", r.read(2))[0])
        elif tag == 8: r.read(2)
        elif tag in (9, 10, 11): cp[i] = ("r", struct.unpack(">HH", r.read(4)))
        elif tag == 12: cp[i] = ("nt", struct.unpack(">HH", r.read(4)))
        elif tag == 15: r.read(3)
        elif tag == 16: r.read(2)
        elif tag in (17, 18): r.read(4)
        elif tag in (19, 20): r.read(2)
        i += 1
    def utf(idx: int) -> str:
        e = cp[idx]
        return e[1] if e and e[0] == "u" else ""
    def cls(idx: int) -> str:
        e = cp[idx]
        return utf(e[1]) if e and e[0] == "c" else ""
    caccess = struct.unpack(">H", r.read(2))[0]  # R7: 捕获类级访问标志
    this = cls(struct.unpack(">H", r.read(2))[0])
    sup = cls(struct.unpack(">H", r.read(2))[0]) or "java/lang/Object"
    ifc_n = struct.unpack(">H", r.read(2))[0]
    ifcs = [cls(struct.unpack(">H", r.read(2))[0]) for _ in range(ifc_n)]
    fields: list[tuple[str, int]] = []
    fields_full: list[tuple[str, int, str]] = []   # (name, access, desc) — R6修正: 保留字段类型
    for _ in range(struct.unpack(">H", r.read(2))[0]):        # fields（J3 元数据）
        acc, name_i, _desc_i = struct.unpack(">HHH", r.read(6))
        for _a in range(struct.unpack(">H", r.read(2))[0]):   # 字段属性跳过
            _an_i, alen = struct.unpack(">HI", r.read(6))
            r.read(alen)
        fields.append((utf(name_i), acc))
        fields_full.append((utf(name_i), acc, utf(_desc_i)))
    methods: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for _ in range(struct.unpack(">H", r.read(2))[0]):        # methods
        _acc, name_i, desc_i = struct.unpack(">HHH", r.read(6))
        calls: list[tuple[str, str, str]] = []
        for _a in range(struct.unpack(">H", r.read(2))[0]):
            an_i, alen = struct.unpack(">HI", r.read(6))
            body = r.read(alen)
            if utf(an_i) == "Code":
                code_len = struct.unpack(">I", body[4:8])[0]
                calls = scan_code(body[8:8 + code_len], cp, utf)
        methods[(utf(name_i), utf(desc_i))] = calls
    return {"this": this, "super": sup, "ifcs": ifcs, "fields": fields,
            "fields_full": fields_full, "methods": methods, "caccess": caccess}


def _field_attr_count(r: io.BytesIO) -> int:
    return struct.unpack(">H", r.read(2))[0]


def scan_code(code: bytes, cp: list, utf) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    i = 0
    n = len(code)
    while i < n:
        op = code[i]
        if op == 0xaa:                            # tableswitch
            pad = (4 - ((i + 1) % 4)) % 4
            base = i + 1 + pad
            lo, hi = struct.unpack(">ii", code[base + 4:base + 12])
            i = base + 12 + (hi - lo + 1) * 4
            continue
        if op == 0xab:                            # lookupswitch
            pad = (4 - ((i + 1) % 4)) % 4
            base = i + 1 + pad
            npairs = struct.unpack(">i", code[base + 4:base + 8])[0]
            i = base + 8 + npairs * 8
            continue
        if op == 0xc4:                            # wide
            i += 6 if code[i + 1] == 0x84 else 4
            continue
        if op in (0xb6, 0xb7, 0xb8, 0xb9):        # invoke*
            idx = struct.unpack(">H", code[i + 1:i + 3])[0]
            e = cp[idx] if idx < len(cp) else None
            if e and e[0] == "r":
                _, nt_i = e[1]
                nte = cp[nt_i]
                if nte and nte[0] == "nt":
                    out.append((cls_of(cp, e[1][0]), utf(nte[1][0]), utf(nte[1][1])))
            i += 3 if op != 0xb9 else 5
            continue
        if op == 0xba:                            # invokedynamic
            i += 5
            continue
        i += 1 + OP_LEN.get(op, 0)
    return out


def cls_of(cp: list, idx: int) -> str:
    e = cp[idx]
    if e and e[0] == "c":
        u = cp[e[1]]
        return u[1] if u and u[0] == "u" else ""
    return ""


def load_jars(conn: sqlite3.Connection, targets_dir: str | Path) -> dict:
    classes: dict[str, dict] = {}
    for jar in sorted(Path(targets_dir).glob("*.jar")):
        with zipfile.ZipFile(jar) as z:
            for ent in z.namelist():
                if not ent.endswith(".class") or "-" in Path(ent).stem:
                    continue
                try:
                    ci = parse_class(z.read(ent))
                except Exception:
                    continue
                if ci:
                    classes[ci["this"]] = ci

    _closure_cache: dict[str, set[str]] = {}
    def closure(name: str) -> set[str]:
        if name in _closure_cache:
            return _closure_cache[name]
        seen, stack = set(), [name]
        while stack:
            c = stack.pop()
            if c in seen:
                continue
            seen.add(c)
            if c in classes:
                stack.append(classes[c]["super"])
                stack.extend(classes[c]["ifcs"])
        _closure_cache[name] = seen
        return seen

    ser_cache: dict[str, bool] = {}
    def serializable(name: str) -> bool:
        if name in ser_cache:
            return ser_cache[name]
        ok = any(x == "java/io/Serializable" or x in KNOWN_SERIAL_SUPERS for x in closure(name))
        ser_cache[name] = ok
        return ok

    # ---- 1. 方法节点 ----
    nid = 0
    mid: dict[tuple[str, str, str], int] = {}
    for cn, ci in classes.items():
        ser = 1 if serializable(cn) else 0
        for (mn, md) in ci["methods"]:
            nid += 1
            mid[(cn, mn, md)] = nid
            cat = ""
            role = "NONE"
            for owner_suffix, sname, scat in JAR_SINKS:
                if cn.split("/")[-1] == owner_suffix and mn == sname:
                    role, cat = "SINK", scat
            add_node(conn, Node(nid, "METHOD", cn.replace("/", "."), f"{mn}{md}",
                                role=role, sink_category=cat or None, serializable=ser,
                                evidence=f"{cn}.class"))

    # ---- 2. 模型节点: hubs / JDK sinks / 引擎 ----
    def model(owner: str, sig: str, kind: str, role: str, cat: str | None = None) -> int:
        nonlocal nid
        nid += 1
        add_node(conn, Node(nid, kind, owner, sig, role=role, sink_category=cat,
                            serializable=1, evidence="jdk-model"))
        return nid

    hub_ids = {h: model(f"jdk.hub.{h}", "dispatch()", "ENGINE", "ENGINE") for h in HUBS}
    cmp_hub = model("jdk.hub.CMP_HUB", "dispatch()", "ENGINE", "ENGINE")
    fjson_hub = model("com.alibaba.fastjson.serializer", "getterDispatch()", "ENGINE", "ENGINE")
    reflect_hub = model("jdk.hub.REFLECT_HUB", "dispatch()", "ENGINE", "ENGINE")
    bave = model("javax.management.BadAttributeValueExpException", "readObject()", "METHOD", "SOURCE")
    jdk_sink_ids: dict[tuple[str, str], int] = {}
    for owner, name, cat in JDK_SINKS:
        jdk_sink_ids[(owner, name)] = model(owner, f"{name}(...)", "METHOD", "SINK", cat)
    tpl_get = model("c.s.o.a.x.t.TemplatesImpl", "getOutputProperties()", "METHOD", "NONE")
    add_edge(conn, tpl_get, jdk_sink_ids[("c.s.o.a.x.t.TemplatesImpl", "defineTransletClasses")],
             "call", provenance="jdk-model")

    # ---- 3. 触发边: hub → 符合签名的可序列化类方法 ----
    def hub_fan(hub: int, name: str, desc: str | None, prefixes: tuple[str, ...] = ()) -> int:
        cnt = 0
        for (cn, mn, md), n in mid.items():
            if mn == name and (desc is None or md == desc) and classes[cn] and \
               mid.get((cn, mn, md)) and serializable(cn) and \
               (not prefixes or mn.startswith(prefixes)):
                add_edge(conn, hub, n, "field_dispatch", provenance="jdk-model:implicit-trigger")
                cnt += 1
        return cnt

    fan = {h: hub_fan(hub_ids[h], nm, ds) for h, (nm, ds) in HUBS.items()}
    fan_cmp = hub_fan(cmp_hub, "compare", None) + hub_fan(cmp_hub, "compareTo", None)
    # fastjson getter 引擎语义（跨格式 inner_engine）
    fan_json = 0
    for (cn, mn, md), n in mid.items():
        if md == "()Ljava/lang/String;" or md.startswith("()"):
            if mn.startswith(GETTER_PREFIX) and serializable(cn):
                add_edge(conn, fjson_hub, n, "field_dispatch", provenance="model:fastjson-getter")
                fan_json += 1
    for (cn, mn, md), n in mid.items():          # fastjson toJSONString 入口 → 引擎
        if cn.startswith("com/alibaba/fastjson") and mn in ("toJSONString", "writeTo"):
            add_edge(conn, n, fjson_hub, "format_engine", provenance="model:fastjson-engine")
    add_edge(conn, bave, hub_ids["TOSTRING_HUB"], "triggers", provenance="jdk-model:BAVE")
    # JDK 隐式触发 Source 种子（知识图谱 §3.2）
    trigger_sources = [
        ("java.util.HashMap", "readObject()", hub_ids["HASH_HUB"]),
        ("java.util.HashSet", "readObject()", hub_ids["HASH_HUB"]),
        ("java.util.LinkedHashSet", "readObject()", hub_ids["HASH_HUB"]),
        ("java.util.Hashtable", "readObject()", hub_ids["EQUALS_HUB"]),
        ("java.util.PriorityQueue", "readObject()", cmp_hub),
        ("java.util.TreeMap", "readObject()", cmp_hub),
    ]
    for owner, sig, hub in trigger_sources:
        s = model(owner, sig, "METHOD", "SOURCE")
        add_edge(conn, s, hub, "triggers", provenance="jdk-model:implicit-trigger")
    # 进化引擎种子：LLM 决策的显式入口（绕过序列化启发式的定向边）
    for seed in _ENGINE_SEEDS:
        for (cn, mn, md), n in mid.items():
            if cn.replace("/", ".").startswith(tuple([seed["owner"]])) and mn == seed.get("method", "toString"):
                add_edge(conn, hub_ids.get(seed.get("hub", "TOSTRING_HUB"), hub_ids["TOSTRING_HUB"]),
                         n, "field_dispatch", provenance="evolution:engine-seed")
                break

    # ---- 4. 真实调用边（CHA-lite）----
    real = disp = to_sink = to_reflect = 0
    subtypes: dict[str, list[str]] = {}
    for cn in classes:
        for anc in closure(cn):
            if anc != cn:
                subtypes.setdefault(anc, []).append(cn)
    jdk_sink_lookup = {(o.replace("/", "."), s): (o, s) for o, s, _ in JDK_SINKS}
    for (cn, mn, md), n in mid.items():
        for (tc, tn, td) in classes[cn]["methods"][(mn, md)]:
            key = (tc.replace("/", "."), tn)
            if key in jdk_sink_lookup:
                add_edge(conn, n, jdk_sink_ids[key], "call", provenance="jar-bytecode")
                to_sink += 1
            elif tc == "java/lang/reflect/Method" and tn == "invoke":
                add_edge(conn, n, reflect_hub, "reflection", provenance="jar-bytecode")
                to_reflect += 1
            elif tc in classes:
                targets = [tc] + subtypes.get(tc, [])
                hit = [t for t in targets if (t, tn, td) in mid]
                if len(hit) <= 1:
                    if (tc, tn, td) in mid:
                        add_edge(conn, n, mid[(tc, tn, td)], "call", provenance="jar-bytecode")
                        real += 1
                else:
                    for t in hit:
                        add_edge(conn, n, mid[(t, tn, td)], "field_dispatch",
                                 precision="CHA", provenance="cha-lite")
                        disp += 1
    # 反射 hub → JDK 危险目标（保守受限集）
    for owner, name, _cat in JDK_SINKS:
        add_edge(conn, reflect_hub, jdk_sink_ids[(owner, name)], "reflection",
                 provenance="jdk-model:reflect")
    add_edge(conn, reflect_hub, tpl_get, "reflection", provenance="jdk-model:reflect-getter")

    conn.commit()
    return {"classes": len(classes), "methods": len(mid), "real_call_edges": real,
            "dispatch_edges": disp, "sink_edges": to_sink, "reflect_edges": to_reflect,
            "hub_fanout": {**fan, "CMP_HUB": fan_cmp, "FASTJSON_GETTER": fan_json}}
