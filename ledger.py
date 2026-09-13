"""JGD v0 -- 全局账本（StateLedger）+ 图契约 v0.1（冻结）。

契约 v0.1（2026-09-12 冻结，架构文档 §5.4 D-1）：
  节点: node_id(整数持久) / kind / owner / signature / role / 元数据
  边(11类): call | triggers | field_dispatch | reachable_via_field | reflection |
            proxy | lambda | mh | unsafe | filter_check | format_engine
  每条边: precision(CHA|CHA+dynamic|pointer-sensitive) / provenance / impl_status
验收用例:
  A1  CC6:      HashSet --triggers--> put --field_dispatch--> hashCode ... --> RCE sink
  A2  跨格式:    BAVE --triggers--> toString --format_engine--> JSONArray.toString
                 --field_dispatch--> getOutputProperties --> CLASS_LOAD sink
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

CONTRACT_VERSION = "contract-v0.1"
CONTRACT_FROZEN_AT = "2026-09-12"

EDGE_TYPES = (
    "call", "triggers", "field_dispatch", "reachable_via_field", "reflection",
    "proxy", "lambda", "mh", "unsafe", "filter_check", "format_engine",
)
# JVM 动态边界：区域分割（S1）在这些边上切区域（GadgetHunter 区域语义）
DYNAMIC_BOUNDARY = ("field_dispatch", "reflection", "proxy", "lambda", "mh", "unsafe", "format_engine")
PRECISIONS = ("CHA", "CHA+dynamic", "pointer-sensitive")

DDL = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS nodes(
  node_id INTEGER PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind IN ('CLASS','METHOD','FIELD','DEFENSE','ENGINE')),
  owner TEXT NOT NULL,
  signature TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK(role IN ('SOURCE','GADGET','SINK','DEFENSE','ENGINE','FIELD','NONE')),
  sink_category TEXT,
  serializable INTEGER NOT NULL DEFAULT 0,
  j3_meta TEXT,               -- JSON: writable/transient/final/suid_ok/writeReplace
  evidence TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS edges(
  src_id INTEGER NOT NULL REFERENCES nodes(node_id),
  dst_id INTEGER NOT NULL REFERENCES nodes(node_id),
  edge_type TEXT NOT NULL CHECK(edge_type IN (%(edges)s)),
  precision TEXT NOT NULL CHECK(precision IN ('CHA','CHA+dynamic','pointer-sensitive')),
  provenance TEXT NOT NULL,
  impl_status TEXT NOT NULL CHECK(impl_status IN ('已实现','设计','未定义')),
  evidence TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(src_id, dst_id, edge_type)
);
CREATE TABLE IF NOT EXISTS control_matrix(
  node_id INTEGER NOT NULL, env_id TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK(verdict IN ('ALIVE','DEAD','DEGRADED','NEW','UNKNOWN')),
  evidence TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(node_id, env_id)
);
CREATE TABLE IF NOT EXISTS probe_events(
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL, env_id TEXT NOT NULL,
  probe TEXT NOT NULL, site TEXT NOT NULL,
  payload_sha TEXT NOT NULL, captured TEXT NOT NULL DEFAULT '{}',
  ts INTEGER NOT NULL DEFAULT (CAST(strftime('%%s','now') AS INTEGER))
);
CREATE TABLE IF NOT EXISTS candidates(
  chain_id TEXT PRIMARY KEY,
  scheme TEXT NOT NULL,
  points_path TEXT NOT NULL,      -- JSON: [node_id...]
  ablation TEXT NOT NULL DEFAULT 'full',
  status TEXT NOT NULL CHECK(status IN ('PENDING','CONFIRMED','REFUTED','DEGRADED','REJECTED','BLOCKED_PER_GATE')),
  confidence REAL NOT NULL DEFAULT 0.0,
  evidence TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scheme_runs(
  run_id TEXT PRIMARY KEY, scheme TEXT NOT NULL, ablation TEXT NOT NULL,
  started_at INTEGER NOT NULL, ended_at INTEGER, metrics TEXT NOT NULL DEFAULT '{}'
);
""" % {"edges": ",".join(f"'{e}'" for e in EDGE_TYPES)}


@dataclass(frozen=True)
class Node:
    node_id: int
    kind: str
    owner: str
    signature: str
    role: str = "NONE"
    sink_category: str | None = None
    serializable: int = 0
    j3_meta: str = "{}"
    evidence: str = ""


def open_ledger(path: str | Path = ":memory:") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(DDL)
    conn.execute("INSERT OR REPLACE INTO meta VALUES('contract_version', ?)", (CONTRACT_VERSION,))
    conn.execute("INSERT OR REPLACE INTO meta VALUES('contract_frozen_at', ?)", (CONTRACT_FROZEN_AT,))
    conn.commit()
    return conn


def add_node(conn: sqlite3.Connection, n: Node) -> int:
    conn.execute(
        "INSERT OR REPLACE INTO nodes VALUES(?,?,?,?,?,?,?,?,?)",
        (n.node_id, n.kind, n.owner, n.signature, n.role, n.sink_category,
         n.serializable, n.j3_meta, n.evidence),
    )
    return n.node_id


def add_edge(conn: sqlite3.Connection, src: int, dst: int, edge_type: str,
             precision: str = "CHA", provenance: str = "fixture",
             impl_status: str = "已实现", evidence: str = "") -> None:
    if edge_type not in EDGE_TYPES:
        raise ValueError(f"edge_type {edge_type!r} 不在契约 v0.1 的 11 类边中")
    if precision not in PRECISIONS:
        raise ValueError(f"precision {precision!r} 非法")
    conn.execute("INSERT OR REPLACE INTO edges VALUES(?,?,?,?,?,?,?)",
                 (src, dst, edge_type, precision, provenance, impl_status, evidence))


def seed_acceptance_fixtures(conn: sqlite3.Connection) -> None:
    """两条验收链的最小合成图 + 一个防御节点 + control_matrix 样例。"""
    nodes = [
        # A1: CC6（简化但保语义：隐式触发 + 虚分派 + 反射）
        Node(1, "METHOD", "java.util.HashSet", "readObject()", role="SOURCE", serializable=1),
        Node(2, "METHOD", "java.util.HashMap", "put(java.lang.Object,java.lang.Object)", serializable=1),
        Node(3, "METHOD", "org.apache.commons.collections.keyvalue.TiedMapEntry", "hashCode()", serializable=1),
        Node(4, "METHOD", "org.apache.commons.collections.keyvalue.TiedMapEntry", "getValue()", serializable=1),
        Node(5, "METHOD", "org.apache.commons.collections.map.LazyMap", "get(java.lang.Object)", serializable=1),
        Node(6, "METHOD", "org.apache.commons.collections.functors.ChainedTransformer", "transform(java.lang.Object)", serializable=1),
        Node(7, "METHOD", "org.apache.commons.collections.functors.InvokerTransformer", "transform(java.lang.Object)", serializable=1),
        Node(8, "METHOD", "java.lang.Runtime", "exec(java.lang.String[])", role="SINK", sink_category="RCE"),
        # A2: 外层 Native + 内层 fastjson（跨格式）
        Node(11, "METHOD", "javax.management.BadAttributeValueExpException", "readObject()", role="SOURCE", serializable=1),
        Node(12, "METHOD", "java.lang.Object", "toString()", serializable=1),
        Node(13, "ENGINE", "com.alibaba.fastjson.JSONArray", "toString()", role="ENGINE", serializable=1),
        Node(14, "METHOD", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "getOutputProperties()", serializable=1),
        Node(15, "METHOD", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "defineTransletClasses()", role="SINK", sink_category="CLASS_LOAD"),
        # J3 相关字段与防御节点
        Node(21, "FIELD", "org.apache.commons.collections.keyvalue.TiedMapEntry", "map",
             role="FIELD", j3_meta='{"writable":true,"transient":false,"final":false,"suid_ok":true,"writeReplace":false}'),
        Node(22, "FIELD", "javax.management.BadAttributeValueExpException", "val",
             role="FIELD", j3_meta='{"writable":true,"transient":false,"final":false,"suid_ok":true,"writeReplace":false}'),
        Node(23, "FIELD", "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl", "_bytecodes",
             role="FIELD", j3_meta='{"writable":true,"transient":false,"final":false,"suid_ok":true,"writeReplace":false}'),
        Node(30, "DEFENSE", "com.alibaba.fastjson.JSONArray", "resolveClass-blocklist", role="DEFENSE",
             evidence="fastjson>=1.2.49 重写 resolveClass 过滤危险类"),
    ]
    for n in nodes:
        add_node(conn, n)

    edges = [
        # A1
        (1, 2, "triggers", "CHA+dynamic", "隐式触发: HashSet 反序列化 put key"),
        (2, 3, "field_dispatch", "CHA", "putVal→hash(key)→虚分派"),
        (3, 4, "call", "CHA", ""),
        (4, 5, "call", "CHA", "getValue→map.get"),
        (5, 6, "call", "CHA", "factory.transform"),
        (6, 7, "call", "CHA", ""),
        (7, 8, "reflection", "CHA+dynamic", "InvokerTransformer 反射调用"),
        # J3: 字段可达
        (3, 21, "reachable_via_field", "pointer-sensitive", "TiedMapEntry.map"),
        (11, 22, "reachable_via_field", "pointer-sensitive", "BAVE.val"),
        (14, 23, "reachable_via_field", "pointer-sensitive", "TemplatesImpl._bytecodes"),
        # A2
        (11, 12, "triggers", "CHA+dynamic", "BAVE.readObject→val.toString()"),
        (12, 13, "format_engine", "CHA+dynamic", "进入 fastjson 序列化引擎(inner_engine)"),
        (13, 14, "field_dispatch", "CHA+dynamic", "ListSerializer 逐元素 getter 分派"),
        (14, 15, "call", "CHA", "getOutputProperties→newTransformer→defineTransletClasses"),
        # 防御挂载
        (13, 30, "filter_check", "CHA", "fastjson 内层 resolveClass 检查点"),
    ]
    for src, dst, et, prec, ev in edges:
        add_edge(conn, src, dst, et, precision=prec, evidence=ev)

    conn.executemany("INSERT OR REPLACE INTO control_matrix VALUES(?,?,?,?)", [
        (13, "jdk8-fastjson1.2.47", "ALIVE", "1.2.47 无 resolveClass 重写"),
        (13, "jdk8-fastjson1.2.83", "DEGRADED", ">=1.2.49 resolveClass 过滤 TemplatesImpl → 需引用类型绕过"),
        (30, "jdk8-fastjson1.2.47", "ALIVE", "防御不存在"),
        (30, "jdk8-fastjson1.2.83", "ALIVE", "防御存在但可绕过(引用句柄/再嵌 SignedObject)"),
    ])
    conn.commit()
