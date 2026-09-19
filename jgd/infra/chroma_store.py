"""向量数据库存储层（Chroma，持久化 ~/jgd/chromadb，稠密向量 + HNSW 检索）。"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from jgd import PROJECT_ROOT

CHROMA_DIR = str(Path.home() / "jgd/chromadb")
def _collection_name() -> str:
    """(F1): RAG 按语料指纹分域 — 换语料自动新 collection, 杜绝跨语料污染。"""
    from jgd.infra import scope
    return f"jgd_rag_{scope.corpus_fp()}" if os.environ.get("JGD_TARGET") else "jgd_rag"


COLLECTION = "jgd_rag"
_WORD = re.compile(r"[^A-Za-z0-9\u4e00-\u9fff]+")
DENSE_DIM = 2048

_CN_EN = {
    "反序列化": "deserialization", "序列化": "serialization", "可序列化": "serializable",
    "触发": "trigger", "触发器": "trigger", "桥接": "bridge", "桥": "bridge",
    "字段": "field", "方法": "method", "调用": "invoke call", "转发": "forward",
    "入口": "entry source", "终端": "sink terminal", "命令执行": "exec RCE",
    "字节码": "bytecode defineClass", "加载": "load class", "远程": "remote JNDI",
    "文件写入": "file write FileOutputStream", "嵌套": "nested inner",
    "比较器": "comparator compare", "代理": "proxy InvocationHandler",
    "传播": "propagate transform", "引擎": "engine serializer getter",
    "可注入": "injectable writable", "开放": "open Object interface",
    "哈希": "hashCode hash", "相等": "equals", "字符串": "toString string",
    "绕过": "bypass JPMS filter", "过滤器": "filter JEP290",
    "模板": "TemplatesImpl translet", "注解": "annotation JSONType",
    "缓存": "cache mapping", "映射": "mapping Map", "集合": "collection HashSet",
    "队列": "queue PriorityQueue", "堆": "heap tree",
}


def _expand_query(text: str) -> str:
    expanded = text
    for cn, en in _CN_EN.items():
        if cn in text and en not in expanded:
            expanded += " " + en
    return expanded


def _text(d: dict) -> str:
    return " ".join(filter(None, [d.get("id", ""), d.get("type", ""),
                                  " ".join(d.get("tags", [])),
                                  json.dumps(d.get("payload", {}), ensure_ascii=False)]))


def _tokens(text: str) -> list[str]:
    toks: list[str] = []
    for w in _WORD.split(text):
        if not w:
            continue
        toks.extend([w.lower()] if w.isascii() else list(w))
    return toks


def _hash_dense(text: str) -> list[float]:
    import hashlib
    vec = [0.0] * DENSE_DIM
    for t in _tokens(text):
        h = int(hashlib.md5(t.encode()).hexdigest()[:8], 16)
        vec[h % DENSE_DIM] += 1.0
        vec[-(h % DENSE_DIM) - 1] -= 0.5
    norm = sum(x * x for x in vec) ** 0.5 or 1.0
    return [x / norm for x in vec]


class VStore:
    def __init__(self) -> None:
        import os
        import chromadb
        self.client = chromadb.PersistentClient(path=CHROMA_DIR)
        mode = os.environ.get("JGD_EF", "minilm")
        if mode == "minilm":
            try:
                ef = chromadb.utils.embedding_functions.DefaultEmbeddingFunction()
                self.col = self.client.get_or_create_collection(_collection_name(), embedding_function=ef)
                self.mode = "chroma-default-minilm"
                return
            except Exception:
                mode = "hash"
        self.col = self.client.get_or_create_collection(_collection_name())
        self.mode = "chroma-hash-dense"

    def add(self, docs: list[dict]) -> None:
        if not docs:
            return
        uniq: dict[str, dict] = {}
        for d in docs:
            uniq[d.get("id", "")] = d                 # 同 id 后写覆盖
        docs = list(uniq.values())
        ids = [d.get("id", "") for d in docs]
        texts = [_text(d) for d in docs]
        metas = [{"type": d.get("type", ""),
                  "tags": json.dumps(d.get("tags", []), ensure_ascii=False)} for d in docs]
        if self.mode == "chroma-default-minilm":
            self.col.upsert(ids=ids, documents=texts, metadatas=metas)
        else:
            self.col.upsert(ids=ids, documents=texts, metadatas=metas,
                            embeddings=[_hash_dense(t) for t in texts])

    def count(self) -> int:
        return self.col.count()

    def stats(self) -> dict:
        out: dict[str, int] = {}
        got = self.col.get(include=["metadatas"])
        for m in got.get("metadatas") or []:
            t = (m or {}).get("type", "?")
            out[t] = out.get(t, 0) + 1
        return out

    def query(self, text: str, topk: int = 6, where: dict | None = None):
        if self.mode == "chroma-default-minilm":
            r = self.col.query(query_texts=[_expand_query(text)], n_results=min(topk, max(self.count(), 1)),
                               where=where, include=["documents", "metadatas", "distances"])
        else:
            r = self.col.query(query_embeddings=[_hash_dense(_expand_query(text))],
                               n_results=min(topk, max(self.count(), 1)), where=where,
                               include=["documents", "metadatas", "distances"])
        ids, dists, metas, docs = r["ids"][0], r["distances"][0], r["metadatas"][0], r.get("documents", [[]])[0]
        out = []
        for i in range(len(ids)):
            import json as _j
            try:
                payload = _j.loads(docs[i].split("{", 1)[1].rsplit("}", 1)[0].join(["{", "}"])) \
                    if "{" in docs[i] else {}
            except Exception:
                payload = {}
            out.append((round(dists[i], 4), {
                "id": ids[i], "type": (metas[i] or {}).get("type", ""),
                "tags": (metas[i] or {}).get("tags", "[]"),
                "payload": payload,
                "document_text": docs[i][:300] if i < len(docs) else "",
            }))
        return out


def backfill_jsonl() -> int:
    src = PROJECT_ROOT / "vecrag_store.json"
    if not src.exists():
        return 0
    docs = [{k: v for k, v in d.items() if k != "_tf"}
            for d in json.loads(src.read_text(encoding="utf-8"))]
    st = VStore()
    st.add(docs)
    return len(docs)


def backfill_sink_live() -> int:
    src = PROJECT_ROOT / "sink_points_live.json"
    if not src.exists():
        return 0
    docs: list[dict] = []
    for sink, recs in json.loads(src.read_text(encoding="utf-8")).items():
        for r in recs:
            if r.get("err"):
                continue
            open_inj = [f for f in r.get("fields", []) if f.get("open") and f.get("injectable")]
            docs.append({"id": f"sinkcap:{sink}:{r['class']}",
                         "type": "sink_runtime_capability",
                         "tags": [sink] + (["open_injectable_field"] if open_inj else [])
                                 + (["instantiable"] if r.get("instance") == "OK" else []),
                         "payload": r})
    st = VStore()
    st.add(docs)
    return len(docs)
