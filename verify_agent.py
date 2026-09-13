"""JGDVerifyAgent — 验证回路作为 JGD 的一等 agent 步骤（R6 架构修正）。

背景: 上一轮审计的教训。修正检测器、动态验证、dsh 交叉验证曾在主循环以
临时脚本运行（用户指正: "为什么刚才的调用和产出验证分析逻辑在agent外面?"）。
验证不是编排者的旁路工作，它是挖掘回路的一部分 — 验证结论必须进 RAG、
进状态、进下一轮候选过滤，否则进化循环拿不到反馈。

本 agent 职责（全部在 agent 内完成）:
  1. fixed_scan      — 用 R6 修正后的 static_probe（接收者感知桥检测 + 修正
                       open_fields）重扫语料，产出真桥候选
  2. local_grade     — 本地规则分级: 字段类型平凡(String/List/Map/装箱类)
                       =TRIVIAL；接口/自定义类字段=INTERESTING；公开链语料比对
  3. dynamic_verify  — 多 JDK 动态验证（JDK 11/17），FAIL(能力否定) 与
                       ERROR(环境阻塞) 分开记账
  4. ds_cross_audit  — agent 自己调 llm.ask('ds') 对每个 INTERESTING 候选做
                       对抗审计（发现者≠验证者）
  5. glm_defense     — ds 否决时 glm 有一次辩护权；分歧标记 DISPUTED
  6. persist         — 结论写 RAG(chroma_store) + verify_state.json + 报告

用法: python3 verify_agent.py [--max-dynamic N] [--no-dynamic] [--no-llm]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import chroma_store
import scope
import llm
import matrix_agent as ma
from chains_2026 import CHAINS_2026

STATE = scope.DATA / "verify_state.json"
REPORT = scope.DATA / "verify_report.md"
CANDIDATES = scope.DATA / "verify_candidates.json"

TRIVIAL_FIELD_TYPES = (
    "java/lang/String", "java/lang/Integer", "java/lang/Long",
    "java/lang/Boolean", "java/lang/Double", "java/lang/Float",
    "java/lang/CharSequence", "java/lang/Number",
    "java/util/List", "java/util/Map", "java/util/Set",
    "java/util/Collection", "java/util/HashMap", "java/util/ArrayList",
)
KNOWN_FINAL_JDK = ("java/lang/String", "java/lang/Integer", "java/lang/Long",
                   "java/lang/Boolean", "java/io/File", "java/net/Socket")


def field_type_of(desc: str) -> str:
    """Lcom/foo/Bar; -> com/foo/Bar (数组/原生按原样返回)."""
    d = desc.strip()
    if d.startswith("["):
        return "ARRAY:" + field_type_of(d[1:])
    if d.startswith("L") and d.endswith(";"):
        return d[1:-1]
    return d


SUBCLASS_CACHE = scope.DATA / "verify_subclasses.json"


def find_concrete_subclasses(targets: list[str], budget_s: float = 240.0) -> dict[str, list]:
    """在语料中为抽象候选找具体可序列化子类 (agent 自有能力, 带缓存+时间预算)。

    抽象类本身不能进反序列化流(OIS/Unsafe 都拒绝抽象类实例化),
    桥要成立必须存在具体 + Serializable 的子类作为流内载体。
    """
    import zipfile
    import staticagent
    cache: dict[str, list] = (json.loads(SUBCLASS_CACHE.read_text(encoding="utf-8"))
                              if SUBCLASS_CACHE.exists() else {})
    want = {t.replace(".", "/") for t in targets if t not in cache}
    if not want:
        return {t: cache.get(t, []) for t in targets}

    import time as _t
    t0 = _t.time()
    hits: dict[str, list] = {w: [] for w in want}
    for jar in sorted(ma.IMPACT.glob("*.jar")):
        if _t.time() - t0 > budget_s:
            break
        try:
            with zipfile.ZipFile(jar) as z:
                for ent in z.namelist():
                    if not ent.endswith(".class") or "$" in ent:
                        continue
                    cn = ent[:-6]
                    if cn in want:
                        continue  # 目标自身不算
                    try:
                        ci = staticagent.parse_class(z.read(ent))
                    except Exception:
                        continue
                    if not ci or ci.get("super") not in want:
                        continue
                    abstract = bool(ci.get("caccess", 0) & 0x0400)
                    ser = ("java/io/Serializable" in ci.get("ifcs", [])
                           or ci.get("super") in staticagent.KNOWN_SERIAL_SUPERS)
                    if not abstract:
                        hits[ci["super"]].append(
                            {"cls": cn.replace("/", "."), "jar": jar.name,
                             "serializable": ser})
        except Exception:
            continue
    for k, v in hits.items():
        cache[k.replace("/", ".")] = v
    SUBCLASS_CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=1),
                              encoding="utf-8")
    return {t: cache.get(t, []) for t in targets}


def enrich_with_hierarchy(graded: list[dict]) -> None:
    """就地补充: 抽象标志 + 具体子类搜索结果 (只对 INTERESTING 候选)."""
    import zipfile
    import staticagent
    seen: set[str] = set()
    targets: list[str] = []
    for g in graded:
        if g["grade"] != "INTERESTING" or g["cls"] in seen:
            continue
        seen.add(g["cls"])
        jar = g.get("jar", "")
        jp = ma.IMPACT / jar if (ma.IMPACT / jar).exists() else HERE / "_verify" / jar
        try:
            with zipfile.ZipFile(jp) as z:
                ci = staticagent.parse_class(
                    z.read(g["cls"].replace(".", "/") + ".class"))
            g["abstract"] = bool((ci or {}).get("caccess", 0) & 0x0400)
        except Exception:
            g["abstract"] = None  # jar 不可达, 未知
        if g["abstract"]:
            targets.append(g["cls"])
    if targets:
        print(f"  [hierarchy] {len(targets)} 个抽象候选 → 搜索具体子类...")
        subs = find_concrete_subclasses(targets)
        for g in graded:
            if g.get("abstract"):
                g["concrete_subclasses"] = subs.get(g["cls"], [])


_PUBLIC_CLS_CACHE: set[str] | None = None


def public_chain_classes() -> set[str]:
    global _PUBLIC_CLS_CACHE
    if _PUBLIC_CLS_CACHE is None:
        _PUBLIC_CLS_CACHE = {h["cls"].replace(".", "/")
                             for c in CHAINS_2026 if isinstance(c, dict)
                             for h in c.get("hops", []) if isinstance(h, dict) and "cls" in h}
    return _PUBLIC_CLS_CACHE


def local_grade(cand: dict) -> dict:
    """本地规则分级, 不调 LLM。"""
    ft = field_type_of(cand.get("field_desc", ""))
    trivial = (not ft) or any(t in ft for t in TRIVIAL_FIELD_TYPES)
    cls_slash = cand.get("cls", "").replace(".", "/")
    in_public = cls_slash in public_chain_classes()
    if in_public:
        grade = "KNOWN_IN_PUBLIC"
    else:
        grade = "TRIVIAL" if trivial else "INTERESTING"
    return {"grade": grade, "field_type": ft, "in_public_chain": in_public,
            "trivial_field": trivial}


def ds_cross_audit(cand: dict, grade: dict, dynamic: dict | None) -> dict:
    """verifier 对抗审计 — 发现者是静态检测器, 验证者是另一个模型。"""
    ev = {
        "class": cand["cls"],
        "jar": cand.get("jar", "?"),
        "bridge": f"{cand['trigger']}() -> this.{cand['field']} ({cand['field_desc']})"
                  f" -> {cand['target']}",
        "field_type": grade["field_type"],
        "abstract": cand.get("abstract"),
        "concrete_subclasses": cand.get("concrete_subclasses"),
        "open_fields": dynamic.get("open_fields") if dynamic else None,
        "dynamic_verdict": dynamic.get("dynamic_verdict") if dynamic else "NOT_RUN",
        "probed_via_subclass": cand.get("probed_via_subclass"),
        "in_public_chain_corpus": grade["in_public_chain"],
        "local_grade": grade["grade"],
    }
    prompt = (
        "你是反序列化 gadget 链的对抗审计员（发现者≠验证者）。静态字节码检测器"
        "（接收者感知的操作数栈模拟，已修正旧版假阳性）报告了如下字段桥候选。\n"
        "请严格审计: 1) 桥语义是否成立 2) 字段类型能否承载攻击者控制的对象"
        "（注意 ObjectInputStream 反射写字段有 isInstance 检查; final 类如"
        " String 无法派生; 接口字段可承载 java.lang.reflect.Proxy 动态代理,"
        " 分派进 InvocationHandler.invoke — 这是合法路径, 不要以'接口方法太多"
        "没人能实现'为由否决）3) abstract=true 时该类不能直接进流, 需看"
        " concrete_subclasses 是否提供具体可序列化载体 4) 目标方法是否有副作用/"
        "二次分派深度 5) 是否值得进入挖掘回路的候选池。\n"
        "输出 JSON: {\"verdict\": \"CONFIRM|REJECT|DOWNGRADE\", "
        "\"tier\": \"T1|T2|T3|none\", \"reason\": \"...\", "
        "\"next_hop\": \"建议的下一跳类或none\"}\n\n"
        + json.dumps(ev, ensure_ascii=False, indent=1)
    )
    resp = llm.ask("ds",
                   "你是严谨的 Java 反序列化安全研究员, 只依据给定证据判断, 不臆测。",
                   prompt, temperature=0.1, max_tokens=900)
    out = {"ds_ok": resp.get("ok", False), "raw": (resp.get("content") or "")[:2000]}
    parsed = llm.extract_json(resp.get("content") or "")
    if isinstance(parsed, dict):
        out.update({k: parsed.get(k) for k in ("verdict", "tier", "reason", "next_hop")})
    else:
        out["verdict"] = "AUDIT_UNPARSEABLE"
    return out


def glm_defense(cand: dict, audit: dict) -> dict | None:
    """ds 否决时, glm 作为发现方有一次辩护权（对抗回路, 沿用 cross_audit 模式）。"""
    if audit.get("verdict") not in ("REJECT", "DOWNGRADE"):
        return None
    prompt = (
        "静态检测器发现以下反序列化字段桥候选, 对抗审计员(verifier)给出了否决/降级"
        " 结论。你是发现方辩护人。请只基于证据反驳或接受 — 不许编造字节码。\n"
        f"候选: {cand['cls']} 桥: {cand['trigger']}->this.{cand['field']}"
        f"({cand['field_desc']})->{cand['target']}\n"
        f"审计结论: {audit.get('verdict')} 理由: {audit.get('reason')}\n"
        "输出 JSON: {\"defense\": \"OVERRIDE|ACCEPT\", \"reason\": \"...\"}"
    )
    resp = llm.ask("glm", "你是反序列化链发现方辩护人, 严谨务实。",
                   prompt, temperature=0.2, max_tokens=600)
    parsed = llm.extract_json(resp.get("content") or "")
    if isinstance(parsed, dict):
        return {"defense": parsed.get("defense"), "reason": parsed.get("reason"),
                "glm_ok": resp.get("ok", False)}
    return None


def pick_jdk(needs: int, jdks: dict[int, str]) -> str | None:
    for major in sorted(jdks):
        if needs <= major:
            return jdks[major]
    return None


def _real_evidence_for(cls: str) -> dict | None:
    """R8: 用修正检测器现场取证 (matrix_state 是旧检测器产物, 不用)."""
    for jar in sorted(ma.IMPACT.glob("*.jar")):
        r = ma.static_probe(str(jar), cls)
        if r.get("verdict") == "NOT_FOUND":
            continue
        r["jar"] = jar.name
        return r
    return None


def audit_triggered_chains(max_n: int = 8) -> int:
    """R8 闭环: 挖掘 agent 的 CHAIN_TRIGGERED 发现回灌对抗审计 (发现者≠验证者)."""
    evolve_state = HERE / "evolve_v2_state.json"
    if not evolve_state.exists():
        print("no evolve state")
        return 0
    disc = [d for d in json.loads(evolve_state.read_text(encoding="utf-8"))
            .get("discoveries", [])
            if "TRIGGERED" in ((d.get("chain") or {}).get("chain_verdict") or "")]
    disc = disc[:max_n]
    print(f"CHAIN_TRIGGERED discoveries to audit: {len(disc)}")
    db = chroma_store.VStore()
    results = []
    for d in disc:
        cls = d["cls"]
        ev = _real_evidence_for(cls)
        if ev:
            cand = {"cls": cls, "jar": ev.get("jar", d.get("jar", "?")),
                    "trigger": (ev.get("trigger_methods") or ["toString"])[0],
                    "field": ",".join(b["field"] for b in ev.get("bridge_detail", [])) or "?",
                    "field_desc": ",".join(b["field_desc"] for b in ev.get("bridge_detail", [])) or "?",
                    "target": ";".join(b["target"] for b in ev.get("bridge_detail", [])) or "?"}
            g = {"field_type": cand["field_desc"],
                 "in_public_chain": cls.replace(".", "/") in public_chain_classes(),
                 "grade": "CHAIN_TRIGGERED"}
            dyn = {"dynamic_verdict": "CHAIN_TRIGGERED(BAVE→bridge→字段对象分派, JDK11全链路)",
                   "open_fields": ev.get("open_fields")}
        else:
            print(f"  {cls.split('.')[-1]}: matrix_state 无静态证据, 跳过")
            continue
        print(f"\n  ds 审计(链) {cls.split('.')[-1]} ...")
        audit = ds_cross_audit(cand, g, dyn)
        print(f"    -> {audit.get('verdict')} tier={audit.get('tier')} "
              f"{(audit.get('reason') or '')[:120]}")
        results.append({"cls": cls, "evidence": {k: cand[k] for k in
                         ("jar", "trigger", "field", "field_desc", "target")},
                        "ds_audit": audit, "final_verdict": audit.get("verdict")})
    out = scope.scoped(HERE / "jgd_chain_audit.json")
    # R12: 合并不覆盖 — ds 审计有非确定性, 历史确认不能被单轮翻供抹掉;
    # 同类取最新结论, 但 CONFIRM 需两轮连续翻供才降级(置信保持)
    history: dict[str, dict] = {}
    if out.exists():
        for r in json.loads(out.read_text(encoding="utf-8")):
            history[r["cls"]] = r
    for r in results:
        old = history.get(r["cls"])
        if (old and old.get("final_verdict") == "CONFIRM"
                and r["final_verdict"] != "CONFIRM"):
            r["flips"] = old.get("flips", 0) + 1
            if r["flips"] < 2:
                r["final_verdict"] = "CONFIRM"  # 首次翻供不采信
                r["ds_audit"] = old.get("ds_audit", r["ds_audit"])
        elif old and old.get("final_verdict") != "CONFIRM":
            r["flips"] = old.get("flips", 0)
        history[r["cls"]] = r
    merged = list(history.values())
    out.write_text(json.dumps(merged, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    db.add([{"id": f"chainaudit:{r['cls']}", "type": "jgd_chain_audit_result",
             "tags": [r["final_verdict"].lower()],
             "payload": r} for r in merged])
    print(f"\n链审计结论: { {r['final_verdict'] for r in merged} } "
          f"(合并后 {len(merged)} 条) -> jgd_chain_audit.json + RAG")
    return len(merged)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-dynamic", type=int, default=12)
    ap.add_argument("--max-audit", type=int, default=15)
    ap.add_argument("--no-dynamic", action="store_true")
    ap.add_argument("--no-llm", action="store_true")
    ap.add_argument("--audit-chains", action="store_true")
    args = ap.parse_args()
    t0 = time.time()

    # R49(语料分域): verify 状态同样按指纹隔离
    _fp = ma.corpus_fingerprint() if hasattr(ma, "corpus_fingerprint") else None
    if _fp and (scope.DATA / "verify_state.json").exists():
        import json as _json
        _old = _json.loads((scope.DATA / "verify_state.json").read_text(
            encoding="utf-8"))
        if _old.get("corpus_fp") not in (None, _fp):
            (scope.DATA / "verify_state.json").rename(
                HERE / f"verify_state.{_old['corpus_fp'][:8]}.json")
            print(f"[r49] verify 语料变更归档 -> {_old['corpus_fp'][:8]}")

    if "--audit-chains" in sys.argv:
        print("=" * 64)
        print("JGDVerifyAgent --audit-chains: 链发现回灌对抗审计")
        print("=" * 64)
        audit_triggered_chains()
        return 0

    print("=" * 64)
    print("JGDVerifyAgent: 修正检测 → 分级 → 动态验证 → ds交叉审计 → glm辩护 → 持久化")
    print("=" * 64)

    # -- 1. fixed_scan: 修正后的检测器重扫语料 ------------------------------
    print("\n[1] fixed_scan (R6 修正检测器, 接收者感知; R22 全语料)...")
    static_results = ma.scan_jars_static(ma.IMPACT, count=250, jar_limit=None)
    scan_bridges = [r for r in static_results if r["verdict"] == "STATIC_BRIDGE_CONFIRMED"]
    print(f"  扫描候选={len(static_results)} 真桥(STATIC_BRIDGE_CONFIRMED)={len(scan_bridges)}")
    jars_touched = sorted({r.get("jar", "?") for r in scan_bridges})
    print(f"  涉及 JAR: {', '.join(jars_touched[:10])}")

    # -- 合并 bridge_compare 语料的 38 行既有对比数据(同一修正检测器产出) ----
    rows: list[dict] = []
    if CANDIDATES.exists():
        rows = json.loads(CANDIDATES.read_text(encoding="utf-8"))
    by_cls: dict[str, dict] = {}
    for r in scan_bridges:
        for b in r.get("bridge_detail", []):
            rows.append({"cls": r["cls"], "jar": r.get("jar", "?"),
                         "trigger": b["trigger"], "field": b["field"],
                         "field_desc": b["field_desc"], "target": b["target"]})
    for row in rows:
        by_cls.setdefault(row["cls"], []).append(row)
    print(f"  候选行总数={len(rows)} 唯一类={len(by_cls)}")

    # -- 2. local_grade ------------------------------------------------------
    print("\n[2] local_grade (本地规则, 无 LLM)...")
    graded = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        key = (row["cls"], row["field"])
        if key in seen:
            continue
        seen.add(key)
        g = local_grade(row)
        graded.append({**row, **g})
    n_int = sum(1 for g in graded if g["grade"] == "INTERESTING")
    print(f"  唯一(类,字段)={len(graded)} INTERESTING={n_int} "
          f"TRIVIAL={sum(1 for g in graded if g['grade']=='TRIVIAL')}")

    # R7: 抽象类不能进流 — 桥要成立需具体可序列化子类 (agent 自身判定)
    print("\n[2b] hierarchy enrich (抽象标志 + 具体子类搜索)...")
    enrich_with_hierarchy(graded)
    n_abs = sum(1 for g in graded if g.get("abstract"))
    n_with_sub = sum(1 for g in graded if g.get("concrete_subclasses"))
    print(f"  抽象候选: {n_abs} | 有具体子类: {n_with_sub}")

    # -- 3. dynamic_verify ---------------------------------------------------
    dynamic_results: dict[str, dict] = {}
    if not args.no_dynamic:
        print(f"\n[3] dynamic_verify (多JDK, 最多 {args.max_dynamic} 个)...")
        jdks = ma.find_jdks()
        print(f"  可用 JDK: {jdks}")
        targets = [g for g in graded if g["grade"] == "INTERESTING"]
        cls_seen: set[str] = set()
        n = 0
        for g in targets:
            probe_cls = g["cls"]
            # R7: 抽象候选改探它的具体可序列化子类(流内真实载体)
            if g.get("abstract"):
                subs = [s for s in g.get("concrete_subclasses", [])
                        if s.get("serializable")]
                if not subs:
                    dynamic_results[g["cls"]] = {
                        "dynamic_verdict": "ABSTRACT_NO_SER_SUBCLASS",
                        "classification": "FAIL"}
                    continue
                probe_cls = subs[0]["cls"]
                g["probed_via_subclass"] = probe_cls
            if probe_cls in cls_seen or n >= args.max_dynamic:
                continue
            cls_seen.add(probe_cls)
            # 找该类的完整 static 结果(含 needs_jdk); 子类找不到就现场构造
            sr = next((r for r in scan_bridges if r["cls"] == probe_cls), None)
            if sr is None:
                major = None
                try:
                    import zipfile as _zf
                    with _zf.ZipFile(ma.IMPACT / g.get("jar", "")) as z:
                        major = ma.read_class_major_version(
                            str(ma.IMPACT / g.get("jar", "")), probe_cls)
                except Exception:
                    pass
                sr = {"cls": probe_cls, "jar": g.get("jar", ""),
                      "needs_jdk": ma.JAVA_VERSIONS.get(major or 55, 11),
                      "verdict": "SUBCLASS_OF_BRIDGE"}
            jdk = pick_jdk(sr.get("needs_jdk", 11), jdks)
            if not jdk:
                dynamic_results[g["cls"]] = {"dynamic_verdict": "SKIP_NO_JDK",
                                             "classification": "ERROR_ENV"}
                continue
            print(f"  验证 {probe_cls.split('.')[-1]} (需JDK {sr.get('needs_jdk')}, "
                  f"用 {jdk.split('/')[-1]})...")
            verified = ma.dynamic_probe_with_jdk(sr, jdk)
            dynamic_results[g["cls"]] = verified
            n += 1
        for cls, d in dynamic_results.items():
            print(f"    {cls.split('.')[-1]:<28} -> {d.get('dynamic_verdict')}")

    # -- 4+5. ds 交叉审计 + glm 辩护 (agent 自己调 LLM) ----------------------
    audited = []
    if not args.no_llm:
        print("\n[4] ds_cross_audit (对抗审计, 发现者≠验证者)...")
        targets = [g for g in graded if g["grade"] == "INTERESTING"]
        targets.sort(key=lambda g: g["cls"] not in dynamic_results)  # 有动态证据的优先
        cls_seen: set[str] = set()
        for g in targets:
            if g["cls"] in cls_seen or len(cls_seen) >= args.max_audit:
                continue
            cls_seen.add(g["cls"])
            print(f"  ds 审计 {g['cls'].split('.')[-1]}...")
            audit = ds_cross_audit(g, g, dynamic_results.get(g["cls"]))
            print(f"    -> {audit.get('verdict')} tier={audit.get('tier')} "
                  f"reason={(audit.get('reason') or '')[:80]}")
            defense = glm_defense(g, audit)
            if defense:
                print(f"    glm 辩护 -> {defense.get('defense')} "
                      f"{(defense.get('reason') or '')[:60]}")
            final = audit.get("verdict", "?")
            if defense and defense.get("defense") == "OVERRIDE" and final == "REJECT":
                final = "DISPUTED"
            audited.append({**g, "ds_audit": audit, "glm_defense": defense,
                            "final_verdict": final,
                            "dynamic": dynamic_results.get(g["cls"])})
    else:
        print("\n[4] ds_cross_audit: --no-llm, 跳过")

    # -- 6. persist ----------------------------------------------------------
    print("\n[5] persist -> RAG + verify_state.json + verify_report.md")
    verdicts = {}
    for a in audited:
        verdicts[a["final_verdict"]] = verdicts.get(a["final_verdict"], 0) + 1
    state = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "scan": {"candidates": len(static_results), "real_bridges": len(scan_bridges),
                 "unique_cls_field": len(graded),
                 "jars": jars_touched},
        "graded": graded,
        "dynamic": {k: {"dynamic_verdict": v.get("dynamic_verdict"),
                        "classification": v.get("classification",
                                                ma.classify_result(v))}
                   for k, v in dynamic_results.items()},
        "audited": audited,
        "verdict_summary": verdicts,
        "duration_s": round(time.time() - t0, 1),
    }
    state["corpus_fp"] = _fp
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")

    db = chroma_store.VStore()
    db.add([{"id": f"verify:{a['cls']}:{a['field']}",
             "type": "verify_agent_result",
             "tags": [a["final_verdict"].lower(), a["grade"].lower(),
                      (a.get("ds_audit") or {}).get("tier") or "none"],
             "payload": a} for a in audited])

    lines = [
        "# JGDVerifyAgent 报告 (R6: 验证在 agent 内)",
        "",
        f"- 扫描: {len(static_results)} 候选, 真桥 {len(scan_bridges)} 类"
        f" (旧检测器 CONFIRMED=98 → 修正后 {len(scan_bridges)},"
        f" 假阳性率约 {100 - round(len(scan_bridges) * 100 / 98)}%)",
        f"- 唯一(类,字段)桥: {len(graded)}, INTERESTING: "
        f"{sum(1 for g in graded if g['grade'] == 'INTERESTING')}",
        f"- 动态验证: {len(dynamic_results)} 类",
        f"- ds 审计: {len(audited)} 类, 结论分布: {verdicts}",
        "",
        "## INTERESTING 候选 (agent 内 ds 交叉审计后)",
        "",
        "| 类 | 桥 | ds | tier | 最终 |",
        "|---|---|---|---|---|",
    ]
    for a in audited:
        lines.append(f"| `{a['cls']}` | {a['trigger']}→{a['field']} "
                     f"({a['field_desc']}) | {a.get('ds_audit', {}).get('verdict')} "
                     f"| {a.get('ds_audit', {}).get('tier')} | {a['final_verdict']} |")
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"\n{'=' * 64}")
    print(f"JGDVerifyAgent 完成 ({state['duration_s']}s)")
    print(f"  真桥类: {len(scan_bridges)} | INTERESTING: "
          f"{sum(1 for g in graded if g['grade'] == 'INTERESTING')}")
    print(f"  ds 审计: {verdicts}")
    print(f"  RAG 总量: {db.count()}")
    print(f"{'=' * 64}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
