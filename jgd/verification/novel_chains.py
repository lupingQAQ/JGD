"""JGDNovelChainsAgent — 新链自动定级 (默认管线阶段, 发现者≠验证者)。

对本次运行 RCE_DEMO_FIRED 且桥类不属于已知链家族/已发布链集的候选,
组装证据包(分派栈/触发模式/尾巴/点火证明)交双模型对抗定级:
  finder(glm) 提议 tier + 新颖性论证 → verifier(ds) 交叉裁决(可否决/降级)。
产物: jgd_novel_chains.<fp8>.json + 控制台摘要; cli 汇入终局报告。
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from jgd import PROJECT_ROOT
from jgd.infra import llm, scope
from jgd.poc.poc_gen import TAIL_LIBS
from jgd.verification.known_chains import KNOWN_CHAINS

HERE = PROJECT_ROOT

# 已发布链桥集 (项目 README 公开的 T1/T2) — 命中则不算新链
PUBLISHED_BRIDGES = {
    "org.apache.activemq.artemis.api.core.ObjLongPair",
    "cn.hutool.core.lang.mutable.MutableObj",
    "org.antlr.v4.runtime.misc.Pair",
}

FAMILY_PREFIXES = tuple(
    {c.replace("/", ".") for chain in KNOWN_CHAINS for c in chain["classes"]
     if not c.startswith(("java/", "javax/", "jdk/", "sun/", "com/sun/"))}
    | {"com.sun.syndication", "org.apache.commons.collections",
       "org.apache.commons.beanutils", "com.alibaba.fastjson", "com.mchange"})


def _known_bridge(bridge: str) -> bool:
    if bridge in PUBLISHED_BRIDGES:
        return True
    return any(bridge.startswith(p) for p in FAMILY_PREFIXES)


def _evidence_for(bridge: str, state: dict) -> dict:
    for e in state.get("evidence", []):
        if (e.get("bridge") or "").replace("/", ".") == bridge:
            r = e.get("result", {})
            return {"dispatch_stack": (r.get("dispatch_stack") or [])[:14],
                    "verdict": r.get("verdict"),
                    "hop2_marker": r.get("hop2_marker")}
    return {}


def _grade_candidate(cand: dict) -> dict:
    prompt = (
        "你是 Java 反序列化 gadget chain 新颖性评估员(发现侧)。对以下已在本机"
        "动态点火(RCE_DEMO_FIRED, 良性标记文件)的链给出分级提议:\n"
        "- T1: 全新入口类(触发侧前所未见)\n"
        "- T2: 已知模式的新中间跳板类\n"
        "- T3: 已知链族内的变体/扩展\n"
        "输出 JSON: {\"tier\": \"T1|T2|T3\", \"novel\": true/false, "
        "\"reason\": \"...\"}\n\n" + json.dumps(cand, ensure_ascii=False, indent=1))
    resp = llm.ask("glm", "你是严谨的新颖性评估员, 只依据证据分级。",
                   prompt, temperature=0.1, max_tokens=500)
    return llm.extract_json(resp.get("content") or "") or {"parse_fail": True}


def _verify_candidate(cand: dict, proposal: dict) -> dict:
    prompt = (
        "你是验证侧对抗审计员。发现侧对下述已点火链给出分级提议, 请交叉裁决:"
        "证据是否支撑该 tier 与 novel 判定? 可否决/降级, 并给一句理由。\n"
        "输出 JSON: {\"verdict\": \"CONFIRM|DOWNGRADE|REJECT\", \"tier\": \"...\", "
        "\"novel\": true/false, \"reason\": \"...\"}\n\n"
        f"发现侧提议: {json.dumps(proposal, ensure_ascii=False)}\n"
        f"链证据: {json.dumps(cand, ensure_ascii=False, indent=1)}")
    resp = llm.ask("ds", "你是苛刻的验证侧审计员, 声明不等于证据。",
                   prompt, temperature=0.1, max_tokens=500)
    return llm.extract_json(resp.get("content") or "") or {"parse_fail": True}


def main() -> int:
    print("=" * 64)
    print("JGDNovelChainsAgent: 新链自动定级 (发现者≠验证者)")
    print("=" * 64)
    t0 = time.time()

    poc_path = scope.scoped_dir(HERE / "pocs") / "poc_results.json"
    if not poc_path.exists():
        print("no poc_results — 跳过定级")
        (scope.scoped(HERE / "jgd_novel_chains.json")).write_text(
            json.dumps({"chains": [], "note": "no poc results"},
                       ensure_ascii=False), encoding="utf-8")
        return 0
    poc = json.loads(poc_path.read_text(encoding="utf-8"))
    state_path = scope.DATA / "jgd_chain_state.json"
    state = (json.loads(state_path.read_text(encoding="utf-8"))
             if state_path.exists() else {})

    tail_desc = {lib: d for lib, _c, d in TAIL_LIBS}
    cands = []
    for r in poc.get("results", []):
        if r.get("status") != "RCE_DEMO_FIRED":
            continue
        bridge = r.get("bridge", "")
        if _known_bridge(bridge):
            continue
        cands.append({
            "chain_id": r.get("chain"),
            "bridge": bridge,
            "trigger_mode": "HashMap.readObject→hashCode" if (r.get("mode") or "").startswith("hm:")
            else "BAVE.readObject→toString",
            "closed_by_tail": r.get("closed_by_tail"),
            "tail_lib": tail_desc.get(
                {"rome_tostring": "rome", "rome_equalsbean_hash": "rome",
                 "jackson_tostring": "jackson", "cc3": "commons-collections"}
                .get(r.get("closed_by_tail"), "?"), "?"),
            "fired_at_build": r.get("fired_at_build"),
            "fired_at_deser": r.get("fired_at_deser"),
            "jdk": r.get("jdk"),
            "evidence": _evidence_for(bridge, state),
        })
    print(f"新链候选(已点火且非已知家族): {len(cands)}")

    out = []
    for c in cands:
        prop = _grade_candidate(c)
        verd = _verify_candidate(c, prop)
        tier = verd.get("tier") or prop.get("tier") or "?"
        out.append({**c, "proposal": prop, "verdict": verd,
                    "final_tier": tier,
                    "final_novel": bool(verd.get("novel", prop.get("novel"))),
                    "final_status": verd.get("verdict", "UNPARSED")})
        print(f"  {c['bridge']:<55} tier={tier} "
              f"novel={out[-1]['final_novel']} [{out[-1]['final_status']}]")

    dest = scope.scoped(HERE / "jgd_novel_chains.json")
    dest.write_text(json.dumps({"chains": out, "generated": time.strftime("%F %T")},
                               ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"-> {dest.name} | {len(out)} 条 ({time.time() - t0:.0f}s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
