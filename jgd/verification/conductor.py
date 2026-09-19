"""JGDConductor — 调度逻辑全部在 agent 内（功能和逻辑都必须在 agent 内）。

主循环直到终局判定，单轮内 stage 顺序:
  1. verify_agent            — 修正检测 + 层次取证 + ds 对抗审计 + RAG 沉淀
  2. evolve_v2               — 候选池(含 verify 反馈源) 探测 + FIELD_FORWARD + 链 PoC
  3. verify_agent --audit-chains — 链发现回灌 ds 审计 (仅当本轮有新 TRIGGERED)
  4. chain_complete           — 实时图(指纹校验) + 接收者配对全链路, 直到判定

继续/终止判定(在 agent 内):
  CHAIN_COMPLETE_SINK         → 终局 (sink 可证实执行)
  CHAIN_COMPLETE_DEPTH2       → 记录, 继续找 SINK; 轮次耗尽则以此为终局
  NO_CHAIN + 本轮无新增量      → 终局 (穷尽证明: 覆盖统计随附)
  NO_CHAIN + 本轮有新增量      → 反馈下一轮 (新桥/新发现已进 RAG 与候选池)

主循环只负责: 启动 Conductor、读终局报告。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from jgd import PROJECT_ROOT
from jgd.infra import scope

HERE = PROJECT_ROOT
STATE = scope.DATA / "jgd_conductor_state.json"
REPORT = scope.DATA / "conductor_report.md"
LOG = HERE / "conductor.log"

COMPLETE_VERDICTS = ("CHAIN_COMPLETE_SINK",)


def run_stage(args: list[str], timeout: int = 1800) -> bool:
    print(f"\n$ python3 {' '.join(args)}", flush=True)
    try:
        p = subprocess.run([sys.executable, "-u", *args],
                           capture_output=True, text=True, timeout=timeout,
                           cwd=HERE)
    except subprocess.TimeoutExpired:
        print("  [stage] TIMEOUT", flush=True)
        return False
    tail = "\n".join((p.stdout + p.stderr).splitlines()[-25:])
    print("\n".join("  | " + ln for ln in tail.splitlines()), flush=True)
    return p.returncode == 0


def read_json(p: Path, default=None):
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return default
    return default


class Conductor:
    def __init__(self, max_rounds: int = 4, max_pairs: int = 240):
        self.max_rounds = max_rounds
        self.max_pairs = max_pairs
        self.state = read_json(STATE, {"rounds": [], "verdict": None,
                                       "partial_round": None})
        self.round_log = []

    def save(self):
        self.state["rounds"].extend(self.round_log)
        self.round_log = []
        STATE.write_text(json.dumps(self.state, ensure_ascii=False, indent=1),
                         encoding="utf-8")

    def _save_partial(self, rnd: int, stages_done: list[str]):
        self.state["partial_round"] = {"round": rnd, "stages_done": stages_done}
        self.save()

    def _signal(self) -> dict:
        """本轮增量信号 — 判定穷尽还是反馈。"""
        vs = read_json(scope.DATA / "verify_state.json", {}) or {}
        ev = read_json(HERE / "evolve_v2_state.json", {}) or {}
        cc = read_json(scope.DATA / "jgd_chain_state.json", {}) or {}
        ch = read_json(HERE / "jgd_chain_audit.json", []) or []
        return {
            "audited": len(vs.get("audited", [])),
            "discoveries": len(ev.get("discoveries", [])),
            "triggered": sum(
                1 for d in ev.get("discoveries", [])
                if "TRIGGERED" in ((d.get("chain") or {}).get("chain_verdict") or "")),
            "chain_confirms": sum(1 for r in ch if r.get("final_verdict") == "CONFIRM"),
            "pairs_tried": len(cc.get("tried_pairs", [])),
            "evidence": len(cc.get("evidence", [])),
        }

    def run(self) -> str:
        print("=" * 66)
        print("JGDConductor: 完整链或穷尽证明 — 功能与逻辑全在 agent 内")
        print(f"max_rounds={self.max_rounds} max_pairs/round={self.max_pairs}")
        print("=" * 66, flush=True)

        if self.state.get("verdict"):
            print(f"[conductor] 已有终局判定: {self.state['verdict']}")
            return self.state["verdict"]

        rounds_hist = self.state.get("rounds", [])
        if self.state.get("acceptance_blocked"):
            self.max_rounds = len(rounds_hist) + 2
            print(f"[conductor] ds 拒收上一判定, 延长轮次至 {self.max_rounds}",
                  flush=True)
            self.state["acceptance_blocked"] = False
        prev_signal = rounds_hist[-1].get("signal") if rounds_hist else None
        no_growth_streak = 0
        rnd = len(rounds_hist)
        partial = self.state.get("partial_round") or {}
        stages: list[str] = partial.get("stages_done", []) if partial else []
        if partial and partial.get("round") == rnd + 1:
            rnd = partial["round"] - 1  # 续跑未完成的轮
        while rnd < self.max_rounds:
            rnd += 1
            t0 = time.time()
            print(f"\n{'█' * 33} Round {rnd} / {self.max_rounds} {'█' * 33}",
                  flush=True)

            if "verify" not in stages:
                run_stage(["-m", "jgd.verification.verify_agent",
                           "--max-dynamic", "8", "--max-audit", "12"])
                stages.append("verify")
                self._save_partial(rnd, stages)
            if "evolve" not in stages:
                run_stage(["-m", "jgd.mining.evolve_v2", "3"], timeout=2400)
                stages.append("evolve")
                self._save_partial(rnd, stages)

            sig = self._signal()
            if "audit" not in stages and (
                    not prev_signal or sig["triggered"] > prev_signal["triggered"]):
                run_stage(["-m", "jgd.verification.verify_agent",
                           "--audit-chains"])
                stages.append("audit")
                self._save_partial(rnd, stages)

            if "complete" not in stages:
                run_stage(["-m", "jgd.mining.chain_complete",
                           "--max-pairs", str(self.max_pairs)],
                          timeout=3600)
                stages.append("complete")
                self._save_partial(rnd, stages)
            stages = []

            cc = read_json(scope.DATA / "jgd_chain_state.json", {}) or {}
            verdict = cc.get("verdict")
            sig = self._signal()
            self.round_log.append({
                "round": rnd, "signal": sig, "chain_verdict": verdict,
                "duration_s": round(time.time() - t0, 1)})
            self.state["partial_round"] = None
            self.save()

            print(f"\n[conductor] Round {rnd} signal: {sig} verdict={verdict}",
                  flush=True)

            if verdict in COMPLETE_VERDICTS:
                return self._finish(verdict)
            if verdict == "CHAIN_COMPLETE_DEPTH2":
                continue
            if verdict in ("NO_CHAIN", "NO_BRIDGE"):
                # 穷尽判定需两轮连续无增量 + pairs 真实尝试过(或桥池真空);
                # 首轮/有新增量一律反馈下一轮
                grew = (prev_signal is not None and (
                    sig["discoveries"] > prev_signal["discoveries"]
                    or sig["audited"] > prev_signal["audited"]
                    or sig["pairs_tried"] > prev_signal["pairs_tried"]))
                pairs_real = sig.get("pairs_tried", 0) > 0
                if grew:
                    no_growth_streak = 0
                    print("[conductor] 有新增量, 反馈下一轮", flush=True)
                elif not pairs_real:
                    no_growth_streak += 1
                    print(f"[conductor] pairs=0 (接收者面未铺开), "
                          f"无增量连击 {no_growth_streak}/2", flush=True)
                else:
                    no_growth_streak += 1
                    print(f"[conductor] 无增量连击 {no_growth_streak}/2", flush=True)
                if no_growth_streak >= 2:
                    return self._finish(verdict)
            prev_signal = sig

        cc = read_json(scope.DATA / "jgd_chain_state.json", {}) or {}
        v = cc.get("verdict") or "ROUNDS_EXHAUSTED"
        return self._finish(v)

    def _ds_acceptance(self, verdict: str) -> dict:
        """终局判定 + 本轮 agent 修改必须经 ds 验收。
        用户既定规则: 实现后和 dsh 交叉验证 — 未经 ds 验收的结论不出 agent。"""
        from jgd.infra import llm
        cc = read_json(scope.DATA / "jgd_chain_state.json", {}) or {}
        pb = (cc.get("coverage") or {}).get("per_bridge") or {}
        sum_total = sum(v.get("pairs_total", 0) for v in pb.values())
        sum_tried = sum(v.get("pairs_tried", 0) for v in pb.values())
        mods = [
            " ensure_graph: 图指纹校验, 语料不符实时重建 (990K节点/2.3M边)",
            " jgd_chain_audit 合并+翻供阈值: ds 非确定性下单轮翻供不推翻 CONFIRM",
            " sink 种子扩展: 14条groovy → 430个方法节点(经典RCE/JNDI/字节码族)",
            "参数桥检测: 字段作为参数流入静态助手(MurmurHash.update等)也算桥, "
            "修复 antlr4 Pair 漏检",
            " verdict 残留清除: 修复  零尝试事故(残留 NO_CHAIN 使 pair 循环首桥即 break)",
            " CHA 分派边: (接口,方法)→(实现,方法), 反向可达不再断在多态边界",
            " hop2 可达性判定: 标记物唯一可达路径论证; 写侧触发模板清除; "
            "18 对误判修正且读侧复验全过, 36/36 接收者无自定义 readObject",
            "接收者序列化钩子审计(假阳性风险标注)",
            "桥池放开: 全部 INTERESTING 参与配对(含未审计)",
            "值可达性: String 字段注入 canary, 参数流异常回显=VALUE_FLOW 证据; "
            "DEPTH2 接收者进化为下一轮桥(链延伸至深度3+)",
        ]
        prompt = (
            "你是 JGD 项目的验收审计员(dsh)。主控 agent 即将输出终局判定。\n"
            "验收标准(域内语义, ): 本判定只主张【声明域内】的完成 —\n"
            "  (a) 配对覆盖 pairs_tried==pairs_total 且逐桥账本一致\n"
            "  (b) 空池桥=枚举已执行结果为空(CHA+≤3跳静态边界, 显式声明)\n"
            "  (c) 环境阻塞对显式降级(env_blocked), 不计入已验证\n"
            "  (d) 域边界声明: 非CHA可见接收者(反射/ServiceLoader/动态注册)与\n"
            "      非插桩观测(标记物4方法+签名匹配)是本域的已知边界, 不主张域外无链\n"
            "请验收: 1) 域内完成主张是否被账本支撑 2) 修改清单是否引入新缺陷\n"
            "3) 域边界声明是否诚实完整 4) 挖掘产物(270 DEPTH2+T1入口新链)记录是否可靠。\n"
            "输出 JSON: {\"accepted\": true/false, \"blockers\": [\"...\"], "
            "\"probe_blind_spots\": [\"...\"], \"note\": \"...\"}\n\n"
            + json.dumps({"verdict": verdict,
                          "coverage": cc.get("coverage", {}),
                          "per_bridge_ledger": {
                              "sum_pairs_total": sum_total,
                              "sum_pairs_tried": sum_tried,
                              "bridge_count": len(pb),
                              "consistency": (sum_total ==
                                              (cc.get("coverage", {})
                                               .get("totals", {})
                                               .get("pairs_total"))),
                              "full": {k: pb[k] for k in list(pb)[:200]}},
                          "exhaustion_statements_sample":
                              (cc.get("exhaustion_statements") or [])[:5],
                          "env_blocked_pairs": sum(
                              1 for r in (cc.get("pair_results") or [])
                              if r.get("tax") == "env_blocked_dep_missing"),
                          "evidence_count": len(cc.get("evidence", [])),
                          "modifications": mods,
                          "dynamic_probe_model": (
                              "4层: DynV实例化+BAVE回环 / PV注入+标记物 / CV链PoC(JDK11) / "
                              "CC全链对(hop2标记物+sink异常签名)。"
                              "非JVM插桩: 无javaagent/ClassFileTransformer, "
                              "目标类字节码未修改, 观测仅限标记物的toString/hashCode/"
                              "equals/invoke + 输出签名匹配")},
                         ensure_ascii=False, indent=1))
        resp = llm.ask("ds", "你是严谨的安全研究验收审计员, 只依据给定材料判断。",
                       prompt, temperature=0.1, max_tokens=1600)
        parsed = llm.extract_json(resp.get("content") or "")
        out = parsed if isinstance(parsed, dict) else {"accepted": None,
                                                       "note": "UNPARSEABLE"}
        out["ds_ok"] = resp.get("ok", False)
        self.state["ds_acceptance"] = out
        return out

    def _finish(self, verdict: str) -> str:
        acceptance = self._ds_acceptance(verdict)
        if acceptance.get("accepted") is True:
            self.state["verdict"] = verdict
            self.state["pending_verdict"] = None
            self.state["acceptance_blocked"] = False
        else:
            # ds 拒收 → 判定不算数, 挖掘继续 (延长轮次由 run() 开头处理)
            self.state["verdict"] = None
            self.state["pending_verdict"] = verdict
            self.state["acceptance_blocked"] = True
            verdict = f"ACCEPTANCE_BLOCKED:{verdict}"
        self.save()
        cc = read_json(scope.DATA / "jgd_chain_state.json", {}) or {}
        cov = cc.get("coverage", {})
        lines = [
            "# Conductor 终局报告",
            "",
            f"## 判定: **{verdict}**",
            f"- dsh 验收: accepted={acceptance.get('accepted')} "
            f"blockers={acceptance.get('blockers')}",
            f"- 探针盲区(dsh): {acceptance.get('probe_blind_spots')}",
            f"- 轮次记录: {json.dumps(self.state.get('rounds', [])[-3:], ensure_ascii=False)}",
            f"- 覆盖: {json.dumps(cov.get('totals', {}), ensure_ascii=False)}; "
            f"空池桥(显式穷尽) {len(cov.get('empty_pool_bridges', []))} 个",
            f"- 证据: {len(cc.get('evidence', []))} 条 (chain_complete_report.md)",
            "",
            "判定语义: SINK=sink 可证实执行; DEPTH2=两级攻击者可控分派完整链;",
            "NO_CHAIN=定义范围内(语料+实时图+≤3跳+可注入状态)穷尽无链。",
        ]
        REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\n[conductor] 终局: {verdict} -> {REPORT.name}", flush=True)
        return verdict


if __name__ == "__main__":
    mr = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 4
    raise SystemExit(Conductor(max_rounds=mr).run())
