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

    def _finish(self, verdict: str) -> str:
        """Record the deterministic terminal verdict; LLM gatekeeping is removed."""
        self.state["verdict"] = verdict
        self.state["pending_verdict"] = None
        self.state["gate"] = {"mode": "deterministic", "llm_gate": "removed"}
        self.save()
        cc = read_json(scope.DATA / "jgd_chain_state.json", {}) or {}
        cov = cc.get("coverage", {})
        lines = [
            "# Conductor 终局报告",
            "",
            f"## 判定: **{verdict}**",
            "- LLM 把关: removed (deterministic verifier/terminator owns the verdict)",
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
