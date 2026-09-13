"""JGDAuditTargetAgent — 给任意 jar 产品出链 + PoC 的产品化入口 (R40)。

用法:
    python3 audit_target.py --target /path/to/jars --name "产品名" [--full]

流程 (复用全部既有 agent 能力, 语料按指纹自动重建):
  1. 图: ensure_graph + CHA 分派边 (指纹门控, 语料换了自动重建)
  2. 桥: verify_agent fixed_scan (全语料) + ds 对抗审计 (抽样)
  3. 链: chain_complete 配对 (双载体×契约合成×批处理并行)
  4. sink: 经典种子 + 产品自有 sink 发现 (discover_product_sinks)
  5. PoC: poc_gen 尾巴自动选型 (扫目标在场库) + JEP290 姿态
  6. 报告: audit_report/ 目录打包
"""
from __future__ import annotations

import argparse
import json
import os
sys_path_hack = None
import scope
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))


def run(cmd: list[str], timeout: int = 3000) -> tuple[bool, str]:
    print(f"$ {' '.join(cmd)}", flush=True)
    try:
        p = subprocess.run([sys.executable, "-u", *cmd], capture_output=True,
                           text=True, timeout=timeout, cwd=HERE)
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    tail = "\n".join((p.stdout + p.stderr).splitlines()[-30:])
    print("\n".join("  | " + ln for ln in tail.splitlines()[-12:]), flush=True)
    return p.returncode == 0, tail


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True, help="目标 jar 目录")
    ap.add_argument("--name", default="unnamed-target")
    ap.add_argument("--full", action="store_true",
                    help="跑完整挖掘(默认轻量: 图+桥+链+PoC)")
    args = ap.parse_args()
    t0 = time.time()

    os.environ["JGD_TARGET"] = str(Path(args.target).resolve())
    os.environ["JGD_EF"] = "hash"
    out = HERE / "audit_report"
    out.mkdir(exist_ok=True)

    print("=" * 66)
    print(f"JGDAuditTargetAgent: {args.name} — 一次性终局, 无中间决策")
    print(f"目标语料: {os.environ['JGD_TARGET']}")
    print("=" * 66, flush=True)

    # R50: 全部节点内化执行, 决策(agent自定)不外问; rc 永远收敛为 0,
    # 失败只在报告里记账 (F2 语义)
    ok1, _ = run(["known_chains.py"])
    ok2, _ = run(["verify_agent.py", "--max-dynamic", "6", "--max-audit", "10"])
    ok3, _ = run(["chain_complete.py", "--max-pairs", "99999"])
    ok4, _ = run(["poc_gen.py"])
    statuses = {"known_chains": ok1, "verify": ok2,
                "chains": ok3, "poc": ok4}

    import matrix_agent as ma
    import chain_complete as cc
    from poc_gen import select_tail, jep290_profile, CHAINS

    cc_state = json.loads((scope.DATA / "jgd_chain_state.json")
                          .read_text(encoding="utf-8"))
    cov = cc_state.get("coverage", {}).get("totals", {})
    ev = cc_state.get("evidence", [])
    tails = select_tail(ma.corpus_dir())
    kc = (json.loads((scope.DATA / "known_chains_report.json").read_text(
        encoding="utf-8"))["results"]
        if (scope.DATA / "known_chains_report.json").exists() else [])
    kc_present = [k for k in kc if k.get("present")]

    poc = json.loads((scope.scoped_dir(HERE / "pocs") / "poc_results.json").read_text(
        encoding="utf-8")) if (HERE / "pocs" / "poc_results.json").exists() else {}
    poc_fired = [r for r in poc.get("results", [])
                 if r.get("status") == "RCE_DEMO_FIRED"]

    lines = [
        f"# 反序列化审计报告 — {args.name}",
        "",
        f"- 目标语料: `{os.environ['JGD_TARGET']}` "
        f"({len(list(ma.corpus_dir().glob('*.jar')))} jars)",
        f"- 生成: {time.strftime('%F %T')} ({time.time() - t0:.0f}s)",
        f"- 管线节点: {statuses}",
        "",
        "## 公开链 (四态判定)",
        *[f"- {'✅' if k.get('version', '').startswith('APPLICABLE') else '⚠️'} "
          f"{k['chain']}: {k.get('version', '')[:80]}" for k in kc_present],
        "",
        "## 挖掘覆盖",
        f"- 配对: {cov.get('pairs_tried')}/{cov.get('pairs_total')}",
        f"- 机制完整链: {sum(1 for e in ev if e.get('result', {}).get('verdict') == 'CHAIN_DEPTH2')}",
        f"- 证据(ds审计): {len(ev)}",
        "",
        "## PoC (RCE 闭环)",
        *[f"- ✅ {r['chain']} (tail={r.get('closed_by_tail')}, "
          f"JDK {r.get('jdk')}, ser={r.get('ser')})" for r in poc_fired],
        "",
        "## 域边界声明",
        "- 非CHA可见接收者与未装配尾巴为域外; JEP290 姿态见 pocs/README.md",
    ]
    (out / f"audit_{args.name}.md").write_text("\n".join(lines), encoding="utf-8")

    print("\n" + "=" * 66)
    print(f"【终局产出】{args.name} — jar 进, 链子出 (无中间决策)")
    print("=" * 66)
    print(f"公开链: {len(kc_present)} 在场 "
          f"({sum(1 for k in kc_present if k.get('version', '').startswith('APPLICABLE'))} 版本适用)")
    print(f"配对: {cov.get('pairs_tried')}/{cov.get('pairs_total')} | "
          f"证据 {len(ev)} 条")
    print(f"RCE 闭环 PoC: {len(poc_fired)} 条")
    for r in poc_fired:
        print(f"  ★ {r['chain']} ({r.get('closed_by_tail')}, JDK{r.get('jdk')})")
    print(f"报告 -> {out / f'audit_{args.name}.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
