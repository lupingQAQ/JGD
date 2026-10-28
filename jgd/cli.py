"""JGD CLI: audit, poc, index, db, serve, doctor, version.

The CLI is an adapter. It does not execute target code; dynamic verification
belongs to the sandboxed runtime introduced in a later plan.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from dataclasses import replace
from pathlib import Path

from jgd import ci
from jgd.adapters.sarif import to_sarif
from jgd.config import Budget, JgdConfig, Policy
from jgd.contracts.models import Finding, RunResult
from jgd.dynamic import DynamicProbe, JvmToolchain
from jgd.doctor import run_doctor
from jgd.engine.bridge import scan_bridges
from jgd.engine.known import scan_known
from jgd.index.bytecode import BytecodeIndex
from jgd.index.reader import DisasmClassReader
from jgd.security.archive import SafeJar
from jgd.security.policy import PolicyEngine, Scope
from jgd.security.sandbox import SandboxLimits
from jgd.verification import build_chain_db

TOOL_VERSION = "0.4.0"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="jgd")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit a JAR directory")
    audit.add_argument("--target", required=True, help="JAR directory")
    audit.add_argument("--name", default="target", help="report name (compatibility)")
    audit.add_argument(
        "--profile", choices=["known", "standard", "deep", "full"], default="standard"
    )
    audit.add_argument("--format", default="json", help="comma-separated: json,sarif,md")
    audit.add_argument("--out", default=None, help="run output directory")
    audit.add_argument("--no-poc", action="store_true", help="disable PoC generation")
    audit.add_argument("--no-llm", action="store_true", help="disable LLM advisory")
    audit.add_argument("--offline", action="store_true", help="disable network and LLM")
    audit.add_argument("--dynamic", action="store_true", help="run sandboxed dynamic probes")
    audit.add_argument("--sandbox", choices=["docker", "wsl2", "host"], default="docker")
    audit.add_argument("--unsafe-host", action="store_true", help="allow host sandbox for trusted targets")
    audit.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
    )
    audit.add_argument("--jobs", type=int, default=8)
    audit.add_argument("--ecj", default=None, help="ECJ jar for automatic PoC tails")
    audit.add_argument(
        "--baseline",
        default=None,
        help="prior run.json/findings.json; fail only on new findings",
    )

    index = sub.add_parser("index", help="bytecode index operations")
    index_sub = index.add_subparsers(dest="index_command", required=True)
    index_build = index_sub.add_parser("build", help="build a bytecode index")
    index_build.add_argument("--target", required=True)
    index_build.add_argument("--db", default=None)

    db = sub.add_parser("db", help="known-chain database operations")
    db_sub = db.add_subparsers(dest="db_command", required=True)
    db_build = db_sub.add_parser("build", help="build the known-chain DB")
    db_build.add_argument("--out", default=None)
    db_verify = db_sub.add_parser("verify", help="verify the known-chain DB")
    db_verify.add_argument("--db", default=None)

    serve = sub.add_parser("serve", help="serve MCP or A2A")
    serve_sub = serve.add_subparsers(dest="serve_command", required=True)
    mcp = serve_sub.add_parser("mcp", help="MCP stdio server")
    mcp.add_argument("--home", default=None)
    a2a = serve_sub.add_parser("a2a", help="A2A HTTP server")
    a2a.add_argument("--host", default="127.0.0.1")
    a2a.add_argument("--port", type=int, default=8080)
    a2a.add_argument("--home", default=None)
    a2a.add_argument("--token", default=None)

    webhook = serve_sub.add_parser("webhook", help="Nexus/CI webhook receiver")
    webhook.add_argument("--host", default="127.0.0.1")
    webhook.add_argument("--port", type=int, default=8090)
    webhook.add_argument("--home", default=None)
    webhook.add_argument("--work-dir", default=None)
    webhook.add_argument("--token", default=None, help="Bearer token")
    webhook.add_argument("--secret", default=None, help="HMAC-SHA256 webhook secret")
    webhook.add_argument(
        "--nexus-base-url",
        default=None,
        help="Only download artifact URLs under this Nexus URL",
    )
    webhook.add_argument(
        "--nexus-token",
        default=None,
        help="Optional Bearer token for downloading private Nexus artifacts",
    )
    webhook.add_argument(
        "--local-root",
        default=None,
        help="Allow local artifact paths under this root",
    )
    webhook.add_argument(
        "--profile", choices=["known", "standard", "deep", "full"], default="standard"
    )
    webhook.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
    )
    webhook.add_argument("--dynamic", action="store_true")
    webhook.add_argument("--sandbox", choices=["docker", "wsl2", "host"], default="docker")
    webhook.add_argument("--unsafe-host", action="store_true")
    webhook.add_argument("--wait", action="store_true", help="Wait for audit before responding")
    webhook.add_argument("--wait-timeout", type=float, default=600.0)

    poc = sub.add_parser("poc", help="build and verify one deserialization chain")
    poc.add_argument("--target", required=True, help="target JAR directory")
    poc.add_argument("--bridge", required=True, help="bridge class name")
    poc.add_argument(
        "--trigger",
        choices=["hash", "hash-build", "equals", "tostring"],
        default="hash",
        help="bridge trigger; hash defers to readObject (recommended)",
    )
    poc.add_argument("--tail", default=None, help="force a tail library (cc3, rome_* ...)")
    poc.add_argument("--jdk11", action="store_true", help="use JDK 11 runtime")
    poc.add_argument("--out", default=None, help="PoC output directory")
    poc.add_argument("--ecj", default=None, help="ECJ compiler jar")
    poc.add_argument(
        "--unsafe-host",
        action="store_true",
        help="required: PoC executes target code; run inside an isolated VM",
    )

    doctor = sub.add_parser("doctor", help="environment preflight")
    doctor.add_argument("--target", default=None)

    sub.add_parser("version", help="print version")
    return parser


def _run_id() -> str:
    return f"{time.strftime('%Y%m%dT%H%M%S')}-{uuid.uuid4().hex[:8]}"


def _known_findings(results: list[dict]) -> list[Finding]:
    out = []
    for i, r in enumerate(results):
        if not r.get("present"):
            continue
        version = r.get("version", "")
        severity = "high" if version.startswith("APPLICABLE") else "medium"
        out.append(
            Finding(
                id=f"JGD-K{i:04d}",
                category="java-deserialization",
                verdict="PRESENT",
                severity=severity,
                confidence=0.9,
                entry={"class": r["chain"]},
                bridge={},
                sink={},
                evidence=[{"type": "known_chain", "version": version, "missing": r.get("missing", [])}],
                remediation={},
            )
        )
    return out


def _bridge_findings(bridges: list[dict]) -> list[Finding]:
    out = []
    for i, b in enumerate(bridges):
        out.append(
            Finding(
                id=f"JGD-B{i:04d}",
                category="java-deserialization",
                verdict="BRIDGE_CANDIDATE",
                severity="medium",
                confidence=0.6,
                entry={"class": b["cls"], "method": b["trigger"]},
                bridge={
                    "class": b["cls"],
                    "field": b["field"],
                    "field_desc": b["field_desc"],
                    "target": b["target"],
                    "via": b.get("via"),
                },
                sink={},
                evidence=[{"type": "static_bridge", "jar": b["jar_path"]}],
                remediation={},
            )
        )
    return out


def _dynamic_classpath(target: Path, bridge: dict, out: Path) -> list[Path]:
    """Use the full target classpath, including nested Spring Boot JARs.

    Bridge constructors often need sibling libraries (Spring, logging, nested
    support classes).  A top-level fat JAR alone cannot load ``BOOT-INF``
    classes, so nested JARs and classes roots are extracted under the run's
    sandbox output directory and added to the dynamic probe classpath.
    """
    jars = sorted(target.glob("*.jar"))
    cp = list(jars) if jars else [Path(bridge["jar_path"])]
    origin = str(bridge.get("origin", "") or "")
    jar_path = Path(bridge["jar_path"])
    if not origin:
        # A bridge indexed from BOOT-INF/classes can have an empty origin on
        # older index rows; detect the fat-JAR layout anyway.
        try:
            with SafeJar(jar_path) as jar:
                is_fat = any(
                    n.startswith(("BOOT-INF/lib/", "BOOT-INF/classes/", "WEB-INF/"))
                    for n in jar.namelist()
                )
        except Exception:
            is_fat = False
        if not is_fat:
            return cp
    libs = out / "dynamic" / "classpath"
    libs.mkdir(parents=True, exist_ok=True)
    try:
        with SafeJar(jar_path) as jar:
            for entry in jar.jar_entries():
                data = jar.read(entry)
                dest = libs / (hashlib.sha256(data).hexdigest()[:16] + ".jar")
                if not dest.exists():
                    dest.write_bytes(data)
                if dest not in cp:
                    cp.append(dest)
            class_root = libs / "classes"
            for prefix in ("BOOT-INF/classes/", "WEB-INF/classes/"):
                for name in jar.namelist():
                    if not name.startswith(prefix) or name.endswith("/"):
                        continue
                    rel = name[len(prefix):]
                    if not rel:
                        continue
                    dest = class_root / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        dest.write_bytes(jar.read(name))
                    except Exception:
                        continue
                if class_root.exists() and class_root not in cp:
                    cp.append(class_root)
    except Exception:
        # Fall back to the top-level classpath; the probe will report the
        # load error instead of aborting the audit.
        return cp
    return cp


def _dynamic_findings(bridges: list[dict], out: Path, policy: Policy, target: Path, errors: list[dict]) -> list[Finding]:
    if not bridges:
        return []
    try:
        sandbox = PolicyEngine(policy, Scope(authorized_targets={str(target)})).sandbox()
        toolchain = JvmToolchain.discover()
        if not toolchain.available:
            raise RuntimeError("JDK with javac is required for --dynamic")
        probe = DynamicProbe(toolchain, sandbox)
        results: list[Finding] = []

        def _finding(i: int, bridge: dict, result) -> Finding:
            return Finding(
                id=f"JGD-D{i:04d}",
                category="java-deserialization",
                verdict=result.verdict,
                severity="medium",
                confidence=0.5,
                entry={"class": bridge["cls"], "method": bridge["trigger"]},
                bridge={
                    "class": bridge["cls"],
                    "field": bridge["field"],
                    "field_desc": bridge["field_desc"],
                    "target": bridge["target"],
                    "via": bridge.get("via"),
                },
                sink={},
                evidence=[
                    {
                        "type": "dynamic_probe",
                        "verdict": result.verdict,
                        "rc": result.rc,
                        "sandbox": policy.sandbox,
                        "batch": True,
                    }
                ],
                remediation={},
            )

        # JVM batch pool: one JVM per target classpath instead of one per bridge.
        groups: dict[tuple[str, ...], list[tuple[int, dict]]] = {}
        cp_cache: dict[str, tuple[str, ...]] = {}
        for i, bridge in enumerate(bridges[:10]):
            key = str(bridge["jar_path"])
            if key not in cp_cache:
                cp_cache[key] = tuple(
                    str(p) for p in _dynamic_classpath(target, bridge, out)
                )
            groups.setdefault(cp_cache[key], []).append((i, bridge))
        for gi, (cp_key, items) in enumerate(groups.items()):
            work = out / "dynamic" / f"batch_{gi}"
            try:
                classpath = [Path(p) for p in cp_key]
                batch = probe.probe_many(
                    [b["cls"] for _, b in items],
                    work,
                    SandboxLimits(timeout_s=max(60, 30 * len(items))),
                    mode="HASHMAP",
                    classpath=classpath,
                )
                for (i, bridge), result in zip(items, batch):
                    results.append(_finding(i, bridge, result))
            except Exception as exc:
                errors.append({"code": "E_DYNAMIC_BATCH", "message": str(exc)})
                for i, bridge in items:
                    try:
                        result = probe.probe_class(
                            bridge["cls"],
                            out / "dynamic" / f"probe_{i}",
                            SandboxLimits(timeout_s=60),
                            mode="HASHMAP",
                            classpath=classpath,
                        )
                        results.append(_finding(i, bridge, result))
                    except Exception as one_exc:
                        errors.append({"code": "E_DYNAMIC", "message": str(one_exc)})
        return sorted(results, key=lambda f: f.id)
    except Exception as exc:
        errors.append({"code": "E_DYNAMIC", "message": str(exc)})
        return []


def _write_report(path: Path, result: RunResult, formats: set[str], findings: list[Finding]) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / "run.json").write_text(
        json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if "json" in formats:
        (path / "findings.json").write_text(
            json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    if "sarif" in formats:
        (path / "report.sarif").write_text(
            json.dumps(to_sarif(findings, TOOL_VERSION), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    if "md" in formats:
        lines = [f"# JGD audit — {result.target.get('root', '')}", ""]
        for f in findings:
            lines.append(f"- **{f.verdict}** `{f.entry.get('class', '')}` ({f.severity})")
        if not findings:
            lines.append("- no findings")
        (path / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _audit(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"jgd: target is not a directory: {target}", file=sys.stderr)
        return 30

    run_id = _run_id()
    out = Path(args.out).resolve() if args.out else (Path.cwd() / "runs" / run_id)
    policy = replace(
        Policy(),
        poc=not args.no_poc,
        llm="off" if (args.no_llm or args.offline) else "on",
        offline=args.offline,
        sandbox=args.sandbox,
        allow_host=args.unsafe_host,
        fail_on=args.fail_on,
    )
    config = JgdConfig(
        home=out,
        target=target,
        profile=args.profile,
        policy=policy,
        budget=Budget(jobs=args.jobs),
    )
    formats = {x.strip() for x in args.format.split(",") if x.strip()}
    errors: list[dict] = []
    db_path = out / "data" / "known_chains.db"
    db_status = "missing"
    db_chains = 0

    try:
        with BytecodeIndex(out / "index.db", reader=DisasmClassReader()) as idx:
            stats = idx.build(target)
            totals = {
                "jars": idx._conn.execute("SELECT COUNT(*) FROM jars").fetchone()[0],
                "classes": idx._conn.execute("SELECT COUNT(*) FROM classes").fetchone()[0],
                "methods": idx._conn.execute("SELECT COUNT(*) FROM methods").fetchone()[0],
            }
            jar_hashes = [
                row[0]
                for row in idx._conn.execute("SELECT sha256 FROM jars ORDER BY path")
            ]
            try:
                if not db_path.exists():
                    build_chain_db.build(db_path, quiet=True)
                    db_status = "built"
                else:
                    from jgd.verification import known_chains

                    db_status = known_chains.db_status(db_path)
                import sqlite3

                conn = sqlite3.connect(str(db_path))
                try:
                    db_chains = conn.execute("SELECT COUNT(*) FROM chains").fetchone()[0]
                finally:
                    conn.close()
                known = scan_known(idx, db_path)
            except Exception as exc:
                db_status = "fallback"
                db_chains = 0
                errors.append({"code": "E_DB_FALLBACK", "message": str(exc)})
                known = scan_known(idx)
            bridges = scan_bridges(idx) if args.profile != "known" else []
    except Exception as exc:
        result = RunResult(
            schema_version="jgd.run/v1",
            run_id=run_id,
            tool={"name": "jgd", "version": TOOL_VERSION},
            target={"root": str(target)},
            status="failed",
            findings=[],
            coverage={},
            errors=[{"code": "E_INDEX", "message": str(exc)}],
        )
        _write_report(out, result, formats, [])
        print(f"jgd: audit failed: {exc}", file=sys.stderr)
        return 30

    findings = _known_findings(known) + _bridge_findings(bridges)
    dynamic = (
        _dynamic_findings(bridges, out, policy, target, errors)
        if args.dynamic
        else []
    )
    poc_findings = (
        _audit_poc_findings(dynamic, target, out, args.ecj, errors)
        if (
            policy.poc
            and args.dynamic
            and args.sandbox == "host"
            and args.unsafe_host
        )
        else []
    )
    findings += dynamic + poc_findings
    baseline_keys = None
    if args.baseline:
        try:
            baseline_keys = ci.load_baseline(args.baseline)
        except Exception as exc:
            print(f"jgd: invalid baseline: {exc}", file=sys.stderr)
            return 30
    gate = ci.evaluate(
        findings,
        baseline=baseline_keys,
        fail_on=args.fail_on,
    )
    # Fingerprint the target by its JAR content hashes, independent of runId/time.
    fingerprint = (
        "sha256:" + hashlib.sha256("".join(sorted(jar_hashes)).encode()).hexdigest()
        if jar_hashes
        else "sha256:empty"
    )
    result = RunResult(
        schema_version="jgd.run/v1",
        run_id=run_id,
        tool={"name": "jgd", "version": TOOL_VERSION},
        target={"root": str(target), "profile": config.profile, "fingerprint": fingerprint},
        status="completed",
        findings=findings,
        coverage={
            "jars": totals["jars"],
            "classes": totals["classes"],
            "methods": totals["methods"],
            "bridges": len(bridges),
            "dynamic": len(dynamic),
            "poc": len(poc_findings),
            "profile": config.profile,
            "db_status": db_status,
            "db_chains": db_chains,
            "gate": {
                "failOn": gate["failOn"],
                "baselineApplied": gate["baselineApplied"],
                "baselineFindings": gate["baselineFindings"],
                "considered": gate["considered"],
                "blocking": gate["blocking"],
                "failed": gate["failed"],
            },
        },
        errors=errors,
    )
    _write_report(out, result, formats, findings)
    ci.write_gate(out / "gate.json", gate)

    failed = gate["failed"]
    print(
        json.dumps(
            {
                "runId": run_id,
                "out": str(out),
                "jars": totals["jars"],
                "classes": totals["classes"],
                "findings": len(findings),
                "bridges": len(bridges),
                "gate": {"failed": gate["failed"], "blocking": gate["blocking"]},
            },
            ensure_ascii=True,
        )
    )
    return 10 if failed else 0


def _audit_poc_findings(
    dynamic: list[Finding],
    target: Path,
    out: Path,
    ecj: str | None,
    errors: list[dict],
) -> list[Finding]:
    """Attempt deterministic closure only for dynamic DESER_OK candidates.

    This is reached only from an explicitly unsafe host-sandbox audit; the
    Linux VM is the intended boundary.
    """
    from jgd.poc import poc_gen

    candidates = [f for f in dynamic if f.verdict == "DESER_OK"][:3]
    results: list[Finding] = []
    for i, source in enumerate(candidates):
        cls = source.entry.get("class", "").replace("/", ".")
        if not cls:
            continue
        try:
            result = poc_gen.run_chain(
                target,
                cls,
                trigger="hash",
                out=out / "poc" / f"candidate_{i}",
                ecj=ecj,
            )
        except Exception as exc:
            errors.append({"code": "E_POC", "message": f"{cls}: {exc}"})
            continue
        if result.get("status") != "RCE_DEMO_FIRED":
            continue
        results.append(
            Finding(
                id=f"JGD-P{i:04d}",
                category="java-deserialization",
                verdict="CHAIN_CONFIRMED",
                severity="critical",
                confidence=0.95,
                entry=source.entry,
                bridge=source.bridge,
                sink={},
                evidence=[
                    {
                        "type": "poc_closure",
                        "status": result.get("status"),
                        "fired_at_build": result.get("fired_at_build"),
                        "fired_at_deser": result.get("fired_at_deser"),
                        "tail": result.get("closed_by_tail"),
                        "payload": result.get("ser"),
                    }
                ],
                remediation={},
            )
        )
    return results


def _poc(args: argparse.Namespace) -> int:
    if not args.unsafe_host:
        print(
            "jgd: poc executes target code and is unsafe on a host; "
            "run inside the Linux VM and pass --unsafe-host",
            file=sys.stderr,
        )
        return 30
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"jgd: target is not a directory: {target}", file=sys.stderr)
        return 30
    out = Path(args.out).resolve() if args.out else (
        Path.cwd() / "runs" / f"poc-{_run_id()}"
    )
    try:
        from jgd.poc import poc_gen

        result = poc_gen.run_chain(
            target,
            args.bridge,
            trigger=args.trigger,
            tail=args.tail,
            jdk11=args.jdk11,
            out=out,
            ecj=args.ecj,
        )
    except Exception as exc:
        print(f"jgd: poc failed: {exc}", file=sys.stderr)
        return 30
    print(json.dumps({
        "status": result.get("status"),
        "chain": result.get("chain"),
        "bridge": result.get("bridge"),
        "fired_at_build": result.get("fired_at_build"),
        "fired_at_deser": result.get("fired_at_deser"),
        "payload": result.get("ser"),
        "out": str(out),
    }, ensure_ascii=True))
    return 0 if result.get("status") == "RCE_DEMO_FIRED" else 10


def _index_build(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    if not target.is_dir():
        print(f"jgd: target is not a directory: {target}", file=sys.stderr)
        return 30
    db = Path(args.db).resolve() if args.db else (Path.cwd() / "data" / "bytecode-index.db")
    try:
        with BytecodeIndex(db, reader=DisasmClassReader()) as idx:
            stats = idx.build(target)
    except Exception as exc:
        print(f"jgd: index failed: {exc}", file=sys.stderr)
        return 30
    print(json.dumps(stats.__dict__, ensure_ascii=True))
    return 0


def _db_build(args: argparse.Namespace) -> int:
    path = build_chain_db.build(args.out)
    print(str(path))
    return 0


def _db_verify(args: argparse.Namespace) -> int:
    import sqlite3

    path = Path(args.db) if args.db else build_chain_db.DEFAULT_DB_PATH
    if not path.exists():
        print(f"jgd: DB not found: {path}", file=sys.stderr)
        return 30
    conn = sqlite3.connect(str(path))
    try:
        count = conn.execute("SELECT COUNT(*) FROM chains").fetchone()[0]
    except Exception as exc:
        print(f"jgd: invalid DB: {exc}", file=sys.stderr)
        return 30
    finally:
        conn.close()
    print(json.dumps({"db": str(path), "chains": count}, ensure_ascii=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    if args.command == "audit":
        return _audit(args)
    if args.command == "poc":
        return _poc(args)
    if args.command == "index" and args.index_command == "build":
        return _index_build(args)
    if args.command == "db" and args.db_command == "build":
        return _db_build(args)
    if args.command == "db" and args.db_command == "verify":
        return _db_verify(args)
    if args.command == "serve" and args.serve_command == "mcp":
        from jgd.adapters.mcp_server import serve as mcp_serve

        return mcp_serve(home=Path(args.home) if args.home else None)
    if args.command == "serve" and args.serve_command == "a2a":
        from jgd.adapters.a2a_server import serve as a2a_serve

        return a2a_serve(
            host=args.host,
            port=args.port,
            home=Path(args.home) if args.home else None,
            token=args.token,
        )
    if args.command == "serve" and args.serve_command == "webhook":
        from jgd.adapters.webhook_server import serve as webhook_serve

        try:
            return webhook_serve(
                host=args.host,
                port=args.port,
                home=Path(args.home) if args.home else None,
                work_dir=Path(args.work_dir) if args.work_dir else None,
                token=args.token,
                secret=args.secret,
                nexus_base_url=args.nexus_base_url,
                nexus_token=args.nexus_token,
                local_root=Path(args.local_root) if args.local_root else None,
                profile=args.profile,
                fail_on=args.fail_on,
                dynamic=args.dynamic,
                sandbox=args.sandbox,
                allow_host=args.unsafe_host,
                wait=args.wait,
                wait_timeout=args.wait_timeout,
            )
        except Exception as exc:
            print(f"jgd: webhook failed: {exc}", file=sys.stderr)
            return 30
    if args.command == "doctor":
        print(
            json.dumps(
                run_doctor(target=Path(args.target) if args.target else None),
                ensure_ascii=True,
                indent=2,
            )
        )
        return 0
    if args.command == "version":
        print(f"jgd {TOOL_VERSION}")
        return 0
    return 30


if __name__ == "__main__":
    raise SystemExit(main())
