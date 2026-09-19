"""Corrected bridge test for matrix_agent.static_probe.

DEFECT IN THE ORIGINAL (matrix_agent.py:154-163)
------------------------------------------------
    for (mn, md), calls in methods.items():
        if mn in ("toString", "hashCode", "equals", "compareTo"):
            for tc, tm, td in calls:               # tc = call OWNER
                if tm in (... "getName" ...):      # only the METHOD NAME is checked
                    bridge_evidence.append(f"{mn}->{tm}")

Both the call owner `tc` and the runtime receiver are ignored.  Consequences:

  * `this.getName()`, `super.getName()`, and `<argument>.getName()` all match.
  * `String.hashCode()`, `String.equals()`, `StringBuilder.toString()`,
    `Object.toString()` all match -- and these dominate real bytecode.
  * A genuine field bridge whose method name is not on the hardcoded list is
    MISSED (e.g. `String.contentEquals`, `String.length`, `Throwable.fillInStackTrace`).

A bridge, if it exists, has this bytecode shape:
    getfield <field>          receiver = this
    <load nothing else>
    invoke<X>                 receiver = THE FIELD VALUE just loaded

Recovering the runtime receiver needs a small operand-stack simulation, because
the JVM is a stack machine.  This module does that and exposes `field_bridges`,
a drop-in replacement for the `bridge_evidence` block.

Usage
-----
    from bridge_probe_fix import field_bridges
    field_bridges(jar_path, "io.agroal.api.security.NamePrincipal")
    # -> [{'trigger': 'hashCode', 'field': 'name',
    #      'field_desc': 'Ljava/lang/String;',
    #      'target': 'java/lang/String.hashCode()I'}, ...]
"""
from __future__ import annotations

from jgd.mining import bcdisasm as disasm  # verified class-file reader

TRIGGERS = ("toString", "hashCode", "equals", "compareTo")


def _slots(desc: str) -> int:
    """Number of category-1 operand slots for a method descriptor's parameters."""
    n, i = 0, 1
    while i < len(desc) and desc[i] != ")":
        c = desc[i]
        if c == "L":
            n += 1
            i = desc.index(";", i) + 1
        elif c == "[":
            while desc[i] == "[":
                i += 1
            i = desc.index(";", i) + 1 if desc[i] == "L" else i + 1
            n += 1
        else:
            n += 2 if c in "JD" else 1
            i += 1
    return n


def field_bridges(jar_path: str, class_name: str) -> list[dict]:
    """Genuine `this.<field>` -> `<field>.method()` bridges inside trigger methods.

    Conservative: a call whose receiver cannot be resolved to a field of *this*
    is dropped rather than attributed optimistically.
    """
    cf = disasm.load(jar_path, class_name)
    if not cf:
        return []
    field_desc = {f["name"]: f["desc"] for f in cf.fields}
    instance_fields = {f["name"] for f in cf.fields if not (f["access"] & 0x0008)}

    results = []
    for m in cf.methods:
        if m["name"] not in TRIGGERS or not m["code"]:
            continue
        # ---- symbolic operand stack (category-1 granularity) ----
        stack: list[str] = []
        local: dict[int, str] = {0: "THIS"}
        # map parameter slots to ARG markers
        slot = 1
        for _ in range(_slots(m["desc"])):
            local.setdefault(slot, "ARG")
            slot += 1

        pending_field = None   # value most recently pushed by getfield
        for off, nm, text, res in cf.disasm(m):
            if nm == "aload":
                stack.append(local.get(int(text), "?"))
            elif nm.startswith("aload_"):
                stack.append(local.get(int(nm[-1]), "?"))
            elif nm in ("iload", "lload", "fload", "dload") or \
                    nm.startswith(("iload_", "lload_", "fload_", "dload_")):
                stack.append("NUM")
            elif nm in ("iconst_m1", "iconst_0", "iconst_1", "iconst_2", "iconst_3",
                        "iconst_4", "iconst_5", "bipush", "sipush",
                        "ldc2_w", "aconst_null", "fconst_0",
                        "fconst_1", "fconst_2", "dconst_0", "dconst_1",
                        "lconst_0", "lconst_1"):
                stack.append("CONST")
            elif nm in ("ldc", "ldc_w"):
                # 常量携带字面量 — Map.get 的分派键需要它
                lit = (text or "").strip().strip('"').strip("'")
                stack.append("CONST:%s" % lit if lit else "CONST")
            elif nm in ("astore",):
                if stack:
                    local[int(text)] = stack.pop()
            elif nm.startswith("astore_"):
                if stack:
                    local[int(nm[-1])] = stack.pop()
            elif nm in ("istore", "lstore", "fstore", "dstore") or \
                    nm.startswith(("istore_", "lstore_", "fstore_", "dstore_")):
                if stack:
                    stack.pop()
            elif nm == "dup":
                if stack:
                    stack.append(stack[-1])
            elif nm in ("pop", "pop2"):
                if stack:
                    stack.pop()
            elif nm == "getfield":
                if stack:
                    stack.pop()                     # the objectref
                fname = res[2] if res else "?"
                stack.append("FIELD:%s" % fname)
                pending_field = fname
            elif nm == "getstatic":
                stack.append("STATIC")
                pending_field = None
            elif nm == "putfield":
                if len(stack) >= 2:
                    stack.pop(); stack.pop()
                pending_field = None
            elif nm in ("invokevirtual", "invokespecial", "invokeinterface"):
                argn = _slots(res[3]) if res else 0
                popped = []
                for _ in range(argn):
                    if stack:
                        popped.append(stack.pop())
                recv = stack.pop() if stack else "EMPTY"
                if recv.startswith("MAPGET:"):
                    # Map 中介分派: field 经 Map.get(key) 后作为 invoke 接收者
                    # (clojure proxy: __clojureFnMappings.get("hashCode").invoke())
                    fpart, _, key = recv[7:].partition("|")
                    if fpart in instance_fields:
                        results.append({
                            "trigger": m["name"],
                            "field": fpart,
                            "field_desc": field_desc.get(fpart, "?"),
                            "target": "%s.%s%s" % (res[1], res[2], res[3]) if res else "?",
                            "offset": off,
                            "via": "mapget",
                            "map_key": key or None,
                            "map_iface": res[1] if res else None,
                        })
                elif recv.startswith("FIELD:") and recv[6:] in instance_fields:
                    if res and res[1] == "java/util/Map" and res[2] == "get":
                        # Map.get 本身不是分派 — 挂起为 MAPGET 等待后续 invoke
                        keylit = ""
                        if popped and popped[0].startswith("CONST:"):
                            keylit = popped[0][6:]
                        stack.append("MAPGET:%s|%s" % (recv[6:], keylit))
                    else:
                        results.append({
                            "trigger": m["name"],
                            "field": recv[6:],
                            "field_desc": field_desc.get(recv[6:], "?"),
                            "target": "%s.%s%s" % (res[1], res[2], res[3]) if res else "?",
                            "offset": off,
                            "via": "recv",
                        })
                rtype = (res[3] if res else "()V").split(")")[1]
                if rtype != "V":
                    stack.append("RET")
                pending_field = None
            elif nm == "invokestatic":
                #  参数桥: 字段作为参数流入静态助手(如 ObjectEqualityComparator
                # .equals(a, p.a)) — 助手内部对接收者做 equals/hashCode 分派。
                # 只认接收者桥会漏掉这种模式(antlr4 Pair 因此漏检)。
                args = []
                for _ in range(_slots(res[3]) if res else 0):
                    args.append(stack.pop() if stack else "EMPTY")
                for a_ in args:
                    if a_.startswith("FIELD:") and a_[6:] in instance_fields:
                        results.append({
                            "trigger": m["name"],
                            "field": a_[6:],
                            "field_desc": field_desc.get(a_[6:], "?"),
                            "target": "%s.%s%s" % (res[1], res[2], res[3]) if res else "?",
                            "offset": off,
                            "via": "arg",
                        })
                rtype_s = (res[3] if res else "()V").split(")")[1]
                # Map 中介分派(静态形态): 字段流入静态 getter(如 clojure RT.get)
                # 的返回值随后被 invoke — 返回标记携带 field|key 供后续消费
                f_arg = next((a for a in args
                              if a.startswith("FIELD:")
                              and a[6:] in instance_fields), None)
                key_lit = next((a[6:] for a in args
                                if a.startswith("CONST:")), "")
                if f_arg and res and res[2] == "get" and rtype_s.startswith("L"):
                    stack.append("MAPGET:%s|%s" % (f_arg[6:], key_lit))
                elif rtype_s != "V":
                    stack.append("RET")
            elif nm == "invokedynamic":
                stack.append("RET")
            elif nm in ("ifnonnull", "ifnull", "ifeq", "ifne", "iflt", "ifge",
                        "ifgt", "ifle"):
                if stack:
                    stack.pop()
            elif nm in ("if_acmpeq", "if_acmpne", "if_icmpeq", "if_icmpne",
                        "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple"):
                if len(stack) >= 2:
                    stack.pop(); stack.pop()
            elif nm in ("new", "checkcast", "instanceof", "anewarray", "newarray"):
                if nm == "new":
                    stack.append("NEW")
            elif nm in ("iadd", "isub", "imul", "idiv", "irem", "iand", "ior",
                        "ixor", "ishl", "ishr", "iushr", "ladd", "lsub", "lmul",
                        "ldiv", "lrem", "land", "lor", "lxor", "fadd", "fsub",
                        "fmul", "fdiv", "frem", "dadd", "dsub", "dmul", "ddiv",
                        "drem", "lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg"):
                if len(stack) >= 2:
                    stack.pop(); stack.pop()
                stack.append("NUM")
            # everything else (returns, goto, iinc, conversions, monitors,
            # athrow, array ops) does not affect our receiver tracking.
    return results


def _selftest():
    cases = [
        ("agroal-api-2.0.jar", "io.agroal.api.security.NamePrincipal", 2),
        ("agroal-api-2.0.jar", "io.agroal.api.security.SimplePassword", 2),
        ("angus-mail-2.0.4.jar",
         "org.eclipse.angus.mail.util.logging.SeverityComparator", 0),
    ]
    ok = True
    for jar, cls, expect in cases:
        got = field_bridges(jar, cls)
        status = "OK " if len(got) == expect else "FAIL"
        if len(got) != expect:
            ok = False
        print("%s %-62s expected=%d got=%d" % (status, cls.split(".")[-1],
                                               expect, len(got)))
        for g in got:
            print("      %s -> this.%s (%s) -> %s" % (
                g["trigger"], g["field"], g["field_desc"], g["target"]))
    print("\nself-test:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_selftest())
