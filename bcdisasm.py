"""Pure-Python JVM class-file reader + bytecode disassembler.

Independent of staticagent.py: keeps full descriptors, field types, access flags,
and resolves every field/method reference owner so that we can distinguish
"this.getName() / super.getName()" from "someField.getName()".
"""
from __future__ import annotations

import struct
import sys
import zipfile

# ---------------------------------------------------------------- access flags
ACC = {
    "PUBLIC": 0x0001, "PRIVATE": 0x0002, "PROTECTED": 0x0004, "STATIC": 0x0008,
    "FINAL": 0x0010, "VOLATILE": 0x0040, "TRANSIENT": 0x0080, "SYNTHETIC": 0x1000,
    "ENUM": 0x4000, "ABSTRACT": 0x0400, "INTERFACE": 0x0200, "NATIVE": 0x0100,
    "BRIDGE": 0x0040, "VARARGS": 0x0080, "STRICT": 0x0800, "SYNC": 0x0020,
}


def flags_to_str(f: int) -> str:
    return " ".join(k for k, v in ACC.items() if f & v) or "0x%04x" % f


# ------------------------------------------------------------- opcode metadata
# ldc=1, ldc_w=2, ldc2_w=2, new/anewarray/checkcast/instanceof=2, invokeinterface=4
# Operand byte counts per JVM SE 8 spec (0xaa/0xab/0xc4 are variable, handled inline).
OP_LEN = {op: 0 for op in range(0x00, 0x100)}
OP_LEN.update({
    0x10: 1, 0x11: 2, 0x12: 1, 0x13: 2, 0x14: 2,
    0x15: 1, 0x16: 1, 0x17: 1, 0x18: 1, 0x19: 1,
    0x36: 1, 0x37: 1, 0x38: 1, 0x39: 1, 0x3a: 1,
    0x84: 2, 0x99: 2, 0x9a: 2, 0x9b: 2, 0x9c: 2, 0x9d: 2, 0x9e: 2,
    0x9f: 2, 0xa0: 2, 0xa1: 2, 0xa2: 2, 0xa3: 2, 0xa4: 2,
    0xa5: 3, 0xa6: 3, 0xa7: 2, 0xa8: 2, 0xa9: 1,
    0xb2: 2, 0xb3: 2, 0xb4: 2, 0xb5: 2, 0xb6: 2, 0xb7: 2, 0xb8: 2,
    0xb9: 4, 0xba: 4, 0xbb: 2, 0xbc: 1, 0xbd: 2,
    0xc0: 2, 0xc1: 2, 0xc5: 3, 0xc6: 3, 0xc7: 3, 0xc8: 4, 0xc9: 4,
})

NAME = {
    0x00: "nop", 0x01: "aconst_null", 0x02: "iconst_m1", 0x03: "iconst_0",
    0x04: "iconst_1", 0x05: "iconst_2", 0x06: "iconst_3", 0x07: "iconst_4",
    0x08: "iconst_5", 0x09: "lconst_0", 0x0a: "lconst_1", 0x0b: "fconst_0",
    0x0c: "fconst_1", 0x0d: "fconst_2", 0x0e: "dconst_0", 0x0f: "dconst_1",
    0x10: "bipush", 0x11: "sipush", 0x12: "ldc", 0x13: "ldc_w", 0x14: "ldc2_w",
    0x15: "iload", 0x16: "lload", 0x17: "fload", 0x18: "dload", 0x19: "aload",
    0x1a: "iload_0", 0x1b: "iload_1", 0x1c: "iload_2", 0x1d: "iload_3",
    0x1e: "lload_0", 0x1f: "lload_1", 0x20: "lload_2", 0x21: "lload_3",
    0x22: "fload_0", 0x23: "fload_1", 0x24: "fload_2", 0x25: "fload_3",
    0x26: "dload_0", 0x27: "dload_1", 0x28: "dload_2", 0x29: "dload_3",
    0x2a: "aload_0", 0x2b: "aload_1", 0x2c: "aload_2", 0x2d: "aload_3",
    0x2e: "iaload", 0x2f: "laload", 0x30: "faload", 0x31: "daload",
    0x32: "aaload", 0x33: "baload", 0x34: "caload", 0x35: "saload",
    0x36: "istore", 0x37: "lstore", 0x38: "fstore", 0x39: "dstore",
    0x3a: "astore", 0x3b: "istore_0", 0x3c: "istore_1", 0x3d: "istore_2",
    0x3e: "istore_3", 0x3f: "lstore_0", 0x40: "lstore_1", 0x41: "lstore_2",
    0x42: "lstore_3", 0x43: "fstore_0", 0x44: "fstore_1", 0x45: "fstore_2",
    0x46: "fstore_3", 0x47: "dstore_0", 0x48: "dstore_1", 0x49: "dstore_2",
    0x4a: "dstore_3", 0x4b: "astore_0", 0x4c: "astore_1", 0x4d: "astore_2",
    0x4e: "astore_3", 0x4f: "iastore", 0x50: "lastore", 0x51: "fastore",
    0x52: "dastore", 0x53: "aastore", 0x54: "bastore", 0x55: "castore",
    0x56: "sastore", 0x57: "pop", 0x58: "pop2", 0x59: "dup", 0x5a: "dup_x1",
    0x5b: "dup_x2", 0x5c: "dup2", 0x5d: "dup2_x1", 0x5e: "dup2_x2",
    0x5f: "swap", 0x60: "iadd", 0x61: "ladd", 0x62: "fadd", 0x63: "dadd",
    0x64: "isub", 0x65: "lsub", 0x66: "fsub", 0x67: "dsub", 0x68: "imul",
    0x69: "lmul", 0x6a: "fmul", 0x6b: "dmul", 0x6c: "idiv", 0x6d: "ldiv",
    0x6e: "fdiv", 0x6f: "ddiv", 0x70: "irem", 0x71: "lrem", 0x72: "frem",
    0x73: "drem", 0x74: "ineg", 0x75: "lneg", 0x76: "fneg", 0x77: "dneg",
    0x78: "ishl", 0x79: "lshl", 0x7a: "ishr", 0x7b: "lshr", 0x7c: "iushr",
    0x7d: "lushr", 0x7e: "iand", 0x7f: "land", 0x80: "ior", 0x81: "lor",
    0x82: "ixor", 0x83: "lxor", 0x84: "iinc", 0x85: "i2l", 0x86: "i2f",
    0x87: "i2d", 0x88: "l2i", 0x89: "l2f", 0x8a: "l2d", 0x8b: "f2i",
    0x8c: "f2l", 0x8d: "f2d", 0x8e: "d2i", 0x8f: "d2l", 0x90: "d2f",
    0x91: "i2b", 0x92: "i2c", 0x93: "i2s", 0x94: "lcmp", 0x95: "fcmpl",
    0x96: "fcmpg", 0x97: "dcmpl", 0x98: "dcmpg", 0x99: "ifeq", 0x9a: "ifne",
    0x9b: "iflt", 0x9c: "ifge", 0x9d: "ifgt", 0x9e: "ifle", 0x9f: "if_icmpeq",
    0xa0: "if_icmpne", 0xa1: "if_icmplt", 0xa2: "if_icmpge", 0xa3: "if_icmpgt",
    0xa4: "if_icmple", 0xa5: "if_acmpeq", 0xa6: "if_acmpne", 0xa7: "goto",
    0xa8: "jsr", 0xa9: "ret", 0xaa: "tableswitch", 0xab: "lookupswitch",
    0xac: "ireturn", 0xad: "lreturn", 0xae: "freturn", 0xaf: "dreturn",
    0xb0: "areturn", 0xb1: "return", 0xb2: "getstatic", 0xb3: "putstatic",
    0xb4: "getfield", 0xb5: "putfield", 0xb6: "invokevirtual",
    0xb7: "invokespecial", 0xb8: "invokestatic", 0xb9: "invokeinterface",
    0xba: "invokedynamic", 0xbb: "new", 0xbc: "newarray", 0xbd: "anewarray",
    0xbe: "arraylength", 0xbf: "athrow", 0xc0: "checkcast", 0xc1: "instanceof",
    0xc2: "monitorenter", 0xc3: "monitorexit", 0xc4: "wide", 0xc5: "multianewarray",
    0xc6: "ifnull", 0xc7: "ifnonnull", 0xc8: "goto_w", 0xc9: "jsr_w",
}

INVOKE = {"invokevirtual", "invokespecial", "invokestatic", "invokeinterface"}
FIELD_OPS = {"getfield", "putfield", "getstatic", "putstatic"}


class ClassFile:
    def __init__(self, data: bytes):
        self.raw = data
        r = _R(data)
        assert r.u4() == 0xCAFEBABE, "not a class file"
        self.minor = r.u2()
        self.major = r.u2()
        n = r.u2()
        cp = [None] * n
        i = 1
        while i < n:
            tag = r.u1()
            if tag == 1:
                ln = r.u2()
                cp[i] = ("utf", r.bytes(ln).decode("utf-8", "replace"))
            elif tag in (3, 4):
                cp[i] = ("num", r.u4())
            elif tag in (5, 6):
                cp[i] = ("long", r.u8())
                i += 1
            elif tag == 7:
                cp[i] = ("class", r.u2())
            elif tag == 8:
                cp[i] = ("string", r.u2())
            elif tag in (9, 10, 11):
                cp[i] = ("ref", r.u2(), r.u2())
            elif tag == 12:
                cp[i] = ("nat", r.u2(), r.u2())
            elif tag == 15:
                cp[i] = ("mh", r.u1(), r.u2())
            elif tag == 16:
                cp[i] = ("mt", r.u2())
            elif tag in (17, 18):
                cp[i] = ("dyn", r.u2(), r.u2())
            elif tag in (19, 20):
                cp[i] = ("module", r.u2())
            else:
                raise ValueError("bad cp tag %d at %d" % (tag, i))
            i += 1
        self.cp = cp

        self.access = r.u2()
        self.this = self.cls(r.u2())
        self.super = self.cls(r.u2())
        self.ifcs = [self.cls(r.u2()) for _ in range(r.u2())]

        self.fields = []
        for _ in range(r.u2()):
            acc, ni, di = r.u2(), r.u2(), r.u2()
            attrs = self._attrs(r)
            self.fields.append({
                "name": self.utf(ni), "desc": self.utf(di), "access": acc,
                "attrs": attrs,
                "constant_value": self._const_value(attrs),
            })

        self.methods = []
        for _ in range(r.u2()):
            acc, ni, di = r.u2(), r.u2(), r.u2()
            attrs = self._attrs(r)
            code = attrs.get("Code")
            self.methods.append({
                "name": self.utf(ni), "desc": self.utf(di), "access": acc,
                "attrs": attrs,
                "code": self._code_body(code),
            })

    # -------------------------------------------------------------- helpers
    def utf(self, i):
        e = self.cp[i]
        return e[1] if e and e[0] == "utf" else ""

    def cls(self, i):
        e = self.cp[i]
        if e and e[0] == "class":
            return self.utf(e[1])
        return ""

    def _attrs(self, r):
        out = {}
        for _ in range(r.u2()):
            ni, ln = r.u2(), r.u4()
            out[self.utf(ni)] = r.bytes(ln)
        return out

    def _const_value(self, attrs):
        b = attrs.get("ConstantValue")
        if not b:
            return None
        idx = struct.unpack(">H", b[:2])[0]
        e = self.cp[idx]
        if not e:
            return None
        if e[0] == "string":
            return self.utf(e[1])
        if e[0] == "num":
            return e[1]
        return e[1]

    def _code_body(self, code_attr):
        if not code_attr:
            return None
        max_stack, max_locals = struct.unpack(">HH", code_attr[:4])
        clen = struct.unpack(">I", code_attr[4:8])[0]
        return {"max_stack": max_stack, "max_locals": max_locals,
                "code": code_attr[8:8 + clen]}

    def ref(self, idx):
        """Resolve a CONSTANT_Fieldref/Methodref/InterfaceMethodref."""
        e = self.cp[idx]
        if not e or e[0] != "ref":
            return ("", "", "")
        owner = self.cls(e[1])
        nt = self.cp[e[2]]
        if not nt or nt[0] != "nat":
            return (owner, "", "")
        return (owner, self.utf(nt[1]), self.utf(nt[2]))

    # ---------------------------------------------------------- disassembly
    def disasm(self, m):
        """Yield (offset, opcode_name, operand_text, resolved) tuples."""
        body = m["code"]
        if not body:
            return []
        code = body["code"]
        out = []
        i, n = 0, len(code)
        while i < n:
            op = code[i]
            nm = NAME.get(op, "op_%02x" % op)
            text, res = "", None
            need = OP_LEN.get(op, 0)
            if i + 1 + need > n:
                out.append((i, "<TRUNCATED:%s>" % nm,
                            "needs %d operand bytes, have %d" % (need, n - i - 1), None))
                break
            if op in (0xaa, 0xab):
                pad = (4 - ((i + 1) % 4)) % 4
                base = i + 1 + pad
                if op == 0xaa:
                    lo, hi = struct.unpack(">ii", code[base + 4:base + 12])
                    tgts = [struct.unpack(">i", code[base + 12 + 4 * k:base + 16 + 4 * k])[0]
                            for k in range(hi - lo + 1)]
                    text = "low=%d high=%d targets=%s" % (lo, hi, tgts)
                    i = base + 12 + 4 * (hi - lo + 1)
                else:
                    npairs = struct.unpack(">i", code[base + 4:base + 8])[0]
                    pairs = [struct.unpack(">ii", code[base + 8 + 8 * k:base + 16 + 8 * k])
                             for k in range(npairs)]
                    text = "pairs=%s" % (pairs,)
                    i = base + 8 + 8 * npairs
                out.append((i, nm, text, None))
                continue
            if op == 0xc4:
                sub = code[i + 1]
                if sub == 0x84:
                    idx, con = struct.unpack(">Hh", code[i + 2:i + 6])
                    text = "%s %d" % (NAME.get(sub), con)
                    i += 6
                else:
                    idx = struct.unpack(">H", code[i + 2:i + 4])[0]
                    text = "%s %d" % (NAME.get(sub), idx)
                    i += 4
                out.append((i, "wide", text, None))
                continue
            ln = OP_LEN.get(op, 0)
            oper = code[i + 1:i + 1 + ln]
            if op == 0xaa or op == 0xab:
                pass
            elif op == 0x10:
                text = str(struct.unpack(">b", oper)[0])
            elif op == 0x11:
                text = str(struct.unpack(">h", oper)[0])
            elif op in (0x12,):
                text = self._ldc(oper[0])
            elif op in (0x13, 0x14):
                text = self._ldc(struct.unpack(">H", oper)[0])
            elif op in (0x15, 0x16, 0x17, 0x18, 0x19, 0x36, 0x37, 0x38, 0x39, 0x3a,
                        0xbc, 0xa9):
                text = str(oper[0])
            elif op == 0x84:
                text = "%d %d" % struct.unpack(">Bb", oper)
            elif op in (0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2,
                        0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xc6, 0xc7):
                # 3-byte form is <opcode> <branchbyte1> <branchbyte2>; the 2-byte
                # signed offset lives in the trailing 2 bytes, not all 3.
                text = "-> %d" % (i + struct.unpack(">H", oper[-2:])[0])
            elif op in (0xc8, 0xc9):
                text = "-> %d" % (i + struct.unpack(">i", oper)[0])
            elif op in (0xb2, 0xb3, 0xb4, 0xb5):
                o, nmf, d = self.ref(struct.unpack(">H", oper)[0])
                text = "%s.%s:%s" % (o.replace("/", "."), nmf, d)
                res = ("field", o, nmf, d)
            elif op in (0xb6, 0xb7, 0xb8):
                o, nmf, d = self.ref(struct.unpack(">H", oper)[0])
                text = "%s.%s%s" % (o.replace("/", "."), nmf, d)
                res = ("method", o, nmf, d)
            elif op == 0xb9:
                o, nmf, d = self.ref(struct.unpack(">H", oper[0:2])[0])
                text = "%s.%s%s" % (o.replace("/", "."), nmf, d)
                res = ("method", o, nmf, d)
            elif op == 0xba:
                o, nmf, d = self.ref(struct.unpack(">H", oper[0:2])[0])
                text = "%s.%s%s" % (o.replace("/", "."), nmf, d)
                res = ("indy", o, nmf, d)
            elif op in (0xbb, 0xbd, 0xc0, 0xc1):
                text = self.cls(struct.unpack(">H", oper)[0]).replace("/", ".")
            elif op == 0xc5:
                ci, dim = struct.unpack(">HB", oper)
                text = "%s dims=%d" % (self.cls(ci).replace("/", "."), dim)
            out.append((i, nm, text, res))
            i += 1 + ln
        return out

    def _ldc(self, idx):
        e = self.cp[idx]
        if not e:
            return str(idx)
        if e[0] == "string":
            return '"%s"' % self.utf(e[1])
        if e[0] == "class":
            return "class %s" % self.cls(e[1]).replace("/", ".")
        if e[0] == "num":
            return str(e[1])
        if e[0] in ("dyn", "mh", "mt"):
            return "%s#%d" % (e[0], idx)
        return str(e)

    def find_method(self, name, desc=None):
        for m in self.methods:
            if m["name"] == name and (desc is None or m["desc"] == desc):
                return m
        return None

    def field_by_name(self, name):
        for f in self.fields:
            if f["name"] == name:
                return f
        return None


class _R:
    def __init__(self, b):
        self.b, self.i = b, 0

    def bytes(self, k):
        v = self.b[self.i:self.i + k]
        self.i += k
        return v

    def u1(self):
        v = self.b[self.i]
        self.i += 1
        return v

    def u2(self):
        v = struct.unpack(">H", self.b[self.i:self.i + 2])[0]
        self.i += 2
        return v

    def u4(self):
        v = struct.unpack(">I", self.b[self.i:self.i + 4])[0]
        self.i += 4
        return v

    def u8(self):
        v = struct.unpack(">Q", self.b[self.i:self.i + 8])[0]
        self.i += 8
        return v


def load(jar, cls):
    with zipfile.ZipFile(jar) as z:
        return ClassFile(z.read(cls.replace(".", "/") + ".class"))


def dump(jar, cls, methods=None, flds=True):
    cf = load(jar, cls)
    print("=" * 78)
    print("CLASS %s   major=%d (%s)" % (cf.this.replace("/", "."),
                                        cf.major, "JDK %d" % (cf.major - 44)))
    print("  access=[%s]" % flags_to_str(cf.access))
    print("  super=%s" % cf.super.replace("/", "."))
    print("  interfaces=%s" % [x.replace("/", ".") for x in cf.ifcs])
    ser = ("java/io/Serializable" in cf.ifcs
           or cf.super == "java/io/Serializable")
    print("  directSerializable=%s" % ser)
    if flds:
        print("  FIELDS:")
        for f in cf.fields:
            print("    %-28s %-34s [%s] const=%s" % (
                f["name"], f["desc"], flags_to_str(f["access"]), f["constant_value"]))
    print("  METHODS:")
    for m in cf.methods:
        print("    %-26s %-46s [%s]%s" % (
            m["name"], m["desc"], flags_to_str(m["access"]),
            "  <<< NO CODE (abstract/native)" if m["code"] is None else ""))
    for m in cf.methods:
        if methods and m["name"] not in methods:
            continue
        if m["code"] is None:
            continue
        print("-" * 78)
        print("CODE %s%s  max_stack=%d max_locals=%d" % (
            m["name"], m["desc"], m["code"]["max_stack"], m["code"]["max_locals"]))
        for off, nm, text, res in cf.disasm(m):
            tag = "   <== " + res[0].upper() if res else ""
            print("  %5d: %-16s %s%s" % (off, nm, text, tag))
    return cf


if __name__ == "__main__":
    jar, cls = sys.argv[1], sys.argv[2]
    ms = sys.argv[3].split(",") if len(sys.argv) > 3 else None
    dump(jar, cls, ms)
