"""综合实现: 多JDK矩阵 + ASM静态分析 + FAIL/ERROR区分 + 图/RAG混合架构。

四项修复同时落地:
1. JDK 17 安装 + 多JDK探针池
2. ASM 静态分析(不实例化, 读字节码判桥行为) — 替代 Class.forName
3. 结果分类: CONFIRMED / FAIL(能力否定) / ERROR_ENV(环境阻塞) / ERROR_DEP(依赖缺失)
4. SQLite 留图 + RAG 存衍生知识(已共识,此处固化)
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import scope

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))
import staticagent
import chroma_store
import llm
import bridge_fix          # R6修正: 接收者感知的字段桥检测(操作数栈模拟)

DYN = Path.home() / "jgd/dyn"
ECJ = Path.home() / "jgd/tools/ecj.jar"
IMPACT = Path.home() / "jgd/targets-impact/all-jars"
TOP50 = Path.home() / "jgd/targets-top50"
CLASSIC = Path.home() / "jgd/targets"
STATE = scope.DATA / "matrix_state.json"


def corpus_dir() -> Path:
    """R40: 目标语料参数化 — JGD_TARGET 指向任意 jar 产品目录,
    默认回落研究语料。图/缓存全部按指纹自动失效。"""
    import os
    t = os.environ.get("JGD_TARGET")
    if t:
        p = Path(t)
        if p.is_dir():
            return p
    return IMPACT

# JDK 版本映射
JAVA_VERSIONS = {52: 8, 53: 9, 54: 10, 55: 11, 56: 12, 57: 13, 58: 14,
                 59: 15, 60: 16, 61: 17, 62: 18, 63: 19, 64: 20, 65: 21}

EXCLUDE = [
    "org.apache.commons.collections", "org.apache.commons.beanutils",
    "com.sun.syndication", "com.alibaba.fastjson", "com.mchange",
    "BadAttributeValueExpException", "java.security.SignedObject",
    "sun.reflect.annotation", "java.",
]


def sh(cmd, timeout=120):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=HERE)
    return p.returncode, p.stdout + p.stderr


# ============================================================
# 1. 多 JDK 探针池
# ============================================================

def find_jdks() -> dict[int, str]:
    """发现系统上所有可用 JDK。"""
    jdks = {}
    # 系统 JDK
    for base in ["/usr/lib/jvm", "/opt/java", Path.home() / "jgd/jdk"]:
        if not Path(base).exists():
            continue
        for d in sorted(Path(base).iterdir()):
            java_bin = d / "bin" / "java"
            if java_bin.exists():
                rc, out = sh([str(java_bin), "-version"], timeout=10)
                for line in out.splitlines():
                    if "version" in line and '"' in line:
                        ver = line.split('"')[1].split(".")[0]
                        try:
                            major = int(ver)
                            jdks[major] = str(d)
                        except ValueError:
                            pass
    return jdks


def install_jdk17():
    """安装 JDK 17 (如果不存在)。"""
    jdks = find_jdks()
    if 17 in jdks:
        print(f"  JDK 17 已存在: {jdks[17]}")
        return jdks[17]

    # 尝试 apt install
    print("  安装 OpenJDK 17...")
    rc, out = sh(["sudo", "apt-get", "install", "-y", "openjdk-17-jdk-headless"],
                 timeout=300)
    if rc != 0:
        # 尝试不带 sudo
        rc, out = sh(["apt-get", "install", "-y", "openjdk-17-jdk-headless"], timeout=300)
    if rc != 0:
        # 下载 Temurin
        print("  apt 失败, 尝试下载 Temurin 17...")
        jdk_dir = Path.home() / "jgd/jdk17"
        if not jdk_dir.exists():
            jdk_dir.mkdir(parents=True)
            url = "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse"
            rc, out = sh(["curl", "-sfL", "--retry", "2", "-o",
                         str(jdk_dir / "jdk17.tar.gz"), url], timeout=300)
            if rc == 0:
                sh(["tar", "xzf", str(jdk_dir / "jdk17.tar.gz"), "-C", str(jdk_dir)], timeout=120)
                # 找解压后的目录
                for d in jdk_dir.iterdir():
                    if (d / "bin" / "java").exists():
                        print(f"  Temurin 17 安装: {d}")
                        return str(d)
        print("  JDK 17 安装失败")
        return None
    # 重新扫描
    jdks = find_jdks()
    return jdks.get(17)


def read_class_major_version(jar_path: str, class_name: str) -> int:
    """读取 .class 文件的主版本号(不需要 JVM)。"""
    try:
        path = class_name.replace(".", "/") + ".class"
        with zipfile.ZipFile(jar_path) as z:
            if path not in z.namelist():
                return 0
            data = z.read(path)
            # class 文件头: magic(4) + minor(2) + major(2)
            return struct.unpack(">H", data[6:8])[0]
    except Exception:
        return 0


# ============================================================
# 2. ASM 静态分析(不实例化, 读字节码)
# ============================================================

def static_probe(jar_path: str, class_name: str) -> dict:
    """纯字节码分析判断桥行为 — 不需要 JVM, 不实例化, 不受 JDK 版本限制。"""
    try:
        path = class_name.replace(".", "/") + ".class"
        with zipfile.ZipFile(jar_path) as z:
            if path not in z.namelist():
                return {"cls": class_name, "verdict": "NOT_FOUND"}
            data = z.read(path)

        ci = staticagent.parse_class(data)
        if not ci:
            return {"cls": class_name, "verdict": "PARSE_FAIL"}

        # 检查 Serializable
        serializable = ("java/io/Serializable" in ci["ifcs"] or
                       ci["super"] in staticagent.KNOWN_SERIAL_SUPERS)

        # 检查触发器方法
        methods = ci["methods"]
        trigger_methods = []
        for (mn, md), calls in methods.items():
            if mn in ("toString", "hashCode", "equals", "compareTo"):
                trigger_methods.append(mn)

        # R6修正: 桥证据改为接收者感知检测。
        # 旧逻辑只匹配被调方法名(忽略 owner/接收者), 产生大量假阳性
        # (String.hashCode/StringBuilder.toString/参数上的调用全部误报),
        # 同时漏掉白名单外的真转发(String.contentEquals 等)。
        # field_bridges() 做符号化操作数栈模拟, 只认
        # 「getfield <本类实例字段> 后接收者恰为该字段值」的调用。
        bridge_detail = bridge_fix.field_bridges(jar_path, class_name)
        bridge_evidence = [f"{b['trigger']}→{b['field']}.{b['target']}"
                           for b in bridge_detail]

        # R6修正: 开放字段判定。旧逻辑排除 final — 方向反了:
        # ObjectInputStream 反射写字段不走构造器、不检查 final,
        # final 字段恰恰是典型的反序列化可控字段。
        # 正确排除集: static(不参与默认序列化) + transient(跳过默认序列化)。
        open_fields = []
        for fname, faccess, fdesc in ci.get("fields_full", []):
            if not (faccess & 0x0008) and not (faccess & 0x0080):  # 非static非transient
                open_fields.append({"name": fname, "type": fdesc})

        major_ver = struct.unpack(">H", data[6:8])[0]

        if bridge_evidence:
            verdict = "STATIC_BRIDGE_CONFIRMED"
        elif serializable and trigger_methods:
            verdict = "SERIALIZABLE_WITH_TRIGGERS"
        elif trigger_methods:
            verdict = "TRIGGERS_ONLY"
        elif serializable:
            verdict = "SERIALIZABLE_ONLY"
        else:
            verdict = "NOT_RELEVANT"

        return {
            "cls": class_name,
            "verdict": verdict,
            "serializable": serializable,
            "trigger_methods": trigger_methods,
            "bridge_evidence": bridge_evidence,
            "bridge_detail": bridge_detail,
            "open_fields": open_fields,
            "class_major_version": major_ver,
            "needs_jdk": JAVA_VERSIONS.get(major_ver, 0),
            "method_count": len(methods),
        }
    except Exception as e:
        return {"cls": class_name, "verdict": f"ERROR: {type(e).__name__}"}


# ============================================================
# 3. FAIL vs ERROR 区分
# ============================================================

def classify_result(result: dict) -> str:
    """区分 CONFIRMED / FAIL / ERROR_ENV / ERROR_DEP。"""
    v = result.get("verdict", "")

    if "STATIC_BRIDGE" in v or "CONFIRMED" in v:
        return "CONFIRMED"
    elif v == "DESER_OK":
        return "CONFIRMED"  # 动态: BAVE 载体序列化+readObject 全程存活
    elif v.startswith("DESER_EX"):
        return "FAIL"  # 反序列化抛异常: 该类与载体组合被能力否定
    elif v in ("NOT_RELEVANT", "TRIGGERS_ONLY", "SERIALIZABLE_ONLY",
               "SERIALIZABLE_WITH_TRIGGERS"):
        return "FAIL"  # 能力否定: 类确实没有桥行为
    elif "UnsupportedClassVersion" in v:
        return "ERROR_ENV"  # 环境阻塞: JDK 版本不够
    elif "NoClassDefFound" in v or "ClassNotFound" in v:
        return "ERROR_DEP"  # 依赖缺失
    elif "INST_FAIL" in v or "PARSE_FAIL" in v:
        return "ERROR_DEP"  # 实例化/解析失败(通常是依赖)
    else:
        return "ERROR_UNKNOWN"


# ============================================================
# 4. 主流程: 静态扫描 + 多JDK动态验证 + 分类 + 进化
# ============================================================

def scan_jars_static(jar_dir: Path, count=50, jar_limit=30) -> list[dict]:
    """ASM 静态扫描(不需要 JVM) — 第一层过滤。

    R22: jar_limit 原硬编码 30 —— 828 jar 只扫过 ~30 个, 798 个 jar 的桥类
    从未进入候选流(用户裁决链存在 → 覆盖优先)。jar_limit=None 扫全语料。
    """
    results = []
    scanned = 0
    for jar in sorted(jar_dir.glob("*.jar")):
        scanned += 1
        if jar_limit is not None and scanned > jar_limit:
            break
        try:
            with zipfile.ZipFile(jar) as z:
                for ent in z.namelist():
                    if not ent.endswith(".class") or "-" in Path(ent).stem:
                        continue
                    cn = ent[:-6].replace("/", ".")
                    if any(cn.startswith(p) for p in EXCLUDE) or "$" in cn:
                        continue

                    result = static_probe(str(jar), cn)
                    if result["verdict"] in ("STATIC_BRIDGE_CONFIRMED",
                                            "SERIALIZABLE_WITH_TRIGGERS"):
                        result["jar"] = jar.name
                        result["classification"] = classify_result(result)
                        results.append(result)

                    if len(results) >= count:
                        return results
        except Exception:
            continue
    return results


def dynamic_probe_with_jdk(result: dict, jdk_path: str) -> dict:
    """用指定 JDK 运行时验证静态分析结果。"""
    java_bin = Path(jdk_path) / "bin" / "java"
    if not java_bin.exists():
        return {**result, "dynamic_verdict": "JDK_NOT_FOUND"}

    cls = result["cls"]
    jar = result.get("jar", "")
    n = int(time.time() * 1000) % 100000

    # 构建简单的运行时验证: 尝试加载类并调用 toString
    # (R7修正: 类名必须与文件名 DynV{n}.java 一致, 否则 ECJ 报
    #  "public type must be defined in its own file" -> 全量 COMPILE_FAIL)
    java_code = f"""import java.io.*;
import java.lang.reflect.*;

public class DynV{n} {{
    public static void main(String[] args) {{
        try {{
            Class<?> c = Class.forName("{cls}");
            boolean ser = Serializable.class.isAssignableFrom(c);
            Object obj = null;
            try {{ obj = c.getDeclaredConstructor().newInstance(); }}
            catch (Throwable t) {{
                try {{
                    Constructor<?> ctor = sun.reflect.ReflectionFactory
                        .getReflectionFactory()
                        .newConstructorForSerialization(c,
                            Object.class.getDeclaredConstructor());
                    ctor.setAccessible(true); obj = ctor.newInstance();
                }} catch (Throwable t2) {{}}
            }}
            if (obj == null) {{ System.out.println("DYN=INST_FAIL"); return; }}
            try {{ obj.toString(); }} catch (Throwable ignore) {{}}
            if (ser) {{
                try {{
                    javax.management.BadAttributeValueExpException b =
                        new javax.management.BadAttributeValueExpException(null);
                    Field vf = b.getClass().getDeclaredField("val");
                    vf.setAccessible(true); vf.set(b, obj);
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    new ObjectOutputStream(bos).writeObject(b);
                    try {{
                        new ObjectInputStream(
                            new ByteArrayInputStream(bos.toByteArray())).readObject();
                        System.out.println("DYN=DESER_OK");
                    }} catch (Throwable t) {{
                        System.out.println("DYN=DESER_EX:" + t.getClass().getSimpleName());
                    }}
                }} catch (Throwable t) {{
                    System.out.println("DYN=SER_FAIL");
                }}
            }} else {{
                System.out.println("DYN=NOT_SER");
            }}
        }} catch (Throwable t) {{
            System.out.println("DYN=ERROR:" + t.getClass().getSimpleName());
        }}
    }}
}}
"""
    (DYN / f"DynV{n}.java").write_text(java_code, encoding="utf-8")

    # 编译(用 ECJ, 与 JDK 无关)
    cp = f"{DYN}:{IMPACT}/*:{CLASSIC}/*:{TOP50}/*"
    rc, out = sh(["java", "-jar", str(ECJ), "-11", "-nowarn",
                  "-cp", cp, "-d", str(DYN),
                  str(DYN / f"DynV{n}.java")])
    if rc != 0:
        return {**result, "dynamic_verdict": "COMPILE_FAIL"}

    # 用指定 JDK 运行
    rc, out = sh([str(java_bin), "-cp", cp, f"DynV{n}"])
    dyn_v = "UNKNOWN"
    for line in out.splitlines():
        if line.startswith("DYN="):
            dyn_v = line[4:]
            break

    return {**result, "dynamic_verdict": dyn_v,
            "dynamic_classification": classify_result({"verdict": dyn_v})}


def main():
    t0 = time.time()
    print("=" * 60)
    print("JGDMatrixAgent: 多JDK + ASM静态 + FAIL/ERROR区分")
    print("=" * 60)

    # 1. 发现/安装 JDK
    print("\n[1] JDK 发现...")
    jdks = find_jdks()
    print(f"  可用 JDK: {jdks}")
    jdk17 = jdks.get(17)
    if not jdk17:
        jdk17 = install_jdk17()
        if jdk17:
            print(f"  JDK 17 已安装: {jdk17}")
        else:
            print("  JDK 17 不可用, 仅用 JDK 11")

    # 2. ASM 静态扫描(不需要 JVM)
    print(f"\n[2] ASM 静态扫描(纯字节码, 不实例化)...")
    static_results = scan_jars_static(IMPACT, count=50)
    bridge_candidates = [r for r in static_results
                        if r["verdict"] == "STATIC_BRIDGE_CONFIRMED"]
    serializable_triggers = [r for r in static_results
                            if r["verdict"] == "SERIALIZABLE_WITH_TRIGGERS"]
    print(f"  扫描结果: {len(static_results)} 个候选")
    print(f"    STATIC_BRIDGE_CONFIRMED: {len(bridge_candidates)}")
    print(f"    SERIALIZABLE_WITH_TRIGGERS: {len(serializable_triggers)}")

    for r in bridge_candidates[:10]:
        print(f"    ★ {r['cls'].split('.')[-1]:<30} triggers={r['trigger_methods'][:3]} "
              f"bridge={r['bridge_evidence'][:3]} jdk={r['needs_jdk']}")

    # 3. 对 STATIC_BRIDGE 用多 JDK 动态验证
    if bridge_candidates:
        print(f"\n[3] 动态验证 STATIC_BRIDGE 候选...")
        for r in bridge_candidates[:10]:
            needs_jdk = r.get("needs_jdk", 11)
            if needs_jdk <= 11:
                jdk_path = "/usr/lib/jvm/java-11-openjdk-amd64"
            elif needs_jdk <= 17 and jdk17:
                jdk_path = jdk17
            else:
                r["dynamic_verdict"] = "SKIP_JDK_TOO_NEW"
                r["classification"] = "ERROR_ENV"
                continue

            print(f"    验证 {r['cls'].split('.')[-1]} (JDK {needs_jdk})...")
            verified = dynamic_probe_with_jdk(r, jdk_path)
            r.update(verified)

    # 4. 分类统计
    print(f"\n[4] 结果分类(FAIL vs ERROR 区分)...")
    categories = {}
    for r in static_results + bridge_candidates:
        cat = r.get("classification", classify_result(r))
        categories[cat] = categories.get(cat, 0) + 1
    for cat, count in sorted(categories.items()):
        print(f"  {cat}: {count}")

    # 5. 持久化到 SQLite(图) + RAG(知识)
    db = chroma_store.VStore()
    db.add([{"id": f"matrix:{r['cls']}",
             "type": "matrix_probe_result",
             "tags": [r.get("classification", "unknown").lower(),
                     r.get("verdict", "").lower()],
             "payload": r} for r in static_results])

    (scope.DATA / "matrix_state.json").write_text(
        json.dumps({"jdks": {str(k): v for k, v in jdks.items()},
                   "static_results": static_results,
                   "bridge_candidates": bridge_candidates,
                   "categories": categories},
                  ensure_ascii=False, indent=1), encoding="utf-8")

    print(f"\n{'=' * 60}")
    print(f"JGDMatrixAgent 完成 ({time.time()-t0:.0f}s)")
    print(f"  JDK: {list(jdks.keys())} (+17={'已装' if jdk17 else '未装'})")
    print(f"  静态候选: {len(static_results)}")
    print(f"  静态桥: {len(bridge_candidates)}")
    print(f"  分类: {categories}")
    print(f"  RAG: {db.count()}")
    print(f"{'=' * 60}")

    # 输出静态桥详情
    if bridge_candidates:
        print(f"\n{'★' * 30}")
        print(f"静态分析确认的桥类(不需要 JVM):")
        for r in bridge_candidates:
            print(f"  {r['cls']}")
            print(f"    triggers: {r['trigger_methods']}")
            print(f"    bridge evidence: {r['bridge_evidence']}")
            print(f"    serializable: {r['serializable']}")
            print(f"    needs JDK: {r.get('needs_jdk', '?')}")
            print(f"    dynamic: {r.get('dynamic_verdict', '未验证')}")
        print(f"{'★' * 30}")

    return len(bridge_candidates)


if __name__ == "__main__":
    raise SystemExit(main())
