"""Minimal, sandbox-routed JVM probe.

The probe confirms class load/instantiation/serialization round-trip. It does
not claim a gadget chain; chain pairing remains in the mining engine. All
target code execution goes through a ``Sandbox``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from jgd.security.sandbox import HostSandbox, Sandbox, SandboxLimits, SandboxResult, wsl_path

_PROBE_SRC = r'''
import java.io.*;
import java.lang.reflect.*;

public class DynProbe {
    public static void main(String[] args) throws Exception {
        String cls = args[0];
        String mode = args.length > 1 ? args[1] : "HASHMAP";
        try {
            Class<?> c = Class.forName(cls);
            Object o;
            try { o = c.getDeclaredConstructor().newInstance(); }
            catch (Throwable t) {
                Constructor<?> ctor = sun.reflect.ReflectionFactory
                    .getReflectionFactory()
                    .newConstructorForSerialization(c, Object.class.getDeclaredConstructor());
                ctor.setAccessible(true);
                o = ctor.newInstance();
            }
            if (!(o instanceof Serializable)) {
                System.out.println("DYN=NOT_SERIALIZABLE");
                return;
            }
            Object carrier;
            if ("BAVE".equals(mode)) {
                try {
                    javax.management.BadAttributeValueExpException b =
                        new javax.management.BadAttributeValueExpException(null);
                    Field f = b.getClass().getDeclaredField("val");
                    f.setAccessible(true);
                    f.set(b, o);
                    carrier = b;
                } catch (Throwable t) {
                    java.util.HashMap<Object,Object> m = new java.util.HashMap<>();
                    m.put(o, "v");
                    carrier = m;
                }
            } else {
                java.util.HashMap<Object,Object> m = new java.util.HashMap<>();
                m.put(o, "v");
                carrier = m;
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            new ObjectOutputStream(bos).writeObject(carrier);
            byte[] b = bos.toByteArray();
            try {
                new ObjectInputStream(new ByteArrayInputStream(b)).readObject();
                System.out.println("DYN=DESER_OK");
            } catch (Throwable t) {
                System.out.println("DYN=DESER_EX:" + t.getClass().getName());
            }
        } catch (Throwable t) {
            System.out.println("DYN=ERROR:" + t.getClass().getName());
        }
    }
}
'''


_BATCH_SRC = r'''
import java.io.*;
import java.lang.reflect.*;

public class DynProbeBatch {
    static String probe(String cls, String mode) {
        try {
            Class<?> c = Class.forName(cls);
            Object o;
            try { o = c.getDeclaredConstructor().newInstance(); }
            catch (Throwable t) {
                Constructor<?> ctor = sun.reflect.ReflectionFactory
                    .getReflectionFactory()
                    .newConstructorForSerialization(c, Object.class.getDeclaredConstructor());
                ctor.setAccessible(true);
                o = ctor.newInstance();
            }
            if (!(o instanceof Serializable)) return "NOT_SERIALIZABLE";
            Object carrier;
            if ("BAVE".equals(mode)) {
                try {
                    javax.management.BadAttributeValueExpException b =
                        new javax.management.BadAttributeValueExpException(null);
                    Field f = b.getClass().getDeclaredField("val");
                    f.setAccessible(true);
                    f.set(b, o);
                    carrier = b;
                } catch (Throwable t) {
                    java.util.HashMap<Object,Object> m = new java.util.HashMap<>();
                    m.put(o, "v"); carrier = m;
                }
            } else {
                java.util.HashMap<Object,Object> m = new java.util.HashMap<>();
                m.put(o, "v"); carrier = m;
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            new ObjectOutputStream(bos).writeObject(carrier);
            byte[] b = bos.toByteArray();
            try {
                new ObjectInputStream(new ByteArrayInputStream(b)).readObject();
                return "DESER_OK";
            } catch (Throwable t) {
                return "DESER_EX:" + t.getClass().getName();
            }
        } catch (Throwable t) {
            return "ERROR:" + t.getClass().getName();
        }
    }
    public static void main(String[] args) {
        String mode = args.length > 0 ? args[0] : "HASHMAP";
        String[] classes = { __CLASSES__ };
        for (int i = 0; i < classes.length; i++) {
            System.out.println("DYN[" + i + "]=" + probe(classes[i], mode));
        }
    }
}
'''


@dataclass(frozen=True)
class JvmToolchain:
    java: Path
    javac: Path | None

    @property
    def available(self) -> bool:
        return self.java.exists() and self.javac is not None and self.javac.exists()

    @classmethod
    def discover(cls, root: Path | None = None) -> "JvmToolchain":
        root = root or Path(__file__).resolve().parents[1]
        home = os.environ.get("JAVA_HOME")
        java = Path(home) / "bin" / "java.exe" if home else None
        javac = Path(home) / "bin" / "javac.exe" if home else None
        if not java or not java.exists():
            which_java = shutil.which("java")
            java = Path(which_java) if which_java else None
        if not javac or not javac.exists():
            which_javac = shutil.which("javac")
            javac = Path(which_javac) if which_javac else None
        tools = root / ".tools" / "jdk17"
        if tools.exists() and (java is None or not java.exists()):
            found = list(tools.rglob("java.exe"))
            if found:
                java = found[0]
                jc = list(found[0].parent.glob("javac.exe"))
                javac = jc[0] if jc else javac
        return cls(java=java or Path("java"), javac=javac)

    def run_java(self, args: list[str], limits: SandboxLimits = SandboxLimits()) -> SandboxResult:
        """Trusted toolchain check only; target execution must use DynamicProbe."""
        return HostSandbox(allow_host=True).run([str(self.java), *args], limits=limits)


@dataclass(frozen=True)
class DynamicResult:
    verdict: str
    rc: int
    stdout: str
    stderr: str
    command: list[str]


class DynamicProbe:
    def __init__(self, toolchain: JvmToolchain, sandbox: Sandbox) -> None:
        self.toolchain = toolchain
        self.sandbox = sandbox

    def probe_class(
        self,
        class_name: str,
        work_dir: Path,
        limits: SandboxLimits = SandboxLimits(),
        mode: str = "HASHMAP",
        classpath: list[Path] | None = None,
    ) -> DynamicResult:
        if not self.toolchain.available or self.toolchain.javac is None:
            raise RuntimeError("JDK with javac is required for dynamic probes")
        work_dir.mkdir(parents=True, exist_ok=True)
        src = work_dir / "DynProbe.java"
        src.write_text(_PROBE_SRC, encoding="utf-8")
        cp = os.pathsep.join([str(work_dir), *(str(p) for p in (classpath or []))])
        compile_cmd = [
            str(self.toolchain.javac),
            "-d",
            str(work_dir),
            "-cp",
            cp,
            str(src),
        ]
        compiled = subprocess.run(
            compile_cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if compiled.returncode != 0:
            raise RuntimeError(f"probe compile failed: {compiled.stderr[-500:]}")
        run_cmd = [
            str(self.toolchain.java),
            "-cp",
            cp,
            "DynProbe",
            class_name.replace("/", "."),
            mode,
        ]
        mounts = None
        run_workdir: Path | str = work_dir
        if self.sandbox.name == "wsl2":
            work_wsl = wsl_path(work_dir)
            cp_wsl = ":".join(
                [work_wsl, *(wsl_path(p) for p in (classpath or []))]
            )
            run_cmd = [
                "java",
                "-cp",
                cp_wsl,
                "DynProbe",
                class_name.replace("/", "."),
                mode,
            ]
            run_workdir = work_wsl
        elif self.sandbox.name == "docker":
            mounts = {work_dir: (Path("/work"), False)}
            cp_parts = ["/work"]
            for i, p in enumerate(classpath or []):
                dst = Path(f"/target/{i}.jar")
                mounts[p] = (dst, True)
                cp_parts.append(str(dst))
            run_cmd = [
                "java",
                "-cp",
                ":".join(cp_parts),
                "DynProbe",
                class_name.replace("/", "."),
                mode,
            ]
            run_workdir = Path("/work")
        result = self.sandbox.run(
            run_cmd, mounts=mounts, limits=limits, workdir=run_workdir
        )
        verdict = "UNKNOWN"
        for line in (result.stdout + "\n" + result.stderr).splitlines():
            if line.startswith("DYN="):
                verdict = line[4:].strip()
                break
        return DynamicResult(
            verdict=verdict,
            rc=result.rc,
            stdout=result.stdout,
            stderr=result.stderr,
            command=result.command,
        )

    def probe_many(
        self,
        class_names: list[str],
        work_dir: Path,
        limits: SandboxLimits = SandboxLimits(),
        mode: str = "HASHMAP",
        classpath: list[Path] | None = None,
    ) -> list[DynamicResult]:
        """Probe several classes in one JVM (one classpath batch).

        The probe class is compiled once and the target classes are tested in a
        single JVM.  This is the "JVM pool" fast path for the common case where
        many bridges share one target JAR.
        """
        names = [c for c in class_names if c]
        if not names:
            return []
        if len(names) == 1:
            return [
                self.probe_class(
                    names[0], work_dir, limits, mode=mode, classpath=classpath
                )
            ]
        if not self.toolchain.available or self.toolchain.javac is None:
            raise RuntimeError("JDK with javac is required for dynamic probes")
        work_dir.mkdir(parents=True, exist_ok=True)
        src = work_dir / "DynProbeBatch.java"
        classes = ", ".join(json.dumps(n.replace("/", ".")) for n in names)
        src.write_text(_BATCH_SRC.replace("__CLASSES__", classes), encoding="utf-8")
        cp = os.pathsep.join([str(work_dir), *(str(p) for p in (classpath or []))])
        compiled = subprocess.run(
            [str(self.toolchain.javac), "-d", str(work_dir), "-cp", cp, str(src)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if compiled.returncode != 0:
            raise RuntimeError(f"batch probe compile failed: {compiled.stderr[-500:]}")
        run_cmd = [
            str(self.toolchain.java),
            "-cp",
            cp,
            "DynProbeBatch",
            mode,
        ]
        mounts = None
        run_workdir: Path | str = work_dir
        if self.sandbox.name == "wsl2":
            work_wsl = wsl_path(work_dir)
            cp_wsl = ":".join([work_wsl, *(wsl_path(p) for p in (classpath or []))])
            run_cmd = ["java", "-cp", cp_wsl, "DynProbeBatch", mode]
            run_workdir = work_wsl
        elif self.sandbox.name == "docker":
            mounts = {work_dir: (Path("/work"), False)}
            cp_parts = ["/work"]
            for i, p in enumerate(classpath or []):
                dst = Path(f"/target/{i}.jar")
                mounts[p] = (dst, True)
                cp_parts.append(str(dst))
            run_cmd = ["java", "-cp", ":".join(cp_parts), "DynProbeBatch", mode]
            run_workdir = Path("/work")
        result = self.sandbox.run(
            run_cmd, mounts=mounts, limits=limits, workdir=run_workdir
        )
        by_index: dict[int, str] = {}
        for line in (result.stdout + "\n" + result.stderr).splitlines():
            if not line.startswith("DYN[") or "]=" not in line:
                continue
            head, value = line[4:].split("]=", 1)
            try:
                by_index[int(head)] = value.strip()
            except ValueError:
                continue
        return [
            DynamicResult(
                verdict=by_index.get(i, "UNKNOWN"),
                rc=result.rc,
                stdout=result.stdout,
                stderr=result.stderr,
                command=result.command,
            )
            for i in range(len(names))
        ]
