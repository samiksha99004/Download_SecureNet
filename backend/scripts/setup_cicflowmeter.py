"""
Prepare CICFlowMeter for SecureNet's live monitoring (run once; SETUP runs it too).

Collects what the headless capture program needs into backend/tools/cicflowmeter/ (gitignored):
  lib/      CICFlowMeter-4.0.jar + jnetpcap + the three small libraries its flow code uses
  native/   jnetpcap.dll (talks to Npcap)
  classes/  SecureNetLiveCapture.class, compiled from backend/cicflowmeter/SecureNetLiveCapture.java
  cicflowmeter.json   java.exe, classpath and native path used by the backend

Sources (override with environment variables):
  CICFLOWMETER_HOME  a built CICFlowMeter-4.0 checkout   (default F:\\CICFlowMeter-master)
  JAVA_HOME          a Java 8 JDK (javac + java)          (default F:\\jdk8\\jdk8u504-b01)
  dependency jars are looked up in the Gradle / Maven caches (GRADLE_USER_HOME, F:\\gradle_home,
  F:\\m2, ~/.gradle, ~/.m2).

    backend\\venv\\Scripts\\python.exe scripts\\setup_cicflowmeter.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
SOURCE = BACKEND / "cicflowmeter" / "SecureNetLiveCapture.java"
TARGET = BACKEND / "tools" / "cicflowmeter"

DEPENDENCIES = ["slf4j-api-1.7.25.jar", "commons-lang3-3.6.jar", "commons-math3-3.5.jar", "tika-core-1.17.jar"]


def fail(message: str) -> None:
    print(f"CICFlowMeter setup: {message}")
    sys.exit(1)


def find_java_home() -> Path:
    candidates = [os.environ.get("JAVA_HOME"), r"F:\jdk8\jdk8u504-b01"]
    jdk8 = Path(r"F:\jdk8")
    if jdk8.is_dir():
        candidates += [str(p) for p in sorted(jdk8.iterdir())]
    for c in candidates:
        if c and (Path(c) / "bin" / "javac.exe").is_file():
            return Path(c)
    fail("no Java 8 JDK found (set JAVA_HOME to a folder with bin\\javac.exe).")


def find_cicflowmeter() -> Path:
    home = Path(os.environ.get("CICFLOWMETER_HOME", r"F:\CICFlowMeter-master"))
    if not (home / "build" / "libs" / "CICFlowMeter-4.0.jar").is_file():
        fail(f"{home}\\build\\libs\\CICFlowMeter-4.0.jar not found — build CICFlowMeter first (gradlew build) "
             "or set CICFLOWMETER_HOME.")
    return home


def find_jar(name: str) -> Path:
    roots = [os.environ.get("GRADLE_USER_HOME"), r"F:\gradle_home", r"F:\m2",
             str(Path.home() / ".gradle"), str(Path.home() / ".m2")]
    for root in roots:
        if root and Path(root).is_dir():
            for path in Path(root).rglob(name):
                return path
    fail(f"{name} not found in the Gradle/Maven caches (build CICFlowMeter once so Gradle downloads it).")


def main() -> None:
    java_home = find_java_home()
    home = find_cicflowmeter()
    native_src = home / "jnetpcap" / "win" / "jnetpcap-1.4.r1425"
    if not (native_src / "jnetpcap.dll").is_file():
        fail(f"{native_src}\\jnetpcap.dll not found.")

    lib, native, classes = TARGET / "lib", TARGET / "native", TARGET / "classes"
    for folder in (lib, native, classes):
        folder.mkdir(parents=True, exist_ok=True)
    jars = [home / "build" / "libs" / "CICFlowMeter-4.0.jar", native_src / "jnetpcap.jar"]
    jars += [find_jar(name) for name in DEPENDENCIES]
    for jar in jars:
        shutil.copy2(jar, lib / jar.name)
    for dll in native_src.glob("*.dll"):
        shutil.copy2(dll, native / dll.name)

    classpath = os.pathsep.join(str(lib / j.name) for j in jars)
    javac = java_home / "bin" / "javac.exe"
    result = subprocess.run([str(javac), "-encoding", "UTF-8", "-source", "8", "-target", "8", "-nowarn",
                             "-cp", classpath, "-d", str(classes), str(SOURCE)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        fail("compiling the capture program failed:\n" + result.stderr)

    config = {
        "java": str(java_home / "bin" / "java.exe"),
        "classpath": classpath + os.pathsep + str(classes),
        "native": str(native),
        "main": "SecureNetLiveCapture",
        "cicflowmeter_home": str(home),
    }
    (TARGET / "cicflowmeter.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

    header = subprocess.run([config["java"], f"-Djava.library.path={native}", "-cp", config["classpath"],
                             config["main"], "--header"], capture_output=True, text=True, timeout=60)
    if header.returncode != 0 or "Flow Duration" not in header.stdout:
        fail("the capture program does not start:\n" + header.stderr)
    print(f"CICFlowMeter ready in {TARGET} ({len(header.stdout.split(','))} columns per flow)")


if __name__ == "__main__":
    main()
