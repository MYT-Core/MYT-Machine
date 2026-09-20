"""Local CI-equivalent runner; logs and environments live outside distributions."""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--environments", required=True)
p.add_argument("--node-floor", required=True)
p.add_argument("--node-current", required=True)
p.add_argument("--logs", required=True)
args = p.parse_args()
root = Path(__file__).resolve().parents[2]
out = Path(args.environments)
platform = "windows" if os.name == "nt" else "linux"
results = []
logs = Path(args.logs)
logs.mkdir(parents=True, exist_ok=False)
allowed_skips = json.loads((root / "review/phase4f/windows-baseline-skips.json").read_text())
environment = os.environ.copy()
environment.pop("NODE_OPTIONS", None)
environment.pop("NODE_PATH", None)
environment["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root / "tests")))
environment["PYTHONUTF8"] = "1"


def run(name, command, env=environment):
    with (logs / (name + ".log")).open("w", encoding="utf-8") as log:
        done = subprocess.run(command, cwd=root, env=env, stdout=log, stderr=log, check=False)
    text = (logs / (name + ".log")).read_text(encoding="utf-8")
    skips = {}
    for method, klass, reason in re.findall(r"^(test_\w+) \(([^)]+)\) \.\.\. skipped '([^']+)'$", text, re.MULTILINE):
        key = klass if klass.endswith("." + method) else klass + "." + method
        skips[key] = reason
    expected = allowed_skips if platform == "windows" and name.endswith("-full") else {}
    safe = done.returncode == 0 and skips == expected and "ResourceWarning" not in text
    if name.endswith("-full"):
        safe = safe and re.findall(r"Ran (\d+) tests", text) == ["553"]
    results.append({"gate": name, "exit_code": done.returncode, "passed": safe,
                    "platform_skips": skips, "resource_warnings": "ResourceWarning" in text,
                    "test_counts": re.findall(r"Ran (\d+) tests", text),
                    "skipped": re.findall(r"skipped=(\d+)", text)})
    (logs / ("matrix-" + platform + ".json")).write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(name, "PASS" if safe else "FAIL", flush=True)
    return safe


for node_name in ("floor", "current"):
    node = getattr(args, "node_" + node_name)
    run(platform + "-node-" + node_name, [node, "--test",
        str(root / "companions/bbs/test/core.test.mjs"),
        str(root / "companions/bbs/test/header.test.mjs")])

for version in ("3.10", "3.12", "3.13"):
    for mode in ("floor", "latest"):
        base = out / (platform + "-" + version + "-" + mode)
        python = base / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        env = {**environment, "MYT_TEST_NODE": args.node_current}
        label = platform + "-" + version + "-" + mode
        run(label + "-versions", [str(python), "-c",
            "import sys,cryptography,myt_machine; print(sys.version); print(cryptography.__version__); print(myt_machine.__version__)"], env)
        run(label + "-pip-check", [str(python), "-m", "pip", "check"], env)
        run(label + "-full", [str(python), "-m", "unittest", "discover", "-s", "tests", "-v"], env)
        run(label + "-attacks", [str(python), "-m", "unittest", "discover",
                                "-s", "review/phase4f", "-p", "attack*.py", "-v"], env)
        run(label + "-compile", [str(python), "-m", "compileall", "-q", "src", "tests"], env)

base = out / (platform + "-3.12-floor")
python = base / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
env = {**environment, "MYT_TEST_NODE": args.node_floor}
run(platform + "-node-floor-python-integration", [str(python), "-m", "unittest",
    "discover", "-s", "tests", "-p", "test_disclosure*.py", "-v"], env)
run(platform + "-node-floor-independent", [str(python), "-m", "unittest",
    "discover", "-s", "review/phase4f", "-p", "attack*.py", "-v"], env)
sys.exit(0 if all(r["passed"] for r in results) else 1)
