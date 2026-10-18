"""A mutation sweep for argue.py.

Every mutant is a one-line change that breaks a specific analysis rule. The
sweep applies each one to a *scratch copy* of the tool (never the working
tree), compiles it, and requires the selftest to notice. If a mutant survives,
the selftest has a hole.

The sweep is canary-guarded: a semantically-identical edit must SURVIVE, which
proves the harness is testing behaviour and not merely diffing text.

    python ci/mutation.py
"""
from __future__ import annotations

import hashlib
import pathlib
import py_compile
import shutil
import subprocess
import sys
import tempfile

LIVE = pathlib.Path("argue.py")

# (label, search, replace) -- each must make the selftest FAIL.
MUTANTS = [
    ("unknown references ignored",
     "        if e[\"src\"] not in nodes or e[\"dst\"] not in nodes:",
     "        if False:"),
    ("self loops ignored",
     "        if e[\"src\"] == e[\"dst\"]:",
     "        if False:"),
    ("attacks on non-claims ignored",
     "        if e[\"label\"] == \"attacks\" and nodes[e[\"dst\"]][\"kind\"] != \"claim\":",
     "        if False:"),
    ("cycles never reported",
     "            if len(comp) > 1:",
     "            if False:"),
    ("unsupported claims never reported",
     "            if not insup[i]:",
     "            if False:"),
    ("assumption-only never reported",
     "            elif all(nodes[e[\"src\"]][\"kind\"] == \"assumption\" for e in insup[i]):",
     "            elif False:"),
    ("one-sided claims never reported",
     "            if insup[i] and not inatk[i]:",
     "            if False:"),
    ("dangling evidence never reported",
     "        if kind == \"evidence\" and outdeg[i] == 0 and indeg[i] > 0:",
     "        if False:"),
    ("unreferenced counters never reported",
     "        if kind == \"counter\" and outdeg[i] == 0:",
     "        if False:"),
    ("orphan nodes never reported",
     "        if indeg[i] == 0 and outdeg[i] == 0:",
     "        if False:"),
    ("errors no longer affect the exit code",
     "    if any(f[\"severity\"] == \"error\" for f in findings):",
     "    if False:"),
]

# A behaviour-preserving edit. The selftest must still pass.
CANARY = ("drop a return annotation",
          "def sha256_hex(text: str) -> str:",
          "def sha256_hex(text):")


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_selftest(path: pathlib.Path):
    proc = subprocess.run([sys.executable, str(path), "selftest"],
                          capture_output=True, text=True, timeout=600)
    return proc.returncode, proc.stdout + proc.stderr


def mutate_into(scratch_dir: pathlib.Path, label, old, new):
    with open(LIVE, encoding="utf-8", newline="") as fh:
        src = fh.read()
    if old not in src:
        print("  [ERROR] pattern not found for: %s" % label)
        return None
    target = scratch_dir / "argue_mutant.py"
    with open(target, "w", encoding="utf-8", newline="") as fh:
        fh.write(src.replace(old, new, 1))
    try:
        py_compile.compile(str(target), doraise=True)
    except py_compile.PyCompileError as exc:
        print("  [ERROR] mutant does not compile: %s (%s)" % (label, exc))
        return None
    return target


def main() -> int:
    before = digest(LIVE)
    killed = 0
    total = 0
    failed = False

    workdir = pathlib.Path(tempfile.mkdtemp(prefix="argue-mut-"))
    try:
        for label, old, new in MUTANTS:
            total += 1
            target = mutate_into(workdir, label, old, new)
            if target is None:
                failed = True
                continue
            rc, out = run_selftest(target)
            if rc != 0:
                killed += 1
                print("  [KILLED] %s" % label)
            else:
                print("  [ALIVE ] %s  <-- the selftest missed this" % label)
                failed = True

        # The canary must survive: a change with no behavioural effect.
        label, old, new = CANARY
        target = mutate_into(workdir, label, old, new)
        if target is None:
            failed = True
        else:
            rc, out = run_selftest(target)
            if rc == 0:
                print("  [SURVIVED] canary: %s" % label)
            else:
                print("  [DIED   ] canary: %s  <-- harness is not sound" % label)
                failed = True
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    after = digest(LIVE)
    if before != after:
        print("ERROR: the live argue.py changed during the sweep")
        failed = True

    print("%d/%d real mutants killed, canary survived" % (killed, total))
    if failed or killed != total:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
