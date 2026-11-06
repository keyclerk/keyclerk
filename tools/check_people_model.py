# SPDX-License-Identifier: EUPL-1.2
"""Decision 0032: check docs/specs/People.als with the Alloy Analyzer (6.2.0, headless). Every `run` must find an
instance (the design is not vacuous), every `check Holds_*` must find no counterexample, and every `check Breaks_*`
(the design with one rule left out, from the adversarial review) must find one. Needs Java and the Alloy jar:

    python tools/check_people_model.py --alloy PATH/org.alloytools.alloy.dist.jar
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SPEC = Path(__file__).resolve().parent.parent / "docs" / "specs" / "People.als"
EXPECTED = 14                       # the commands in People.als: a lost check fails loudly


def alloy(jar: str, *args: str) -> str:
    r = subprocess.run(["java", "-Djava.awt.headless=true", "-jar", jar, *args], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, timeout=1800, cwd=SPEC.parent)
    return r.stdout + r.stderr


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--alloy", required=True, help="the Alloy Analyzer jar")
    a = ap.parse_args(argv)
    commands = [m.groups() for m in re.finditer(r"^\s*(\d+)\s*\.\s*(Run|Check) (\w+)", alloy(a.alloy, "commands", SPEC.name),
                                                 re.M)]
    if len(commands) != EXPECTED:
        print(f"{len(commands)} commands found, {EXPECTED} expected: a check was added or lost; update EXPECTED",
              file=sys.stderr)
        return 2
    ok = True
    for idx, kind, name in commands:
        out = alloy(a.alloy, "exec", "-f", "-q", "-c", idx, "-t", "text", "-o", "-", SPEC.name)
        if "error" in out.lower() and "State 0" not in out:
            print(f"ERROR {name}: {out.strip().splitlines()[-1][:120]}")
            ok = False
            continue
        found = "State 0" in out
        want = kind == "Run" or name.startswith("Breaks_")
        held = found == want
        ok &= held
        print(f"{'OK  ' if held else 'FAIL'} {name}: {'instance' if found else 'none'}"
              + ("" if held else f" (expected {'an instance' if want else 'none'})"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
