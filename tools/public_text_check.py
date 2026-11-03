#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Check text before it is posted in public: issue and pull request bodies, comments, reviews, discussions, and the
commit messages and added lines of a range.

Everything posted on a public repository is public at once and cannot be withdrawn. This runs the release leak gate's
rules (tools/leak_gate.py) on that text, plus private patterns that would publish what they guard if they were listed
here: one regular expression per line in the KEYCLERK_PRIVATE_PATTERNS environment variable (a CI secret, given only
to the project's own people's events), reported by number only.

    python tools/public_text_check.py --text body.md                 # before posting a body or comment
    python tools/public_text_check.py --range origin/main..HEAD      # commit messages and added lines
    python tools/public_text_check.py --diff pr.diff                 # the added lines of a unified diff, as data

Exit 1 with one line per hit. The public text workflow runs it on every event and labels a hit for a maintainer.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("leak_gate", ROOT / "tools" / "leak_gate.py")
leak_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(leak_gate)


def private_patterns(env=None) -> list[re.Pattern]:
    env = os.environ if env is None else env
    return [re.compile(p.strip(), re.I) for p in env.get("KEYCLERK_PRIVATE_PATTERNS", "").splitlines() if p.strip()]


def published_decisions() -> frozenset[str]:
    d = ROOT / "docs" / "decisions"
    return frozenset(m.group(1).lower() for f in d.glob("*.md") if (m := re.match(r"(00\d\d[a-z]?)-", f.name, re.I)))


# GitHub's own public addresses: bots sign their commits with them (Dependabot's Signed-off-by), and a noreply address
# names an account, not a mailbox. Every other address is still a hit.
GITHUB_PUBLIC = re.compile(r"(?i)\b(?:support|noreply)@github\.com\b|[\w.+\[\]-]+@users\.noreply\.github\.com\b")


def scan(where: str, text: str, env=None) -> list[str]:
    hits = leak_gate.scan_text(where, GITHUB_PUBLIC.sub("github-address", text), [], published_decisions())
    for n, line in enumerate(text.splitlines(), 1):
        for i, rx in enumerate(private_patterns(env), 1):
            if rx.search(line):
                hits.append(f"{where}:{n}: private pattern {i}")
    return hits


def range_text(rng: str) -> list[tuple[str, str]]:
    """(where, text) for each commit message and for the lines the range adds."""
    out = []
    # git from PATH with a fixed argument list; the range is the caller's own (a maintainer's pre-push check)
    log = subprocess.run(["git", "log", "--format=%H%x00%B%x01", rng], capture_output=True, text=True,  # noqa: S603,S607
                         encoding="utf-8", check=True).stdout
    for entry in filter(None, (e.strip("\n") for e in log.split("\x01"))):
        sha, _, msg = entry.partition("\x00")
        out.append((f"commit {sha[:12]}", msg))
    diff = subprocess.run(["git", "diff", "--unified=0", "--no-color", rng], capture_output=True, text=True,  # noqa: S603,S607
                          encoding="utf-8", errors="replace", check=True).stdout
    return out + added_lines(diff)


def added_lines(diff: str) -> list[tuple[str, str]]:
    """(path, text) of the lines a unified diff adds. The public text workflow gets a pull request's diff through the
    API and checks it here, so the proposed commits never enter the workspace of a privileged job."""
    out, path, added = [], None, []
    for line in diff.splitlines() + ["+++ end"]:
        if line.startswith("+++ "):
            if path and added:
                out.append((path, "\n".join(added)))
            path, added = line[6:] if line.startswith("+++ b/") else None, []
        elif line.startswith("+") and path:
            added.append(line[1:])
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", type=Path, help="a file holding the text to post")
    g.add_argument("--range", help="a git revision range, such as origin/main..HEAD")
    g.add_argument("--diff", type=Path, help="a file holding a unified diff")
    a = ap.parse_args(argv)
    if a.text:
        items = [(a.text.name, a.text.read_text(encoding="utf-8"))]
    elif a.diff:
        items = added_lines(a.diff.read_text(encoding="utf-8", errors="replace"))
    else:
        items = range_text(a.range)
    hits = [h for where, text in items for h in scan(where, text)]
    for h in hits:
        print(h)
    if not hits:
        print(f"public text check: clean ({len(items)} item(s))")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
