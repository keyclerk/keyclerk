#!/usr/bin/env python3
# SPDX-License-Identifier: EUPL-1.2
"""Changelog fragments: each pull request adds a file under changelog.d/ instead of editing CHANGELOG.md.

When every pull request edits the top of CHANGELOG.md, each merge makes the next open one conflict. A fragment is its
own file and never conflicts. Its name is `<id>.<section>.md`: the issue number (or a short slug) and the kind of
change, for example `changelog.d/31.added.md`. It holds Markdown bullets in the style of CHANGELOG.md: a line starting
"- ", continuation lines indented two spaces, at most 120 columns, ASCII only.

    python tools/changelog.py check                 # the fragments are well formed (tests/test_changelog.py runs it)
    python tools/changelog.py show                  # the next release's section with the fragments folded in
    python tools/changelog.py release 0.27.0        # write "## 0.27.0 (<today>)" and remove the fragments

release runs on the branch of the release pull request; the signed tag follows its merge, and the release workflow
takes that section as the release notes.
"""
from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SECTIONS = ("security", "changed", "added", "deprecated", "removed", "fixed")   # what a deployer must read first
NAME = re.compile(r"^(?P<id>[a-z0-9][a-z0-9-]*)\.(?P<section>[a-z]+)\.md$")
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
WIDTH = 120


def fragments(root: Path) -> list[Path]:
    d = root / "changelog.d"
    return sorted(p for p in d.glob("*.md") if p.name != "README.md") if d.is_dir() else []


def _order(path: Path):
    m = NAME.match(path.name)
    i = m["id"]
    return (SECTIONS.index(m["section"]), 0 if i.isdigit() else 1, int(i) if i.isdigit() else 0, i)


def problems(path: Path) -> list[str]:
    m = NAME.match(path.name)
    if not m:
        return [f"{path.name}: name it <issue or slug>.<section>.md, for example 31.added.md"]
    if m["section"] not in SECTIONS:
        return [f"{path.name}: unknown section {m['section']!r}; use one of {', '.join(SECTIONS)}"]
    text = path.read_text(encoding="utf-8")
    out = []
    lines = text.rstrip("\n").split("\n")
    if not lines or not lines[0].startswith("- "):
        out.append(f"{path.name}: start with a bullet, '- '")
    for n, line in enumerate(lines, 1):
        if len(line) > WIDTH:
            out.append(f"{path.name}:{n}: longer than {WIDTH} columns")
        if not line.isascii():
            out.append(f"{path.name}:{n}: not plain ASCII")
        if line and not (line.startswith("- ") or line.startswith("  ")):
            out.append(f"{path.name}:{n}: a continuation line is indented two spaces")
    return out


def check(root: Path = ROOT) -> list[str]:
    return [p for f in fragments(root) for p in problems(f)]


def body(root: Path = ROOT) -> str:
    return "".join(f.read_text(encoding="utf-8").rstrip("\n") + "\n" for f in sorted(fragments(root), key=_order))


def release(root: Path, version: str, date: str) -> str:
    if not VERSION.match(version):
        raise SystemExit(f"{version!r} is not X.Y.Z")
    bad = check(root)
    if bad:
        raise SystemExit("fix the fragments first:\n" + "\n".join(bad))
    frags = fragments(root)
    if not frags:
        raise SystemExit("no fragments in changelog.d/: a release without notes fails at the tag")
    path = root / "CHANGELOG.md"
    text = path.read_text(encoding="utf-8")
    if re.search(rf"^## {re.escape(version)} ", text, re.M):
        raise SystemExit(f"CHANGELOG.md already has a section for {version}")
    first = re.search(r"^## ", text, re.M)
    section = f"## {version} ({date})\n{body(root)}\n"
    text = text[:first.start()] + section + text[first.start():] if first else text.rstrip("\n") + "\n\n" + section
    path.write_text(text, encoding="utf-8", newline="\n")
    for f in frags:
        f.unlink()
    return section


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    sub.add_parser("show")
    r = sub.add_parser("release")
    r.add_argument("version")
    r.add_argument("--date", default=datetime.date.today().isoformat())
    a = ap.parse_args(argv)
    if a.cmd == "check":
        bad = check()
        print("\n".join(bad) if bad else f"{len(fragments(ROOT))} fragment(s), well formed")
        return 1 if bad else 0
    if a.cmd == "show":
        print(body() or "(no fragments)", end="")
        return 0
    print(release(ROOT, a.version, a.date), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
