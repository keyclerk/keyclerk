# SPDX-License-Identifier: EUPL-1.2
"""The leak gate: nothing internal leaves in a public release.

    python tools/leak_gate.py DIR [--names FILE]

Scans every file under DIR and exits 1 with file:line for each hit. What counts as internal:
- deployment and operator names (the same reversed list as tests/test_no_deployment_names.py), except the steward's
  own name in the steward files (NOTICE, CLA.md);
- internal finding and work ids (one to three capitals, a hyphen and a number), references to decision records by
  number unless that record is released in the same tree (docs/decisions/NNNN-*.md), internal process wording, and
  the private products named in the internal repository;
- private hosts and namespaces, local paths, e-mail addresses;
- secret shapes (private key blocks, provider tokens);
- personal names from FILE (one per line, kept outside every repository), so this file names nobody.

A public decision record or document that needs a word on the list is reworded; the gate has no allow-list beyond the
steward's name, on purpose.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_WORDS = ["hdv", "emohdv", "ralusni", "elsi", "telsi", "ffiks", "moortrahc", "sorahp", "yekiler", "edcr"]
_WHOLE = {"elsi", "telsi", "ffiks", "edcr"}
DEPLOYMENT = re.compile("|".join(rf"\b{w[::-1]}s?\b" if w in _WHOLE else w[::-1] for w in _WORDS), re.I)
STEWARD = re.compile(rf"\b{'emoHDV'[::-1]}\b")
STEWARD_FILES = {"NOTICE", "CLA.md", "REUSE.toml"}   # the copyright line names the steward, as in the engine's own guard
_PRIVATE = ["/moc.baltig", "buh-edcr"]          # reversed, so this file names no private host once it is public
RULES: list[tuple[str, re.Pattern]] = [
    # ids with a hyphen: findings, work items, steps (P-256 and SHA-256 are not ids: no P, no SHA here)
    ("internal id", re.compile(r"\b(?:KC|AG|HA|LF|RK|R|W|ADR|KO|KE|AL|C|F|G)-\d+[a-z]?\b|\bRK-E\d+\b")),
    ("internal decision reference", re.compile(r"\b(?:decision|amendment)s? 00\d\d[a-z]?\b", re.I)),
    # built from pieces, so this file does not contain the words it looks for
    ("internal process wording", re.compile(r"\b(?:" + "red" + r"[- ]" + "team" + r"(?:ed)?|" + "decide" + r"\s" + "loop"
                                            + r"|" + "work" + r"\s" + "order" + r")\b", re.I)),
    ("private host or namespace", re.compile("|".join(re.escape(w[::-1]) for w in _PRIVATE)
                                             + r"|\b[\w-]+\.(?:internal|lan|local)\b", re.I)),
    ("local path", re.compile(r"\b[A-Z]:\\|/home/[\w.-]+/|/mnt/[a-z]/|\\" + "sresU"[::-1] + r"\\", re.I)),
    ("e-mail address", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("provider token", re.compile(r"\b(?:glpat-[\w-]{20,}|gh[pousr]_\w{30,}|AKIA[0-9A-Z]{16}|xox[abprs]-[\w-]{10,})")),
]


_DECISION_NO = re.compile(r"00\d\d[a-z]?", re.I)


def scan_text(rel: str, text: str, names: list[re.Pattern], published: frozenset[str] = frozenset()) -> list[str]:
    """published: the decision records released alongside (their numbers, such as "0014" or "0011a"); a reference to
    one of them is a reference to public text, so it passes."""
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        check = STEWARD.sub("", line) if Path(rel).name in STEWARD_FILES else line
        if DEPLOYMENT.search(check):
            hits.append(f"{rel}:{n}: deployment or operator name")
        for what, rx in RULES:
            found = [m.group(0) for m in rx.finditer(check)]
            if what == "internal decision reference":     # an amendment (0014d) lives inside its record (0014)
                found = [m for m in found if not {(n := _DECISION_NO.search(m).group(0).lower()), n[:4]} & published]
            if found:
                hits.append(f"{rel}:{n}: {what}: {found[0][:40]}")
        for rx in names:
            if rx.search(check):
                hits.append(f"{rel}:{n}: a personal name")
    return hits


def scan(root: Path, names_file: Path | None = None) -> list[str]:
    names = []
    if names_file and names_file.exists():
        names = [re.compile(rf"\b{re.escape(w.strip())}\b", re.I)
                 for w in names_file.read_text(encoding="utf-8").splitlines() if w.strip()]
    folders = [root / "docs" / "decisions", root]          # a release tree, or a decisions folder scanned directly
    published = frozenset(m.group(1).lower() for d in folders for f in d.glob("*.md")
                          if (m := re.match(r"(00\d\d[a-z]?)-", f.name, re.I)))   # records released in this tree
    hits = []
    for f in sorted(root.rglob("*")):
        if not f.is_file() or {".git", ".ruff_cache", ".pytest_cache", ".hypothesis", "__pycache__"} & set(f.parts):
            continue
        rel = f.relative_to(root).as_posix()
        if DEPLOYMENT.search(rel):
            hits.append(f"{rel}: deployment or operator name in the path")
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError:                     # binary: images, compiled modules. A compiler or an image
            hits += scan_binary(rel, f.read_bytes(), names)   # tool can still write a path or a name into them
            continue
        hits += scan_text(rel, text, names, published)
    return hits


BINARY_RULES = ("local path", "private key", "provider token")


def scan_binary(rel: str, data: bytes, names: list[re.Pattern]) -> list[str]:
    """What a binary file must not carry either: a local path, a key, a token or a personal name in its bytes."""
    text = data.decode("latin-1")
    hits = [f"{rel}: {what} in a binary file: {m.group(0)[:40]!r}" for what, rx in RULES if what in BINARY_RULES
            for m in [rx.search(text)] if m]
    return hits + [f"{rel}: a personal name in a binary file" for rx in names if rx.search(text)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="leak_gate", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--names", help="a file of personal names, one per line, kept outside every repository")
    a = ap.parse_args(argv)
    hits = scan(Path(a.dir), Path(a.names) if a.names else None)
    for h in hits:
        print(h)
    print(f"leak gate: {len(hits)} hits in {a.dir}" if hits else f"leak gate: clean ({a.dir})")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
