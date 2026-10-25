# SPDX-License-Identifier: EUPL-1.2
"""The engine names no deployment: no file in this repository may mention one. Deployments keep their names, their
configuration, their policy packs and their examples in their own repositories."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# kept reversed, so the guard itself names nothing: an operator's prefix and company, a platform, its terms for sites,
# sub-sites, nodes, its control room and its pane
_WORDS = ["hdv", "emohdv", "ralusni", "elsi", "telsi", "ffiks", "moortrahc", "sorahp"]
_WHOLE = {"elsi", "telsi", "ffiks"}
FORBIDDEN = re.compile("|".join(rf"\b{w[::-1]}s?\b" if w in _WHOLE else w[::-1] for w in _WORDS), re.I)
SKIP = {".git", "__pycache__", ".pytest_cache", ".hypothesis", ".venv", "build", "dist"}
# The steward is not a deployment: the licence and contribution files name it (copyright, the contributor agreement).
# In those files only, and only the steward's own name; every other word above stays forbidden there too.
STEWARD_FILES = {"NOTICE", "CLA.md", "REUSE.toml"}
STEWARD = re.compile(rf"\b{'emoHDV'[::-1]}\b")


def test_no_file_names_a_deployment():
    hits = []
    for f in ROOT.rglob("*"):
        if not f.is_file() or SKIP & set(f.parts) or f.suffix == ".pyc" or f.name.endswith(".egg-info"):
            continue
        rel = f.relative_to(ROOT)
        if FORBIDDEN.search(str(rel)):
            hits.append(f"{rel}: in the path")
        try:
            text = f.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for n, line in enumerate(text.splitlines(), 1):
            if rel.name in STEWARD_FILES:                  # the repository's and each public release's own files
                line = STEWARD.sub("", line)
            if FORBIDDEN.search(line):
                hits.append(f"{rel}:{n}: {line.strip()[:80]}")
    assert hits == []


def test_the_steward_exemption_is_narrow():
    """The steward's name passes only in the steward files; any other forbidden word still fails there."""
    other = _WORDS[2][::-1]
    assert FORBIDDEN.search(STEWARD.sub("", f"{'emoHDV'[::-1]} and {other}"))
    assert not FORBIDDEN.search(STEWARD.sub("", f"Copyright {'emoHDV'[::-1]}"))
    assert "README.md" not in STEWARD_FILES
