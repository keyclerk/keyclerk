# SPDX-License-Identifier: EUPL-1.2
"""docs/references.md names what KeyClerk builds on (operator, 2026-10-25): every RFC the engine or its published
documents name, and every package it depends on, has an entry with an https link; no tag twice, no entry without one."""
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFS = (ROOT / "docs" / "references.md").read_text(encoding="utf-8")
ENTRY = re.compile(r"^- \[([A-Z0-9][A-Z0-9-]*)\](.*?)(?=^- \[|^#|\Z)", re.M | re.S)
NAMED_IN = ["keyclerk/**/*.py", "keyclerk/policy/*.rego", "docs/decisions/*.md", "docs/install.md",
            "docs/migrate-to-change-log.md", "docs/what-sets-keyclerk-apart.md", "README.md"]
PACKAGES = {"pyyaml": "PYYAML", "jsonschema": "JSONSCHEMA-PY", "cryptography": "CRYPTOGRAPHY", "segno": "SEGNO",
            "wasmtime": "WASMTIME"}


def _entries() -> dict[str, str]:
    found = ENTRY.findall(REFS)
    tags = [t for t, _ in found]
    assert len(tags) == len(set(tags)), sorted({t for t in tags if tags.count(t) > 1})
    return dict(found)


def test_every_entry_has_an_https_link():
    for tag, text in _entries().items():
        assert re.search(r"<https://[^>\s]+>", text), tag


def test_every_rfc_the_engine_names_has_an_entry():
    named = set()
    for pattern in NAMED_IN:
        for f in ROOT.glob(pattern):
            named |= {f"RFC{n}" for n in re.findall(r"RFC ?(\d{3,5})", f.read_text(encoding="utf-8", errors="ignore"))}
    cited = set(_entries()) | set(re.findall(r"\[(RFC\d+)\]", REFS))
    assert named and not sorted(named - cited), sorted(named - cited)


def test_every_runtime_dependency_has_an_entry():
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["dependencies"]
    names = {re.split(r"[<>=!~ \[]", d, maxsplit=1)[0].lower() for d in deps}
    assert names <= set(PACKAGES), sorted(names - set(PACKAGES))   # a new dependency: add it here and in the page
    assert not [n for n in names if PACKAGES[n] not in _entries()]


def test_the_readme_points_at_the_page():
    assert "docs/references.md" in (ROOT / "README.md").read_text(encoding="utf-8")
