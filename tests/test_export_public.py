# SPDX-License-Identifier: EUPL-1.2
"""The public export (tools/export_public.py): only what the manifest lists, the leak gate clean, the conformance
cases unchanged apart from neutral names, and a release that leaks is refused and leaves nothing behind. The public
specification keeps up with the internal one: every format and call the internal page names, it names too."""
import collections
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import export_public as X  # noqa: E402


def _strip(x):
    if isinstance(x, dict):
        return {k: (None if k == "name" else _strip(v)) for k, v in x.items()}
    if isinstance(x, list):
        return [_strip(v) for v in x]
    return x


def test_the_edge_protocol_release_is_clean_and_complete(tmp_path):
    out = tmp_path / "edge"
    assert X.export("edge-protocol", out) == []
    listed = set(X.yaml.safe_load((ROOT / "tools" / "public_manifest.yaml").read_text(encoding="utf-8"))
                 ["edge-protocol"]["files"]) | {"RELEASE.txt"}
    assert {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()} == listed
    version = re.search(r'^__version__ = "([^"]+)"', (ROOT / "keyclerk" / "__init__.py").read_text(encoding="utf-8"), re.M)
    assert f"KeyClerk: {version.group(1)}" in (out / "RELEASE.txt").read_text(encoding="utf-8")   # this checkout's
    texts = [f for f in out.rglob("*") if f.is_file() and b"\0" not in f.read_bytes()]
    assert texts and not [f.name for f in texts if b"\r" in f.read_bytes()]     # LF, as git publishes it
    src = json.loads((ROOT / "tests" / "conformance" / "edge.json").read_text(encoding="utf-8"))
    pub = json.loads((out / "conformance" / "edge.json").read_text(encoding="utf-8"))
    assert _strip(src) == _strip(pub)                          # the vectors are the engine's, only names differ
    for fam, val in pub.items():
        cases = val.get("cases") if isinstance(val, dict) else (val if fam == "cases" else None)
        if cases:
            names = [c["name"] for c in cases if "name" in c]
            assert not [n for n, k in collections.Counter(names).items() if k > 1], fam


def test_a_leak_refuses_the_export_and_leaves_nothing(tmp_path, monkeypatch):
    real = X.TRANSFORMS["neutral_case_names"]
    monkeypatch.setitem(X.TRANSFORMS, "neutral_case_names",
                        lambda raw: real(raw).replace(b'"note"', b'"note' + b" see " + b"KC" + b"-99" + b'"', 1))
    out = tmp_path / "edge"
    assert X.export("edge-protocol", out)
    assert not out.exists()


def test_an_export_never_writes_into_an_existing_folder(tmp_path):
    with pytest.raises(SystemExit):
        X.export("edge-protocol", tmp_path)


def test_the_public_spec_names_every_format_and_call_of_the_internal_one():
    internal = (ROOT / "docs" / "keyclerk-edge-interface.md").read_text(encoding="utf-8")
    public = (ROOT / "docs" / "public" / "edge-protocol.md").read_text(encoding="utf-8")
    retired = {"kc-unlock-v1"}                                 # named internally only to say it is gone
    formats = set(re.findall(r"\bkc-[a-z0-9-]+-v\d\b", internal)) - retired
    calls = set(re.findall(r"`(?:GET|POST) (/edge/[a-z/{}]+)", internal))
    assert formats and calls
    assert not [f for f in formats if f not in public], "a format missing from the public spec"
    assert not [c for c in calls if c not in public], "a call missing from the public spec"


def test_the_engine_profile_takes_only_tracked_files_and_keeps_the_private_ones_out():
    manifest = X.yaml.safe_load((ROOT / "tools" / "public_manifest.yaml").read_text(encoding="utf-8"))
    chosen = X._selection(manifest["engine"])
    assert "keyclerk/desk.py" in chosen and "LICENSE" in chosen
    assert not [p for p in chosen if p.startswith(("docs/reviews/", "docs/public/", ".gitlab"))]
    assert "docs/decisions/0022-signed-change-log-and-sqlite-store.md" in chosen   # published once rewritten (2026-10-25)
    assert "docs/decisions/0014-edges-bundles-person-keys-relay.md" in chosen       # the rewritten records ship
    assert "docs/roadmap.md" not in chosen
    import subprocess
    tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split())
    sources = {s if isinstance(s, str) else s["from"] for s in chosen.values()}
    assert sources <= tracked                                   # nothing untracked or ignored can leave
