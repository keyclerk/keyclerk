# SPDX-License-Identifier: EUPL-1.2
"""The leak gate (tools/leak_gate.py) catches every class of internal material, passes what a public text needs, names
nothing itself, and passes the public specification as it stands."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import leak_gate as G  # noqa: E402

# planted leaks, built at run time so this file passes the gate and the deployment-name guard itself
LEAKS = {
    "deployment name": "deployed for " + "elsi"[::-1] + " sites",
    "internal id": "fixed in " + "KC" + "-12",
    "internal id (lettered)": "see " + "RK-E" + "3",
    "decision reference": "per " + "decision" + " 0014",
    "process wording": "found in the " + "red" + " team",
    "private host": "pushed to " + "gitlab" + ".com/x/y",
    "local path": "C:" + "\\" + "Users" + "\\" + "x",
    "e-mail": "mail " + "someone" + "@" + "example.org",
    "private key": "-----BEGIN " + "PRIVATE KEY-----",
    "token": "glpat" + "-" + "a" * 24,
}


@pytest.mark.parametrize("what, text", sorted(LEAKS.items()))
def test_every_class_of_leak_is_caught(what, text):
    assert G.scan_text("x.md", text, []), what


@pytest.mark.parametrize("text", ["the P-256 curve and SHA-256", "kc-edge-bundle-v3", "TPM2_ECDH_ZGen",
                                  "an edge id that has ended", "EUPL-1.2"])
def test_what_a_public_text_needs_passes(text):
    assert G.scan_text("x.md", text, []) == []


def test_personal_names_come_from_a_file_outside_the_repository(tmp_path):
    names = tmp_path / "names.txt"
    names.write_text("Placeholder\n", encoding="utf-8")
    d = tmp_path / "out"
    d.mkdir()
    (d / "a.md").write_text("written by placeholder", encoding="utf-8")
    assert G.scan(d, names) and not G.scan(d, None)


def test_the_steward_name_passes_only_in_the_steward_files():
    steward = "emoHDV"[::-1]
    assert G.scan_text("NOTICE", f"Copyright {steward}", []) == []
    assert G.scan_text("REUSE.toml", f'SPDX-FileCopyrightText = "2026 {steward}"', []) == []
    assert G.scan_text("README.md", f"Copyright {steward}", [])


def test_the_gate_names_nothing_itself_and_passes_the_public_spec():
    assert G.scan_text("tools/leak_gate.py", (ROOT / "tools" / "leak_gate.py").read_text(encoding="utf-8"), []) == []
    assert G.scan(ROOT / "docs" / "public") == []


def test_a_reference_to_a_released_decision_record_passes_an_unreleased_one_does_not(tmp_path):
    (tmp_path / "docs" / "decisions").mkdir(parents=True)
    (tmp_path / "docs" / "decisions" / "0014-edges.md").write_text("# 0014\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("See decision 0014 and Decision 0011a.\n", encoding="utf-8")
    hits = G.scan(tmp_path)
    assert any("0011a" in h for h in hits) and not any(": decision 0014" in h for h in hits)
    (tmp_path / "docs" / "decisions" / "0011a-admin.md").write_text("# 0011a\n", encoding="utf-8")
    assert not [h for h in G.scan(tmp_path) if "decision reference" in h]


def test_a_decisions_folder_scanned_directly_knows_its_own_records(tmp_path):
    (tmp_path / "0005-desk.md").write_text("See decision 0004 and decision 0005.\n", encoding="utf-8")
    (tmp_path / "0004-scope.md").write_text("# 0004\n", encoding="utf-8")
    assert not [h for h in G.scan(tmp_path) if "decision reference" in h]


def test_an_amendment_is_published_with_its_record(tmp_path):
    (tmp_path / "docs" / "decisions").mkdir(parents=True)
    (tmp_path / "docs" / "decisions" / "0014-edges.md").write_text("# 0014\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("Amendment 0014d binds the node; decision 0015 is not released.\n", encoding="utf-8")
    hits = [h for h in G.scan(tmp_path) if "decision reference" in h]
    assert len(hits) == 1 and "0015" in hits[0]


def test_a_binary_file_is_read_for_paths_keys_and_names(tmp_path):
    """A compiler wrote the build machine's source path into every compiled policy (found by the estate gate before
    the engine's first public push, 2026-10-25): binaries are scanned too, not skipped."""
    path = "C:" + chr(92) + "Users" + chr(92) + "someone" + chr(92) + "x.rego"      # built: no path in this file
    (tmp_path / "module.wasm").write_bytes(b"\x00asm\x01\x00\x00\x00\xff\xfe " + path.encode() + b" \x00")
    (tmp_path / "picture.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\xffAuthor: Jan Peeters\x00")
    names = tmp_path / "names.txt"
    names.write_text("Peeters\n", encoding="utf-8")
    hits = G.scan(tmp_path, names)
    assert any("module.wasm: local path in a binary file" in h for h in hits)
    assert any("picture.png: a personal name in a binary file" in h for h in hits)


def test_the_compiled_policies_carry_no_build_path():
    """tools/build_policy.py builds from the policy folder by file name: a module names its source, nothing more."""
    for f in sorted((ROOT / "keyclerk" / "policy").glob("*.wasm")):
        assert not G.scan_binary(f.name, f.read_bytes(), []), f.name
