# SPDX-License-Identifier: EUPL-1.2
"""The edge protocol cites what it builds on (CONTRIBUTING.md, "References"): its own check passes on the published
text and fails on a citation dropped, a link missing or a reference no longer cited."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check", ROOT / "docs/public/edge-protocol/tools/check.py")
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)
SPEC = (ROOT / "docs/public/edge-protocol.md").read_text(encoding="utf-8")


def test_the_published_specification_cites_everything_it_names():
    assert check.reference_errors(SPEC) == []


def test_a_term_without_its_citation_at_first_mention_is_caught():
    broken = SPEC.replace("Ed25519 [RFC8032]", "Ed25519", 1)
    assert any("Ed25519 first appears without [RFC8032]" in e for e in check.reference_errors(broken))


def test_a_reference_without_a_link_is_caught():
    broken = SPEC.replace("<https://www.rfc-editor.org/rfc/rfc8032>", "(see the RFC)", 1)
    assert any("[RFC8032] has no https link" in e for e in check.reference_errors(broken))


def test_a_reference_no_longer_cited_and_a_citation_without_reference_are_caught():
    body, refs = SPEC.split("\n## References", 1)
    errs = check.reference_errors(body.replace("[RFC7643]", "[RFC9999]") + "\n## References" + refs)
    assert any("[RFC7643] is never cited" in e for e in errs)
    assert any("[RFC9999] is cited but has no reference" in e for e in errs)


def test_without_a_references_section_the_check_says_what_is_needed():
    assert check.reference_errors(SPEC.split("\n## References")[0])[0].startswith("edge-protocol.md: no References")
