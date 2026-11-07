# SPDX-License-Identifier: EUPL-1.2
"""Changelog fragments: the checker, the fold at release, and the repository's own fragments."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("changelog", ROOT / "tools" / "changelog.py")
changelog = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(changelog)


def _repo(tmp_path, frags, text="# Changelog\n\nIntro.\n\n## 0.26.3 (2026-10-26)\n- Old entry.\n"):
    (tmp_path / "changelog.d").mkdir()
    (tmp_path / "changelog.d" / "README.md").write_text("not a fragment\n", encoding="utf-8")
    for name, body in frags.items():
        (tmp_path / "changelog.d" / name).write_text(body, encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(text, encoding="utf-8")
    return tmp_path


def test_the_repository_fragments_are_well_formed():
    assert changelog.check() == []


@pytest.mark.parametrize("name, body, expect", [
    ("31.added.md", "- Fine.\n", None),
    ("desk-timeouts.fixed.md", "- Fine, with a\n  continuation.\n", None),
    ("31.feature.md", "- x\n", "unknown section"),
    ("thirty one.added.md", "- x\n", "name it"),
    ("31.added.md", "No bullet.\n", "start with a bullet"),
    ("31.added.md", "- " + "x" * 130 + "\n", "longer than"),
    ("31.added.md", "- café\n", "not plain ASCII"),
    ("31.added.md", "- a\nnot indented\n", "indented two spaces"),
])
def test_problems(tmp_path, name, body, expect):
    root = _repo(tmp_path, {name: body})
    found = changelog.check(root)
    if expect is None:
        assert found == []
    else:
        assert any(expect in p for p in found), found


def test_release_folds_in_section_order_and_removes_the_fragments(tmp_path):
    root = _repo(tmp_path, {"40.fixed.md": "- Fixed.\n", "31.added.md": "- Added.\n", "27.security.md": "- Guarded.\n"})
    changelog.release(root, "0.27.0", "2026-11-20")
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert text.index("## 0.27.0 (2026-11-20)\n- Guarded.\n- Added.\n- Fixed.\n") < text.index("## 0.26.3")
    assert text.startswith("# Changelog\n\nIntro.\n\n## 0.27.0")
    assert changelog.fragments(root) == []
    assert (root / "changelog.d" / "README.md").exists()


def test_release_refuses_without_fragments_twice_or_a_bad_version(tmp_path):
    root = _repo(tmp_path, {})
    with pytest.raises(SystemExit, match="no fragments"):
        changelog.release(root, "0.27.0", "2026-11-20")
    (tmp_path / "b").mkdir()
    root2 = _repo(tmp_path / "b",{"1.added.md": "- x\n"}, text="# Changelog\n\n## 0.27.0 (2026-11-01)\n- y\n")
    with pytest.raises(SystemExit, match="already has a section"):
        changelog.release(root2, "0.27.0", "2026-11-20")
    with pytest.raises(SystemExit, match="is not X.Y.Z"):
        changelog.release(root2, "v0.27", "2026-11-20")


def test_release_notes_extraction_matches_the_release_workflow(tmp_path):
    # release.yml takes the lines after "## <version> " up to the next "## ": the fold must produce exactly that
    root = _repo(tmp_path, {"31.added.md": "- Added.\n"})
    changelog.release(root, "0.27.0", "2026-11-20")
    lines, on = [], False
    for line in (root / "CHANGELOG.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("## 0.27.0 "):
            on = True
            continue
        if line.startswith("## "):
            on = False
        if on:
            lines.append(line)
    assert [line for line in lines if line.strip()] == ["- Added."]



def test_a_release_whose_deployer_contract_changed_needs_an_upgrading_line(tmp_path, monkeypatch):
    """the edge implementation's 0.27.0 upgrade took three attempts: each new requirement surfaced as its own refusal at start.
    A release that changes what a deployer must supply now says so under Upgrading, or it is refused."""
    root = _repo(tmp_path, {"1-a.added.md": "- A new thing.\n"})
    monkeypatch.setattr(changelog, "contract_changed", lambda root: True)
    with pytest.raises(SystemExit, match="Upgrading"):
        changelog.release(root, "9.9.9", "2026-11-05")
    (root / "changelog.d" / "1-b.changed.md").write_text("- **Upgrading:** the signer needs `--new`.\n",
                                                         encoding="utf-8")
    assert "**Upgrading:**" in changelog.release(root, "9.9.9", "2026-11-05")


def test_a_repository_without_a_deployer_guide_releases_without_an_upgrading_line(tmp_path):
    """The edge protocol's repository shares this tool and has no deployer guide: nothing a deployer supplies changed."""
    root = _repo(tmp_path, {"1-a.added.md": "- A new thing.\n"})
    assert not changelog.contract_changed(root)
    assert "A new thing" in changelog.release(root, "9.9.9", "2026-11-06")


def test_a_release_candidate_has_its_section_and_becomes_the_release(tmp_path):
    """0.29.0-rc.1 gets its own section (the release workflow reads it for the candidate's tag); the release after it,
    without new fragments, renames that section, so the release carries the candidate's notes."""
    root = _repo(tmp_path, {"31.added.md": "- Added.\n"})
    changelog.release(root, "0.29.0-rc.1", "2026-11-07")
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 0.29.0-rc.1 (2026-11-07)\n- Added.\n" in text
    changelog.release(root, "0.29.0", "2026-11-08")
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## 0.29.0 (2026-11-08)\n- Added.\n" in text and "rc.1" not in text
    with pytest.raises(SystemExit, match="no fragments"):
        changelog.release(root, "0.30.0", "2026-11-09")       # another version's notes are never taken over
