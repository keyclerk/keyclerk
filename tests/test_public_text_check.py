# SPDX-License-Identifier: EUPL-1.2
"""The public text check: the leak gate's rules on posted text, private patterns by number, commit ranges."""
import importlib.util
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("public_text_check", ROOT / "tools" / "public_text_check.py")
ptc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ptc)
NAME = ptc.leak_gate._WORDS[2][::-1]          # a deployment name, built so this file names none


def test_clean_text_passes():
    assert ptc.scan("body.md", "Restore safety: a restored desk never signs a revision number twice.\n", env={}) == []


def test_a_deployment_name_is_a_hit():
    hits = ptc.scan("body.md", f"Seen on the {NAME} ring.\n", env={})
    assert hits and "deployment or operator name" in hits[0]


def test_a_private_pattern_is_reported_by_number_only():
    env = {"KEYCLERK_PRIVATE_PATTERNS": "\n(?i)secret-host-[0-9]+\n"}
    hits = ptc.scan("comment", "line one\nreach secret-host-7 for it\n", env=env)
    assert hits == ["comment:2: private pattern 1"]
    assert "secret-host" not in hits[0]


def test_no_patterns_without_the_secret():
    assert ptc.private_patterns({}) == []


def test_a_range_checks_messages_and_added_lines(tmp_path, monkeypatch):
    # A git hook (the pre-push gate runs this suite in one) exports GIT_DIR and friends: inherited, they would point
    # every git call below at the repository being pushed instead of this scratch one (it happened, 2026-11-03).
    for var in [v for v in os.environ if v.startswith("GIT_")]:
        monkeypatch.delenv(var)

    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    git("config", "user.email", "maintainer" + "@" + "example.org")   # in pieces: the leak gate reads this file
    git("config", "user.name", "Maintainer")
    git("config", "commit.gpgsign", "false")
    (tmp_path / "a.md").write_text("start\n", encoding="utf-8")
    git("add", "a.md")
    git("commit", "-q", "-m", "First")
    (tmp_path / "a.md").write_text(f"start\nadded on the {NAME} ring\n", encoding="utf-8")
    git("commit", "-q", "-am", "Second: harmless message")
    monkeypatch.chdir(tmp_path)
    items = dict(ptc.range_text("HEAD~1..HEAD"))
    assert any(k.startswith("commit ") and "harmless" in v for k, v in items.items())
    assert items["a.md"] == f"added on the {NAME} ring"
    assert ptc.main(["--range", "HEAD~1..HEAD"]) == 1
