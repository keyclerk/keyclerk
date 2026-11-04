# SPDX-License-Identifier: EUPL-1.2
"""The view log keeps every look: a full log rotates to a kept archive instead of dropping its oldest lines, and
archives go only after their retention (review 2026-10-26, C4)."""
from datetime import datetime, timedelta, timezone

from keyclerk import clock, config
from keyclerk.desk import DeskFiles


class _Files(DeskFiles):
    def __init__(self, path):
        self.path = path


def _lines(path):
    return [line for f in sorted(path.glob("views*.log")) for line in f.read_text(encoding="utf-8").splitlines()]


def test_reads_cannot_push_earlier_looks_out(tmp_path, monkeypatch):
    monkeypatch.setattr(DeskFiles, "VIEW_LOG_MAX", 400)
    files = _Files(tmp_path)
    t = datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)
    for i in range(60):
        with clock.at(t + timedelta(seconds=i)):
            files.log_view({"viewer": "officer", "subject": f"anchor-{i:02d}"})
    kept = _lines(tmp_path)
    assert len(kept) == 60, "a look was dropped"
    assert any('"anchor-00"' in line for line in kept)
    assert len(list(tmp_path.glob("views-*.log"))) >= 2
    assert (tmp_path / "views.log").stat().st_size <= 400 + 100


def test_archives_go_after_their_retention(tmp_path, monkeypatch):
    monkeypatch.setattr(DeskFiles, "VIEW_LOG_MAX", 10)
    monkeypatch.setattr(config, "current", lambda: {"store": {"view_log_keep_days": 30}})
    files = _Files(tmp_path)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for day in (0, 1, 40, 41):
        with clock.at(start + timedelta(days=day)):
            files.log_view({"viewer": "officer", "subject": f"day-{day}"})
    names = sorted(p.name for p in tmp_path.glob("views-*.log"))
    # rotations closed archives on day 1, 40 and 41; on day 41 the one closed on day 1 is older than 30 days
    assert names == ["views-20260210T000000Z.log", "views-20260211T000000Z.log"]


def test_the_default_retention_is_about_thirteen_months(tmp_path, monkeypatch):
    monkeypatch.setattr(DeskFiles, "VIEW_LOG_MAX", 10)
    monkeypatch.setattr(config, "current", lambda: {})
    files = _Files(tmp_path)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for day in (0, 1, 300, 301):
        with clock.at(start + timedelta(days=day)):
            files.log_view({"viewer": "officer", "subject": f"day-{day}"})
    assert len(list(tmp_path.glob("views-*.log"))) == 3          # nothing older than 400 days yet


def test_two_rotations_in_one_second_keep_both(tmp_path, monkeypatch):
    monkeypatch.setattr(DeskFiles, "VIEW_LOG_MAX", 10)
    files = _Files(tmp_path)
    with clock.at(datetime(2026, 11, 3, 9, 0, tzinfo=timezone.utc)):
        for i in range(4):
            files.log_view({"viewer": "officer", "subject": f"s-{i}"})
    assert len(_lines(tmp_path)) == 4
