"""Decision 0022 S4: one clock per judgement. Every engine check reads "now" from keyclerk.clock, so a whole check,
and the old and new states a signer compares, are judged at one moment, and a scoped check compares exactly with the
full one."""
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from keyclerk import clock, records
from keyclerk.reconcile import check_records

ROOT = Path(__file__).resolve().parent.parent / "keyclerk"
CHECK_MODULES = ("delegation", "grants", "leases", "places", "situation", "visits", "edge_records", "records",
                 "access_state", "reconcile", "approvals", "edge")
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "records.yaml"


def test_no_check_module_reads_the_clock_any_other_way():
    hits = []
    for name in CHECK_MODULES:
        for n, line in enumerate((ROOT / f"{name}.py").read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"datetime\.(now|utcnow|today)\(|date\.today\(", line):
                hits.append(f"{name}.py:{n}: {line.strip()}")
    assert hits == []


def test_a_check_is_judged_at_the_moment_set(monkeypatch):
    from keyclerk import delegation
    doc = records.loads(FIXTURE.read_text(encoding="utf-8"))
    t = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
    seen, real = [], delegation.membership_status

    def spy(d, m, at):
        seen.append(at)
        return real(d, m, at)
    monkeypatch.setattr(delegation, "membership_status", spy)
    with clock.at(t + timedelta(days=3)):
        a = check_records(doc)
    with clock.at(t + timedelta(days=3)):
        assert check_records(doc) == a                    # the same moment, the same answer
    wall = datetime.now(timezone.utc)
    assert t + timedelta(days=3) in seen                  # "now" is the moment set, not the wall clock
    assert not any(abs(x - wall) < timedelta(minutes=5) for x in seen)


def test_a_moment_has_a_zone():
    with pytest.raises(ValueError):
        with clock.at(datetime(2026, 1, 1)):
            pass
