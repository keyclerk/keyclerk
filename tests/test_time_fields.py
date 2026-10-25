"""Every time in the records is a time to records.canonical and records.validate: a date-time the canonical form does
not know compares by spelling, not meaning (a lease proof's expiry written as a YAML timestamp and as the desk's text
differed), which breaks the history guard's comparison and every equivalence test built on it (decision 0022)."""
import json
from datetime import datetime, timezone
from pathlib import Path

from keyclerk import records as R

SCHEMA = Path(__file__).resolve().parent.parent / "keyclerk" / "schema" / "records.schema.json"
OUTSIDE_SCHEMA = {"decided_at"}          # a risk acceptance's decision time (risk_port), not part of the records schema


def schema_times() -> set[str]:
    found: set[str] = set()

    def walk(node, key=None):
        if isinstance(node, dict):
            if node.get("format") == "date-time" and key:
                found.add(key)
            for k, v in node.items():
                if k == "properties" and isinstance(v, dict):
                    for pk, pv in v.items():
                        walk(pv, pk)
                else:
                    walk(v, key)
        elif isinstance(node, list):
            for v in node:
                walk(v, key)
    walk(json.loads(SCHEMA.read_text(encoding="utf-8")))
    return found


def test_the_schema_date_times_and_time_fields_agree():
    assert schema_times() == R.TIME_FIELDS - OUTSIDE_SCHEMA


def test_a_time_under_any_of_them_compares_by_meaning():
    t = datetime(2026, 10, 27, 17, 0, tzinfo=timezone.utc)
    for f in sorted(R.TIME_FIELDS):
        assert R.canonical({f: t}) == R.canonical({f: "2026-10-27T17:00:00Z"}) == R.canonical({f: "2026-10-27T19:00:00+02:00"}), f
