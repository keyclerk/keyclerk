# SPDX-License-Identifier: EUPL-1.2
"""Visits live outside the signed records (a review finding, 2026-10-23): a visit is its own file, vouched for by the desk's
signed log, so personal data of visitors is not copied into every revision and is erased after its retention; the log
names visits by id only."""
import json
from datetime import datetime, timezone

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk.desk import Desk, Store
import pytest
from test_visits import ANN, CARLA, FIXTURES, GUARD, LAB, Clock, W, entry, register, visit_desk  # noqa: F401


@pytest.fixture
def desk(tmp_path):
    """The YAML store alone: these tests read its visit files."""
    return visit_desk(tmp_path)


def _log(desk):
    return (desk.store.path / "log.jsonl").read_text(encoding="utf-8")


def test_a_visit_is_its_own_file_and_makes_no_revision(desk):
    rev = desk.store.revision()
    r = register(desk)
    assert r["outcome"] == "applied" and desk.store.revision() == rev
    published = yaml.safe_load((desk.store.path / "records.yaml").read_text(encoding="utf-8"))
    assert not published.get("visits") and not published.get("visit_events")
    assert [f.name.split(".")[0] for f in (desk.store.path / "visits").glob("*.yaml")] == ["V-example-0001"]
    assert desk.store.load()["visits"][0]["purpose"] == "supplier meeting"


def test_the_log_names_visits_by_id_only(desk):
    register(desk)
    desk.test_clock.at("11:05")
    entry(desk, "P1", "qr")
    log = _log(desk)
    assert "V-example-0001" in log
    for secret in ("supplier meeting", "RAV4", "2-XXX-111", "backpack", "passenger"):
        assert secret not in log, secret


def test_a_closed_visit_is_erased_after_its_retention(desk):
    register(desk)
    desk.test_clock.t = datetime(2026, 11, 24, 17, 0, tzinfo=timezone.utc)     # closes 26/10 16:00, plus 29 days
    desk.tick()
    assert desk.store.visit_ids() == ["V-example-0001"]
    desk.test_clock.t = datetime(2026, 11, 26, 17, 0, tzinfo=timezone.utc)     # past 30 days
    desk.tick()
    assert desk.store.visit_ids() == [] and not list((desk.store.path / "visits").glob("*.yaml"))
    assert not desk.store.load().get("visits")
    last = [json.loads(x) for x in _log(desk).splitlines()][-1]
    assert last["action"] == "visit_erased" and last["visits"] == {"V-example-0001": None}
    assert desk.store.verify_log() == []


def test_a_restart_finds_its_visits_and_sets_aside_what_no_log_line_vouches_for(desk, tmp_path):
    register(desk)
    stray = desk.store.path / "visits" / "V-example-0002.deadbeefdeadbeef.yaml"
    stray.write_text("visit: {visit_id: V-example-0002}\n", encoding="utf-8")
    key = desk.store.key_path
    desk.store.close()
    again = Store(desk.store.path, key)
    assert again.visit_ids() == ["V-example-0001"]
    assert again.load()["visits"][0]["visit_id"] == "V-example-0001"
    assert not stray.exists() and any("never committed" in n for n in again.recovered)


def test_a_seed_with_visits_is_split_into_visit_files(desk, tmp_path):
    register(desk)
    seed2 = tmp_path / "seed2.yaml"
    seed2.write_text(yaml.safe_dump(json.loads(json.dumps(desk.store.load(), default=str)), sort_keys=False),
                     encoding="utf-8")
    other = Store(tmp_path / "other", desk.store.key_path, seed2)
    assert other.visit_ids() == ["V-example-0001"] and not other.legacy_visits()
    assert not yaml.safe_load((tmp_path / "other" / "records.yaml").read_text(encoding="utf-8")).get("visits")


def test_a_store_that_kept_visits_in_its_records_goes_on_doing_so(desk, monkeypatch):
    """A store written by 0.15 or earlier: its visits stay in the records until it is seeded again."""
    monkeypatch.setattr(Store, "legacy_visits", lambda self: True)
    rev = desk.store.revision()
    register(desk)
    assert desk.store.revision() == rev + 1 and desk.store.visit_ids() == []
    assert yaml.safe_load((desk.store.path / "records.yaml").read_text(encoding="utf-8"))["visits"]
