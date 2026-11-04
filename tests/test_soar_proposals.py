# SPDX-License-Identifier: EUPL-1.2
"""Issue 30 (decision 0018 H5): a SOAR is a workload that may only propose protective changes, never a grant. Each is
checked by the engine and signed when it applies; past the hourly ceiling, or for a person on call, or where policy says
so, it waits for the security officer, the root or a person on call, and the ceiling raises an incident."""
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import delegation as D
from keyclerk import situation
from keyclerk.access_state import suspended
from keyclerk.desk import Desk, Refusal, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NOW = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
SOAR = {"anchor": None, "roles": [], "azp": "soar-client", "csrf": None}
INGRID, ANN = {"anchor": "idp:31ee-ingrid", "roles": []}, {"anchor": "idp:7c1f-ann", "roles": []}
EVA, BERT = "idp:55bb-eva", "idp:91d0-bert"            # bert is on call in the fixture


@pytest.fixture
def desk(tmp_path, monkeypatch):
    raw = (FIXTURES / "records.yaml").read_text(encoding="utf-8")
    raw = raw.replace("persons:\n", "persons:\n  - {person: soar, kind: workload, anchors: [\"wl:soar\"], "
                                    "owner: \"idp:31ee-ingrid\"}\n", 1)
    raw = raw.replace("situation_feeds:\n", "situation_feeds:\n  - {feed: soar, max_level: high, note: \"the SOAR\"}\n", 1)
    (tmp_path / "records.yaml").write_text(raw, encoding="utf-8")
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    cfg = {"client": "soar-client", "workload": "wl:soar", "feed": "soar", "max_per_hour": 3}
    monkeypatch.setattr(Desk, "_soar_cfg", staticmethod(lambda: cfg))
    d = Desk(Store(tmp_path / "store", key, tmp_path / "records.yaml"), clock=lambda: NOW)
    d.cfg = cfg
    yield d
    d.store.close()


def test_a_soar_suspension_is_a_signed_record_that_takes_effect(desk):
    r = desk.propose(SOAR, {"action": "suspend_person", "anchor": EVA, "reason": "impossible travel alert 4711"})
    assert r["outcome"] == "applied", r
    doc = desk.store.load()
    s = next(x for x in doc["suspensions"] if x["anchor"] == EVA)
    assert s["by"] == "wl:soar" and suspended(doc, EVA, NOW)
    assert not D.member_of(doc, EVA, "site-heverlee", NOW)            # the membership no longer counts
    line = next(e for e in reversed(desk.store.log(20)) if e.get("change_id") == r["change_id"])
    assert line["actor"] == "wl:soar" and line["sha256"]
    assert not desk.store.verify_log()


def test_a_soar_never_grants_nor_approves(desk):
    with pytest.raises(Refusal, match="never a grant"):
        desk.propose(SOAR, {"action": "add_member", "group": "office-staff", "anchor": EVA, "days": 1})
    with pytest.raises(PermissionError):
        desk.approve(SOAR, "C-a0b1c2d3e4f5")
    with pytest.raises(Refusal, match="never a grant"):
        desk.propose(SOAR, {"action": "lift_suspension", "suspension_id": "S-x"})


def test_a_person_on_call_is_spared_until_a_person_confirms(desk):
    r = desk.propose(SOAR, {"action": "suspend_person", "anchor": BERT, "reason": "alert 4712"})
    assert r["outcome"] == "pending" and "on call" in r["reasons"][0]
    assert not suspended(desk.store.load(), BERT, NOW)
    with pytest.raises(Refusal, match="security officer, the root or a person on call"):
        desk.approve(ANN, r["change_id"])                              # a manager cannot wave it through
    assert desk.approve(INGRID, r["change_id"])["outcome"] == "applied"   # the security officer confirms
    assert suspended(desk.store.load(), BERT, NOW)


def test_past_the_hourly_ceiling_a_person_decides_and_an_incident_is_raised(desk):
    for who in (EVA, "idp:66cc-finn", "ext:3a71-carla"):                 # the ceiling is 3 in this fixture
        assert desk.propose(SOAR, {"action": "suspend_person", "anchor": who, "reason": "alert"})["outcome"] == "applied"
    r = desk.propose(SOAR, {"action": "end_membership", "membership_id": "M-example-0003", "reason": "alert 4713"})
    assert r["outcome"] == "pending" and any("ceiling" in x for x in r["reasons"])
    assert len([e for e in desk.store.log(50) if e.get("action") == "soar_ceiling"]) == 1
    desk.propose(SOAR, {"action": "suspend_person", "anchor": "idp:2b9e-owner", "reason": "alert 4714"})
    assert len([e for e in desk.store.log(50) if e.get("action") == "soar_ceiling"]) == 1   # once an hour
    assert desk.approve(INGRID, r["change_id"])["outcome"] == "applied"   # a person decides


def test_a_soar_raises_a_level_through_its_feed_and_never_lowers_one(desk):
    doc = desk.store.load()
    before = situation.levels(doc, None, NOW)["restriction"]
    up = situation.LEVELS[situation.LEVELS.index(before) + 1]
    r = desk.propose(SOAR, {"action": "raise_situation", "level": up, "reason": "phishing campaign"})
    assert r["outcome"] == "applied", r
    assert situation.levels(desk.store.load(), None, NOW)["restriction"] == up
    rec = next(x for x in desk.store.load()["situations"] if x["source"] == "feed:soar")
    assert rec["by"] == "feed:soar" and rec["nonce"]
    with pytest.raises(Refusal, match="only raises"):
        desk.propose(SOAR, {"action": "raise_situation", "level": before, "reason": "lower it"})
    with pytest.raises(Refusal, match="would leave the level"):            # capped at one step above people's level
        desk.propose(SOAR, {"action": "raise_situation", "level": "severe", "reason": "a place",
                            "scope": {"kind": "place", "id": "place:herent-mast"}})


def test_a_soar_ends_a_membership(desk):
    r = desk.propose(SOAR, {"action": "end_membership", "membership_id": "M-example-0002", "reason": "alert 4715"})
    assert r["outcome"] == "applied", r
    assert not D.member_of(desk.store.load(), EVA, "site-heverlee", NOW)


def test_policy_can_hold_an_action_for_a_person(desk):
    desk.cfg["apply_at_once"] = ["raise_situation"]
    r = desk.propose(SOAR, {"action": "suspend_person", "anchor": EVA, "reason": "alert 4716"})
    assert r["outcome"] == "pending" and "policy" in r["reasons"][0]


def test_without_a_workload_in_the_records_the_soar_is_refused(desk):
    desk.cfg["workload"] = "wl:nobody"
    with pytest.raises(Refusal, match="names no workload"):
        desk.propose(SOAR, {"action": "suspend_person", "anchor": EVA})


def test_the_suspension_shows_on_the_persons_view(desk):
    desk.propose(SOAR, {"action": "suspend_person", "anchor": EVA, "reason": "impossible travel alert 4717"})
    seen = desk.person({"anchor": None, "roles": ["keyclerk-viewer"]}, EVA)["suspensions"]
    assert len(seen) == 1 and seen[0]["by"] == "wl:soar" and seen[0]["lifted"] is None
    assert seen[0]["reason"] == "impossible travel alert 4717"
