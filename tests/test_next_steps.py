# SPDX-License-Identifier: EUPL-1.2
"""Every refusal and every change that waits says why, what would complete the intent, and who can do it."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import remedies
from keyclerk.desk import Desk, Refusal, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
W = lambda a: {"anchor": a, "roles": [], "sub": a}   # noqa: E731
ANN, BERT, EVA = W("idp:7c1f-ann"), W("idp:91d0-bert"), W("idp:55bb-eva")


@pytest.fixture
def desk(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    return Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))


def names(step):
    return {w["name"] for w in step["who"]}


def test_a_change_that_waits_names_who_can_add_the_key(desk):
    r = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    assert r["outcome"] == "pending" and r["next"]
    step = r["next"][0]
    assert "manages site-wilsele must agree" in step["why"] and "bert" in names(step) and "ann" not in names(step)
    pend = desk.changes(ANN)["pending"][0]
    assert "bert" in {w["name"] for w in pend["waiting_for"]}


def test_a_refusal_says_whom_to_ask(desk):
    with pytest.raises(Refusal) as e:
        desk.propose(EVA, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn"})
    step = e.value.next[0]
    assert "do not manage office-staff" in step["why"] and "ask one of them" in step["do"].lower()
    assert "ann" in names(step) and "eva" not in names(step)


def test_an_approval_by_the_wrong_person_points_to_the_right_one(desk):
    r = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    with pytest.raises(Refusal) as e:
        desk.approve(ANN, r["change_id"])
    assert "bert" in names(e.value.next[0])


def test_every_reason_gets_a_step_and_an_unknown_one_goes_to_the_root():
    why, do, who = remedies.match("M-x-0001: something nobody wrote a rule for")
    assert why.startswith("Something") and "root" in do and who == "root"
    why, do, who = remedies.match("M-x-0001: needs a second key from outside the actor's chain (elevated group)")
    assert "elevated" in why and who == "approvers"


def test_a_second_key_is_a_person_of_the_organisation_never_an_external_or_an_agent(desk):
    from datetime import datetime, timezone
    from keyclerk import delegation as D
    doc = desk.store.load()
    others = [a for p in doc["persons"] if p["kind"] != "tenant" for a in p["anchors"]]
    tenants = [a for p in doc["persons"] if p["kind"] == "tenant" for a in p["anchors"]]
    assert others, "the fixture has externals or agents"
    now = datetime.now(timezone.utc)
    m = next(x for x in doc["memberships"] if x["under"] != "root")
    keys = D.outside_key(doc, others + tenants, m["by"], m["member"].get("anchor"), m["under"], now, now)
    assert keys and not set(keys) & set(others)
