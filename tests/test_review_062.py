# SPDX-License-Identifier: EUPL-1.2
"""Regressions for the review of 0.5.0..0.6.1 (docs/reviews)."""
import json
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import approvals, config, guard
from keyclerk.desk import Desk, Refusal, Store
from keyclerk.oidc import Oidc
from tests.test_approvals import AUD, ISS, Broker

FIXTURES = Path(__file__).resolve().parent / "fixtures"
W = lambda a: {"anchor": a, "roles": [], "sub": a}   # noqa: E731
ANN, BERT, EVA, FINN = W("idp:7c1f-ann"), W("idp:91d0-bert"), W("idp:55bb-eva"), W("idp:66cc-finn")


@pytest.fixture
def broker():
    return Broker()


@pytest.fixture
def desk(tmp_path, broker, monkeypatch):
    real = config.current
    monkeypatch.setattr(config, "current", lambda: {**real(), "approvals": {"proofs": "required", "accepted_without_proof": []}})
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    proofs = approvals.BrokerProofs({ISS}, {AUD}, 300, "https://id.test/x", tmp_path / "k.json", fetch=broker.jwks)
    return Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"), proofs=proofs)


def test_kc63_tokens_never_reach_the_log_or_an_answer(desk, broker):
    r = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    tok = broker.token(desk.statement(BERT, r["change_id"])["nonce"], "idp:91d0-bert")
    done = desk.approve(BERT, r["change_id"], tok)
    assert done["outcome"] == "applied" and tok not in json.dumps(done)
    assert done["records"]["approval_proofs"][0]["sha256"] and "token" not in done["records"]["approval_proofs"][0]
    assert tok not in (desk.store.path / "log.jsonl").read_text(encoding="utf-8")
    assert tok in desk.store.raw().decode()                                # only the signed records hold it


def test_kc63_an_id_token_is_never_a_bearer_token(broker):
    o = Oidc(public_issuer=ISS, internal_issuer=ISS, client_id=AUD, redirect_uri="https://desk.test/callback",
             viewer_role="keyclerk-viewer")
    o.jwks, o.jwks_at = {k["kid"]: k for k in broker.jwks()["keys"]}, time.time()
    now = int(time.time())
    idt = broker.sign({"iss": ISS, "aud": "other", "azp": "other", "typ": "ID", "nonce": "n", "exp": now + 300, "sub": "s"})
    with pytest.raises(guard.InputRejected, match="not an access token"):
        o.bearer(idt, ("other",))
    at = broker.sign({"iss": ISS, "aud": "account", "azp": "other", "typ": "Bearer", "exp": now + 300, "sub": "s"})
    assert o.bearer(at, ("other",))["sub"] == "s"


def test_kc65_next_steps_name_managers_only_of_a_group_one_may_see(desk):
    with pytest.raises(Refusal) as e:
        desk.propose(FINN, {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"})
    root = {w["name"] for w in e.value.next[0]["who"]}
    assert root == {"owner"}                                              # finance is not finn's to see


def test_kc66_who_can_approve_is_worked_out_once_and_stored(desk):
    r = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    p = desk.store.pending()[r["change_id"]]
    assert p["waiting_for"] and p["waiting_rev"] == desk.store.revision()


def test_kc69_only_who_may_see_or_approve_a_change_gets_its_statement(desk):
    r = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    assert desk.statement(BERT, r["change_id"])["by"] == "idp:91d0-bert"
    with pytest.raises(Refusal, match="no such change"):
        desk.statement(FINN, r["change_id"])                              # the same answer as for a missing change


def test_kc70_phone_links_outlive_a_restart(desk):
    key = desk.link_key
    desk.store.close()
    again = Desk(Store(desk.store.path, desk.store.key_path))
    assert again.link_key == key
