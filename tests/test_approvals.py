# SPDX-License-Identifier: EUPL-1.2
"""Approvals as the approver's own signature (decision 0006): a key someone adds to a change must carry a
proof the broker signed after a fresh sign-in, bound to exactly those records and that person; the reconciler checks
every one, so the desk's signing key alone can no longer write a second key."""
import base64
import copy
import json
import time
import types
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import approvals, config, guard, records
from keyclerk.desk import Desk, Refusal, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ISS, AUD = "https://id.test/realms/example", "keyclerk-desk"
W = lambda a: {"anchor": a, "roles": [], "sub": a}   # noqa: E731
ANN, BERT = W("idp:7c1f-ann"), W("idp:91d0-bert")
B64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()   # noqa: E731


class Broker:
    """A broker that signs ID tokens with its own RSA key and publishes the public half."""

    def __init__(self, kid="k1"):
        self.key, self.kid = rsa.generate_private_key(public_exponent=65537, key_size=2048), kid

    def jwks(self):
        n = self.key.public_key().public_numbers()
        return {"keys": [{"kty": "RSA", "kid": self.kid, "use": "sig", "e": B64(n.e.to_bytes(3, "big")),
                          "n": B64(n.n.to_bytes(256, "big"))}]}

    def token(self, nonce, anchor, aud=AUD, iss=ISS, fresh=True, **extra):
        now = int(time.time())
        claims = {"iss": iss, "aud": aud, "nonce": nonce, "anchor": anchor, "iat": now, "exp": now + 300,
                  "auth_time": now - (5 if fresh else 3600), **extra}
        return self.sign(claims)

    def sign(self, claims):
        h = B64(json.dumps({"alg": "RS256", "kid": self.kid}).encode())
        p = B64(json.dumps(claims).encode())
        sig = self.key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{h}.{p}.{B64(sig)}"


@pytest.fixture
def broker():
    return Broker()


@pytest.fixture
def proofs(broker, tmp_path):
    return approvals.BrokerProofs({ISS}, {AUD}, 300, "https://id.test/realms/example/protocol/openid-connect/certs",
                                  tmp_path / "keys.json", fetch=broker.jwks)


@pytest.fixture
def required(monkeypatch):
    real = config.current

    def with_policy(allowed=()):
        policy = {"proofs": "required", "max_age_seconds": 300, "accepted_without_proof": list(allowed)}
        monkeypatch.setattr(config, "current", lambda: {**real(), "approvals": policy})
        return policy
    return with_policy


def seed_allowlist(doc):
    return [{"record": rid, "by": by, "sha256": approvals.record_hash(kind, rec)} for kind, rid, rec, by in approvals.keys_in(doc)]


# --- the proof ------------------------------------------------------------------------------------------------------

def test_a_proof_fits_only_its_records_its_person_its_broker_and_a_fresh_sign_in(broker, proofs):
    rec = ("memberships", {"membership_id": "M-1", "group": "g", "member": {"anchor": "idp:x"}, "approved_by": ["idp:a"]})
    nonce = approvals.statement("example", [rec], "idp:a")
    assert nonce == approvals.statement("example", [(rec[0], {**rec[1], "approved_by": ["idp:a", "idp:b"]})], "idp:a")
    assert proofs(broker.token(nonce, "idp:a"), nonce, "idp:a")["anchor"] == "idp:a"
    other = approvals.statement("example", [("memberships", {**rec[1], "group": "h"})], "idp:a")
    for bad, why in ((broker.token(other, "idp:a"), "another change"), (broker.token(nonce, "idp:b"), "someone else"),
                     (broker.token(nonce, "idp:a", aud="other"), "another client"),
                     (broker.token(nonce, "idp:a", iss="https://evil"), "another issuer"),
                     (broker.token(nonce, "idp:a", fresh=False), "fresh sign-in"),
                     (Broker("k1").token(nonce, "idp:a"), "does not verify")):
        with pytest.raises(guard.InputRejected, match=why):
            proofs(bad, nonce, "idp:a")


def test_keys_the_broker_published_once_still_verify_after_it_rotates(broker, tmp_path):
    p1 = approvals.BrokerProofs({ISS}, {AUD}, 300, "https://id.test/x", tmp_path / "keys.json", fetch=broker.jwks)
    nonce = approvals.statement("example", [], "idp:a")
    tok = broker.token(nonce, "idp:a")
    p1(tok, nonce, "idp:a")
    rotated = Broker("k2")
    p2 = approvals.BrokerProofs({ISS}, {AUD}, 300, "https://id.test/x", tmp_path / "keys.json", fetch=rotated.jwks)
    assert p2(tok, nonce, "idp:a")                                       # from the archive


# --- the reconciler ------------------------------------------------------------------------------------------------

def _args(tmp_path, rec_file):
    return types.SimpleNamespace(config=str(FIXTURES / "config.yaml"), records=str(rec_file), keycloak="http://localhost:1",
                                 realm="example", client="c", secret_file="x", reader_client=None, reader_secret_file=None,
                                 state=str(tmp_path / "state"), signing_key=None, allow_unsigned=True, trust=None,
                                 interval=60, once=True, apply=True, config_hash="t", approval_issuer=[ISS],
                                 approval_audience=[AUD])


def test_the_reconciler_refuses_an_approval_nobody_signed_and_accepts_pinned_and_proven_ones(tmp_path, proofs, broker, required):
    from tests.test_reconcile import Broker as Target, write
    doc = records.load(FIXTURES / "records.yaml")
    assert list(approvals.keys_in(doc))                                   # the fixture has approvals
    required()
    run = __import__("keyclerk.reconcile", fromlist=["x"]).run_once(_args(tmp_path, FIXTURES / "records.yaml"), None, Target(), proofs)
    assert not run["applied"] and "without a valid proof" in run["refused"]
    required(seed_allowlist(doc))                                         # pinned, record by record
    from keyclerk import reconcile as Rc
    assert Rc.run_once(_args(tmp_path, FIXTURES / "records.yaml"), None, Target(), proofs)["applied"]
    forged = copy.deepcopy(doc)                                           # the desk's key alone writes a second key
    m = next(x for x in forged["memberships"] if not x.get("approved_by"))
    m["approved_by"] = ["idp:55bb-eva"]
    run = Rc.run_once(_args(tmp_path, write(tmp_path, forged, "forged.yaml")), None, Target(), proofs)
    assert not run["applied"] and m["membership_id"] in run["refused"]
    nonce = approvals.statement(forged["realm"], [("memberships", m)], "idp:55bb-eva")
    forged["approval_proofs"] = [{"records": [m["membership_id"]], "by": "idp:55bb-eva", "token": broker.token(nonce, "idp:55bb-eva")}]
    assert Rc.run_once(_args(tmp_path, write(tmp_path, forged, "proven.yaml")), None, Target(), proofs)["applied"]


# --- the desk ------------------------------------------------------------------------------------------------------

@pytest.fixture
def desk(tmp_path, proofs):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    return Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"), proofs=proofs)


def test_through_the_desk_an_approval_is_a_fresh_sign_in_that_signs_the_change(desk, broker, proofs, required):
    policy = required()
    r = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    with pytest.raises(Refusal, match="your own signature"):
        desk.approve(BERT, r["change_id"])
    st = desk.statement(BERT, r["change_id"])
    with pytest.raises(Refusal, match="does not fit"):
        desk.approve(BERT, r["change_id"], broker.token(st["nonce"], "idp:55bb-eva"))      # someone else's proof
    done = desk.approve(BERT, r["change_id"], broker.token(st["nonce"], "idp:91d0-bert"))
    assert done["outcome"] == "applied"
    doc = desk.store.load()
    assert doc["approval_proofs"][0]["by"] == "idp:91d0-bert"
    policy["accepted_without_proof"] = seed_allowlist(records.load(FIXTURES / "records.yaml"))
    assert approvals.check(doc, proofs, policy) == []                     # what the reconciler will find


# --- history --------------------------------------------------------------------------------------------------------

def test_suspensions_and_proofs_keep_their_history():
    old = records.load(FIXTURES / "records.yaml")
    old["suspensions"] = [{"suspension_id": "S-1", "anchor": "idp:66cc-finn", "at": "2026-10-01T00:00:00Z", "by": "idp:2b9e-owner"}]
    old["approval_proofs"] = [{"records": ["M-1"], "by": "idp:a", "token": "t"}]
    new = copy.deepcopy(old)
    new["suspensions"][0]["lifted"] = {"at": "2026-10-02T00:00:00Z", "by": ["idp:a", "idp:b"]}
    assert records.guard(old, new) == []                                  # a lift is the one change allowed
    assert any("suspension dropped" in e for e in records.guard(old, {**new, "suspensions": []}))
    changed = copy.deepcopy(new)
    changed["suspensions"][0]["by"] = "idp:someone-else"
    assert any("suspension changed" in e for e in records.guard(old, changed))
    relift = copy.deepcopy(new)
    relift["suspensions"][0]["lifted"]["by"] = ["idp:c", "idp:d"]
    assert any("lift changed" in e for e in records.guard(new, relift))
    assert any("proof was dropped" in e for e in records.guard(old, {**new, "approval_proofs": []}))


def test_a_pinned_approval_holds_only_for_the_record_as_approved_and_ids_are_not_shared_across_kinds(proofs):
    doc = records.load(FIXTURES / "records.yaml")
    policy = {"proofs": "required", "accepted_without_proof": seed_allowlist(doc)}
    assert approvals.check(doc, proofs, policy) == []
    edited = copy.deepcopy(doc)
    m = next(x for x in edited["memberships"] if x.get("approved_by"))
    m["end"] = "2030-01-01T00:00:00Z"                                     # the pinned record made longer
    assert any("changed since it was approved" in e for e in approvals.check(edited, proofs, policy))
    clash = copy.deepcopy(doc)
    d = next(x for x in clash["delegations"] if x.get("approved_by")) if any(x.get("approved_by") for x in clash["delegations"])         else clash["delegations"][0]
    clash["suspensions"] = [{"suspension_id": d["delegation_id"], "anchor": "idp:66cc-finn", "at": "2026-10-01T00:00:00Z",
                             "by": "idp:2b9e-owner", "lifted": {"at": "2026-10-02T00:00:00Z", "by": ["idp:a", "idp:b"]}}]
    assert any("two kinds of record" in e for e in approvals.check(clash, proofs, policy))



# --- switching proofs on in a running deployment (found in a full-stack run) -------------------------------------------

def test_switching_proofs_on_names_the_pin_command_and_pinned_approvals_survive_an_end(tmp_path, proofs, required, capsys):
    """A deployment that switches proofs on has approvals made before them: the reconciler says how to keep them, the
    pin command prints the entries for review, and ending a pinned record (a separate revocation) keeps it pinned."""
    from tests.test_reconcile import Broker as Target, write
    from keyclerk import reconcile as Rc
    doc = records.load(FIXTURES / "records.yaml")
    required()
    run = Rc.run_once(_args(tmp_path, FIXTURES / "records.yaml"), None, Target(), proofs)
    assert not run["applied"] and "python -m keyclerk.approvals pin" in run["refused"]
    assert approvals.main(["pin", str(FIXTURES / "records.yaml")]) == 0
    out = capsys.readouterr().out
    printed = json.loads(out.split("\n", 1)[1])["accepted_without_proof"]
    assert printed == seed_allowlist(doc)
    required(printed)
    assert Rc.run_once(_args(tmp_path, FIXTURES / "records.yaml"), None, Target(), proofs)["applied"]
    ended = copy.deepcopy(doc)
    m = next(x for x in ended["memberships"] if x.get("approved_by"))
    ended.setdefault("admin_revocations", []).append({"id": m["membership_id"], "at": "2026-10-24T09:00:00Z",
                                                      "by": "idp:2b9e-owner", "mode": "retire", "reason": "ended for the test"})
    run = Rc.run_once(_args(tmp_path, write(tmp_path, ended, "ended.yaml")), None, Target(), proofs)
    assert "without a valid proof" not in str(run.get("refused"))


def test_the_signer_will_not_start_unchecked_when_proofs_are_required(tmp_path, monkeypatch):
    import yaml
    from keyclerk import signer
    monkeypatch.setattr(config, "_current", config._current)          # signer.main configures; restore it after
    cfg = yaml.safe_load((FIXTURES / "config.yaml").read_text(encoding="utf-8"))
    cfg["approvals"] = {**(cfg.get("approvals") or {}), "proofs": "required"}
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(cfg), encoding="utf-8")
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    with pytest.raises(SystemExit, match="no --approval-issuer"):
        signer.main(["--key", str(key), "--state", str(tmp_path / "state"), "--config", str(tmp_path / "config.yaml"),
                     "--listen", "tcp:127.0.0.1:0"])
