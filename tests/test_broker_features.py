# SPDX-License-Identifier: EUPL-1.2
"""What the broker offers, used: back-channel logout ends sessions at once, DPoP binds a bearer token to its client's
key, approvals carry the authentication level a passkey gives, phone links are short-lived and signed, a writer
without user management does not log out, and manual changes are attributed from the broker's admin events."""
import base64
import hashlib
import json
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import approvals, dpop, guard
from keyclerk.connectors.keycloak import KeycloakTarget
from keyclerk.desk import Desk, Store
from keyclerk.oidc import BACKCHANNEL_EVENT, Oidc
from tests.test_approvals import AUD, ISS, Broker

B64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()   # noqa: E731
FIXTURES = Path(__file__).resolve().parent / "fixtures"


# --- back-channel logout ---------------------------------------------------------------------------------------------

@pytest.fixture
def oidc():
    b = Broker()
    o = Oidc(public_issuer=ISS, internal_issuer=ISS, client_id=AUD, redirect_uri="https://desk.test/callback",
             viewer_role="keyclerk-viewer")
    o.jwks, o.jwks_at = {k["kid"]: k for k in b.jwks()["keys"]}, time.time()
    o.broker = b
    return o


def logout_token(o, aud=AUD, **over):
    now = int(time.time())
    claims = {"iss": ISS, "aud": aud, "iat": now, "jti": str(uuid.uuid4()), "sub": "s-ann", "sid": "sid-1",
              "events": {BACKCHANNEL_EVENT: {}}, **over}
    return o.broker.sign(claims)


def test_the_broker_ends_a_desk_session_at_once_and_a_replay_or_a_stranger_cannot(oidc):
    cookie = oidc.session({"sub": "s-ann", "sid": "sid-1", "anchor": "idp:7c1f-ann", "roles": []})
    other = oidc.session({"sub": "s-eva", "sid": "sid-2", "anchor": "idp:55bb-eva", "roles": []})
    assert oidc.who(cookie)
    tok = logout_token(oidc)
    oidc.backchannel(tok)
    assert oidc.who(cookie) is None and oidc.who(other)                   # only that person's session ends
    with pytest.raises(guard.InputRejected, match="replayed"):
        oidc.backchannel(tok)
    for bad, why in ((logout_token(oidc, aud="other"), "another client"), (logout_token(oidc, nonce="x"), "not a logout"),
                     (logout_token(oidc, events={}), "not a logout"),
                     (logout_token(oidc, iat=int(time.time()) - 3600), "too old"),
                     (Broker().sign({"iss": ISS}), "does not verify")):
        with pytest.raises(guard.InputRejected, match=why):
            oidc.backchannel(bad)
    time.sleep(0.01)
    later = oidc.session({"sub": "s-ann", "sid": "sid-3", "anchor": "idp:7c1f-ann", "roles": []})
    assert oidc.who(later)                                                # signing in again afterwards works


# --- DPoP -------------------------------------------------------------------------------------------------------------

def _ec_jwk(key):
    n = key.public_key().public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": B64(n.x.to_bytes(32, "big")), "y": B64(n.y.to_bytes(32, "big"))}


def proof(key, method, url, token, **over):
    h = B64(json.dumps({"typ": "dpop+jwt", "alg": "ES256", "jwk": _ec_jwk(key)}).encode())
    claims = {"htm": method, "htu": url, "iat": int(time.time()), "jti": str(uuid.uuid4()),
              "ath": B64(hashlib.sha256(token.encode()).digest()), **over}
    p = B64(json.dumps(claims).encode())
    r, s = decode_dss_signature(key.sign(f"{h}.{p}".encode(), ec.ECDSA(hashes.SHA256())))
    return f"{h}.{p}.{B64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def test_a_dpop_bound_token_works_only_with_its_key_for_this_request_once():
    key, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    jkt, url, tok = dpop.thumbprint(_ec_jwk(key)), "https://desk.test/api/v1/me", "access-token"
    good = proof(key, "GET", url, tok)
    dpop.check(good, "GET", url, tok, jkt)
    for bad, why in ((good, "used before"), (proof(other, "GET", url, tok), "not the token's"),
                     (proof(key, "POST", url, tok), "another request"), (proof(key, "GET", url + "x", tok), "another request"),
                     (proof(key, "GET", url, "other-token"), "another token"),
                     (proof(key, "GET", url, tok, iat=int(time.time()) - 600), "not fresh")):
        with pytest.raises(guard.InputRejected, match=why):
            dpop.check(bad, "GET", url, tok, jkt)
    with pytest.raises(guard.InputRejected, match="not bound"):
        dpop.check(proof(key, "GET", url, tok), "GET", url, tok, None)


# --- the approval level -------------------------------------------------------------------------------------------

def test_a_proof_must_carry_the_approval_level_when_the_deployment_asks_for_one(tmp_path):
    b = Broker()
    p = approvals.BrokerProofs({ISS}, {AUD}, 300, "https://id.test/x", tmp_path / "k.json", fetch=b.jwks, acr="approval")
    nonce = approvals.statement("example", [], "idp:a")
    with pytest.raises(guard.InputRejected, match="authentication level"):
        p(b.token(nonce, "idp:a"), nonce, "idp:a")                       # a password sign-in: no passkey level
    with pytest.raises(guard.InputRejected, match="authentication level"):
        p(b.token(nonce, "idp:a", acr="1"), nonce, "idp:a")
    assert p(b.token(nonce, "idp:a", acr="approval"), nonce, "idp:a")


# --- phone links --------------------------------------------------------------------------------------------------

def test_a_phone_link_is_short_lived_signed_and_names_one_approver(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    desk = Desk(Store(tmp_path / "s", key, FIXTURES / "records.yaml"), public_base="https://desk.test")
    r = desk.propose({"anchor": "idp:7c1f-ann", "roles": []},
                     {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    link = desk.phone_link({"anchor": "idp:91d0-bert", "roles": []}, r["change_id"])
    assert link["url"].startswith("https://desk.test/approve/") and link["qr"].startswith("/approve-qr/")
    q = {k: v[0] for k, v in parse_qs(urlparse(link["url"]).query).items()}
    assert desk.phone_link_valid(r["change_id"], q["for"], q["exp"], q["sig"])
    assert not desk.phone_link_valid(r["change_id"], "idp:55bb-eva", q["exp"], q["sig"])      # another approver
    assert not desk.phone_link_valid(r["change_id"], q["for"], str(int(q["exp"]) + 999), q["sig"])
    past = int(time.time()) - 1
    assert not desk.phone_link_valid(r["change_id"], q["for"], str(past), desk._link_sig(r["change_id"], q["for"], past))


# --- the writer without user management, and attribution -----------------------------------------------------------

def test_a_writer_without_user_management_does_not_log_out_and_manual_adds_are_attributed():
    t = KeycloakTarget(realm="example", keycloak="http://localhost:1", logout_on_removal=False)
    t.logout = lambda uid: (_ for _ in ()).throw(AssertionError("must not log out"))
    t.admin_token = "x"
    t.on_removed({"id": str(uuid.uuid4())})
    uid, gid = str(uuid.uuid4()), str(uuid.uuid4())
    t._ids, t._anchors = {("/groups/finance", uid): gid}, {("/groups/finance", "idp:x"): uid}
    calls = []

    def admin(path, params=None, **k):
        calls.append((path, params))
        if path == "/admin-events":
            return [{"time": 1, "authDetails": {"userId": "a1b2c3d4-0000-4000-8000-000000000000", "clientId": "admin-cli",
                                                "ipAddress": "10.0.0.9"}}]
        return {"username": "mallory"}
    t._admin = admin
    by = t.who_added("/groups/finance", "idp:x")
    assert by["by_name"] == "mallory" and by["by_client"] == "admin-cli"
    assert calls[0][1]["resourcePath"] == f"users/{uid}/groups/{gid}"
    t.attributions_left = 0
    assert t.who_added("/groups/finance", "idp:x") is None                # bounded per run
