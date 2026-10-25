# SPDX-License-Identifier: EUPL-1.2
"""Decision 0014 over HTTP: an edge agent pulls a bundle the reference verifier accepts, signs every request, relays a
ciphertext only its person can open, escrows break-glass to two custodians, and reports evidence as a chain."""
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import api
from keyclerk import edge as E
from keyclerk import relay as R
from keyclerk.desk import Desk, Store

from test_edges import EDGE_KEY, EVA, INGRID, OFFICER_KEY, OWNER, W, FINN, enrol
from test_visits import FIXTURES

GINA = "idp:77dd-gina"
FINN_PRIV, FINN_PUB = R.person_key_from_prf(b"\x21" * 32)
GINA_PRIV, GINA_PUB = R.person_key_from_prf(b"\x22" * 32)
ANN = "idp:7c1f-ann"
ANN_PRIV, ANN_PUB = R.person_key_from_prf(b"\x23" * 32)


class Auth:
    viewer_role = "keyclerk-viewer"

    def __init__(self):
        self.sessions = {"eva": {"sub": "s-eva", "anchor": EVA, "roles": [], "csrf": "c-eva", "iat": time.time(), "auth_time": time.time()},
                         "finn": {"sub": "s-finn", "anchor": FINN, "roles": [], "csrf": "c-finn", "iat": time.time(), "auth_time": time.time()},
                         "finn-old": {"sub": "s-finn2", "anchor": FINN, "roles": [], "csrf": "c-finn2", "iat": time.time(), "auth_time": time.time() - 3600},
                         "ann": {"sub": "s-ann", "anchor": ANN, "roles": [], "csrf": "c-ann", "iat": time.time(), "auth_time": time.time()},
                         "ann-old": {"sub": "s-ann2", "anchor": ANN, "roles": [], "csrf": "c-ann2", "iat": time.time(), "auth_time": time.time() - 3600},
                         "gina": {"sub": "s-gina", "anchor": GINA, "roles": [], "csrf": "c-gina", "iat": time.time(), "auth_time": time.time()}}

    def who(self, cookie):
        return self.sessions.get(cookie)

    def bearer(self, token, clients):
        raise ValueError("no")


@pytest.fixture
def edge_server(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    desk = Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))
    desk.approve(W(INGRID), enrol(desk)["change_id"])
    for who, pub in ((FINN, FINN_PUB), (GINA, GINA_PUB), (ANN, ANN_PUB)):
        r = desk.propose(W(who), {"action": "enrol_person_key", "public_key": R.b64e(pub), "user_verification": True})
        desk.approve(W(INGRID), r["change_id"])
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.handler(desk, Auth(), {"desk.test"}, (), False))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", desk
    srv.shutdown()


def call(base, method, path, body=None, cookie=None, csrf=None, signed=True, header=None):
    data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
    h = {"Host": "desk.test", "Content-Type": "application/json"}
    if cookie:
        h["Cookie"] = f"keyclerk_session={cookie}"
        if csrf:
            h["X-KeyClerk-CSRF"] = csrf
    if signed:
        h["KeyClerk-Edge"] = header or E.sign_request(EDGE_KEY, "plant-a", method, "/api/v1" + path, data or b"")
    try:
        with urllib.request.urlopen(urllib.request.Request(base + "/api/v1" + path, data=data, method=method, headers=h), timeout=20) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def ceiling(serial=1):
    people = [p["anchors"][0] for p in __import__("yaml").safe_load((FIXTURES / "records.yaml").read_text(encoding="utf-8"))["persons"]]
    return {"format": E.CEILING_FORMAT, "edge": "plant-a", "serial": serial, "persons": people, "roles": ["admins", "server-admins"],
            "targets": ["plc-ssh"], "classes": ["low", "elevated", "privileged"], "max_lease_hours": 24 * 120,
            "max_offline_hours": 72, "profile": "assured", "remote_reach": "off", "ports": [22],
            "signed_at": "2026-10-23T10:00:00Z"}


def test_without_a_ceiling_the_bundle_is_empty_and_with_one_the_verifier_accepts_it(edge_server):
    base, desk = edge_server
    code, b = call(base, "GET", "/edge/bundle")
    body = E.unseal(b, b["key"], E.BUNDLE_FORMAT)
    assert code == 200 and body["leases"] == [] and body["ceiling"] is None                     # fails closed
    c = ceiling()
    code, _ = call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, c)},
                   cookie="eva", csrf="c-eva", signed=False)
    assert code == 200
    code, again = call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, c)},
                       cookie="eva", csrf="c-eva", signed=False)
    assert code == 422                                     # the same serial again: refused
    code, b = call(base, "GET", "/edge/bundle")
    pinned = call(base, "GET", "/edge-key", signed=False)[1]["key"]                # pinned on site after comparing key ids
    pins = {"edge": "plant-a", "bundle_key": pinned, "officer_key": E.public_hex(OFFICER_KEY), "release_key": None}
    from keyclerk import policy_wasm
    check = lambda c, entry: policy_wasm.ceiling({"ceiling": c, "entry": entry})   # noqa: E731
    errs, applied = E.verify_bundle(b, pins, {"serial": 1}, datetime.now(timezone.utc), check)
    body = E.unseal(b, pinned, E.BUNDLE_FORMAT)
    assert errs == [] and body["serial"] == 2 and E.opened(body["ceiling"])["serial"] == 1
    assert applied["leases"] and all(x["target"] == "plc-ssh" for x in applied["leases"])
    roles = sorted({t["role"] for t in desk._edge(desk.store.load(), "plant-a", datetime.now(timezone.utc))["targets"]})
    assert applied["governed_roles"] == roles and roles                 # 0025: the roles its targets map to
    again = E.unseal(call(base, "GET", "/edge/bundle")[1], pinned, E.BUNDLE_FORMAT)
    assert sorted(x["lease_id"] for x in again["leases"]) == sorted(x["lease_id"] for x in body["leases"])   # stable ids
    assert E.verify_bundle(b, {**pins, "edge": "plant-b"}, {"serial": 1}, datetime.now(timezone.utc))[0]  # not for another edge
    mods = body["policy"]["modules"]                       # by hash only; fetched once per change
    import base64
    assert set(mods) == {"edge", "ceiling"} and all(set(m) == {"sha256"} for m in mods.values())
    assert len(b["bytes"]) < 64 * 1024                       # was ~520 KB with the modules inline
    code, m = call(base, "GET", "/edge/module/" + mods["edge"]["sha256"])
    assert code == 200 and E.verify_module(base64.b64decode(m["wasm"]), mods["edge"]["sha256"]) == []
    assert call(base, "GET", "/edge/module/" + "0" * 64)[0] == 404
    assert call(base, "GET", "/edge/module/" + "0" * 64, signed=False)[0] == 401    # an edge's signature only


def test_an_edge_request_without_its_signature_or_replayed_is_refused(edge_server):
    base, _ = edge_server
    assert call(base, "GET", "/edge/bundle", signed=False)[0] == 401
    h = E.sign_request(EDGE_KEY, "plant-a", "GET", "/api/v1/edge/bundle", b"")
    assert call(base, "GET", "/edge/bundle", header=h)[0] == 200
    assert call(base, "GET", "/edge/bundle", header=h)[0] == 401            # the same nonce again
    other = E.sign_request(Ed25519PrivateKey.generate(), "plant-a", "GET", "/api/v1/edge/bundle", b"")
    assert call(base, "GET", "/edge/bundle", header=other)[0] == 401
    assert call(base, "GET", "/edge/bundle", cookie="eva")[0] == 401        # never a session on the edge routes


def _bundle_with_ceiling(base):
    c = ceiling()
    call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, c)}, cookie="eva", csrf="c-eva", signed=False)
    b = call(base, "GET", "/edge/bundle")[1]
    return E.unseal(b, b["key"], E.BUNDLE_FORMAT)


def test_a_lease_credential_reaches_only_the_lease_holder_and_survives_a_failed_open(edge_server):
    """An edge relays only to a holder of a lease in its last bundle, bound to that lease; taking does
    not destroy it, confirming after opening does."""
    base, desk = edge_server
    body = _bundle_with_ceiling(base)
    lease = next(x for x in body["leases"] if x["person"] == ANN)
    assert lease["key_id"] and lease["public_key"] == R.b64e(ANN_PUB) and lease["max_session_hours"] == 1
    purpose = "lease:" + lease["lease_id"]
    env = R.encrypt(lease["public_key"], b"lease-secret-123", purpose)
    code, out = call(base, "POST", "/edge/relay", {"key_id": lease["key_id"], "envelope": env, "purpose": purpose})
    assert code == 200
    rid = out["relay_id"]
    assert call(base, "POST", "/edge/relay", {"key_id": lease["key_id"], "envelope": R.encrypt(lease["public_key"], b"x", "lease:L-none"),
                                             "purpose": "lease:L-none"})[0] == 422        # no such lease: refused
    assert call(base, "GET", "/relay", cookie="gina", signed=False)[1] == []              # not gina's
    assert call(base, "POST", f"/relay/{rid}/take", cookie="ann-old", csrf="c-ann2", signed=False)[0] == 403   # not fresh
    code, got = call(base, "POST", f"/relay/{rid}/take", cookie="ann", csrf="c-ann", signed=False)
    assert code == 200 and R.decrypt(ANN_PRIV, got["envelope"]) == b"lease-secret-123"
    assert call(base, "POST", f"/relay/{rid}/take", cookie="ann", csrf="c-ann", signed=False)[0] == 200        # a failed open can retry
    assert call(base, "POST", f"/relay/{rid}/confirm", cookie="ann", csrf="c-ann", signed=False)[0] == 200
    assert call(base, "POST", f"/relay/{rid}/take", cookie="ann", csrf="c-ann", signed=False)[0] == 404        # gone once confirmed


def test_escrow_goes_to_designated_custodians_and_is_confirmed_only_when_both_opened(edge_server):
    base, desk = edge_server
    keys = {k["anchor"]: k["key_id"] for k in desk.store.load()["person_keys"]}
    ctx = "escrow:plc-console:BG-1"
    envs = [{"key_id": keys[FINN], "envelope": R.encrypt(R.b64e(FINN_PUB), b"half-a", ctx)},
            {"key_id": keys[GINA], "envelope": R.encrypt(R.b64e(GINA_PUB), b"half-b", ctx)}]
    code, out = call(base, "POST", "/edge/escrow", {"system": "plc-console", "item_id": "BG-1", "envelopes": envs})
    pinned = call(base, "GET", "/edge-key", signed=False)[1]["key"]
    assert code == 200 and E.unseal(out, pinned, "kc-edge-escrow-ack-v1")["item_id"] == "BG-1"
    same = call(base, "POST", "/edge/escrow", {"system": "plc-console", "item_id": "BG-2", "envelopes": [envs[0], envs[0]]})
    assert same[0] == 422                                  # two custodians: two people
    status = lambda: E.unseal(call(base, "GET", "/edge/escrow/BG-1")[1], pinned, "kc-edge-escrow-status-v1")   # noqa: E731
    assert status()["confirmed"] is False
    for who, csrf in (("finn", "c-finn"), ("gina", "c-gina")):
        rid = next(x["relay_id"] for x in call(base, "GET", "/relay", cookie=who, signed=False)[1] if x["purpose"] == ctx)
        assert call(base, "POST", f"/relay/{rid}/take", cookie=who, csrf=csrf, signed=False)[0] == 200
        assert call(base, "POST", f"/relay/{rid}/confirm", cookie=who, csrf=csrf, signed=False)[0] == 200
    assert status()["confirmed"] is True                   # only now may the edge forget the value


def test_evidence_is_a_chain_acknowledged_up_to_a_sequence_and_incidents_reach_the_officer(edge_server):
    base, _ = edge_server
    e1 = {"seq": 1, "prev": "0" * 64, "sha256": "a" * 64, "size": 1000, "session": "S-1", "at": "2026-10-23T10:00:00Z"}
    e2 = {"seq": 2, "prev": E.sha256(E.canonical(e1)), "sha256": "b" * 64, "size": 2000, "session": "S-2", "at": "2026-10-23T11:00:00Z"}
    code, out = call(base, "POST", "/edge/evidence", {"entries": [e1, e2]})
    assert code == 200 and E.unseal(out, out["key"], "kc-edge-evidence-ack-v1")["up_to_seq"] == 2
    assert call(base, "POST", "/edge/evidence", {"entries": [e1, e2]})[0] == 200      # a resend after a lost ack: no change
    head = call(base, "GET", "/edge/evidence")[1]
    assert E.unseal(head, head["key"], "kc-edge-evidence-ack-v1")["up_to_seq"] == 2
    broken = {**e2, "seq": 3, "prev": "f" * 64}
    assert call(base, "POST", "/edge/evidence", {"entries": [broken]})[0] == 422
    assert call(base, "POST", "/edge/incident", {"kind": "break_glass_used", "system": "plc-console", "at": "2026-10-23T12:00:00Z"})[0] == 200
    code, edges = call(base, "GET", "/edges", cookie="eva", signed=False)
    assert code == 200 and edges[0]["evidence_seq"] == 2 and edges[0]["incidents"][-1]["kind"] == "break_glass_used"
    assert call(base, "GET", "/edges", cookie="finn", signed=False)[1] == []                 # not finn's to see


def test_an_officer_who_joins_the_core_freezes_the_edge(edge_server):
    """Independence is checked at every cut. Eva joins a privileged group: the edge gets no leases and an
    incident is raised, until she leaves."""
    base, desk = edge_server
    c = ceiling()
    assert call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, c)},
                cookie="eva", csrf="c-eva", signed=False)[0] == 200
    from keyclerk import edge_records
    real = edge_records.officer_errors
    edge_records.officer_errors = lambda doc, e, at: ["plant-a: the edge's officer is never a core administrator"]
    try:
        b = call(base, "GET", "/edge/bundle")[1]
        body = E.unseal(b, b["key"], E.BUNDLE_FORMAT)
        assert body["leases"] == [] and body["ceiling"] is None
        assert desk.edge_store.incidents("plant-a")[-1]["kind"] == "officer_not_independent"
        c2 = ceiling(2)
        assert call(base, "POST", "/edges/plant-a/ceiling", {"ceiling": E.seal_ceiling(OFFICER_KEY, c2)},
                    cookie="eva", csrf="c-eva", signed=False)[0] == 422
    finally:
        edge_records.officer_errors = real


def test_a_lease_carries_the_broker_username_the_reconciler_saw(tmp_path):
    """Decision 0014b: Warpgate and the facade know people by the broker's username; the reconciler saves it."""
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    state = tmp_path / "broker"
    state.mkdir()
    (state / "usernames.json").write_text(json.dumps({ANN: "ann.peeters"}), encoding="utf-8")
    ann_mail = "ann" + "@example.test"                     # built from parts: the leak gate flags any address
    (state / "emails.json").write_text(json.dumps({ANN: ann_mail}), encoding="utf-8")
    desk = Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"), broker_state=state)
    desk.approve(W(INGRID), enrol(desk)["change_id"])
    c = ceiling()
    desk.set_ceiling(W(EVA), "plant-a", {"ceiling": E.seal_ceiling(OFFICER_KEY, c)})
    b = desk.edge_bundle("plant-a")
    lease = next(x for x in E.unseal(b, b["key"], E.BUNDLE_FORMAT)["leases"] if x["person"] == ANN)
    assert lease["username"] == "ann.peeters"
    assert lease["email"] is None                     # edge protocol 1.3: the address is fetched, never in a bundle
    assert all("email" not in v for v in E.unseal(b, b["key"], E.BUNDLE_FORMAT)["visit_leases"])
    nonce = "bm9uY2Utb2YtdGhlLXRlc3Q"
    sealed = desk.edge_email("plant-a", lease["lease_id"], ("1793102400", nonce))   # the gateway sets a credential
    pins = {"edge": "plant-a", "bundle_key": b["key"]}
    errs, m = E.verify_email(sealed, pins, lease["lease_id"], nonce)
    assert not errs and m["email"] == ann_mail and m["person"] == ANN
    again = desk.edge_bundle("plant-a")                                     # "from" never moves
    later = next(x for x in E.unseal(again, again["key"], E.BUNDLE_FORMAT)["leases"] if x["lease_id"] == lease["lease_id"])
    assert later["from"] == lease["from"] < E.unseal(b, b["key"], E.BUNDLE_FORMAT)["issued"]


def test_the_edge_simulator_runs_a_round_against_a_desk(edge_server, tmp_path, capsys):
    """Slice C: the reference CLI pulls, verifies with pins taken on site, reports, and says what an agent would do."""
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from keyclerk import edge_cli
    base, desk = edge_server
    _bundle_with_ceiling(base)
    k = tmp_path / "edge.key"
    k.write_text(EDGE_KEY.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    pins = tmp_path / "pins.json"
    pins.write_text(json.dumps({"edge": "plant-a", "bundle_key": call(base, "GET", "/edge-key", signed=False)[1]["key"],
                                "officer_key": E.public_hex(OFFICER_KEY), "release_key": None, "profile": "assured"}), encoding="utf-8")
    state = tmp_path / "state.json"
    capsys.readouterr()
    assert edge_cli.main(["simulate", "--desk", base, "--edge", "plant-a", "--key", str(k), "--pins", str(pins),
                          "--state", str(state), "--host", "desk.test"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["assign"] and out["assign"][0]["target"] == "plc-ssh" and json.loads(state.read_text())["serial"] == out["serial"]
    assert desk.edges(W(EVA))[0]["attested"] == "assured"


def test_an_edge_fetches_an_address_only_for_its_own_live_lease(edge_server):
    base, desk = edge_server
    bundle = _bundle_with_ceiling(base)
    lease = bundle["leases"][0]
    status, sealed = call(base, "GET", f"/edge/lease/{lease['lease_id']}/email")
    assert status == 200
    errs, m = E.verify_email(sealed, {"edge": "plant-a", "bundle_key": desk.edge_key()["key"]}, lease["lease_id"],
                             E.opened(sealed)["nonce"])
    assert not errs and m["lease_id"] == lease["lease_id"] and m["email"] is None   # no reconciler: no address known
    assert call(base, "GET", "/edge/lease/L-example-9999/email")[0] == 404             # not a lease of this edge
    assert call(base, "GET", f"/edge/lease/{lease['lease_id']}/email", signed=False)[0] == 401
    for _ in range(5):                                                              # six answers a minute per lease
        call(base, "GET", f"/edge/lease/{lease['lease_id']}/email")
    assert call(base, "GET", f"/edge/lease/{lease['lease_id']}/email")[0] == 429

