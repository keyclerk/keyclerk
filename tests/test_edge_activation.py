# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 point 2 (edge protocol 1.5): a node of a high-availability edge says how it became active. The desk
records the active node and raises an incident when it changes; a break-glass promotion must carry the site key's
promotion statement for this edge and this node, and is an incident in itself."""
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import edge_relay as R
from test_edge_api import EDGE_KEY, _bundle_with_ceiling, call, edge_server  # noqa: F401

NODE2 = Ed25519PrivateKey.from_private_bytes(b"n" * 32)
SITE = Ed25519PrivateKey.from_private_bytes(b"s" * 32)


def _two_nodes(desk, monkeypatch, site=True):
    k1 = desk.edge_keys_of("plant-a")[0]
    monkeypatch.setattr(desk, "edge_keys_of", lambda eid: [k1, E.public_hex(NODE2)])
    real = desk.store.load

    def load():
        doc = real()
        for e in doc.get("edges", []):
            if e["edge_id"] == "plant-a":
                e["node2"] = {"enrolment_key": E.public_hex(NODE2)}
                if site:
                    e["site_key"] = E.public_hex(SITE)
        return doc
    monkeypatch.setattr(desk.store, "load", load)
    return k1


def _report(base, key, activation):
    body = {"applied_serial": 1, "attestation": {"profile": "basic"}, "drift": [], "activation": activation}
    raw = json.dumps(body).encode()
    return call(base, "POST", "/edge/report", body,
                header=E.sign_request(key, "plant-a", "POST", "/api/v1/edge/report", raw))


def _kinds(desk):
    return [i["kind"] for i in desk.edge_store.incidents("plant-a")]


def _promotion(node_key, edge="plant-a", purpose="promotion", at=None, hours=None):
    """A site statement the site key and the node sign; a promotion (kc-edge-site-v2, edge protocol 1.6) is valid for a
    day from now unless at and hours say otherwise."""
    at = at or datetime.now(timezone.utc) - timedelta(minutes=1)
    st = R.site_statement(purpose, edge, E.public_hex(SITE), E.public_hex(node_key), at,
                          "node 1 burned out, no witness on site", at + timedelta(hours=hours) if hours else None)
    fmt = R.site_format(purpose)
    return E.cosign(node_key, E.cosign(SITE, st, fmt), fmt)


def test_the_active_node_is_on_record_and_a_change_is_an_incident(edge_server, monkeypatch):
    base, desk = edge_server
    _bundle_with_ceiling(base)
    k1 = _two_nodes(desk, monkeypatch)
    assert _report(base, EDGE_KEY, {"by": "witness", "at": "2026-11-04T08:00:00Z"})[0] == 200
    assert desk.edge_store.state("plant-a")["active_node"] == E.key_id(k1) and "node_promoted" not in _kinds(desk)
    assert _report(base, NODE2, {"by": "local_witness", "at": "2026-11-04T08:30:00Z"})[0] == 200
    assert desk.edge_store.state("plant-a")["active_node"] == E.key_id(E.public_hex(NODE2))
    assert "node_promoted" in _kinds(desk)


def test_a_break_glass_promotion_is_verified_and_an_incident(edge_server, monkeypatch):
    base, desk = edge_server
    _bundle_with_ceiling(base)
    _two_nodes(desk, monkeypatch)
    now = E._iso(datetime.now(timezone.utc))
    code, out = _report(base, NODE2, {"by": "break_glass", "at": now, "statement": _promotion(NODE2)})
    assert code == 200, out
    assert "break_glass_promotion" in _kinds(desk)
    seen = desk.edge_store.state("plant-a")["nodes"][E.key_id(E.public_hex(NODE2))]["activation"]
    assert seen["by"] == "break_glass" and "burned out" in seen["reason"]


def test_a_promotion_that_does_not_verify_is_refused(edge_server, monkeypatch):
    base, desk = edge_server
    _bundle_with_ceiling(base)
    _two_nodes(desk, monkeypatch)
    at = "2026-11-04T09:05:00Z"
    for bad in (_promotion(EDGE_KEY),                                    # promotes the other node
                _promotion(NODE2, edge="plant-b"),                        # another edge
                _promotion(NODE2, purpose="provisional")):                # another purpose
        assert _report(base, NODE2, {"by": "break_glass", "at": at, "statement": bad})[0] == 400
    assert _report(base, NODE2, {"by": "break_glass", "at": at})[0] == 400             # no statement
    assert _report(base, NODE2, {"by": "witness", "at": at, "statement": _promotion(NODE2)})[0] == 400
    assert _report(base, NODE2, {"by": "timer", "at": at})[0] == 400                  # never on its own timer
    assert "break_glass_promotion" not in _kinds(desk)


def test_without_a_site_key_a_break_glass_promotion_cannot_be_accepted(edge_server, monkeypatch):
    base, desk = edge_server
    _bundle_with_ceiling(base)
    _two_nodes(desk, monkeypatch, site=False)
    code, out = _report(base, NODE2, {"by": "break_glass", "at": "2026-11-04T09:05:00Z", "statement": _promotion(NODE2)})
    assert code >= 400 and "site key" in out["error"]["message"]


def test_an_expired_or_replayed_promotion_is_refused(edge_server, monkeypatch):
    """Edge protocol 1.6: a promotion statement expires, and promotes a node once. A spare promoted, repaired back and
    promoted again needs a fresh statement each time."""
    base, desk = edge_server
    _bundle_with_ceiling(base)
    _two_nodes(desk, monkeypatch)
    old = datetime.now(timezone.utc) - timedelta(hours=30)
    code, out = _report(base, NODE2, {"by": "break_glass", "at": "2026-11-04T09:05:00Z",
                                      "statement": _promotion(NODE2, at=old, hours=24)})
    assert code == 400 and "expired" in json.dumps(out)
    iso = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")                                   # noqa: E731
    now = datetime.now(timezone.utc)
    first = _promotion(NODE2, at=now - timedelta(minutes=10))                          # signed, then acted on
    promoted = iso(now - timedelta(minutes=5))
    assert _report(base, NODE2, {"by": "break_glass", "at": promoted, "statement": first})[0] == 200
    assert _report(base, NODE2, {"by": "break_glass", "at": promoted, "statement": first})[0] == 200   # the same, again
    later = iso(now)
    code, out = _report(base, NODE2, {"by": "break_glass", "at": later, "statement": first})
    assert code == 400 and "fresh statement" in json.dumps(out)              # a new activation, the old statement


def test_an_activation_lies_inside_its_promotion_statement(edge_server, monkeypatch):
    """0.29 review S10: the activation time is bound to the statement, from its at to its not_after, so a statement
    signed for one promotion cannot be presented for an activation from before it was signed (one after it lapsed is
    refused as expired, one in the future as such)."""
    base, desk = edge_server
    _bundle_with_ceiling(base)
    _two_nodes(desk, monkeypatch)
    now = datetime.now(timezone.utc)
    st = _promotion(NODE2, at=now - timedelta(minutes=10), hours=1)                 # live until 50 minutes from now
    code, out = _report(base, NODE2, {"by": "break_glass", "at": E._iso(now - timedelta(hours=1)), "statement": st})
    assert code == 400 and "outside its promotion statement" in json.dumps(out), out
    assert _report(base, NODE2, {"by": "break_glass", "at": E._iso(now), "statement": st})[0] == 200
