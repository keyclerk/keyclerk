# SPDX-License-Identifier: EUPL-1.2
"""Decision 0027 (edge protocol 1.5): a relay tightens with a key the officer certified, and never grants. The edge
checks the chain from its pinned officer key through the certificate to the tightening, and applies only what narrows
its state; the site key's statements serve one purpose each."""
from datetime import datetime, timedelta, timezone

import pytest

from keyclerk import edge as E
from keyclerk import edge_relay as R

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
OFFICER, RELAY, OTHER = (E.Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in (7, 8, 9))
SITE, NODE = (E.Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32) for n in (10, 11))
PINS = {"edge": "edge-a", "officer_key": E.public_hex(OFFICER)}
STATE = {"serial": 12, "newest": "2026-11-05T11:00:00Z", "relay_counters": {}}
APPLIED = {"leases": [{"lease_id": "L-1", "until": "2026-11-05T18:00:00Z"}],
           "visit_leases": [{"lease_id": "V-1", "until": "2026-11-06T09:00:00Z"}]}
RELEASE = {"serial": 5, "floor": 3}


def _cert(ops=R.OPERATIONS, edges=("edge-a", "edge-b"), days=7, key=OFFICER, relay=RELAY):
    c = R.relay_certificate(E.public_hex(key), E.public_hex(relay), list(edges), list(ops), 1,
                            NOW - timedelta(hours=1), NOW - timedelta(hours=1) + timedelta(days=days))
    return E.cosign(key, c, R.RELAY_FORMAT)


def _tighten(cert, ops, counter=1, parent=12, edge="edge-a", key=RELAY, at=NOW):
    return E.seal(key, R.tightening(cert, edge, parent, counter, ops, at), R.TIGHTEN_FORMAT)


def _check(cert, t, state=STATE, now=NOW):
    return R.verify_tighten(cert, t, PINS, state, APPLIED, now, RELEASE)


def test_a_certified_relay_narrows_the_edge():
    c = _cert()
    ops = [{"op": "revoke_lease", "lease_id": "L-1"}, {"op": "end_lease", "lease_id": "V-1", "until": "2026-11-05T13:00:00Z"},
           {"op": "cut_sessions", "lease_id": "*"}, {"op": "suspend_edge"}, {"op": "rollback_release", "serial": 4},
           {"op": "hold_release"}]
    errs, eff = _check(c, _tighten(c, ops))
    assert errs == [] and eff["revoked"] == ["L-1"] and eff["ends"] == {"V-1": "2026-11-05T13:00:00Z"}
    assert eff["suspended"] and eff["hold_release"] and eff["rollback_release"] == 4 and eff["cut_sessions"] == ["*"]
    assert eff["state"]["relay_counters"] == {E.public_hex(RELAY): 1} and eff["lapses"] == E.opened(c)["expires"]


@pytest.mark.parametrize("op, why", [
    ({"op": "end_lease", "lease_id": "L-1", "until": "2026-11-06T00:00:00Z"}, "only ends it earlier"),
    ({"op": "revoke_lease", "lease_id": "L-9"}, "no lease this edge holds"),
    ({"op": "rollback_release", "serial": 2}, "floor"),
    ({"op": "rollback_release", "serial": 5}, "not below the current"),
    ({"op": "grant_lease", "lease_id": "L-1"}, "does not allow"),
    ({"op": "suspend_edge", "until": "2026-11-06T00:00:00Z"}, "takes nothing"),
])
def test_anything_that_would_widen_or_is_not_an_operation_is_refused(op, why):
    c = _cert()
    errs, eff = _check(c, _tighten(c, [op]))
    assert eff == {} and any(why in e for e in errs), errs


def test_a_tightening_is_refused_whole_when_one_operation_widens():
    c = _cert()
    errs, eff = _check(c, _tighten(c, [{"op": "revoke_lease", "lease_id": "L-1"},
                                       {"op": "end_lease", "lease_id": "L-1", "until": "2026-11-07T00:00:00Z"}]))
    assert errs and eff == {}


def test_the_chain_from_the_pinned_officer_is_checked():
    t_ok = [{"op": "revoke_lease", "lease_id": "L-1"}]
    other = _cert(key=OTHER)                                            # not the pinned officer
    assert _check(other, _tighten(other, t_ok))[0]
    c = _cert()
    assert _check(c, _tighten(c, t_ok, key=OTHER))[0]                   # not the certified relay key
    assert any("another certificate" in e for e in _check(c, _tighten(_cert(days=8), t_ok))[0])
    narrow = _cert(ops=["revoke_lease"])
    assert any("does not allow" in e for e in _check(narrow, _tighten(narrow, [{"op": "suspend_edge"}]))[0])
    elsewhere = _cert(edges=["edge-b"])
    assert any("does not name this edge" in e for e in _check(elsewhere, _tighten(elsewhere, t_ok))[0])
    assert any("another edge" in e for e in _check(c, _tighten(c, t_ok, edge="edge-b"))[0])


def test_a_newer_parent_bundle_supersedes_and_a_counter_never_repeats():
    c, ops = _cert(), [{"op": "revoke_lease", "lease_id": "L-1"}]
    assert any("supersedes" in e for e in _check(c, _tighten(c, ops, parent=11))[0])
    errs, eff = _check(c, _tighten(c, ops, counter=3))
    assert not errs
    assert any("a replay" in e for e in _check(c, _tighten(c, ops, counter=3), {**STATE, **eff["state"]})[0])
    assert not _check(c, _tighten(c, ops, counter=4), {**STATE, **eff["state"]})[0]


def test_a_certificate_lapses_in_the_edges_trusted_time_and_lives_31_days_at_most():
    c, ops = _cert(days=1), [{"op": "revoke_lease", "lease_id": "L-1"}]
    late = {**STATE, "newest": "2026-11-07T00:00:00Z"}                   # a clock set back does not revive it
    assert any("expired" in e for e in _check(c, _tighten(c, ops), late)[0])
    with pytest.raises(ValueError, match="31 days"):
        R._cert(_cert(days=32), PINS["officer_key"])
    assert any("future" in e for e in _check(c, _tighten(c, ops, at=NOW + timedelta(hours=1)))[0])


def test_the_site_key_signs_one_purpose_at_a_time():
    st = R.site_statement("provisional", "edge-a", E.public_hex(SITE), E.public_hex(NODE), NOW, "the old box burned")
    sealed = E.cosign(NODE, E.cosign(SITE, st, R.SITE_FORMAT), R.SITE_FORMAT)
    assert R.verify_site(sealed, E.public_hex(SITE), "edge-a", "provisional")["node_key"] == E.public_hex(NODE)
    with pytest.raises(ValueError, match="kc-edge-site-v2"):            # 1.6: a promotion is its own format
        R.verify_site(sealed, E.public_hex(SITE), "edge-a", "promotion")
    with pytest.raises(ValueError, match="another edge"):
        R.verify_site(sealed, E.public_hex(SITE), "edge-b", "provisional")
    with pytest.raises(ValueError):
        R.verify_site(E.cosign(SITE, st, R.SITE_FORMAT), E.public_hex(SITE), "edge-a", "provisional")   # no node
    with pytest.raises(ValueError):
        R.verify_site(sealed, E.public_hex(OTHER), "edge-a", "provisional")                           # not the site key


def test_a_promotion_statement_has_a_validity_window():
    """kc-edge-site-v2 (edge protocol 1.6): not_after after at and at most a day later; expired, it promotes nothing."""
    def promo(not_after=None):
        st = R.site_statement("promotion", "edge-a", E.public_hex(SITE), E.public_hex(NODE), NOW, "no witness on site",
                              not_after)
        return E.cosign(NODE, E.cosign(SITE, st, R.SITE_FORMAT_V2), R.SITE_FORMAT_V2)
    st = R.verify_site(promo(), E.public_hex(SITE), "edge-a", "promotion", NOW)
    assert st["not_after"] == E._iso(NOW + timedelta(hours=24))
    with pytest.raises(ValueError, match="expired"):
        R.verify_site(promo(), E.public_hex(SITE), "edge-a", "promotion", NOW + timedelta(hours=25))
    with pytest.raises(ValueError, match="at most 24 hours"):
        R.verify_site(promo(NOW + timedelta(hours=48)), E.public_hex(SITE), "edge-a", "promotion", NOW)
    with pytest.raises(ValueError, match="after at"):
        R.verify_site(promo(NOW), E.public_hex(SITE), "edge-a", "promotion", NOW)
