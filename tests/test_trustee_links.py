# SPDX-License-Identifier: EUPL-1.2
"""#41 F1: an HA change link or a restore link holds, where a verifier pins a trustee set, only with one officer's and
one root trust owner's signatures over a statement that names its position; the records key alone never decides it."""
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E
from keyclerk import trustees as T
from keyclerk.store import link as L
from tests.test_trustees import pinned_set, trustee_sigs

REALM = "example"
KEY = Ed25519PrivateKey.generate()
PIN = E.public_hex(KEY)
HEAD = hashlib.sha256(b"head").digest()
SIZE = 7
PROOFS = [{"by": "idp:55bb-eva", "proof": "a" * 64}, {"by": "idp:2b9e-owner", "proof": "b" * 64}]


def restore_link(sigs=None, mark=40, seq=SIZE, prev=HEAD):
    entry = {"change_id": "C-t1", "action": "restore", "outcome": "applied", "actor": None, "records": {}}
    body = L.link_body(REALM, seq, prev.hex(), 1, "2026-11-06T20:00:00Z", [], entry,
                       restore={"mark": mark, "confirmations": PROOFS, **({"trustees": sigs} if sigs else {})})
    return L.seal_body(KEY, body)


def ha_off_link(sigs=None):
    entry = {"change_id": "C-t2", "action": "ha_off", "outcome": "applied", "actor": None, "records": {}}
    body = L.link_body(REALM, SIZE, HEAD.hex(), 1, "2026-11-06T20:00:00Z",
                       [{"op": "del", "kind": "head", "key": "ha"}], entry,
                       ha={"mode": "off", "confirmations": PROOFS, **({"trustees": sigs} if sigs else {})})
    return L.seal_body(KEY, body)


def check(sealed):
    return L.check_next(sealed, PIN, REALM, SIZE, HEAD, 1)


@pytest.fixture
def pinned(monkeypatch):
    ts = pinned_set(REALM)
    monkeypatch.setattr(T, "pinned", lambda: {"set": ts, "since": 0})
    return ts


def restore_sigs(mark=40, seq=SIZE, prev=HEAD, who=("eva", "owner")):
    return trustee_sigs("kc-restore-v1", L.restore_statement(REALM, seq, prev.hex(), mark), who)


def test_without_a_pin_the_links_hold_as_before(monkeypatch):
    monkeypatch.setattr(T, "pinned", lambda: None)
    check(restore_link())
    check(ha_off_link())


def test_with_a_pin_a_link_without_trustee_signatures_is_refused(pinned):
    with pytest.raises(L.StoreRefused, match="without trustee signatures"):
        check(restore_link())
    with pytest.raises(L.StoreRefused, match="without trustee signatures"):
        check(ha_off_link())


def test_with_a_pin_a_link_signed_by_an_officer_and_a_root_trust_owner_holds(pinned):
    check(restore_link(restore_sigs()))
    st = L.ha_statement(REALM, SIZE, HEAD.hex(), "off", None, None)
    check(ha_off_link(trustee_sigs("kc-ha-change-v1", st)))


def test_signatures_for_another_position_or_mark_do_not_hold(pinned):
    with pytest.raises(L.StoreRefused, match="do not hold"):
        check(restore_link(restore_sigs(seq=SIZE - 1)))
    with pytest.raises(L.StoreRefused, match="do not hold"):
        check(restore_link(restore_sigs(mark=4000), mark=40))         # the key cannot push the mark up (F8)
    with pytest.raises(L.StoreRefused, match="do not hold"):           # a restore statement never stands for HA
        check(ha_off_link(restore_sigs()))


def test_two_officers_are_not_the_threshold(pinned):
    with pytest.raises(L.StoreRefused, match="one officer and one root"):
        check(restore_link(restore_sigs(who=("eva", "ingrid"))))


def test_links_before_the_pinned_position_hold_as_they_were_written(monkeypatch):
    ts = pinned_set(REALM)
    monkeypatch.setattr(T, "pinned", lambda: {"set": ts, "since": SIZE + 1})
    check(restore_link())                                              # history from before the pin


def test_a_malformed_trustees_field_is_refused_by_the_format(pinned):
    with pytest.raises(L.StoreRefused, match="two to four"):
        check(restore_link([{"trustee_id": "eva", "sig": "00"}]))
