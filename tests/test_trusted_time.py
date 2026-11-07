# SPDX-License-Identifier: EUPL-1.2
"""Edge protocol 1.5, section 1 (decision 0032 point 35): the edge's trusted time never lets a wall clock set back or
held still keep a lease alive, and nothing is live after a reboot until a fresh bundle verifies."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from keyclerk import edge as E

T0 = datetime(2026, 11, 5, 10, tzinfo=timezone.utc)
SET = json.loads((Path(__file__).resolve().parent / "conformance" / "edge.json").read_text(encoding="utf-8"))


def test_a_wall_clock_held_still_is_overtaken_by_the_boot_clock():
    t = E.trusted_time(T0, T0, 1000, 1000 + 86400, True)
    assert t["trusted"] == T0 + timedelta(days=1) and t["skewed"] and t["live"]


def test_a_wall_clock_set_forward_stands_so_leases_end_early():
    t = E.trusted_time(T0 + timedelta(days=1), T0, 1000, 1060, True)
    assert t["trusted"] == T0 + timedelta(days=1) and t["skewed"]


def test_within_the_skew_the_wall_clock_stands():
    assert E.trusted_time(T0 + timedelta(seconds=3500), T0, 0, 3600, True) == {
        "trusted": T0 + timedelta(seconds=3500), "skewed": False, "live": True}


def test_nothing_is_live_after_a_reboot_or_without_a_bundle():
    assert not E.trusted_time(T0, T0, 1000, 30, False)["live"]
    assert not E.trusted_time(T0, None, None, 30, True)["live"]


def test_the_vectors_name_the_cases_an_edge_must_pass():
    names = {c["name"] for c in SET["trusted_time"]["cases"]}
    assert "the wall clock held at the last bundle for a day" in names
    assert "rebooted since the last bundle: nothing is live" in names


def test_the_desk_answers_an_edges_time_request_for_that_request_only():
    from keyclerk.desk import Refusal

    class _D:
        bundle_key = __import__("cryptography.hazmat.primitives.asymmetric.ed25519",
                                fromlist=["Ed25519PrivateKey"]).Ed25519PrivateKey.from_private_bytes(b"b" * 32)

        def clock(self):
            return T0

        def _node_seen(self, *a):
            pass

        def _seal(self, kind, edge_id, **fields):          # the checking signer's answer (tests/test_edge_sealer.py)
            assert kind == "time"
            return E.time_answer(self.bundle_key, edge_id, fields["nonce"], self.clock())

        def edge_key(self):
            return {"key": E.public_hex(self.bundle_key)}
    from keyclerk.desk import Desk
    d = _D()
    nonce = "bm9uY2Utb2YtdGhlLXRpbWU"
    sealed = Desk.edge_time(d, "plant-a", ("1793102400", nonce))
    pins = {"edge": "plant-a", "bundle_key": d.edge_key()["key"]}
    errs, m = E.verify_time(sealed, pins, nonce, 1.5)
    assert not errs and m["issued"] == "2026-11-05T10:00:00Z"
    assert E.verify_time(sealed, pins, nonce, 31)[0]                     # held back past the wait
    assert E.verify_time(sealed, pins, "b3RoZXI", 1)[0]                  # another request's answer
    import pytest
    with pytest.raises(Refusal, match="signed request"):
        Desk.edge_time(d, "plant-a", None)
