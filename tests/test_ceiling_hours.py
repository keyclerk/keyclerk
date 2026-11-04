# SPDX-License-Identifier: EUPL-1.2
"""Review finding D4 (edge protocol 1.4): the ceiling judges a lease by its hours rounded up. Rounded down, a lease of
8 hours 30 minutes passed a ceiling of 8 hours, at the desk and in the edge's verifier alike."""
from datetime import datetime, timezone

from keyclerk import edge as E
from keyclerk.edge_cli import _ceiling_check
from tests.test_edge_conformance import SET

T0 = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


def _bundle(until: str):
    bk, ok = E.Ed25519PrivateKey.from_private_bytes(b"b" * 32), E.Ed25519PrivateKey.from_private_bytes(b"o" * 32)
    ceiling = E.seal_ceiling(ok, {"format": E.CEILING_FORMAT, "edge": "edge-a", "serial": 2, "persons": ["idp:7c1f-ann"],
                                  "roles": [], "targets": ["plc-ssh"], "classes": ["low"], "max_lease_hours": 8,
                                  "max_offline_hours": 12, "profile": "assured", "remote_reach": "off", "ports": [22],
                                  "signed_at": "2026-10-23T10:00:00Z"})
    lease = {"lease_id": "L-1", "person": "idp:7c1f-ann", "username": "ann", "target": "plc-ssh", "role": "operator",
             "class": "low", "roles": [], "from": "2026-10-23T11:00:00Z", "until": until}
    sealed = E.build_bundle("edge-a", 7, T0, {"low": 12}, [lease], [], [], ceiling,
                            {"modules": {}, "release": None, "entrypoints": []}, bk)
    pins = {"edge": "edge-a", "bundle_key": E.public_hex(bk), "officer_key": E.public_hex(ok), "release_key": None}
    return E.verify_bundle(sealed, pins, {"serial": 6}, datetime(2026, 10, 23, 13, 0, tzinfo=timezone.utc),
                           _ceiling_check)


def test_a_lease_half_an_hour_over_the_ceiling_is_refused_by_the_edge():
    errs, applied = _bundle("2026-10-23T19:30:00Z")                    # 8 h 30 m under a ceiling of 8 h
    assert not errs and applied["refused_by_ceiling"] == ["L-1"] and applied["leases"] == []
    errs, applied = _bundle("2026-10-23T19:00:00Z")                    # exactly 8 h
    assert not errs and [x["lease_id"] for x in applied["leases"]] == ["L-1"]


def test_ceiling_hours_round_up_and_the_vectors_say_so():
    assert E.ceiling_hours(T0, T0.replace(hour=20)) == 8
    assert E.ceiling_hours(T0, T0.replace(hour=20, second=1)) == 9
    assert E.ceiling_hours(T0, T0) == 1
    assert {c["name"]: c["expected"]["hours"] for c in SET["ceiling_hours"]["cases"]}["eight hours and 59 minutes"] == 9
