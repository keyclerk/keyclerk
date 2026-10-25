# SPDX-License-Identifier: EUPL-1.2
"""More bundle-verifier vectors, contributed by an independent edge implementation from its own verifier tests:
revocation, visit leases, the newest-time floor, canonical refusal, format and key id, the ceiling's key set
and signature, the release manifest, horizons, integer bounds. Moved here so the reference and its vectors ship
together; the verdicts are always computed from this checkout's keyclerk.edge, never copied.
Fixed seed keys as in gen_edge_conformance.py; never use them for anything else.
"""
import base64
import hashlib
import json
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk import edge as E


def key(n):
    return Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)


BK, OK, OTHER, RK = key(1), key(2), key(3), key(4)
T0 = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
HZ = {"low": 168, "elevated": 24, "privileged": 1}
PINS = {"edge": "edge-a", "bundle_key": E.public_hex(BK), "officer_key": E.public_hex(OK), "release_key": None}
CEILING = {"format": E.CEILING_FORMAT, "edge": "edge-a", "serial": 2, "persons": ["idp:7c1f-ann"], "roles": [],
           "targets": ["plc-ssh"], "classes": ["low", "elevated", "privileged"], "max_lease_hours": 720,
           "max_offline_hours": 12, "profile": "assured", "remote_reach": "off", "ports": [22],
           "signed_at": "2026-10-23T10:00:00Z"}
POL = {"modules": {}, "release": None, "entrypoints": []}
NOW = "2026-10-23T13:00:00Z"


def lease(lid="L-1", cls="low", frm="2026-10-23T11:00:00Z", until="2026-11-23T11:00:00Z"):
    return {"lease_id": lid, "person": "idp:7c1f-ann", "username": "ann", "email": "ann" + "@example.test",   # the verified e-mail; built from parts so no address sits in the source
            "target": "plc-ssh", "role": "operator", "class": cls, "roles": [], "from": frm, "until": until}


def visit(lid="V-1", frm="2026-10-23T11:00:00Z", until="2026-10-23T18:00:00Z"):
    return {"lease_id": lid, "person": "idp:7c1f-ann", "username": "ann", "ssh_key": "ssh-ed25519 AAAA test",
            "targets": ["plc-ssh"], "role": "visitor", "from": frm, "until": until}


def bundle(serial=7, leases=None, visits=(), revoked=(), ceiling=CEILING, sealed=None, pol=POL, hz=HZ, k=BK, issued=T0,
           governed=None):
    if ceiling is not None and sealed is None:
        sealed = E.seal_ceiling(OK, ceiling)                 # amendment 0014d: the officer seals it
    return E.build_bundle("edge-a", serial, issued, hz, [lease()] if leases is None else leases, list(visits),
                          list(revoked), sealed if ceiling is not None else None, pol, k, governed_roles=governed)


def raw_seal(raw: bytes, k=BK):
    """Signed bytes exactly as given (not passed through canonical)."""
    return {"bytes": base64.b64encode(raw).decode(), "signature": k.sign(raw).hex(), "key": E.public_hex(k),
            "key_id": E.key_id(E.public_hex(k))}


def body(**over):
    b = json.loads(base64.b64decode(bundle()["bytes"]))
    b.update(over)
    return b


def dumps(obj) -> bytes:
    """Python's canonical form, without the engine's own checks (so a vector can hold what the engine refuses)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def module(wasm: bytes):
    return {"sha256": hashlib.sha256(wasm).hexdigest()}          # by hash only (0.23.0); bytes: the modules family


WASM = b"\x00asm\x01\x00\x00\x00"
REL_PINS = {**PINS, "release_key": E.public_hex(RK)}


def cases():
    good_mod = {"modules": {"edge": module(WASM)}, "release": E.sign_release(RK, {"edge": module(WASM)["sha256"]}),
                "entrypoints": []}
    upper_hash = {"modules": {"edge": {"sha256": module(WASM)["sha256"].upper()}},
                  "release": E.sign_release(RK, {"edge": module(WASM)["sha256"].upper()}), "entrypoints": []}
    inline = {"modules": {"edge": {**module(WASM), "wasm": base64.b64encode(WASM).decode()}},
              "release": E.sign_release(RK, {"edge": module(WASM)["sha256"]}), "entrypoints": []}
    not_released = {"modules": {"edge": module(WASM)}, "release": E.sign_release(RK, {"edge": "1" * 64}),
                    "entrypoints": []}
    no_horizon = raw_seal(dumps(body(leases=[lease(cls="elevated")], horizons={"low": 168})))
    return [
        ("a revoked lease is not live", bundle(revoked=["L-1"]), PINS, {"serial": 6}, NOW),
        ("only leases inside their window are live",
         bundle(leases=[lease(), lease("L-2", frm="2026-10-23T14:00:00Z"), lease("L-3", until="2026-10-23T12:30:00Z")]),
         PINS, {"serial": 6}, NOW),
        ("a live visit lease and an ended one", bundle(visits=[visit(), visit("V-2", until="2026-10-23T12:59:59Z")]),
         PINS, {"serial": 6}, NOW),
        ("a revoked visit lease", bundle(visits=[visit()], revoked=["V-1"]), PINS, {"serial": 6}, NOW),
        ("the clock before the newest signed time", bundle(), PINS, {"serial": 6, "newest": "2026-10-23T13:10:00Z"},
         "2026-10-23T13:04:59Z"),
        ("the clock within the skew of the newest", bundle(), PINS, {"serial": 6, "newest": "2026-10-23T13:05:00Z"}, NOW),
        ("issued before the newest signed time", bundle(), PINS, {"serial": 6, "newest": "2026-10-23T12:05:01Z"}, NOW),
        ("newest stays when the bundle is older but within the skew", bundle(), PINS,
         {"serial": 6, "newest": "2026-10-23T12:04:00Z"}, NOW),
        ("non-canonical signed bytes (whitespace)",
         raw_seal(json.dumps(body(), sort_keys=True).encode()), PINS, {"serial": 6}, NOW),
        ("non-canonical signed bytes (unsorted)",
         raw_seal(json.dumps(dict(reversed(list(body().items()))), separators=(",", ":")).encode()), PINS, {"serial": 6}, NOW),
        ("a duplicate name in the signed bytes",
         raw_seal(dumps(body())[:-1] + b',"serial":8}'), PINS, {"serial": 6}, NOW),
        ("a float in the signed bytes", raw_seal(dumps(body()).replace(b'"serial":7', b'"serial":7.0')), PINS, {"serial": 6}, NOW),
        ("another format inside", E.seal(BK, {k: v for k, v in body().items() if k not in ("format", "key_id")},
                                         E.CARRIED_FORMAT), PINS, {"serial": 6}, NOW),
        ("a key id that is not the pinned key's", raw_seal(dumps(body(key_id="0000000000000000"))), PINS,
         {"serial": 6}, NOW),
        ("a ceiling with an extra member", bundle(ceiling={**CEILING, "note": "x"}), PINS, {"serial": 6}, NOW),
        ("a ceiling signed by another key", bundle(sealed=E.seal_ceiling(OTHER, CEILING)), PINS, {"serial": 6}, NOW),
        ("0014d a ceiling with a re-encoded body (same content, not the signed bytes)",
         bundle(sealed={**E.seal_ceiling(OK, CEILING), "bytes": base64.b64encode(
             json.dumps(E.opened(E.seal_ceiling(OK, CEILING)), sort_keys=True).encode()).decode()}), PINS, {"serial": 6}, NOW),
        ("0014d a ceiling sealed as another format",
         bundle(sealed=E.seal(OK, {k: v for k, v in CEILING.items() if k != "format"}, E.OFFICER_FORMAT)), PINS,
         {"serial": 6}, NOW),
        ("a ceiling for another edge", bundle(ceiling={**CEILING, "edge": "edge-b"}), PINS, {"serial": 6}, NOW),
        ("a ceiling at the serial held", bundle(), PINS, {"serial": 6, "ceiling_serial": 2}, NOW),
        ("a bundle without the ceiling held", bundle(leases=[], ceiling=None), PINS, {"serial": 6, "ceiling_serial": 2},
         NOW),
        ("a ceiling with no offline hours", bundle(ceiling={**CEILING, "max_offline_hours": 0}), PINS, {"serial": 6},
         NOW),
        ("a ceiling with a port out of range", bundle(ceiling={**CEILING, "ports": [0]}), PINS, {"serial": 6}, NOW),
        ("a ceiling with an unknown class", bundle(ceiling={**CEILING, "classes": ["low", "root"]}), PINS, {"serial": 6},
         NOW),
        ("a class without a horizon at the moment of issue", no_horizon, PINS, {"serial": 6}, "2026-10-23T12:00:00Z"),
        ("a class without a horizon later", no_horizon, PINS, {"serial": 6}, NOW),
        ("a released module", bundle(pol=good_mod), REL_PINS, {"serial": 6}, NOW),
        ("a module hash in upper case", bundle(pol=upper_hash), REL_PINS, {"serial": 6}, NOW),
        ("a module with its bytes inline (the v2 shape)", bundle(pol=inline), REL_PINS, {"serial": 6}, NOW),
        ("a module that is not the released one", bundle(pol=not_released), REL_PINS, {"serial": 6}, NOW),
        ("a release key pinned and no manifest", bundle(), REL_PINS, {"serial": 6}, NOW),
        ("only the bundle names another edge", E.seal(BK, {k: v for k, v in body(edge="edge-b").items()
                                                           if k not in ("format", "key_id")}, E.BUNDLE_FORMAT),
         PINS, {"serial": 6}, NOW),
        ("the clock alone before the newest signed time", bundle(), PINS, {"serial": 6, "newest": "2026-10-23T12:04:00Z"},
         "2026-10-23T11:58:00Z"),
        ("the newest signed time rises to the issue time", bundle(), PINS,
         {"serial": 6, "newest": "2026-10-23T11:00:00Z"}, NOW),
        ("a serial written as true", raw_seal(dumps(body(serial=True))), PINS, {"serial": 0}, NOW),
        ("a serial beyond 2^53-1", raw_seal(dumps(body(serial=2 ** 53))), PINS, {"serial": 6}, NOW),
        ("a serial of 2^53-1", raw_seal(dumps(body(serial=2 ** 53 - 1))), PINS, {"serial": 6}, NOW),
        ("a negative horizon", raw_seal(dumps(body(horizons={**HZ, "low": -1}))), PINS, {"serial": 6}, NOW),
        ("a lease carries the verified e-mail, a lease without one is still live",
         bundle(leases=[lease(), {**lease("L-2"), "email": None}]), PINS, {"serial": 6}, NOW),
        ("the edge clock 60 s behind the desk: a lease with a stable from is still live", bundle(), PINS,
         {"serial": 6}, "2026-10-23T11:59:00Z"),
        ("a sealed bundle with an extra member", {**bundle(), "note": "x"}, PINS, {"serial": 6}, NOW),
        ("a ceiling sealed with an extra member", bundle(sealed={**E.seal_ceiling(OK, CEILING), "note": "x"}), PINS,
         {"serial": 6}, NOW),
        ("base64 of the signed bytes with a line break inside",
         (lambda s: {**s, "bytes": s["bytes"][:40] + "\n" + s["bytes"][40:]})(bundle()), PINS, {"serial": 6}, NOW),
        ("a lease time in a loose form", raw_seal(dumps(body(leases=[lease(frm="2026-10-23T1:00:00Z")]))), PINS,
         {"serial": 6}, NOW),
        # decision 0025: the roles KeyClerk governs on this edge, in SCIM Group shape
        ("0025 governed roles present", bundle(governed=["operator", "engineer"]), PINS, {"serial": 6}, NOW),
        ("0025 governed roles absent: no catalogue, the edge keeps its own targets file", bundle(), PINS,
         {"serial": 6}, NOW),
        ("0025 governed roles signed and empty: none governed here", bundle(governed=[]), PINS, {"serial": 6}, NOW),
        ("0025 governed roles with an externalId", raw_seal(dumps(body(governed_roles=[
            {"displayName": "operator", "externalId": "plc-operator"}]))), PINS, {"serial": 6}, NOW),
        ("0025 governed roles naming a role twice", raw_seal(dumps(body(governed_roles=[
            {"displayName": "operator"}, {"displayName": "operator"}]))), PINS, {"serial": 6}, NOW),
        ("0025 governed roles with an unknown member", raw_seal(dumps(body(governed_roles=[
            {"displayName": "operator", "members": []}]))), PINS, {"serial": 6}, NOW),
        ("0025 governed roles as null", raw_seal(dumps(body(governed_roles=None))), PINS, {"serial": 6}, NOW),
        ("0025 governed roles as bare names", raw_seal(dumps(body(governed_roles=["operator"]))), PINS,
         {"serial": 6}, NOW),
    ]
