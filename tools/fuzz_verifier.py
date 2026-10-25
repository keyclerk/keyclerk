# SPDX-License-Identifier: EUPL-1.2
"""Fuzzes the edge's bundle verifier (keyclerk.edge.verify_bundle) with Atheris, under ClusterFuzzLite
(.clusterfuzzlite/ in the public repository; the edge protocol fuzzes its section 4 reader the same way).

Two shapes of input, chosen by the first byte: the rest as a whole sealed object in JSON (the envelope's own checks),
or the rest as the signed bytes of a bundle sealed with the fuzzer's key (everything after the signature: canonical
JSON, the bundle's shape, its times, leases, ceiling, policy and governed roles). What must hold for every input:
- verify_bundle answers with errors or with what applies, and never raises;
- an accepted bundle names this edge and a serial above the floor, and the state it returns moves no floor back.
"""
import base64
import json
import sys
from datetime import datetime, timezone

import atheris

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from keyclerk import edge as E

KEY = Ed25519PrivateKey.from_private_bytes(bytes([9]) * 32)
OFFICER = Ed25519PrivateKey.from_private_bytes(bytes([10]) * 32)
PINS = {"edge": "edge-a", "bundle_key": E.public_hex(KEY), "officer_key": E.public_hex(OFFICER), "release_key": None}
STATE = {"serial": 6, "newest": "2026-10-23T11:00:00Z", "ceiling_serial": 1}
NOW = datetime(2026, 10, 23, 13, 0, tzinfo=timezone.utc)


def _sealed_raw(raw: bytes) -> dict:
    return {"bytes": base64.b64encode(raw).decode("ascii"), "signature": KEY.sign(raw).hex(), "key": PINS["bundle_key"],
            "key_id": E.key_id(PINS["bundle_key"])}


def test_one_input(data: bytes) -> None:
    if not data:
        return
    mode, rest = data[0] % 2, data[1:]
    if mode == 0:
        try:
            sealed = json.loads(rest.decode("utf-8", errors="replace"))
        except (ValueError, RecursionError):
            return
    else:
        sealed = _sealed_raw(rest)
    errors, applied = E.verify_bundle(sealed, PINS, dict(STATE), NOW)     # must not raise
    if errors:
        return
    body = E.unseal(sealed, PINS["bundle_key"], E.BUNDLE_FORMAT)
    assert body["edge"] == PINS["edge"], "accepted a bundle for another edge"
    assert body["serial"] > STATE["serial"], "accepted a serial at or below the floor"
    assert applied["state"]["serial"] == body["serial"], "the returned state is not the bundle's serial"
    assert applied["state"]["ceiling_serial"] >= STATE["ceiling_serial"], "the ceiling floor moved back"


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
