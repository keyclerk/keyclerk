# SPDX-License-Identifier: EUPL-1.2
"""The conformance families beside the bundle verifier (amendment 0014d, kc-unlock-v2, the ended notice), as they sit in
tests/conformance/edge.json: an agent in any language runs the same cases and must reach the same verdicts.

    statements  unseal_multi(sealed, required, format): ok, and what it says when ok
    ceilings    check_ceiling(edge, officer_key, sealed, floor): ok
    ended       verify_ended(sealed, pins, enrolment_key): ok
    unlock      the code from either side: the node with its key and the desk's public key, the desk with its key and
                the node's public key; both equal expected.code, or both refuse (expected.code null)
    module_bytes  verify_module(bytes, sha256): ok
    email       verify_email(sealed, pins, lease_id, nonce): ok, and sha256 of the address when ok (edge protocol 1.3)
"""
from __future__ import annotations

import base64
import hashlib

from keyclerk import edge as E

FAMILIES = ("statements", "ceilings", "ended", "unlock", "module_bytes", "requests", "email")


def verdict(family: str, c: dict) -> dict:
    """What this checkout's reference says for one case."""
    if family == "statements":
        try:
            return {"ok": True, "says": E.unseal_multi(c["sealed"], c["required"], c["format"])}
        except ValueError:
            return {"ok": False, "says": None}
    if family == "ceilings":
        errs, _ = E.check_ceiling(c["edge"], c["officer_key"], c["sealed"], c["floor"])
        return {"ok": not errs}
    if family == "ended":
        errs, _ = E.verify_ended(c["sealed"], c["pins"], c["enrolment_key"])
        return {"ok": not errs}
    if family == "unlock":
        codes = []
        for own in ("edge_private", "desk_private"):
            try:
                secret = E.unlock_secret(E.unlock_private(c[own]), c["desk_public"], c["edge_public"], c["edge"], c["node"])
                codes.append(E.unlock_code(secret, c["edge"], c["node"], c["person"], c["fingerprint"], c["target"],
                                           c["nonce"], c["minutes"]))
            except ValueError:
                codes.append(None)
        return {"code": codes[0] if codes[0] == codes[1] else "the two sides differ"}
    if family == "requests":                     # kc-edge-request-v2: the bytes an edge signs, and the desk's verdict
        body = base64.b64decode(c["body"])
        message = E.request_message(c["edge"], c["method"], c["path"], c["seconds"], c["nonce"], body)
        try:
            E.check_request(c["header"], c["method"], c["path"], body,
                            lambda e: c["public_key"] if e == c["edge"] else None, E.Replay(), c["now"])
            ok = True
        except ValueError:
            ok = False
        return {"message": base64.b64encode(message).decode(), "ok": ok}
    if family == "email":
        errs, m = E.verify_email(c["sealed"], c["pins"], c["lease_id"], c["nonce"])
        email = m.get("email") if not errs else None     # by its digest: no address in a published file
        return {"ok": not errs, "email_sha256": hashlib.sha256(email.encode()).hexdigest() if email else None}
    if family == "module_bytes":
        return {"ok": not E.verify_module(base64.b64decode(c["wasm"]), c["sha256"])}
    raise ValueError(f"no conformance family {family}")


def failures(doc: dict) -> list[str]:
    return [f"{fam}: {c['name']}" for fam in FAMILIES for c in doc.get(fam, {}).get("cases", [])
            if verdict(fam, c) != c["expected"]]


def count(doc: dict) -> int:
    return sum(len(doc.get(f, {}).get("cases", [])) for f in ("verifier",) + FAMILIES)
