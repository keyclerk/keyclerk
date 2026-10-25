# SPDX-License-Identifier: EUPL-1.2
"""Write tests/conformance/edge.json: input and expected output pairs for the edge policy (decision 0014 point 6).

KeyClerk's tests evaluate every pair against keyclerk/policy/edge.wasm and ceiling.wasm; an edge agent runs the same
file against the module it received in a bundle, so the two cannot drift. Run it after changing edge.rego or
ceiling.rego, and commit the result.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))   # edge_verifier_vectors
from keyclerk import policy_wasm  # noqa: E402

L = {"lease_id": "L-1", "person": "idp:7c1f-ann", "target": "plc-ssh", "class": "privileged", "from": 1000, "until": 100000}
V = {"lease_id": "V-1", "person": "idp:7c1f-ann", "targets": ["plc-ssh"], "from": 1000, "until": 300000}
C = {"persons": ["idp:7c1f-ann"], "roles": ["operators"], "targets": ["plc-ssh"], "classes": ["low", "elevated"],
     "max_lease_hours": 8, "max_offline_hours": 72, "profile": "assured"}
ADMIT = {"person": "idp:7c1f-ann", "target": "plc-ssh", "leases": [L], "visit_leases": [V], "revoked": []}

CASES = [
    ("edge", "settings", "the default settings", {}),
    ("edge", "admit", "a lease inside its window and horizon admits", {**ADMIT, "now": 2000, "issued": 1500, "visit_leases": []}),
    ("edge", "admit", "past the privileged horizon a lease no longer admits", {**ADMIT, "now": 9000, "issued": 1500, "visit_leases": []}),
    ("edge", "admit", "a visit lease admits in its own window", {**ADMIT, "now": 200000, "issued": 1500}),
    ("edge", "admit", "a revoked lease never admits", {**ADMIT, "now": 2000, "issued": 1500, "visit_leases": [], "revoked": ["L-1"]}),
    ("edge", "admit", "another person is not admitted", {**ADMIT, "person": "idp:0000-x", "now": 2000, "issued": 1500}),
    ("edge", "admit", "another target is not admitted", {**ADMIT, "target": "db", "now": 2000, "issued": 1500}),
    ("edge", "visit_window", "inside policy and ceiling", {"hours": 48, "max_offline_hours": 72}),
    ("edge", "visit_window", "longer than policy", {"hours": 96, "max_offline_hours": 200}),
    ("edge", "visit_window", "longer than the ceiling", {"hours": 48, "max_offline_hours": 24}),
    ("edge", "attestation", "PCR 7 at its baseline: assured", {"quote": {"pcrs": {"7": "0000000000000000000000000000000000000000000000000000000000000000"}}, "baseline": {"7": "0000000000000000000000000000000000000000000000000000000000000000"}, "ek_certified": False}),
    ("edge", "attestation", "PCR 7 moved: not assured", {"quote": {"pcrs": {"7": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}, "baseline": {"7": "0000000000000000000000000000000000000000000000000000000000000000"}, "ek_certified": True}),
    ("edge", "attestation", "PCR 7 not quoted: not assured", {"quote": {"pcrs": {"0": "0000000000000000000000000000000000000000000000000000000000000000"}}, "baseline": {"7": "0000000000000000000000000000000000000000000000000000000000000000"}, "ek_certified": True}),
    ("ceiling", "decision", "inside the ceiling", {"ceiling": C, "entry": {"kind": "lease", "person": "idp:7c1f-ann", "targets": ["plc-ssh"], "class": "low", "hours": 4}}),
    ("ceiling", "decision", "a role inside the ceiling", {"ceiling": C, "entry": {"kind": "lease", "person": "idp:1111-bo", "roles": ["operators"], "targets": ["plc-ssh"], "class": "low", "hours": 4}}),
    ("ceiling", "decision", "outside on every count", {"ceiling": C, "entry": {"kind": "lease", "person": "idp:0000-x", "targets": ["db"], "class": "privileged", "hours": 9}}),
    ("ceiling", "decision", "a visit on a basic attestation", {"ceiling": C, "entry": {"kind": "visit", "person": "idp:7c1f-ann", "targets": ["plc-ssh"], "hours": 24, "attested_profile": "basic"}}),
    ("ceiling", "decision", "a visit on an assured attestation", {"ceiling": C, "entry": {"kind": "visit", "person": "idp:7c1f-ann", "targets": ["plc-ssh"], "hours": 24, "attested_profile": "assured"}}),
]


def evaluate(policy: str, entry: str, inp: dict):
    return policy_wasm.load(policy).eval(f"keyclerk/{policy}/{entry}", inp)


def _key(n: int):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(bytes([n]) * 32)      # fixed keys: the vectors are reproducible


def raw_seal(key, sealed: dict, edit) -> dict:
    """A sealed object whose signed bytes were edited, then signed again: valid signature, malformed content."""
    import base64
    raw = edit(base64.b64decode(sealed["bytes"]))
    return {"bytes": base64.b64encode(raw).decode("ascii"), "signature": key.sign(raw).hex(), "key": sealed["key"],
            "key_id": sealed["key_id"]}


def reseal(key, sealed: dict, edit) -> dict:
    """The same bundle with its document edited and sealed again (canonical bytes, valid signature)."""
    import base64
    import json
    doc = edit(json.loads(base64.b64decode(sealed["bytes"])))
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {"bytes": base64.b64encode(raw).decode("ascii"), "signature": key.sign(raw).hex(), "key": sealed["key"],
            "key_id": sealed["key_id"]}


def trailing_bits(b64: str) -> str:
    """The same bytes with a non-zero unused bit in the last base64 character (the bytes' length is not a multiple of
    three): lenient decoders accept it, a canonical check does not."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    body, pad = b64.rstrip("="), len(b64) - len(b64.rstrip("="))
    assert pad, "the bytes' length is a multiple of three: no unused bits"
    return body[:-1] + alphabet[alphabet.index(body[-1]) | 1] + "=" * pad


def verifier_cases() -> dict:
    """Bundles and the reference verifier's answers (keyclerk.edge.verify_bundle): an agent in any language checks
    the same bytes give the same verdicts. Keys are fixed seeds; never use them for anything else."""
    from datetime import datetime, timezone
    from keyclerk import edge as E
    bk, ok, other = _key(1), _key(2), _key(3)
    t0 = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
    ceiling = {"format": E.CEILING_FORMAT, "edge": "edge-a", "serial": 2, "persons": ["idp:7c1f-ann"], "roles": [], "targets": ["plc-ssh"],
               "classes": ["low", "elevated", "privileged"], "max_lease_hours": 720, "max_offline_hours": 12, "profile": "assured",
               "remote_reach": "off", "ports": [22], "signed_at": "2026-10-23T10:00:00Z"}
    sig = E.seal_ceiling(ok, ceiling)                    # amendment 0014d: sealed by the officer
    lease = {"lease_id": "L-1", "person": "idp:7c1f-ann", "username": "ann", "target": "plc-ssh", "role": "operator", "class": "low",
             "roles": [], "from": "2026-10-23T11:00:00Z", "until": "2026-11-23T11:00:00Z"}
    hz = {"low": 168, "elevated": 24, "privileged": 1}
    pol = {"modules": {}, "release": None, "entrypoints": []}
    good = E.build_bundle("edge-a", 7, t0, hz, [lease], [], [], sig, pol, bk)
    pins = {"edge": "edge-a", "bundle_key": E.public_hex(bk), "officer_key": E.public_hex(ok), "release_key": None}
    padded = next(b for b in (E.build_bundle("edge-a", 7, t0, hz, [{**lease, "lease_id": "L-1" + "0" * i}], [], [], sig, pol, bk)
                              for i in range(3)) if b["bytes"].endswith("="))      # unused bits need padding
    cases = [
        ("a valid bundle", good, pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("a bundle for another edge", good, {**pins, "edge": "edge-b"}, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("an old serial", good, pins, {"serial": 7}, "2026-10-23T13:00:00Z"),
        ("issued in the future", good, pins, {"serial": 6}, "2026-10-23T11:00:00Z"),
        ("a wrong signer", E.build_bundle("edge-a", 7, t0, hz, [lease], [], [], sig, pol, other), pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("leases without a ceiling", E.build_bundle("edge-a", 7, t0, hz, [lease], [], [], None, pol, bk), pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("a ceiling older than the one held", good, pins, {"serial": 6, "ceiling_serial": 3}, "2026-10-23T13:00:00Z"),
        ("the ceiling caps a low lease at 12 hours offline", good, pins, {"serial": 6}, "2026-10-24T01:00:00Z"),
        # found while porting the verifier to Go: each is refused, none raises
        ("a fractional float in the signed bytes", raw_seal(bk, good, lambda s: s.replace(b'"serial":7', b'"serial":7.5')), pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("NaN in the signed bytes", raw_seal(bk, good, lambda s: s.replace(b'"serial":7', b'"serial":NaN')), pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("a bundle without horizons", E.seal(bk, {k: v for k, v in E.unseal(good, E.public_hex(bk), E.BUNDLE_FORMAT).items() if k not in ("horizons", "format", "key_id")}, E.BUNDLE_FORMAT), pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("a lease with a malformed until", reseal(bk, good, lambda d: {**d, "leases": [{**d["leases"][0], "until": "soon"}]}), pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("serial true in the signed bytes", reseal(bk, good, lambda d: {**d, "serial": True}), pins, {"serial": 0}, "2026-10-23T13:00:00Z"),
        ("issued with a one-digit hour", reseal(bk, good, lambda d: {**d, "issued": "2026-10-23T1:00:00Z"}), pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("an upper-case signature", {**good, "signature": good["signature"].upper()}, pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("base64 with non-zero trailing bits", {**padded, "bytes": trailing_bits(padded["bytes"])}, pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("an outer key_id that is not the pinned key's", {**good, "key_id": "0" * 16}, pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
        ("a module named by a short hash, without a release key", E.build_bundle("edge-a", 7, t0, hz, [lease], [], [], sig,
            {"modules": {"edge": {"sha256": "0" * 63}}, "release": None, "entrypoints": []}, bk), pins, {"serial": 6}, "2026-10-23T13:00:00Z"),
    ]
    import edge_verifier_vectors                        # an edge implementation's vectors, verdicts from this checkout
    cases += edge_verifier_vectors.cases()
    out = []
    for name, sealed, p, st, now in cases:
        errs, applied = E.verify_bundle(sealed, p, st, datetime.strptime(now, E.ISO).replace(tzinfo=timezone.utc))
        out.append({"name": name, "sealed": sealed, "pins": p, "state": st, "now": now,
                    "expected": {"ok": not errs, "leases": [x["lease_id"] for x in applied.get("leases", [])],
                                 "visit_leases": [x["lease_id"] for x in applied.get("visit_leases", [])],
                                 "governed_roles": applied.get("governed_roles") if not errs else None,
                                 "state": applied.get("state") if not errs else None}})
    return {"note": "verify_bundle(sealed, pins, state, now); ok means no errors; leases and visit_leases are the live "
                    "ids; state is what the edge stores after a bundle it accepts; governed_roles is the displayName list of an accepted "
                    "bundle's governed_roles, null when the bundle has none", "cases": out}


def families() -> dict:
    """The families beside the bundle verifier (keyclerk/edge_conformance.py): the multi-signed statement, the sealed
    ceiling, the ended notice, kc-unlock-v2 codes, fetched modules. Fixed seed keys; never use them for anything else."""
    import base64
    from datetime import datetime, timezone
    from keyclerk import edge as E
    from keyclerk import edge_conformance as EC
    ok, n1, n2, other, bk = _key(2), _key(5), _key(6), _key(3), _key(1)
    OK_, N1, N2, OT = (E.public_hex(k) for k in (ok, n1, n2, other))
    st1 = E.officer_statement("edge-a", "idp:51aa-eva", OK_, [E.node(N1)])
    st2 = E.officer_statement("edge-a", "idp:51aa-eva", OK_, [E.node(N1), E.node(N2)])
    one = E.cosign(n1, E.cosign(ok, st1))
    two = E.cosign(n2, E.cosign(n1, E.cosign(ok, st2)))
    F = E.OFFICER_FORMAT
    statements = [
        ("officer and node, one node", one, [OK_, N1], F),
        ("officer and both nodes (the HA profile)", two, [OK_, N1, N2], F),
        ("a node's signature missing", E.cosign(ok, st2) | {}, [OK_, N1, N2], F),
        ("an extra signature", E.cosign(other, one), [OK_, N1], F),
        ("the same key twice", {**one, "signatures": one["signatures"] + one["signatures"][:1]}, [OK_, N1], F),
        ("a wrong key_id", {**one, "signatures": [{**s, "key_id": "0" * 16} for s in one["signatures"]]}, [OK_, N1], F),
        ("an upper-case signature", {**one, "signatures": [{**s, "signature": s["signature"].upper()} for s in one["signatures"]]},
         [OK_, N1], F),
        ("non-canonical bytes signed by all", (lambda raw: {"bytes": base64.b64encode(raw).decode(), "signatures": sorted(
            [{"key": E.public_hex(k), "key_id": E.key_id(E.public_hex(k)), "signature": k.sign(raw).hex()} for k in (ok, n1)],
            key=lambda s: s["key"])})(json.dumps({**st1}, sort_keys=True).encode()), [OK_, N1], F),
        ("another format", E.cosign(n1, E.cosign(ok, {**st1, "format": E.CEILING_FORMAT}, E.CEILING_FORMAT), E.CEILING_FORMAT),
         [OK_, N1], F),
        ("an extra member beside bytes and signatures", {**one, "note": "x"}, [OK_, N1], F),
    ]
    cdoc = {"edge": "edge-a", "serial": 2, "persons": ["idp:7c1f-ann"], "roles": [], "targets": ["plc-ssh"], "classes": ["low"],
            "max_lease_hours": 720, "max_offline_hours": 12, "profile": "assured", "remote_reach": "off", "ports": [22],
            "signed_at": "2026-10-23T10:00:00Z"}
    sc = E.seal_ceiling(ok, cdoc)
    ceilings = [
        ("a sealed ceiling", sc, "edge-a", OK_, 0),
        ("below the floor held", sc, "edge-a", OK_, 3),
        ("for another edge", sc, "edge-b", OK_, 0),
        ("sealed by another key", E.seal_ceiling(other, cdoc), "edge-a", OK_, 0),
        ("a member missing", E.seal_ceiling(ok, {k: v for k, v in cdoc.items() if k != "ports"}), "edge-a", OK_, 0),
        ("the bytes re-encoded with spaces", {**sc, "bytes": base64.b64encode(json.dumps(E.opened(sc), sort_keys=True).encode()).decode()},
         "edge-a", OK_, 0),
    ]
    t = datetime(2026, 10, 24, 9, 0, tzinfo=timezone.utc)
    pins = {"edge": "edge-a", "bundle_key": E.public_hex(bk), "officer_key": OK_, "release_key": None}
    notice = E.ended_notice(bk, "edge-a", t, "decommissioned", [N1])
    ended = [
        ("this node's notice", notice, pins, N1),
        ("a notice for the other node's key", notice, pins, N2),
        ("a notice for another edge", E.ended_notice(bk, "edge-b", t, "decommissioned", [N1]), pins, N1),
        ("both nodes ended (the HA profile)", E.ended_notice(bk, "edge-a", t, "decommissioned", [N1, N2]), pins, N2),
        ("the v1 shape: no enrolment keys", E.seal(bk, {"edge": "edge-a", "ended": "2026-10-24T09:00:00Z", "reason": "x"},
                                                   E.ENDED_FORMAT), pins, N1),
        ("signed by another key", E.ended_notice(other, "edge-a", t, "decommissioned", [N1]), pins, N1),
    ]
    dp, ep = "1" * 63 + "7", "2" * 63 + "9"           # fixed P-256 scalars for the vectors only
    dpub, epub = (E.unlock_public(E.unlock_private(x)) for x in (dp, ep))
    nid = E.key_id(N1)
    u = {"desk_private": dp, "edge_private": ep, "desk_public": dpub, "edge_public": epub, "edge": "edge-a", "node": nid,
         "person": "idp:7c1f-ann", "fingerprint": "SHA256:abcdefghijklmnop", "target": "plc-ssh", "nonce": "n0nce0001",
         "minutes": 30}
    unlock = [
        ("a code both sides compute", u),
        ("another node gives another code", {**u, "node": E.key_id(N2)}),
        ("another nonce gives another code", {**u, "nonce": "n0nce0002"}),
        ("a field with a pipe is refused", {**u, "target": "plc|ssh"}),
        ("an unlock key that is not on the curve", {**u, "edge_public": E._b64u(b"\x04" + b"\x01" * 64)}),
    ]
    rk = _key(7)
    RK = E.public_hex(rk)
    T = 1793102400                                       # fixed moment of the signed requests

    def req(name, path, method="GET", body=b"", signed_path=None, signed_body=None, key=rk, now=T):
        header = E.sign_request(key, "edge-a", method, signed_path or path, body if signed_body is None else signed_body,
                                seconds=T, nonce="bm9uY2Utb2YtdGhlLWNhc2U")
        return (name, {"edge": "edge-a", "method": method, "path": path, "body": base64.b64encode(body).decode(),
                       "seconds": T, "nonce": "bm9uY2Utb2YtdGhlLWNhc2U", "header": header, "public_key": RK, "now": now})
    bundle = "/api/v1/edge/bundle"
    requests = [
        req("a plain pull", bundle),
        req("a long-poll: after and wait are in the signed path", bundle + "?after=7&wait=55"),
        req("the wait changed after signing", bundle + "?after=7&wait=55", signed_path=bundle + "?after=7&wait=5"),
        req("the parameters reordered after signing", bundle + "?wait=55&after=7", signed_path=bundle + "?after=7&wait=55"),
        req("a report with a body", "/api/v1/edge/report", "POST", b'{"applied":[]}'),
        req("the body changed after signing", "/api/v1/edge/report", "POST", b'{"applied":[1]}',
            signed_body=b'{"applied":[]}'),
        req("signed by another key", bundle, key=_key(8)),
        req("the clock more than five minutes off", bundle, now=T + 301),
    ]
    wasm = b"\x00asm\x01\x00\x00\x00"
    import hashlib
    modules = [
        ("bytes matching the hash", wasm, hashlib.sha256(wasm).hexdigest()),
        ("bytes not matching the hash", wasm + b"\x00", hashlib.sha256(wasm).hexdigest()),
        ("not WebAssembly", b"\x7fELF", hashlib.sha256(b"\x7fELF").hexdigest()),
    ]
    nonce = "bm9uY2Utb2YtdGhlLWNhc2U"
    ann = "kc:" + "a" * 32

    address = "ann" + "@" + "example.org"           # inside the sealed bytes only: the vectors record its digest

    def answer(email=address, edge="edge-a", lease="L-example-0001", n=nonce, key=bk):
        return E.email_answer(key, edge, lease, ann, email, n, t)
    email = [
        ("the address for this lease and request", answer()),
        ("no verified address: null", answer(email=None)),
        ("an answer for another edge", answer(edge="edge-b")),
        ("an answer for another lease", answer(lease="L-example-0002")),
        ("an answer to another request (replayed)", answer(n="b3RoZXItcmVxdWVzdC1ub25jZQ")),
        ("signed by another key", answer(key=other)),
        ("not an address", answer(email="ann")),
        ("an ended notice is not an answer", notice),
    ]
    raw = {
        "statements": [{"name": n, "sealed": s, "required": r, "format": f} for n, s, r, f in statements],
        "ceilings": [{"name": n, "sealed": s, "edge": e, "officer_key": k, "floor": fl} for n, s, e, k, fl in ceilings],
        "ended": [{"name": n, "sealed": s, "pins": p, "enrolment_key": k} for n, s, p, k in ended],
        "unlock": [{"name": n, **c} for n, c in unlock],
        "module_bytes": [{"name": n, "wasm": base64.b64encode(w).decode(), "sha256": h} for n, w, h in modules],
        "requests": [{"name": n, **c} for n, c in requests],
        "email": [{"name": n, "sealed": s, "pins": pins, "lease_id": "L-example-0001", "nonce": nonce} for n, s in email],
    }
    notes = {"statements": "unseal_multi(sealed, required, format); ok, and what it says when ok",
             "ceilings": "check_ceiling(edge, officer_key, sealed, floor)", "ended": "verify_ended(sealed, pins, enrolment_key)",
             "unlock": "kc-unlock-v2: the node (edge_private, desk_public) and the desk (desk_private, edge_public) reach "
                       "the same code, or both refuse (code null)",
             "module_bytes": "verify_module(bytes, sha256)",
             "requests": "kc-edge-request-v2 (section 3): message is the bytes the edge signs, base64; ok is the desk's check "
                         "of the header against the request as received (method, path with its query, body), the pinned "
                         "key and the moment now (unix seconds); the query is signed exactly as sent",
             "email": "verify_email(sealed, pins, lease_id, nonce), edge protocol 1.3: ok, and email_sha256, the sha256 hex "
                      "of the address it gives (null when ok with no address, or when refused); nonce is the nonce of the "
                      "edge's own signed request the answer is for"}
    out = {}
    for fam, cases in raw.items():
        for c in cases:
            c["expected"] = EC.verdict(fam, c)
        out[fam] = {"note": notes[fam], "cases": cases}
    return out


def build() -> dict:
    mods = {p: hashlib.sha256((ROOT / "keyclerk" / "policy" / f"{p}.wasm").read_bytes()).hexdigest() for p in ("edge", "ceiling")}
    cases = [{"policy": p, "entrypoint": f"keyclerk/{p}/{e}", "name": n, "input": i, "expected": evaluate(p, e, i)}
             for p, e, n, i in CASES]
    return {"format": "kc-conformance-v1", "modules": mods,
            "note": "evaluate each input against the module named; the result must equal expected (sets as sorted lists)",
            "cases": cases, "verifier": verifier_cases(), **families()}


def main() -> int:
    out = ROOT / "tests" / "conformance" / "edge.json"
    out.write_text(json.dumps(build(), indent=1, sort_keys=True, default=sorted) + "\n", encoding="utf-8", newline="\n")
    print(out.relative_to(ROOT), len(CASES), "cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
