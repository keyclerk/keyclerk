"""Write tests/conformance/log.json: the change log's links, checkpoints and tree roots with their verdicts (decision
0022: canonical bytes and tree, with vectors). The key is derived from a fixed seed and Ed25519 signatures are
deterministic, so running it again writes the same file; a test holds that. Run it after changing keyclerk/store/link.py
or merkle.py, and commit the result. """
from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from keyclerk import edge as E  # noqa: E402
from keyclerk import log_conformance  # noqa: E402
from keyclerk.store import link as L  # noqa: E402
from keyclerk.store.memory import MemoryStore  # noqa: E402

OUT = ROOT / "tests" / "conformance" / "log.json"
KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"kc-log-conformance-v1 records key").digest())
OTHER = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"kc-log-conformance-v1 another key").digest())
PINNED = E.public_hex(KEY)
REALM = "example"
AT = "2026-10-24T12:00:00Z"
TOKEN = "eyJ.a-broker-id-token.sig"


def put(kind, rec, key=None):
    return {"op": "put", "kind": kind, "key": key or L.record_key(kind, rec), "record": rec}


CHANGES = [
    ("the genesis", [put("head", {"value": "example"}, "realm"),
                     put("groups", {"group_id": "ops", "risk": "low"}),
                     put("persons", {"person": "idp:0001", "name": "A"})],
     {"action": "seed", "actor": None, "outcome": "applied"}),
    ("a membership", [put("memberships", {"membership_id": "M-example-0001", "anchor": "idp:0001", "group": "ops",
                                          "start": "2026-10-24T00:00:00Z", "end": "2027-10-24T00:00:00Z"})],
     {"action": "add_member", "actor": "idp:0001", "outcome": "applied"}),
    ("an approval proof, by the hash of its token", [put("approval_proofs", L.proof_record(
        {"records": ["M-example-0001"], "by": "idp:0001", "token": TOKEN}))],
     {"action": "approve", "actor": "idp:0001", "outcome": "applied"}),
    ("a delete", [{"op": "del", "kind": "memberships", "key": "M-example-0001"}],
     {"action": "remove_member", "actor": "idp:0001", "outcome": "applied"}),
]


def signed_raw(key, label: str, raw: bytes) -> dict:
    """Sealed bytes exactly as given: how a malformed body still carries a valid signature."""
    return {"bytes": base64.b64encode(raw).decode("ascii"), "signature": key.sign(L._message(label, raw)).hex()}


def body(seq, prev, ops, entry, fence=1, realm=REALM):
    return {"format": L.LINK_FORMAT, "realm": realm, "seq": seq, "prev": prev, "fence": fence, "at": AT,
            "change": {"ops": ops, "entry": entry}}


YAML = {"realm": REALM, "home": "example-host",
        "groups": [{"group_id": "ops"}, {"group_id": "plant"}, {"group_id": "visitors"}],
        "memberships": [{"membership_id": "M-example-0001", "group": "ops", "start": "2026-10-24T00:00:00Z",
                         "member": {"anchor": "idp:0001"}}],
        "grants": [], "revocations": [], "suspensions": [],
        "approval_proofs": [{"records": ["M-example-0001"], "by": "idp:0001", "token": TOKEN}],
        "revision": 12}


def migration_cases() -> list[dict]:
    """One signed YAML revision migrated in two parts, then one ordinary change; and the ways it must fail."""
    import yaml
    from keyclerk.store import migrate as M
    raw = yaml.dump(YAML, sort_keys=False)
    sha = hashlib.sha256(raw.encode()).hexdigest()
    head, ops, side = M.split(M.R.loads(raw))
    p1, p2 = ops[:3], ops[3:]
    side_rows = [["genesis_yaml", sha, {"text": raw}]] + [[k, key, rec] for k, items in side.items() for key, rec in items]

    def chain(parts, sig=None, extra=None, k=None):
        sig = sig or KEY.sign(raw.encode()).hex()
        out, h = [], None
        g = L.seal_link(KEY, REALM, 0, L.ZERO, 1, AT, head, {"action": "migrated"},
                        yaml={"revision": 12, "sha256": sha, "signature": sig, "parts": k or len(parts)})
        out.append(g)
        h = L.open_link(g, PINNED)[1]
        for i, p in enumerate(parts, 1):
            s = L.seal_link(KEY, REALM, i, h.hex(), 1, AT, p, {"action": "migrate"},
                            migrate={"part": i, "parts": k or len(parts)})
            out.append(s)
            h = L.open_link(s, PINNED)[1]
        for seq, ops_, mig in extra or []:
            s = L.seal_link(KEY, REALM, seq, h.hex(), 1, AT, ops_, {"action": "test"}, migrate=mig)
            out.append(s)
            h = L.open_link(s, PINNED)[1]
        return out

    change = [put("groups", {"group_id": "zz-new"})]
    cases = [
        ("a migration in two parts, proven at link 2, then a change", side_rows, chain([p1, p2], extra=[(3, change, None)])),
        ("the YAML bytes erased: accepted, not re-provable", side_rows[1:], chain([p1, p2], extra=[(3, change, None)])),
        ("a change inside the migration", side_rows, chain([p1], extra=[(2, change, None)], k=2)),
        ("a migrate link after the migration", side_rows, chain([p1, p2], extra=[(3, change, {"part": 3, "parts": 3})])),
        ("a record left out of the migration", side_rows, chain([p1, p2[1:]])),
        ("the YAML revision signed by another key", side_rows, chain([p1, p2], sig=OTHER.sign(raw.encode()).hex())),
    ]
    return [{"name": n, "pinned": PINNED, "realm": REALM, "side": s, "links": ls} for n, s, ls in cases]


def main() -> int:
    store = MemoryStore(PINNED, REALM)
    chain, links = [], []
    for i, (name, ops, entry) in enumerate(CHANGES):
        ctx = {"pinned": PINNED, "realm": REALM, "size": store.size(),
               "head": store.head().hex() if store.head() else None, "fence": 1}
        sealed = L.seal_link(KEY, REALM, i, ctx["head"] or L.ZERO, 1, AT, ops, entry)
        store.append(sealed)
        chain.append((ctx, sealed))
        links.append({"name": name, **ctx, "sealed": sealed})
    ctx2, s2 = chain[2]
    prev2 = ctx2["head"]
    b2 = body(2, prev2, CHANGES[2][1], CHANGES[2][2])
    raw2 = E.canonical(b2)
    bad = [
        ("a byte of the body changed", ctx2, {**s2, "bytes": base64.b64encode(raw2.replace(b"approve", b"apprOve")).decode()}),
        ("signed by another key", ctx2, L.seal_link(OTHER, REALM, 2, prev2, 1, AT, CHANGES[2][1], CHANGES[2][2])),
        ("signed under the checkpoint label", ctx2, signed_raw(KEY, L.CHECKPOINT_FORMAT, raw2)),
        ("not canonical: a space after a colon", ctx2, signed_raw(KEY, L.LINK_FORMAT, raw2.replace(b'"seq":2', b'"seq": 2'))),
        ("a duplicate key", ctx2, signed_raw(KEY, L.LINK_FORMAT, raw2.replace(b'"seq":2', b'"seq":2,"seq":2'))),
        ("a float", ctx2, signed_raw(KEY, L.LINK_FORMAT, raw2.replace(b'"fence":1', b'"fence":1.0'))),
        ("base64 with a line break", ctx2, {**s2, "bytes": s2["bytes"][:76] + "\n" + s2["bytes"][76:]}),
        ("the link before it, again", ctx2, chain[1][1]),
        ("prev names another link", ctx2, L.seal_link(KEY, REALM, 2, chain[1][0]["head"], 1, AT, CHANGES[2][1], CHANGES[2][2])),
        ("seq skipped", ctx2, L.seal_link(KEY, REALM, 3, prev2, 1, AT, CHANGES[2][1], CHANGES[2][2])),
        ("fence lower than the link before", {**ctx2, "fence": 2}, s2),
        ("another realm", ctx2, L.seal_link(KEY, "elsewhere", 2, prev2, 1, AT, CHANGES[2][1], CHANGES[2][2])),
        ("a visit in the log", ctx2, signed_raw(KEY, L.LINK_FORMAT, E.canonical(body(2, prev2, [
            {"op": "put", "kind": "visits", "key": "V-1", "record": {"visit_id": "V-1"}}], CHANGES[2][2])))),
        ("a proof that carries its token", ctx2, signed_raw(KEY, L.LINK_FORMAT, E.canonical(body(2, prev2, [put(
            "approval_proofs", {"records": ["M-example-0001"], "by": "idp:0001", "token": TOKEN, "sha256": "0" * 64},
            "0" * 64)], CHANGES[2][2])))),
        ("ops out of order", ctx2, signed_raw(KEY, L.LINK_FORMAT, E.canonical(body(2, prev2, [
            put("groups", {"group_id": "z"}), put("groups", {"group_id": "a"})], CHANGES[2][2])))),
        ("a key that is not the record's own", ctx2, signed_raw(KEY, L.LINK_FORMAT, E.canonical(body(2, prev2, [
            put("groups", {"group_id": "a"}, "b")], CHANGES[2][2])))),
    ]
    links += [{"name": n, **c, "sealed": s} for n, c, s in bad]
    for c in links:
        c["expected"] = log_conformance.verdict("links", c)

    size, root, head = store.size(), store.root(), store.head()
    cpc = {"pinned": PINNED, "realm": REALM, "size": size, "root": root.hex(), "head": head.hex()}
    good = L.seal_checkpoint(KEY, REALM, size, root, head, 1, AT)
    cbody = E.canonical({"format": L.CHECKPOINT_FORMAT, "realm": REALM, "size": size, "root": root.hex(),
                         "head": head.hex(), "fence": 1, "at": AT})
    checkpoints = [
        ("the checkpoint of the four links", cpc, good),
        ("a root that is not the log's", cpc, L.seal_checkpoint(KEY, REALM, size, b"\x11" * 32, head, 1, AT)),
        ("a size that is not the log's", cpc, L.seal_checkpoint(KEY, REALM, size - 1, root, head, 1, AT)),
        ("a head that is not the log's", cpc, L.seal_checkpoint(KEY, REALM, size, root, bytes.fromhex(chain[2][0]["head"]), 1, AT)),
        ("signed by another key", cpc, L.seal_checkpoint(OTHER, REALM, size, root, head, 1, AT)),
        ("signed under the link label", cpc, signed_raw(KEY, L.LINK_FORMAT, cbody)),
    ]
    checkpoints = [{"name": n, **c, "sealed": s} for n, c, s in checkpoints]
    for c in checkpoints:
        c["expected"] = log_conformance.verdict("checkpoints", c)

    tree = [{"name": f"{n} leaves", "leaves": [f"leaf {i}".encode().hex() for i in range(n)]} for n in (*range(1, 9), 13)]
    for c in tree:
        c["expected"] = log_conformance.verdict("tree", c)

    logs = migration_cases()
    for c in logs:
        c["expected"] = log_conformance.verdict("logs", c)

    doc = {"format": "kc-log-conformance-v1",
           "note": "Decision 0022: change links and checkpoints sealed as signed bytes (message = label + LF + bytes; "
                   "link hash = SHA-256(0x00 || message || signature)), RFC 6962 roots, and whole logs migrated from a "
                   "signed YAML revision. Written by tools/gen_log_conformance.py; regenerate after changing the formats.",
           "pinned": PINNED,
           "links": {"cases": links}, "checkpoints": {"cases": checkpoints}, "tree": {"cases": tree},
           "logs": {"cases": logs}}
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
    print(f"{OUT.relative_to(ROOT)}: {log_conformance.count(doc)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
