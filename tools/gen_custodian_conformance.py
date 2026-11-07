# SPDX-License-Identifier: EUPL-1.2
"""Write tests/conformance/custodian.json: what keyclerk-custodian signs and refuses (decision 0033 point 9), in order,
from a fresh state (realm example, origin keyclerk.example/vectors) under a fixed key, so every expected signature is
exact. The Go custodian replays them (cmd/keyclerk-custodian/vectors_test.go); tests/test_custodian_vectors.py holds
them against this generator and the store's own structural check.

    python tools/gen_custodian_conformance.py
"""
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from keyclerk import edge as E  # noqa: E402
from keyclerk.store import link as L  # noqa: E402
from keyclerk.store import merkle  # noqa: E402
from keyclerk.store import note as N  # noqa: E402

OUT = ROOT / "tests" / "conformance" / "custodian.json"
SEED = bytes(range(32))
REALM, ORIGIN = "example", "keyclerk.example/vectors"
AT = "2026-11-07T12:00:00Z"


def body(seq, prev, fence=1, realm=REALM, at=AT, ops=None):
    b = L.link_body(realm, seq, prev, max(fence, 1), at, ops or [{"op": "put", "kind": "head", "key": "realm",
                                                                    "record": {"value": realm}}],
                    {"change_id": "C-0123456789ab", "action": "x", "actor": None, "outcome": "applied", "records": {}})
    return {**b, "fence": fence}


def link_msg(b) -> bytes:
    return L._message(L.LINK_FORMAT, E.canonical(b))


def main() -> int:
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    steps, frontier, size, head = [], [], 0, None

    def step(name, data: bytes, refused: str | None = None):
        s = {"name": name, "data": base64.b64encode(data).decode()}
        if refused:
            s["refused"] = refused
        else:
            s["signature"] = key.sign(data).hex()
        steps.append(s)
        return s

    def took(data: bytes, sig_hex: str):
        nonlocal frontier, size, head
        h = merkle.leaf(data + bytes.fromhex(sig_hex))
        frontier, size, head = merkle.push(frontier, h), size + 1, h

    first = link_msg(body(0, L.ZERO))
    took(first, step("link 0, the next position", first)["signature"])
    step("the same body at position 0 again: the same signature", first)
    step("another body at position 0", link_msg(body(0, L.ZERO, at="2026-11-07T12:00:01Z")), "one body per position")
    step("a link skipping a position", link_msg(body(2, head.hex())), "where link 1 comes next")
    step("a link naming another hash", link_msg(body(1, "f" * 64)), "last link's hash")
    step("a link for another realm", link_msg(body(1, head.hex(), realm="another")), "realm")
    step("a link whose fence is below the last", link_msg(body(1, head.hex(), fence=0)), "fence")
    wide = [{"op": "put", "kind": "memberships", "key": f"M-{i:04d}", "record": {"membership_id": f"M-{i:04d}"}}
            for i in range(501)]
    step("a change of more than 500 records of one kind", link_msg(body(1, head.hex(), ops=wide)), "more than 500")
    second = link_msg(body(1, head.hex()))
    took(second, step("link 1", second)["signature"])
    root = merkle.root(frontier)
    cp = {"format": L.CHECKPOINT_FORMAT, "realm": REALM, "size": size, "root": root.hex(), "head": head.hex(),
          "fence": 1, "at": AT}
    step("a checkpoint over the tree the custodian computed", L._message(L.CHECKPOINT_FORMAT, E.canonical(cp)))
    step("a checkpoint over another root", L._message(L.CHECKPOINT_FORMAT, E.canonical({**cp, "root": "a" * 64})),
         "root or head")
    step("a checkpoint over fewer links than signed", L._message(L.CHECKPOINT_FORMAT, E.canonical({**cp, "size": 1})),
         "over 1 links")
    step("a C2SP checkpoint note of the tree", N.checkpoint_text(ORIGIN, size, root).encode())
    step("a C2SP note under another origin", N.checkpoint_text("keyclerk.example/other", size, root).encode(), "origin")
    step("a statement this custodian does not sign", b"kc-unknown-v1\n{}", "not a statement")
    step("bytes with no structure of the log: a log line's hash", b"0" * 64)
    # the 2026-11-07 review: nothing unrecognised falls through to a signature, and nothing no verifier accepts
    text = N.checkpoint_text(ORIGIN, size, root)
    step("a checkpoint note with a leading zero in its size (fuzz-1)",
         text.replace(f"\n{size}\n", f"\n0{size}\n").encode(), "leading zero")
    step("a checkpoint note with an extension line (A11, diff-4)", (text + "extension\n").encode(), "three lines")
    step("a checkpoint note past 2^53 (A1)", text.replace(f"\n{size}\n", "\n9223372036854775808\n").encode(),
         "never signed")
    step("bytes that are no statement of the log: a YAML revision", b"records:\n  realm: example\n", "not a link")
    raw = E.canonical(body(2, head.hex()))
    step("a link body that is not canonical (diff-1, A12)",
         L.LINK_FORMAT.encode() + b"\n" + raw.replace(b'"at"', b' "at"', 1), "not canonical")
    step("a link whose fence is 2^53 (diff-2)",
         L.LINK_FORMAT.encode() + b"\n" + raw.replace(b'"fence":1', b'"fence":9007199254740992', 1), "2^53")
    short = {"format": L.CHECKPOINT_FORMAT, "realm": REALM, "size": size, "root": root.hex(), "head": head.hex()}
    step("a checkpoint body missing fence and at (diff-3)", L._message(L.CHECKPOINT_FORMAT, E.canonical(short)),
         "not a kc-checkpoint-v1 body")
    doc = {"format": "kc-custodian-vectors-v1", "realm": REALM, "origin": ORIGIN, "seed": SEED.hex(),
           "public": key.public_key().public_bytes_raw().hex(), "steps": steps}
    OUT.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(f"{len(steps)} steps in {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
