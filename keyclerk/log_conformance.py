"""The change log's conformance families (decision 0022: a tree a verifier outside the signer may check is specified
canonically, with vectors), as they sit in tests/conformance/log.json: a
verifier in any language runs the same cases and must reach the same verdicts. The cases pin bytes, not a
canonicalisation rule: a verifier checks a signature over the label and the decoded bytes, never over rebuilt JSON.

    links        check_next(sealed, pinned, realm, size, head, fence): ok, and the link hash when ok
    checkpoints  check_checkpoint(sealed, pinned, realm, size, root, head): ok
    tree         the RFC 6962 root over leaf(d) for each d in leaves (hex): root
    logs         side records put first, then links appended in order until one is refused (decision 0022 S2: the
                 genesis names the signed YAML and k, links 1 to k migrate and nothing else does, link k equals the
                 YAML by meaning): how many were accepted, and what the store says of its migration
"""
from __future__ import annotations

from keyclerk.store import link as L
from keyclerk.store import merkle

FAMILIES = ("links", "checkpoints", "tree", "logs")


def verdict(family: str, c: dict) -> dict:
    """What this checkout's reference says for one case."""
    if family == "links":
        try:
            _, h = L.check_next(c["sealed"], c["pinned"], c["realm"], c["size"],
                                bytes.fromhex(c["head"]) if c["head"] else None, c["fence"])
            return {"ok": True, "hash": h.hex()}
        except L.StoreRefused:
            return {"ok": False, "hash": None}
    if family == "checkpoints":
        try:
            L.check_checkpoint(c["sealed"], c["pinned"], c["realm"], c["size"], bytes.fromhex(c["root"]),
                               bytes.fromhex(c["head"]))
            return {"ok": True}
        except L.StoreRefused:
            return {"ok": False}
    if family == "tree":
        leaves = [merkle.leaf(bytes.fromhex(d)) for d in c["leaves"]]
        frontier: list = []
        for h in leaves:
            frontier = merkle.push(frontier, h)
        r = merkle.mth(leaves)
        return {"root": r.hex() if merkle.root(frontier) == r else "the frontier and the recursion differ"}
    if family == "logs":
        from keyclerk.store.memory import MemoryStore
        store = MemoryStore(c["pinned"], c["realm"])
        for kind, key, rec in c["side"]:
            store.side_put(kind, key, rec)
        for sealed in c["links"]:
            try:
                store.append(sealed)
            except L.StoreRefused:
                break
        return {"accepted": store.size(), "migration": store.migration()}
    raise ValueError(f"no conformance family {family}")


def failures(doc: dict) -> list[str]:
    return [f"{fam}: {c['name']}" for fam in FAMILIES for c in doc.get(fam, {}).get("cases", [])
            if verdict(fam, c) != c["expected"]]


def count(doc: dict) -> int:
    return sum(len(doc.get(f, {}).get("cases", [])) for f in FAMILIES)
