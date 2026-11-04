"""The change log's Merkle tree, RFC 6962 section 2.1 (decision 0022: specified canonically, with vectors, for verifiers
outside the signer).

    leaf(d)    = SHA-256(0x00 || d)          d = a link's signed message and its signature
    node(l, r) = SHA-256(0x01 || l || r)
    MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n])), k the largest power of two below n; MTH of one leaf is its leaf hash

The prefixes keep a leaf from ever passing for a node. A store keeps the frontier (the roots of the perfect subtrees,
largest first, at most log2 n of them), so an append costs a logarithm and the root folds from the frontier.

Consistency proofs are RFC 9162 section 2.1.4 (the same as RFC 6962 section 2.1.2): what a witness checks before it
countersigns a larger tree of the same log (c2sp.org/tlog-witness, keyclerk.witness).
"""
from __future__ import annotations

import hashlib

EMPTY = hashlib.sha256(b"").digest()      # the empty tree: never signed (a checkpoint has at least one link)


def leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def mth(leaves: list[bytes]) -> bytes:
    """The tree hash of leaf hashes, by the RFC's recursion: the reference the frontier is tested against."""
    n = len(leaves)
    if n == 0:
        return EMPTY
    if n == 1:
        return leaves[0]
    k = 1 << ((n - 1).bit_length() - 1)
    return node(mth(leaves[:k]), mth(leaves[k:]))


def push(frontier: list[tuple[int, bytes]], h: bytes) -> list[tuple[int, bytes]]:
    """The frontier after one more leaf hash: (height, hash) pairs, two subtrees of one height merge."""
    out = [*frontier, (0, h)]
    while len(out) > 1 and out[-1][0] == out[-2][0]:
        (hl, left), (_, right) = out[-2], out[-1]
        out[-2:] = [(hl + 1, node(left, right))]
    return out


def root(frontier: list[tuple[int, bytes]]) -> bytes:
    """The tree hash from the frontier: the subtrees folded from the right, as MTH splits them."""
    if not frontier:
        return EMPTY
    r = frontier[-1][1]
    for _, h in reversed(frontier[:-1]):
        r = node(h, r)
    return r


def size(frontier: list[tuple[int, bytes]]) -> int:
    return sum(1 << h for h, _ in frontier)


def consistency(hashes: list[bytes], m: int) -> list[bytes]:
    """The proof that the tree of the first m leaf hashes is a prefix of the tree of all of them (RFC 9162 2.1.4.1);
    empty for m == 0 or m == len(hashes), as the witness protocol sends it."""
    n = len(hashes)
    if not 0 <= m <= n:
        raise ValueError(f"no consistency proof from {m} to {n} leaves")
    if m in (0, n):
        return []

    def sub(m: int, lo: int, hi: int, whole: bool) -> list[bytes]:
        if m == hi - lo:
            return [] if whole else [mth(hashes[lo:hi])]
        k = 1 << ((hi - lo - 1).bit_length() - 1)
        if m <= k:
            return sub(m, lo, lo + k, whole) + [mth(hashes[lo + k:hi])]
        return sub(m - k, lo + k, hi, False) + [mth(hashes[lo:lo + k])]
    return sub(m, 0, n, True)


def consistent(m: int, n: int, old: bytes, new: bytes, proof: list[bytes]) -> bool:
    """Whether proof shows the tree of size m with root old is a prefix of the tree of size n with root new (RFC 9162
    2.1.4.2). Size 0 is consistent with every tree, by an empty proof."""
    if not 0 <= m <= n:
        return False
    if m == 0:
        return not proof
    if m == n:
        return not proof and old == new
    if m & (m - 1) == 0:                  # an exact power of two: the old root is the proof's first node
        proof = [old, *proof]
    if not proof:
        return False
    fn, sn = m - 1, n - 1
    while fn & 1:
        fn, sn = fn >> 1, sn >> 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr, sr = node(c, fr), node(c, sr)
            while not fn & 1 and fn:
                fn, sn = fn >> 1, sn >> 1
        else:
            sr = node(sr, c)
        fn, sn = fn >> 1, sn >> 1
    return fr == old and sr == new and sn == 0
