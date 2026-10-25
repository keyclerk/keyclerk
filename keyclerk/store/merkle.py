"""The change log's Merkle tree, RFC 6962 section 2.1 (decision 0022: specified canonically, with vectors, for verifiers
outside the signer).

    leaf(d)    = SHA-256(0x00 || d)          d = a link's signed message and its signature
    node(l, r) = SHA-256(0x01 || l || r)
    MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n])), k the largest power of two below n; MTH of one leaf is its leaf hash

The prefixes keep a leaf from ever passing for a node. A store keeps the frontier (the roots of the perfect subtrees,
largest first, at most log2 n of them), so an append costs a logarithm and the root folds from the frontier.
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
