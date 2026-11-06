# SPDX-License-Identifier: EUPL-1.2
"""High availability as signed realm configuration (decision 0031 point 3).

A head record in the change log turns the core's HA mode on: `ha {origin, commit_witness, nodes}`. Consumers (desks,
followers, edges' bundles) read it from the signed log, never from its absence, so HA cannot be switched off by leaving
it out, and a new commit witness after a loss is named the same way, by a signed change.

    origin          the log's origin in its C2SP checkpoints (witness.origin)
    commit_witness  the vkey of the one witness whose compare-and-swap is the commit point (Ed25519 cosigner, 0x04)
    nodes           the signer nodes that may hold the records key, by name: the active one and its standbys (two to
                    four); each link a node signs names it (decision 0031 point 11)

Without the record, nothing of this applies: one signer, as in 0.27.0.
"""
from __future__ import annotations

import re

NODE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
FIELDS = {"origin", "commit_witness", "nodes"}


def of(doc: dict) -> dict | None:
    """The realm's HA configuration, or None when HA is off."""
    h = doc.get("ha")
    return h if isinstance(h, dict) and h else None


def check(doc: dict) -> list[str]:
    from keyclerk.store import note as N
    h = doc.get("ha")
    if h is None:
        return []
    if not isinstance(h, dict) or set(h) != FIELDS:
        return ["ha: {origin, commit_witness, nodes}, each given (decision 0031 point 3)"]
    errs = []
    try:
        N.check_name(h["origin"])
        if h["origin"].startswith("kc-"):
            errs.append("ha.origin: not starting kc-, the prefix of KeyClerk's own signed formats")
    except N.NoteRefused as e:
        errs.append(f"ha.origin: {e}")
    try:
        if N.parse_vkey(h["commit_witness"])[1] != N.COSIGNATURE:
            errs.append("ha.commit_witness: the witness's cosigner key (type 0x04), not a log key")
    except N.NoteRefused as e:
        errs.append(f"ha.commit_witness: {e}")
    nodes = h["nodes"]
    if (not isinstance(nodes, list) or not 2 <= len(nodes) <= 4 or len(set(map(str, nodes))) != len(nodes)
            or not all(isinstance(n, str) and NODE.fullmatch(n) for n in nodes)):
        errs.append("ha.nodes: two to four signer node names, each once (lower case, digits and hyphens)")
    return errs


def statement(realm: str, by: str, mode: str, size: int, head: str, value: dict | None, node: str | None) -> str:
    """The nonce a confirmation of an HA change by `by` carries: base64url(sha256(canonical statement)). It names the
    realm, the person, the mode, the base the change is signed on (the log's size and head), the configuration put (its
    hash) and, for a break-glass, the one node that signs on; so it stands for nothing else and is used once."""
    import base64
    import hashlib
    import json
    put = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest() if value else None
    body = json.dumps({"keyclerk-ha-change": 1, "realm": realm, "by": by, "mode": mode, "size": int(size), "head": head,
                       "ha_sha256": put, "node": node}, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(hashlib.sha256(body.encode()).digest()).rstrip(b"=").decode()


def main(argv: list[str] | None = None) -> int:
    """python -m keyclerk.ha nonce|sign: an HA change, offline, every signer node stopped (decision 0031).

    nonce  --signer-state DIR --key FILE --config FILE (--set FILE | --off | --break-glass NODE) --by ID
           [--commit-witness URL]       the statement one person signs in with at the broker (twice: the officer, a
                                        root trust owner)
    sign   ... --proof ID=TOKEN_FILE (twice) --keycloak URL [--approval-issuer ..] [--approval-audience ..]
           [--commit-witness URL]       the HA change link, once both proofs hold
    """
    import argparse
    import json
    import sys
    from pathlib import Path

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from keyclerk import anchors, config, guard
    from keyclerk.signer import Signer, SignerRefused
    ap = argparse.ArgumentParser(prog="keyclerk.ha", description=main.__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("nonce", "sign"):
        p = sub.add_parser(name)
        p.add_argument("--signer-state", required=True)
        p.add_argument("--key", required=True, help="the records key file, as the signer uses it")
        p.add_argument("--config", required=True)
        m = p.add_mutually_exclusive_group(required=True)
        m.add_argument("--set", dest="set_file", help="a YAML file: {origin, commit_witness, nodes}")
        m.add_argument("--off", action="store_true")
        m.add_argument("--break-glass", dest="node", help="the one signer node that signs on, the commit witness lost")
        p.add_argument("--commit-witness", help="the current commit witness's URL (required while HA is on)")
        if name == "nonce":
            p.add_argument("--by", required=True, help="the person's broker id; mapped to the log's anchor")
        else:
            p.add_argument("--proof", action="append", default=[], help="BROKER_ID=FILE holding that person's ID token")
            p.add_argument("--approval-issuer", action="append", default=[])
            p.add_argument("--approval-audience", action="append", default=[])
            p.add_argument("--keycloak", required=True)
            p.add_argument("--max-age", type=int, default=300)
    a = ap.parse_args(argv)
    mode = "set" if a.set_file else "off" if a.off else "break_glass"
    value = guard.load_yaml(Path(a.set_file)) if a.set_file else None
    config.configure(a.config)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(a.key), 200).strip()))
    signer = Signer(key, Path(a.signer_state))
    try:
        store = signer.replica
        if store is None or signer.broken:
            print(f"the signer's state is not ready: {signer.broken or 'no replica'}", file=sys.stderr)
            return 1
        inward = lambda who: anchors.inward(store, who) or who            # noqa: E731
        if a.cmd == "nonce":
            print(statement(store.realm, inward(a.by), mode, store.size(), store.head().hex(), value, a.node))
            print(f"confirms: {mode} at size {store.size()}, head {store.head().hex()[:16]}"
                  + (f", node {a.node} signs on" if a.node else ""), file=sys.stderr)
            return 0
        from keyclerk import approvals
        from keyclerk.commit_witness import CommitClient
        verify = approvals.BrokerProofs(a.approval_issuer, a.approval_audience, a.max_age,
                                        f"{a.keycloak}/realms/{store.realm}/protocol/openid-connect/certs")
        verify.resolve = lambda claims: anchors.resolve(store, claims)
        confirmations = []
        for p in a.proof:
            who, _, f = p.partition("=")
            confirmations.append((inward(who), Path(f).read_text(encoding="utf-8").strip()))
        try:
            out = signer.ha_change(mode, value, a.node, confirmations, verify,
                                   CommitClient(a.commit_witness) if a.commit_witness else None)
        except SignerRefused as e:
            print(f"no HA change: {e}", file=sys.stderr)
            return 1
        print(json.dumps({"mode": mode, "revision": out["revision"], "hash": out["hash"]}, sort_keys=True))
        return 0
    finally:
        signer.close()


if __name__ == "__main__":
    import sys
    sys.exit(main())


def committed(note: str, cfg: dict, pinned: str) -> tuple[int, bytes]:
    """(size, root) of the commit witness's countersigned checkpoint (decision 0031 point 6): the records key's
    signature and the commit witness's cosignature both checked, for the log's origin. ValueError when either fails,
    so a consumer adopts nothing a signer node only claims was committed."""
    from keyclerk.store import note as N
    try:
        text, sigs = N.split(note)
        origin, size, root = N.parse_checkpoint(text)
        if origin != cfg["origin"]:
            raise ValueError(f"a checkpoint of {origin[:60]}, not of this log's origin")
        if N.verify(text, sigs, (origin, N.LOG, bytes.fromhex(pinned))) is None:
            raise ValueError("the checkpoint is not signed by the records key")
        if N.verify(text, sigs, N.parse_vkey(cfg["commit_witness"])) is None:
            raise ValueError("the checkpoint is not countersigned by the log's commit witness")
    except N.NoteRefused as e:
        raise ValueError(str(e)) from None
    return size, root
