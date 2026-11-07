# SPDX-License-Identifier: EUPL-1.2
"""Restore safety (decision 0019 point 5, H8): a desk restored from a backup never signs a revision number twice.

A restored desk starts in restore mode: it writes nothing, is not ready, and answers edges 503, which they treat as an
outage and keep running on their horizons (edge protocol). Edges that report meanwhile leave the serial they applied.
Resuming takes the high-water mark, commits the records again as the revision above it, raises every edge's bundle
serial above what that edge applied, runs the full check, and only then serves. Revisions lost since the backup are an
incident: people propose them again, nothing rebuilds them.

The mark comes from what saw the lost revisions. Until the witness (G10) and the edges' records heads (edge protocol
1.4) give it, two people confirm it by signature: the security officer and a root trust owner (operator 2026-11-03),
each signing in at the broker with the nonce of the restore statement.

    python -m keyclerk.restore start  --store DIR                       restore mode on (a desk running on DIR follows)
    python -m keyclerk.restore status --store DIR [--signer-state DIR] [--witness URL --witness-key VKEY --origin O
                                      --records-key HEX]          what edges reported, and the mark the sources propose
    python -m keyclerk.restore nonce  --store DIR --realm R --mark N --by ANCHOR
    python -m keyclerk.restore resume --store DIR --key FILE --realm R --mark N --proof ANCHOR=TOKEN_FILE ... (2)
    python -m keyclerk.restore recover-log --signer-state DIR --from REPLICA_DB --records-key HEX
                                      (the change log: the signer takes its lost links back from a follower)
    python -m keyclerk.restore leave  --store DIR --config FILE --signer ADDR
                                      (a desk on the change log, once its signer resumed: the erasure journal applied,
                                      edge serials raised, restore mode off)
                                      --approval-issuer URL --approval-audience CLIENT --keycloak URL
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

MARKER = "restore.json"


class RestoreMode(RuntimeError):
    """The desk is being restored: nothing is written and edges are told to wait (an outage, never an ending)."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic(path: Path, obj: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def marker(store_dir: Path) -> dict | None:
    """The restore marker of a store, or None when the store serves normally."""
    f = Path(store_dir) / MARKER
    try:
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None
    except (OSError, ValueError):
        return {"since": None, "edges": {}, "unreadable": True}     # a damaged marker still means restore mode


def start(store_dir: Path, reason: str = "restored from a backup", erasures: list[str] | None = None) -> dict:
    """Restore mode on. erasures: the visit ids the erasure journal lists (decision 0028 point 6), erased again before
    the desk serves."""
    m = marker(store_dir) or {"since": _now(), "reason": reason[:200], "edges": {}}
    if erasures:
        m["erasures"] = sorted(set(m.get("erasures") or []) | set(erasures))
    _atomic(Path(store_dir) / MARKER, m)
    return m


def apply_erasures(store, store_dir: Path) -> list[str]:
    """Erase again what the erasure journal in the marker lists and the restored copy still holds: a backup never
    brings back what was erased (decision 0028 point 6). The activity log keeps one line with the ids."""
    m = marker(store_dir) or {}
    held = set(store.visit_ids())
    vids = sorted(v for v in m.get("erasures") or [] if v in held)
    if vids:
        store.erase_visits(vids, {"change_id": "C-" + os.urandom(6).hex(), "action": "visit_erased", "actor": None,
                                  "outcome": "applied", "records": {}, "reasons": [],
                                  "summary": f"{len(vids)} visit(s) erased again after a restore (erasure journal)"})
    return vids


def _raise_edges(edge_store, m: dict) -> dict:
    raised = {}
    for edge_id, applied in (m.get("edges") or {}).items():
        st = edge_store.state(edge_id)
        if int(applied) > int(st.get("serial", 0)):
            edge_store.update_state(edge_id, serial=int(applied), last_bundle=None)
            raised[edge_id] = int(applied)
    return raised


def leave(store, edge_store, store_dir: Path) -> dict:
    """Leave restore mode on the change log (the desk never signs: its signer resumed through recover-log or the
    restore link). The desk must follow its signer without a break; then the erasure journal is applied, each edge's
    bundle serial raised above what it applied, and the marker goes."""
    m = marker(store_dir)
    if m is None:
        raise RestoreMode("the store is not in restore mode")
    if not hasattr(store, "follow_breaks"):
        raise RestoreMode("this desk keeps the signed YAML store: leave restore mode with resume")
    breaks, problems = store.follow_breaks(), store.verify_log()
    if breaks or problems:
        raise RestoreMode(f"the desk does not follow its signer cleanly ({breaks} break(s), {len(problems)} log "
                          "problem(s)): resume the signer first (recover-log or link), then try again")
    erased = apply_erasures(store, store_dir)
    raised = _raise_edges(edge_store, m)
    (Path(store_dir) / MARKER).unlink()
    return {"erased": erased, "edges_raised": raised}


def observe(store_dir: Path, edge_id: str, applied_serial: int, records_head: dict | None = None) -> None:
    """An authenticated edge reported the bundle serial it applied, and from edge protocol 1.4 the records head of
    that bundle: the highest of each per edge is kept, the serial for resume, the head as a source of the mark."""
    m = marker(store_dir)
    if m is None:
        return
    edges, heads, changed = m.setdefault("edges", {}), m.setdefault("heads", {}), False
    if int(applied_serial) > int(edges.get(edge_id, 0)):
        edges[edge_id], changed = int(applied_serial), True
    if records_head and int(records_head["revision"]) > int((heads.get(edge_id) or {}).get("revision", -1)):
        heads[edge_id], changed = dict(records_head), True
    if changed:
        _atomic(Path(store_dir) / MARKER, m)


def witness_mark(url: str, vkey: str, origin: str, records_key: str) -> dict:
    """The witness's countersigned checkpoint, both signatures checked (keyclerk.witness): how far the log was
    witnessed before the loss."""
    from keyclerk import witness as W
    from keyclerk.store import note as N
    c = W.Cosigner(url, vkey)
    status, _, body = c._call("GET", f"/{W.origin_hash(origin)}/checkpoint")
    if status != 200:
        raise RestoreMode(f"the witness serves no checkpoint of {origin} ({status})")
    text, sigs = N.split(body.decode("utf-8"))
    o, size, _ = N.parse_checkpoint(text)
    from keyclerk import records_keys as RK
    h = RK.pinned()                               # after a rotation each origin has its own key (#41)
    if h is not None:
        records_key = next((w["key"] for w in h.doc["keys"] if w["origin"] == origin), records_key)
    if o != origin or N.verify(text, sigs, (origin, N.LOG, bytes.fromhex(records_key))) is None \
            or N.verify(text, sigs, c.key) is None:
        raise RestoreMode("the witness's checkpoint is not signed by the records key and countersigned by the witness")
    return {"size": size, "witness": c.name}


def mark_sources(m: dict, log_mark: dict | None = None, witnessed: dict | None = None) -> dict:
    """The newest revision anyone saw, by each source (decision 0019 point 5): the heads edges echoed, and the
    witness's size counted from the restored log (each link after the restored ones adds one revision). A proposal:
    two people confirm the mark, as before."""
    out: dict = {}
    heads = m.get("heads") or {}
    if heads:
        edge, h = max(heads.items(), key=lambda kv: kv[1]["revision"])
        out["edges"] = {"revision": int(h["revision"]), "edge": edge, "reported": len(heads)}
    if witnessed and log_mark:
        out["witness"] = {"size": witnessed["size"], "witness": witnessed["witness"],
                          "revision": int(log_mark["revision"]) + max(0, witnessed["size"] - int(log_mark["size"]))}
    if out:
        out["proposed"] = max(v["revision"] for v in out.values())
        out["note"] = ("the newest revision these sources saw: confirm it as the mark with two people (nonce or "
                       "log-nonce, then resume or link)")
    return out


def statement(realm: str, by: str, mark: int, records_sha256: str) -> str:
    """The nonce a confirmation of the high-water mark by `by` carries: base64url(sha256(canonical statement)). It names
    the realm, the person, the mark and the records the desk was restored to, so it stands for nothing else."""
    body = json.dumps({"keyclerk-restore-mark": 1, "realm": realm, "by": by, "mark": int(mark),
                       "records_sha256": records_sha256}, sort_keys=True, separators=(",", ":"))
    return base64.urlsafe_b64encode(hashlib.sha256(body.encode()).digest()).rstrip(b"=").decode()


def confirmers(doc: dict, at: datetime) -> tuple[str | None, set[str]]:
    """Who may confirm a mark: the security officer, and the root trust owners holding the root now."""
    from keyclerk import delegation as D
    root = doc.get("root") or {}
    holders = {h["anchor"] for h in root.get("holders") or []
               if _t(h.get("from")) <= at and (h.get("to") is None or at < _t(h["to"]))}
    current = D.root_at(doc, at)
    return root.get("officer"), holders | ({current} if current else set())


def _t(x):
    from keyclerk import guard
    return x if isinstance(x, datetime) else guard.timestamp(x)


def check_confirmations(doc: dict, realm: str, mark: int, records_sha256: str, proofs: dict[str, str], verify,
                        at: datetime, nonce=None, what: str = "the mark") -> list[str]:
    """Problems with the two confirmations; [] when the officer and a root trust owner, two different people, each
    proved the statement for this mark. verify(token, nonce, by) raises when a proof does not hold. nonce(by), when
    given, is another statement two people confirm the same way (an HA change, decision 0031)."""
    nonce = nonce or (lambda by: statement(realm, by, mark, records_sha256))
    officer, roots = confirmers(doc, at)
    problems, ok = [], set()
    for by, token in proofs.items():
        if by not in roots and by != officer:
            problems.append(f"{by} is neither the security officer nor a root trust owner")
            continue
        try:
            verify(token, nonce(by), by)
            ok.add(by)
        except Exception as e:   # noqa: BLE001 - any failure: this confirmation does not count
            problems.append(f"the proof of {by} does not hold: {type(e).__name__}")
    if officer not in ok:
        problems.append(f"the security officer has not confirmed {what}")
    if not (ok - {officer}) & roots:
        problems.append(f"a root trust owner other than the officer has not confirmed {what}")
    return problems


def resume(store, edge_store, store_dir: Path, realm: str, mark: int, proofs: dict[str, str], verify,
           at: datetime | None = None) -> dict:
    """Leave restore mode: the records again as revision mark + 1, each edge's serial above what it applied, the full
    check, then the marker goes. Refuses, and stays in restore mode, on anything that does not hold."""
    from keyclerk.reconcile import check_records
    m = marker(store_dir)
    if m is None:
        raise RestoreMode("the store is not in restore mode")
    at = at or datetime.now(timezone.utc)
    doc = store.load()
    current = store.revision()
    if not isinstance(mark, int) or mark < current:
        raise RestoreMode(f"the mark {mark} is below the restored revision {current}: give the newest revision anyone saw")
    sha = hashlib.sha256(store.raw()).hexdigest()
    problems = check_confirmations(doc, realm, mark, sha, proofs, verify, at)
    if problems:
        raise RestoreMode("the high-water mark is not confirmed: " + "; ".join(problems))
    errs = check_records(doc, log_backed=False)
    if errs:
        raise RestoreMode(f"the restored records fail the full check: {errs[0]}")
    lost = mark - current
    entry = {"action": "restore_resumed", "actor": None, "outcome": "applied",
             "summary": f"resumed after a restore: revision {current} restored, {lost} revision(s) lost, "
                        f"resuming above {mark}", "reasons": [f"confirmed by {', '.join(sorted(proofs))}"]
             + ([f"incident: revisions {current + 1} to {mark} were lost and are proposed again by people"] if lost else []),
             "records": {}}
    erased = apply_erasures(store, store_dir)          # before anything is signed again; idempotent on a retry
    body = store.resume_above(mark, entry)
    raised = _raise_edges(edge_store, m)
    (Path(store_dir) / MARKER).unlink()
    return {"revision": store.revision(), "lost": lost, "edges_raised": raised, "log": body.get("seq"),
            "erased": erased}


SIDE_KINDS = ("proof_tokens", "anchor_map", "anchor_idp")   # what the lost links' changes wrote beside them


def recover_log(signer_state: Path, follower, pinned: str) -> dict:
    """On the change log a revision number is a position in a signed chain, so a signer restored from an older backup
    may not sign at the positions it lost: that would fork the chain. First choice (operator 2026-11-03): take the lost
    links back from a follower (the reconciler's or a desk's replica) whose chain verifies and starts with exactly the
    restored one. Each link is checked against the pinned records key as it is appended; the signer seals a fresh
    checkpoint when it next starts. Run with the signer stopped. Refuses, changing nothing, on a fork."""
    from keyclerk.store import link as L
    from keyclerk.store import replay
    from keyclerk.store.sqlite import SqliteStore
    state = Path(signer_state)
    mark_file = state / "log-mark.json"
    mark = json.loads(mark_file.read_text(encoding="utf-8"))
    realm = mark["realm"]
    restored = SqliteStore(state / "replica.db", pinned, realm)
    pinned = restored.pinned                      # the restored state's history, or the pinned one (#41)
    try:
        try:
            replay.verify(restored, pinned, realm)
            replay.verify(follower, pinned, realm)
        except L.StoreRefused as e:
            raise RestoreMode(f"a chain does not verify: {e}. After a records-key recovery a follower that still holds "
                              "links the stolen key signed is refused: use one that adopted the recovery, or the "
                              "restore link") from None
        have, more = restored.size(), follower.size()
        for i in range(min(have, more)):                 # a fork shows at any length, so it is looked for first
            if follower.link(i) != restored.link(i):
                raise RestoreMode(f"the follower's chain differs from the restored one at link {i}: it is not the history "
                                  "this signer had; use another follower, or the restore link")
        if more <= have:
            (state / MARKER).unlink(missing_ok=True)      # nothing was lost that this follower saw: the signer resumes
            return {"recovered": 0, "size": have, "revision": replay.revision(restored)}
        for sealed in follower.links(have):
            restored.append(sealed)
        added, differ = [], []
        for kind in SIDE_KINDS:
            mine = dict(restored.side_scan(kind))
            for k, v in follower.side_scan(kind):
                if k not in mine:
                    added.append((kind, k, v))
                elif mine[k] != v:
                    differ.append(f"{kind}/{k}")          # reported, never overwritten: the follower may not own it
        restored.side_put_many(added)
        cp = follower.checkpoint()
        if cp and L.open_checkpoint(cp, pinned)["size"] == restored.size():
            restored.add_checkpoint(cp)
        tmp = state / "log-mark.json.tmp"
        tmp.write_text(json.dumps({"realm": realm, "size": restored.size(), "head": restored.head().hex(),
                                   "revision": replay.revision(restored)}), encoding="utf-8", newline="\n")
        os.replace(tmp, mark_file)
        (state / MARKER).unlink(missing_ok=True)          # the lost positions are back: the signer may sign again
        return {"recovered": more - have, "size": restored.size(), "revision": replay.revision(restored),
                "side_rows_added": len(added), "side_rows_differ": differ[:50]}
    finally:
        restored.close()


def _log_command(a) -> int:
    """log-nonce and link: the signer opened offline (stopped), people named by their broker id and mapped to the
    log's internal anchors (decision 0028)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from keyclerk import anchors, config, guard
    from keyclerk.signer import Signer, SignerRefused
    config.configure(a.config)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(a.key), 200).strip()))
    signer = Signer(key, Path(a.signer_state))
    try:
        store = signer.replica
        if store is None or signer.broken:
            print(f"the signer's state is not ready: {signer.broken or 'no replica'}", file=sys.stderr)
            return 1
        inward = lambda who: anchors.inward(store, who) or who            # noqa: E731
        head = store.head().hex()
        if a.cmd == "log-nonce":
            print(statement(store.realm, inward(a.by), a.mark, head))
            if a.trustee_statement:
                from keyclerk.store import link as L
                Path(a.trustee_statement).write_bytes(
                    b"kc-restore-v1\n" + L.restore_statement(store.realm, store.size(), head, a.mark))
            return 0
        from keyclerk import approvals
        verify = approvals.BrokerProofs(a.approval_issuer, a.approval_audience, a.max_age,
                                        f"{a.keycloak}/realms/{store.realm}/protocol/openid-connect/certs")
        verify.resolve = lambda claims: anchors.resolve(store, claims)
        confirmations = []
        for p in a.proof:
            who, _, f = p.partition("=")
            confirmations.append((inward(who), Path(f).read_text(encoding="utf-8").strip()))
        try:
            from keyclerk.ha import trustee_sigs
            out = signer.restore_link(a.mark, confirmations, verify, trustee_sigs(a.trustee_sig))
        except SignerRefused as e:
            print(f"no restore link: {e}", file=sys.stderr)
            return 1
        print(json.dumps({"revision": out["revision"], "hash": out["hash"]}, sort_keys=True))
        return 0
    finally:
        signer.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="keyclerk.restore", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    rl = sub.add_parser("recover-log")
    rl.add_argument("--signer-state", required=True)
    rl.add_argument("--from", dest="source", required=True, help="a follower's replica.db (the reconciler's or a desk's)")
    rl.add_argument("--records-key", required=True, help="the records public key (hex), pinned")
    for name in ("log-nonce", "link"):                 # the change log, when no follower holds the lost links
        p = sub.add_parser(name)
        p.add_argument("--signer-state", required=True)
        p.add_argument("--key", required=True, help="the records key file, as the signer uses it")
        p.add_argument("--config", required=True)
        p.add_argument("--mark", type=int, required=True)
        if name == "log-nonce":
            p.add_argument("--by", required=True, help="the person's broker id; mapped to the log's anchor")
            p.add_argument("--trustee-statement", help="write the bytes two trustees sign to this file (#41, F1)")
        else:
            p.add_argument("--proof", action="append", default=[], help="BROKER_ID=FILE holding that person's ID token")
            p.add_argument("--trustee-sig", action="append", default=[],
                           help="TRUSTEE_ID=FILE holding that trustee's signature over the trustee statement")
            p.add_argument("--approval-issuer", action="append", default=[])
            p.add_argument("--approval-audience", action="append", default=[])
            p.add_argument("--keycloak", required=True)
            p.add_argument("--max-age", type=int, default=300)
    for name in ("start", "status", "nonce", "resume"):
        p = sub.add_parser(name)
        p.add_argument("--store", required=True)
        if name in ("nonce", "resume"):
            p.add_argument("--realm", required=True)
            p.add_argument("--mark", type=int, required=True)
        if name == "nonce":
            p.add_argument("--by", required=True)
        if name == "status":
            p.add_argument("--signer-state", help="the restored signer's state: its log mark counts the witness's links")
            p.add_argument("--witness", help="a witness's URL (keyclerk.witness or any C2SP witness)")
            p.add_argument("--witness-key", help="the witness's cosigner vkey")
            p.add_argument("--origin", help="the log's origin (witness.origin)")
            p.add_argument("--records-key", help="the records public key (hex)")
        if name == "resume":
            p.add_argument("--key", required=True, help="the records key file, as the desk uses it")
            p.add_argument("--proof", action="append", default=[], help="ANCHOR=FILE holding that person's ID token")
            p.add_argument("--approval-issuer", action="append", default=[])
            p.add_argument("--approval-audience", action="append", default=[])
            p.add_argument("--keycloak", required=True)
            p.add_argument("--max-age", type=int, default=300)
    lv = sub.add_parser("leave", help="a desk on the change log leaves restore mode, once its signer resumed")
    lv.add_argument("--store", required=True)
    lv.add_argument("--config", required=True)
    lv.add_argument("--signer", required=True, help="the checking signer: unix:/path or tcp:127.0.0.1:port")
    lv.add_argument("--signer-token")
    a = ap.parse_args(argv)
    if a.cmd in ("log-nonce", "link"):
        return _log_command(a)
    if a.cmd == "leave":
        from keyclerk import config
        from keyclerk.edge_store import EdgeStore
        from keyclerk.signer import SignerClient
        from keyclerk.store.log_desk import LogStore
        config.configure(a.config)
        store = LogStore(Path(a.store), SignerClient(a.signer, a.signer_token))
        try:
            print(json.dumps(leave(store, EdgeStore(Path(a.store)), Path(a.store)), sort_keys=True))
        except RestoreMode as e:
            print(f"still in restore mode: {e}", file=sys.stderr)
            return 1
        finally:
            store.close()
        return 0
    if a.cmd == "recover-log":
        from keyclerk.store.sqlite import SqliteStore
        realm = json.loads((Path(a.signer_state) / "log-mark.json").read_text(encoding="utf-8"))["realm"]
        follower = SqliteStore(Path(a.source), a.records_key, realm, _readonly=True)
        try:
            print(json.dumps(recover_log(Path(a.signer_state), follower, a.records_key), sort_keys=True))
        except RestoreMode as e:
            print(f"not recovered: {e}", file=sys.stderr)
            return 1
        finally:
            follower.close()
        return 0
    store_dir = Path(a.store)
    if a.cmd == "start":
        print(json.dumps(start(store_dir), sort_keys=True))
        return 0
    if a.cmd == "status":
        m = marker(store_dir) or {}
        log_mark = json.loads((Path(a.signer_state) / "log-mark.json").read_text(encoding="utf-8")) \
            if a.signer_state else None
        witnessed = None
        if a.witness:
            if not (a.witness_key and a.origin and a.records_key):
                print("--witness needs --witness-key, --origin and --records-key", file=sys.stderr)
                return 2
            try:
                witnessed = witness_mark(a.witness, a.witness_key, a.origin, a.records_key)
            except (RestoreMode, OSError, ValueError) as e:
                print(f"the witness is not a source now: {e}", file=sys.stderr)
        print(json.dumps({"restore_mode": bool(m), **m, "mark_sources": mark_sources(m, log_mark, witnessed)},
                         sort_keys=True))
        return 0
    raw = (store_dir / "records.yaml").read_bytes()
    if a.cmd == "nonce":
        print(statement(a.realm, a.by, a.mark, hashlib.sha256(raw).hexdigest()))
        return 0
    from keyclerk import approvals
    from keyclerk.desk import Store
    from keyclerk.edge_store import EdgeStore
    verify = approvals.BrokerProofs(a.approval_issuer, a.approval_audience, a.max_age,
                                    f"{a.keycloak}/realms/{a.realm}/protocol/openid-connect/certs")
    proofs = {}
    for p in a.proof:
        by, _, f = p.partition("=")
        proofs[by] = Path(f).read_text(encoding="utf-8").strip()
    store = Store(store_dir, Path(a.key))
    try:
        print(json.dumps(resume(store, EdgeStore(store_dir), store_dir, a.realm, a.mark, proofs, verify), sort_keys=True))
    except RestoreMode as e:
        print(f"still in restore mode: {e}", file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
