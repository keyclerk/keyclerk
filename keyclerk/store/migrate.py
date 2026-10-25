"""From the signed YAML store to the change log and back (decision 0022 S2): records as code stay a format.

    python -m keyclerk.store.migrate DESK_STORE OUT.db --signer unix:/run/keyclerk/signer.sock --config keyclerk.yaml
    python -m keyclerk.store.migrate DESK_STORE OUT.db --dev-key records.key --config keyclerk.yaml   (development only)
    python -m keyclerk.store.migrate --export OUT.db --pinned HEX --realm REALM --config keyclerk.yaml > records.yaml

The migration runs against a stopped desk: it takes the desk store's lock, so it refuses while a desk (or another
migration) holds it, and it writes a new store file, never an existing one. It needs no import and no approvals
(decision 0022 point 4): the genesis names the last signed YAML revision (its revision, the sha256 of its exact bytes,
its detached signature by the records key, checked, not only its hash) and how many migrate links follow; links 1 to k
put the records, at most MIGRATE_RECORDS records and MIGRATE_BYTES bytes each; at link k the store proves the state
equal to the signed YAML by meaning, or refuses link k and the migration fails as a whole (the new file is removed). A
checkpoint at k+1 closes it. A YAML store holds at most 16 MiB of records (guard.MAX_FILE_BYTES), about 4,000 people; no
desk store can be larger, so every one migrates. The change log itself has no such bound.

Visits, their events and badges, and the tokens behind proofs go to the side table, never into a link. So do the YAML
bytes themselves (genesis_yaml): they hold names, so they stay erasable; erasing them ends only the re-provability of
the migration (a replay then says so), never the chain. The records' git history, where records were kept as code,
still holds those names: purging it is a deployment step outside the engine (DPO finding F5).

split(doc) turns a records document into what the log carries and what it never does: the head fields, the records
as put ops (proofs by the hash of their token), and the side records (visits, their events and badges, proof tokens).
meaning(doc) is what "equal" means between a YAML revision and a replayed log: records.canonical, times as one UTC
spelling, each kind compared as a set (the store orders by key, YAML by hand). export(view) writes a store's records
back as YAML in a deterministic order (head fields as records.HEAD lists them, then each kind by name, each record
by key), so a YAML diff between two exports shows only what changed.
"""
from __future__ import annotations

import functools
import hashlib
import json
from pathlib import Path

import yaml

from keyclerk import edge as E
from keyclerk import records as R
from keyclerk.store import View
from keyclerk.store import link as L
from keyclerk.store import replay as RP
from keyclerk.store.link import StoreRefused

VISIT_KINDS = ("visits", "visit_events", "badges")


@functools.lru_cache(maxsize=1)
def loads_signed(text: str) -> dict:
    """The parse of one signed YAML revision, once for the migration and its proof: the same bytes always parse the
    same, and a parse is most of what a migration costs (pure YAML, through the guard). Callers only read it."""
    return R.loads(text)


def _plain(v):
    """A time under any key as the desk writes it (UTC, Z), a date as ISO text: a YAML timestamp in a field records
    does not list as a time (a proof's expiry) means what the desk's written text for it means."""
    from datetime import date, datetime
    if isinstance(v, datetime):
        if v.tzinfo is None:
            raise StoreRefused(f"a time without a zone ({v}): records never read one as UTC")
        return E._iso(v)
    if isinstance(v, date):
        return v.isoformat()
    raise TypeError(f"{type(v).__name__} is not a records value")


def _json(x):
    """Plain JSON values: times as UTC text (records.canonical), dates as ISO text."""
    return json.loads(json.dumps(R.canonical(x), default=_plain))


def split(doc: dict, visits: list[dict] | None = None) -> tuple[list[dict], list[dict], dict[str, list[tuple[str, dict]]]]:
    """(head ops, record ops, side records by kind) of a records document; visits are the desk's visit files, each
    {"visit", "visit_events", "badges"}, for a store that keeps them outside its records."""
    doc = _json(doc)
    known = set(R.HEAD) | set(R.KINDS)
    if set(doc) - known:
        raise StoreRefused(f"the records hold kinds the log does not know: {', '.join(sorted(set(doc) - known))[:200]}")
    head = [{"op": "put", "kind": "head", "key": f, "record": {"value": doc[f]}} for f in L.HEAD_FIELDS if f in doc]
    ops, side = [], {k: [] for k in L.SIDE_KINDS}
    for kind in L.LOG_KINDS:
        if kind == "head":
            continue
        for rec in doc.get(kind) or []:
            if kind in L.PROOF_KINDS:
                p = L.proof_record(rec)
                side["proof_tokens"].append((p["sha256"], {"token": str(rec.get("token", ""))}))
                rec = p
            ops.append({"op": "put", "kind": kind, "key": L.record_key(kind, rec), "record": rec})
    bundles = [_json(b) for b in visits or []]
    for kind, field in zip(VISIT_KINDS, ("visit_id", "event_id", "badge_id"), strict=True):
        recs = list(doc.get(kind) or [])
        for b in bundles:
            recs += [b["visit"]] if kind == "visits" else b.get(kind, [])
        side[kind] = [(r[field], r) for r in recs]
    for kind, items in side.items():
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise StoreRefused(f"{kind}: one key used twice")
    keys = [(o["kind"], o["key"]) for o in ops]
    if len(keys) != len(set(keys)):
        dup = sorted({k for k in keys if keys.count(k) > 1})[:3]
        raise StoreRefused(f"one key used twice: {dup}")
    return head, ops, {k: v for k, v in side.items() if v}


def meaning(doc: dict) -> dict:
    """A records document for comparison: each list kind as a sorted list of canonical JSON, without the revision."""
    doc = _json(doc)
    out = {}
    for k, v in doc.items():
        if k == "revision":
            continue
        if k in R.KINDS or k in L.LOG_KINDS or k in VISIT_KINDS:
            v = sorted(json.dumps(r, sort_keys=True) for r in v)
            if not v:
                continue
        out[k] = v
    return out


def _anchors_of(doc: dict, visits: list[dict] | None = None) -> list[str]:
    """Every anchor a records document and its visit files hold, by records.ANCHOR_PATHS, internal ones excluded."""
    from keyclerk import anchors as A
    found: set[str] = set()
    docs = [doc] + [{"visits": [b.get("visit")], "visit_events": b.get("visit_events", []), "badges": b.get("badges", [])}
                    for b in visits or []]
    for d in docs:
        for kind in R.ANCHOR_PATHS:
            value = d.get(kind)
            for rec in ([value] if isinstance(value, dict) else value if isinstance(value, list) else []):
                if isinstance(rec, dict):
                    found |= {v for _, v in R.anchor_values(kind, rec) if not A.is_internal(v) and A.is_person(v)}
    return sorted(found)


def mint_rows(doc: dict, visits: list[dict] | None = None) -> list[dict]:
    """A mapping row (decision 0028) for every anchor of a revision and its visit files: a new internal anchor, the
    identity provider's id, a salt, and the person's label where the anchor is a person's."""
    from keyclerk import anchors as A
    labels = {a: p.get("person") for p in doc.get("persons") or [] for a in p.get("anchors") or []}
    return [A.mapping_row(a, label=labels.get(a)) for a in _anchors_of(doc, visits)]


def rekeyed(doc: dict, rows: list[dict]) -> dict:
    """A records document as the log carries it (decision 0028 points 1 and 7): every anchor re-keyed through the
    mapping rows, and an accounts record for each row, {anchor, commit}, beside those the document holds already.
    Deterministic for given rows, so the proof rebuilds it from the kept YAML and the kept rows."""
    from keyclerk import anchors as A
    amap = {r["idp"]: r["anchor"] for r in rows}
    out = A.rekey(doc, amap)
    accounts = {a["anchor"]: a for a in out.get("accounts") or []}
    for r in rows:
        accounts.setdefault(r["anchor"], {"anchor": r["anchor"], "commit": A.commitment(r["salt"], r["idp"])})
    if accounts:
        out["accounts"] = [accounts[a] for a in sorted(accounts)]
    return out


def rekeyed_visits(visits: list[dict] | None, rows: list[dict]) -> list[dict]:
    """The desk's visit files with their anchors re-keyed, as the store's side tables keep them."""
    from keyclerk import anchors as A
    amap = {r["idp"]: r["anchor"] for r in rows}
    out = []
    for b in visits or []:
        d = A.rekey({"visits": [b["visit"]], "visit_events": b.get("visit_events", []), "badges": b.get("badges", [])},
                    amap)
        out.append({**b, "visit": d["visits"][0], "visit_events": d["visit_events"], "badges": d["badges"]})
    return out


def put_rows(store, rows: list[dict]) -> None:
    """The mapping rows into a store's erasable side tables, both directions."""
    from keyclerk import anchors as A
    for r in rows:
        store.side_put("anchor_map", r["anchor"], r)
        store.side_put("anchor_idp", A.idp_key(r["idp"]), {"anchor": r["anchor"]})


def export(view: View) -> str:
    """The store's records as one YAML document, in a deterministic order."""
    doc = RP.records(view)
    order = [k for k in R.HEAD if k in doc and k != "revision"] + sorted(k for k in doc if k not in R.HEAD)
    out = {k: doc[k] for k in order}
    if "revision" in doc:
        out["revision"] = doc["revision"]
    return yaml.dump(out, Dumper=R._Plain, sort_keys=False, default_flow_style=False, allow_unicode=False)


# --- the migration ---------------------------------------------------------------------------------------------------

MIGRATE_RECORDS = 500
MIGRATE_BYTES = 512 * 1024                     # half of a link's bound: the rest is the envelope and the entry


def _parts(ops: list[dict]) -> list[list[dict]]:
    out: list[list[dict]] = [[]]
    size = 0
    for op in ops:
        n = len(E.canonical(op))
        if out[-1] and (len(out[-1]) >= MIGRATE_RECORDS or size + n > MIGRATE_BYTES):
            out.append([])
            size = 0
        out[-1].append(op)
        size += n
    return out


def migrate_yaml(raw: str, signature_hex: str, key, store, at: str, visits: list[dict] | None = None,
                 fence: int = 1) -> dict:
    """Move one signed YAML revision into an empty store; what was moved, counted."""
    data = raw.encode("utf-8")
    sig = signature_hex.strip()
    if E.public_hex(key) != store.pinned:
        raise StoreRefused("the key given is not the store's records key")
    if not E._verifies(store.pinned, sig, data):
        raise StoreRefused("the YAML revision's signature does not verify against the records key: migrate only "
                           "records this key signed (restore records.yaml and records.yaml.sig from the store's revisions)")
    if store.size():
        raise StoreRefused("the store already holds links: a migration goes into a new store")
    doc = loads_signed(raw)
    if doc.get("realm") != store.realm:
        raise StoreRefused(f"the YAML revision is of realm {doc.get('realm')}, the store of {store.realm}")
    rows = mint_rows(doc, visits)                 # decision 0028: no identity provider's id enters the chain
    head, ops, side = split(rekeyed(doc, rows), rekeyed_visits(visits, rows))
    parts = _parts(ops)
    sha = hashlib.sha256(data).hexdigest()
    store.side_put("genesis_yaml", sha, {"text": raw})
    put_rows(store, rows)
    for kind, items in side.items():
        for k, rec in items:
            store.side_put(kind, k, rec)
    n = int(doc.get("revision") or 0)
    h = store.append(L.seal_link(key, store.realm, 0, L.ZERO, fence, at, head,
                                 {"action": "migrated", "actor": None, "outcome": "applied",
                                  "reasons": [f"migrated from signed YAML revision {n}"]},
                                 yaml={"revision": n, "sha256": sha, "signature": sig, "parts": len(parts),
                                       "rekeyed": len(rows)}))
    for i, part in enumerate(parts, 1):
        h = store.append(L.seal_link(key, store.realm, i, h.hex(), fence, at, part, {"action": "migrate"},
                                     migrate={"part": i, "parts": len(parts)}))
    store.add_checkpoint(L.seal_checkpoint(key, store.realm, store.size(), store.root(), h, fence, at))
    return {"revision": n, "links": store.size(), "records": len(ops) + len(head), "migration": store.migration(),
            "anchors": len(rows),
            **{k: len(side.get(k, [])) for k in ("visits", "visit_events", "badges", "proof_tokens")}}


def migrate_desk_store(desk_store: Path, out: Path, signer=None, dev_key: Path | None = None,
                       at: str | None = None) -> dict:
    """Migrate a desk store (stopped) into a new SQLite store; on any refusal the new file is removed.

    signer: the checking signer's client (decision 0022 S3). The signer migrates its own last signed revision (it never
    takes YAML from the desk, which could hand it a false state); the desk's published records must be that revision, byte for byte; the desk's store
    is then built from the signer's links and tokens, with the desk's own visit files, and proves the migration itself.
    dev_key: development only, the records key in this process (S2's path, for a desk without a signer)."""
    from keyclerk.desk import Store as DeskStore, StoreFault
    from keyclerk.store.sqlite import SqliteStore
    out = Path(out)
    if (signer is None) == (dev_key is None):
        raise StoreRefused("migrate through the signer, or with a development key, one of the two")
    if out.exists():
        raise StoreRefused(f"{out} exists: a migration writes a new store file, never an existing one. Choose another "
                           "path, or remove that file if it is a failed attempt")
    try:
        desk = DeskStore(Path(desk_store), Path(dev_key) if dev_key else None, signer=signer)
    except StoreFault as e:
        if "another desk process" in str(e):
            raise StoreRefused(f"a desk process holds {desk_store}: the migration reads the store while nothing writes "
                               "it. Stop the desk (and anything else using that store), then run the migration again") from None
        raise
    store = None
    try:
        raw = desk.raw().decode("utf-8")
        visits = [desk._visit_file(v) for v in desk.visit_ids()]
        realm = R.loads(raw)["realm"]
        store = SqliteStore(out, desk.public_key_hex(), realm)
        if dev_key is not None:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from keyclerk import guard
            key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(dev_key), 200).strip()))
            sig = (desk._sig_bytes() or b"").decode("ascii")
            return migrate_yaml(raw, sig, key, store, at or _now(), visits)
        got = _through_signer(raw, visits, signer, store)
        store.close()
        store = None
        desk.close()
        if Path(out).resolve() == (Path(desk_store) / "log.db").resolve():   # the desk's own replica: finish its files
            got.update(finish_desk(Path(desk_store), signer, got["revision"]))
        return got
    except BaseException:
        if store is not None:
            store.close()
            store = None
            for suffix in ("", "-wal", "-shm"):
                Path(str(out) + suffix).unlink(missing_ok=True)
        raise
    finally:
        if store is not None:
            store.close()
        desk.close()


def _through_signer(raw: str, visits: list[dict], signer, store) -> dict:
    from keyclerk.store.follow import Follower
    head = signer.head()
    if head.get("broken"):
        raise StoreRefused(f"the signer refuses to sign: {head['broken']}")
    if not head.get("size"):
        head = signer.migrate()
    genesis = E._parse(E._raw(signer.links(0, 1)["links"][0]["bytes"]))
    y = genesis["change"].get("yaml")
    if y is None or y["sha256"] != hashlib.sha256(raw.encode("utf-8")).hexdigest():
        raise StoreRefused("the desk's published records are not the revision the signer migrated: restore the desk's "
                           "records.yaml from its revisions, or migrate the signer from the desk's current revision")
    rows, after = [], None
    while True:                                   # the mapping rows the signer minted (decision 0028), paged
        page = signer.anchors(after, 500)["anchors"]
        rows += [r for _, r in page]
        if len(page) < 500:
            break
        after = page[-1][0]
    put_rows(store, rows)
    _, _, side = split(rekeyed(R.loads(raw), rows), rekeyed_visits(visits, rows))
    store.side_put("genesis_yaml", y["sha256"], {"text": raw})        # so the desk's store proves the migration too
    for kind in ("visits", "visit_events", "badges"):
        for key, rec in side.get(kind, []):
            store.side_put(kind, key, rec)
    f = Follower(store, signer, fresh=None)
    after = None
    while True:
        page = signer.tokens(after, 500)["tokens"]
        for sha, token in page:
            store.side_put("proof_tokens", sha, {"token": token})
        if len(page) < 500:
            break
        after = page[-1][0]
    f._pull(store)
    if store.head().hex() != signer.head()["head"]:
        raise StoreRefused("the desk's store did not reach the signer's head: run the migration again")
    return {"revision": y["revision"], "links": store.size(), "records": sum(1 for k in L.LOG_KINDS for _ in store.scan(k)),
            "migration": store.migration(), **{k: len(side.get(k, [])) for k in ("visits", "visit_events", "badges",
                                                                                  "proof_tokens")}}


def rekeyed_pending(pending: dict, rows: list[dict]) -> dict:
    """The desk's pending changes as the log store reads them (decision 0028): every person they name, in their records
    and in actor, approvals and waiting_for, through the mapping rows. A name the rows do not hold stays as it is: the
    store gives it an anchor of its own if the change is ever committed."""
    from keyclerk import anchors as A
    amap = {r["idp"]: r["anchor"] for r in rows}

    def one(v):
        return amap.get(v, v) if isinstance(v, str) else v
    out = {}
    for cid, p in pending.items():
        if not isinstance(p, dict):
            out[cid] = p
            continue
        q = dict(p)
        if isinstance(q.get("records"), dict):
            keep = {v: v for v in _anchors_of(q["records"]) if v not in amap}
            q["records"] = A.rekey(q["records"], {**amap, **keep})
        for field in ("actor", "by", "proposer"):
            q[field] = one(q.get(field)) if field in q else q.get(field)
        for field in ("approvals", "waiting_for"):
            if isinstance(q.get(field), list):
                q[field] = [one(v) for v in q[field]]
        out[cid] = {k: v for k, v in q.items() if k in p}
    return out


def finish_desk(desk_dir: Path, signer, revision: int) -> dict:
    """The desk's own files after its replica is built (S5 step T7), the desk still stopped: the pending changes
    re-keyed (the YAML-era file kept as pending-yaml.json), the YAML-era activity log moved aside as log-yaml.jsonl,
    and the log store's activity log started with one line, migrated from signed YAML revision n. pending-yaml.json,
    log-yaml.jsonl, records.yaml and the revisions name people by the identity provider's id: the runbook's purge
    checklist removes them once the deployment runs on the change log."""
    import json
    import os
    from keyclerk.store.log_desk import LogStore
    desk_dir = Path(desk_dir)
    for kept in ("pending-yaml.json", "log-yaml.jsonl"):
        if (desk_dir / kept).exists():
            raise StoreRefused(f"{desk_dir / kept} exists: this desk was migrated before; restore the YAML store from its "
                               "backup before migrating again")
    rows, after = [], None
    while True:
        page = signer.anchors(after, 500)["anchors"]
        rows += [r for _, r in page]
        if len(page) < 500:
            break
        after = page[-1][0]
    pending_file = desk_dir / "pending.json"
    pending = json.loads(pending_file.read_text(encoding="utf-8")) if pending_file.exists() else {}
    if pending_file.exists():
        os.replace(pending_file, desk_dir / "pending-yaml.json")
    tmp = desk_dir / "pending.json.tmp"
    tmp.write_text(json.dumps(rekeyed_pending(pending, rows), sort_keys=True), encoding="utf-8", newline="\n")
    os.replace(tmp, pending_file)
    if (desk_dir / "log.jsonl").exists():
        os.replace(desk_dir / "log.jsonl", desk_dir / "log-yaml.jsonl")
    store = LogStore(desk_dir, signer)
    try:
        store.note({"action": "migrated", "actor": None, "outcome": "applied", "from_revision": revision,
                    "link": store.store.size() - 1, "summary": f"migrated from signed YAML revision {revision}"})
        return {"pending": len(pending), "head": store.store.head().hex()}
    finally:
        store.close()


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime(E.ISO)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="python -m keyclerk.store.migrate", description=__doc__.split("\n\n")[0],
                                 epilog="Run it with the desk stopped: it takes the desk store's lock and refuses while "
                                        "a desk holds it, so nothing writes the store while it is read. A YAML store "
                                        "holds at most 16 MiB of records (the input guard), about 4,000 people: no desk "
                                        "store is larger, so every one migrates; the change log has no such bound.")
    ap.add_argument("desk_store", nargs="?", help="the desk store folder (records.yaml, records.yaml.sig, log.jsonl)")
    ap.add_argument("out", nargs="?", help="the new SQLite store file")
    ap.add_argument("--signer", help="the checking signer: unix:/path or tcp:127.0.0.1:port (decision 0022 S3)")
    ap.add_argument("--signer-token", help="with a TCP signer: the token file")
    ap.add_argument("--dev-key", help="development only: the records key in this process, for a desk without a signer")
    ap.add_argument("--config", required=True)
    ap.add_argument("--export", metavar="DB", help="write the records of a SQLite store as YAML to standard output")
    ap.add_argument("--pinned", help="with --export: the store's records public key (hex)")
    ap.add_argument("--preview", action="store_true",
                    help="no longer needed (0.25.0 asked for it while the change log was not offered); accepted")
    ap.add_argument("--realm", help="with --export: the store's realm")
    a = ap.parse_args(argv)
    from keyclerk import config
    config.configure(a.config)
    try:
        if a.export:
            from keyclerk.store.sqlite import SqliteStore
            if not (a.pinned and a.realm):
                ap.error("--export needs --pinned and --realm")
            s = SqliteStore(Path(a.export), a.pinned, a.realm)
            try:
                sys.stdout.write(export(s))
            finally:
                s.close()
            return 0
        if not (a.desk_store and a.out) or (a.signer is None) == (a.dev_key is None):
            ap.error("DESK_STORE, OUT and one of --signer or --dev-key are needed")
        client = None
        if a.signer:
            from keyclerk.signer import SignerClient
            client = SignerClient(a.signer, a.signer_token)
        got = migrate_desk_store(Path(a.desk_store), Path(a.out), signer=client,
                                 dev_key=Path(a.dev_key) if a.dev_key else None)
    except Exception as e:   # noqa: BLE001 - a refusal by the store or the signer, said with its reason
        from keyclerk.signer import SignerRefused
        if not isinstance(e, (StoreRefused, SignerRefused)):
            raise
        sys.stderr.write(f"keyclerk.store.migrate: refused: {e}\n")
        return 1
    sys.stderr.write("keyclerk.store.migrate: " + ", ".join(f"{k} {v}" for k, v in got.items()) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
