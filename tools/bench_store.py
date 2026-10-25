"""What the signed change log on SQLite costs for a generated organisation of N people (decision 0022 S1).

The organisation is bench_checks' (the fixture plus N generated people with valid memberships). Its signed YAML revision
goes into the log by migrate_yaml (in parts, proven at the last one; above the 16 MiB a YAML store may hold, the same
records go in as plain links), then: the SQLite file size, a snapshot through the online backup API (time and size: the
background full check reads one), a replay of every link into the reference store, proving the migration again (time),
the records read back from SQLite (time), and what a person waits for in the store: one change (one record put) appended
to the store of N people, the median of CHANGES appends. "migrate" is the whole state written as links, which only a
migration does.

    python tools/bench_store.py [N ...]          default 1000 5000
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from bench_checks import organisation  # noqa: E402
from keyclerk import edge as E  # noqa: E402
from keyclerk import guard  # noqa: E402
from keyclerk.store import link as L  # noqa: E402
from keyclerk.store import migrate as M  # noqa: E402
from keyclerk.store import replay as RP  # noqa: E402
from keyclerk.store.sqlite import SqliteStore  # noqa: E402

CHANGES = 20
AT = "2026-10-24T12:00:00Z"


def run(n: int, key: Ed25519PrivateKey, tmp: Path) -> str:
    from keyclerk.desk import _Dumper, _jsonable_records
    doc = organisation(n)
    raw = yaml.dump(_jsonable_records({**doc, "revision": 1}), Dumper=_Dumper, sort_keys=False, allow_unicode=False)
    s = SqliteStore(tmp / f"bench-{n}.db", E.public_hex(key), doc["realm"])
    try:
        return _run(n, key, doc, raw, s)
    finally:
        s.close()


def _run(n: int, key: Ed25519PrivateKey, doc: dict, raw: str, s: SqliteStore) -> str:
    t = time.perf_counter()
    if len(raw.encode("utf-8")) <= guard.MAX_FILE_BYTES:
        mode = "migrate"
        M.migrate_yaml(raw, key.sign(raw.encode("utf-8")).hex(), key, s, AT)
    else:                                     # above what a YAML store may hold: the same records as plain links
        mode = "links  "
        head, ops, _ = M.split(doc)
        h = s.append(L.seal_link(key, s.realm, 0, L.ZERO, 1, AT, head, {"action": "bench"}))
        for part in M._parts(ops):
            h = s.append(L.seal_link(key, s.realm, s.size(), h.hex(), 1, AT, part, {"action": "bench"}))
    t_write = time.perf_counter() - t
    records = sum(1 for k in L.LOG_KINDS for _ in s.scan(k))
    s._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    size = s.path.stat().st_size
    one = []
    for i in range(CHANGES):
        rec = {"group_id": f"bench-{i}", "risk": "low"}
        sealed = L.seal_link(key, s.realm, s.size(), s.head().hex(), 1, AT,
                             [{"op": "put", "kind": "groups", "key": rec["group_id"], "record": rec}], {"action": "bench"})
        t = time.perf_counter()
        s.append(sealed)
        one.append(time.perf_counter() - t)
    t_one = sorted(one)[len(one) // 2]
    t = time.perf_counter()
    snap = s.snapshot()
    t_snap = time.perf_counter() - t
    snap_size = os.path.getsize(snap._tmp)
    try:
        t = time.perf_counter()
        mem = RP.replay(snap.links(), s.pinned, s.realm, RP.side_of(snap))
        t_replay = time.perf_counter() - t
        t = time.perf_counter()
        back = RP.records(snap)
        t_read = time.perf_counter() - t
        assert RP.records(mem) == back and mem.migration() == ("proven" if mode == "migrate" else None)
    finally:
        snap.close()
    return (f"{n:6d} people {records:8d} records {s.size():5d} links: {mode} {t_write:6.2f} s, "
            f"file {size / 1e6:6.1f} MB, snapshot {t_snap:5.2f} s ({snap_size / 1e6:.1f} MB), replay {t_replay:6.2f} s, "
            f"read all {t_read:5.2f} s, one change {t_one * 1000:5.1f} ms (median of {CHANGES})")


def main(argv: list[str]) -> int:
    sizes = [int(a) for a in argv] or [1000, 5000]
    key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(dir=ROOT) as d:
        for n in sizes:
            print(run(n, key, Path(d)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
