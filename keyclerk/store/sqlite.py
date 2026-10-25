"""The SQLite store (decision 0022 point 2): standard library sqlite3, one file, write-ahead log, plain SQL.

Each record is kept whole as canonical JSON, with generated, indexed columns the database computes from it, so
an index can never drift from its record. The links and checkpoints are kept as the bytes that were signed.
Every append runs in one immediate transaction that reads the head, fence and frontier from the database itself, so
two processes can never both append link n.

Refused at open: SQLite older than 3.38 (generated columns, STRICT tables, built-in JSON), and a database on a network
or sync filesystem where that can be detected (the write-ahead log needs one host and a local disk; on a network volume
it corrupts). A snapshot is the online backup API into a file of its own (a long read would starve the write-ahead log),
never a file copy and never the live database: the background full check reads it while appends go on. It is written
beside the store and needs the store's size again in free space there (about 13 KB per person: 65 MB at 5,000 people,
about 6.6 GB at 500,000); the background full check is to refuse to start, saying why and what to free, when that space
is missing (decision 0022 S4). """
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path
from typing import Iterator

from keyclerk import edge as E
from keyclerk.store import check_kind, check_range, check_ref, check_side, refs_of
from keyclerk.store import link as L
from keyclerk.store import merkle
from keyclerk.store.link import StoreRefused

MIN_SQLITE = (3, 38, 0)
APPLICATION_ID = 0x4B434C47                    # "KCLG"
SCHEMA_VERSION = 2                             # 2: the refs index (decision 0022 S4)
STORE_FORMAT = "keyclerk-sqlite-store-v1"
COLUMNS = {"anchor": "anchor", "group": "grp", "start": "t_start", "end": "t_end"}   # index -> generated column

SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE links (seq INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE, fence INTEGER NOT NULL,
                    bytes BLOB NOT NULL, signature TEXT NOT NULL) STRICT;
CREATE TABLE checkpoints (size INTEGER PRIMARY KEY, bytes BLOB NOT NULL, signature TEXT NOT NULL) STRICT;
CREATE TABLE records (
  kind TEXT NOT NULL, key TEXT NOT NULL, seq INTEGER NOT NULL,
  body TEXT NOT NULL CHECK (json_valid(body)),
  anchor  TEXT GENERATED ALWAYS AS (CASE json_type(body, '$.anchor') WHEN 'text' THEN json_extract(body, '$.anchor') END) VIRTUAL,
  grp     TEXT GENERATED ALWAYS AS (CASE json_type(body, '$.group') WHEN 'text' THEN json_extract(body, '$.group') END) VIRTUAL,
  t_start TEXT GENERATED ALWAYS AS (CASE json_type(body, '$.start') WHEN 'text' THEN json_extract(body, '$.start') END) VIRTUAL,
  t_end   TEXT GENERATED ALWAYS AS (CASE json_type(body, '$.end') WHEN 'text' THEN json_extract(body, '$.end') END) VIRTUAL,
  PRIMARY KEY (kind, key)) STRICT, WITHOUT ROWID;
CREATE INDEX records_anchor ON records (kind, anchor, key);
CREATE INDEX records_grp ON records (kind, grp, key);
CREATE INDEX records_t_start ON records (kind, t_start, key);
CREATE INDEX records_t_end ON records (kind, t_end, key);
CREATE TABLE refs (kind TEXT NOT NULL, field TEXT NOT NULL, value TEXT NOT NULL, key TEXT NOT NULL,
                   PRIMARY KEY (kind, field, value, key)) STRICT, WITHOUT ROWID;
CREATE INDEX refs_key ON refs (kind, key);
CREATE TABLE side (kind TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL CHECK (json_valid(body)),
                   PRIMARY KEY (kind, key)) STRICT, WITHOUT ROWID;
"""


# --- where a store may live ------------------------------------------------------------------------------------------

REMOTE_LINUX = {"nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "ceph", "glusterfs", "lustre", "afs", "davfs", "ncpfs",
                "virtiofs", "gpfs", "beegfs"}
REMOTE_MAC = {"smbfs", "nfs", "afpfs", "webdav", "cifs"}
LOCAL_WINDOWS = {"NTFS", "ReFS"}


def _unescape(p: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), p)


def filesystem(path: Path) -> tuple[str, str | None]:
    """(the filesystem the directory is on, why it is not safe for the store or None); ("unknown", None) when it cannot
    be told."""
    path = Path(os.path.realpath(path))
    if sys.platform == "win32":
        return _windows(path)
    if sys.platform.startswith("linux"):
        return _linux(path)
    if sys.platform == "darwin":
        return _mac(path)
    return "unknown", None


def _windows(path: Path) -> tuple[str, str | None]:
    import ctypes
    from ctypes import wintypes
    p = str(path)
    if p.startswith("\\\\") and not p.startswith("\\\\?\\"):
        return "network share", "a UNC path is a network share"
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    buf = ctypes.create_unicode_buffer(1024)
    if not k32.GetVolumePathNameW(wintypes.LPCWSTR(p), buf, 1024):
        return "unknown", None
    vol = buf.value
    if k32.GetDriveTypeW(wintypes.LPCWSTR(vol)) == 4:           # DRIVE_REMOTE
        return "network drive", f"{vol} is a network drive"
    name = ctypes.create_unicode_buffer(64)
    if not k32.GetVolumeInformationW(wintypes.LPCWSTR(vol), None, 0, None, None, None, name, 64):
        return "unknown", None
    if name.value not in LOCAL_WINDOWS:
        return name.value, f"{vol} is a {name.value} volume, not a local NTFS or ReFS one (a sync drive presents its own)"
    return name.value, None


def _linux(path, mountinfo: str | None = None) -> tuple[str, str | None]:
    best, fstype, path = "", "unknown", path.as_posix()
    if mountinfo is None:
        try:
            mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
        except OSError:
            return "unknown", None
    for line in mountinfo.splitlines():
        left, _, right = line.partition(" - ")
        fields, tail = left.split(), right.split()
        if len(fields) < 5 or not tail:
            continue
        mnt = _unescape(fields[4])
        inside = path == mnt or path.startswith(mnt.rstrip("/") + "/")
        if inside and len(mnt) >= len(best):
            best, fstype = mnt, tail[0]
    if fstype in REMOTE_LINUX or fstype.startswith("fuse"):
        return fstype, f"{best} is a {fstype} filesystem"
    return fstype, None


def _mac(path: Path) -> tuple[str, str | None]:
    import subprocess
    try:
        out = subprocess.run(["/sbin/mount"], capture_output=True, text=True, timeout=10, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return "unknown", None
    best, fstype, opts = "", "unknown", []
    for line in out.splitlines():
        m = re.match(r".+? on (.+) \(([^,)]+)(?:, ([^)]*))?\)$", line)
        if not m:
            continue
        mnt = m.group(1)
        if (str(path) == mnt or str(path).startswith(mnt.rstrip("/") + "/")) and len(mnt) >= len(best):
            best, fstype, opts = mnt, m.group(2), [o.strip() for o in (m.group(3) or "").split(",")]
    if fstype in REMOTE_MAC or "fuse" in fstype or (fstype != "unknown" and "local" not in opts):
        return fstype, f"{best} is a {fstype} filesystem, not a local one"
    return fstype, None


def check_local(path: Path) -> None:
    name, why = filesystem(path)
    if why:
        where = "a local NTFS or ReFS volume" if sys.platform == "win32" else "a local disk (not NFS, SMB or a FUSE or sync drive)"
        raise StoreRefused(f"the store at {path} is on {name}: {why}. SQLite's write-ahead log needs one host and a local "
                           f"disk, or the database can be corrupted. Put the store on {where}.")


def hold(path: Path, why: str):
    """An exclusive lock on a file for the life of the process (the operating system drops it with the file): one
    writer. StoreRefused, with `why`, when another process holds it."""
    f = open(path, "a+b")   # noqa: SIM115 - held for the life of the writer
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        raise StoreRefused(why) from None
    return f


def check_version() -> None:
    if sqlite3.sqlite_version_info < MIN_SQLITE:
        raise StoreRefused(f"this Python's SQLite is {sqlite3.sqlite_version}; the store needs 3.38 or later (generated "
                           "columns, STRICT tables, built-in JSON). Use a Python built with a newer SQLite.")


# --- the store ---------------------------------------------------------------------------------------------------------

class SqliteStore:
    def __init__(self, path, pinned: str, realm: str, _readonly: bool = False):
        check_version()
        E.load_public(pinned)
        self.path = Path(path)
        self.pinned, self.realm = pinned, realm
        self._readonly, self._lock = _readonly, threading.RLock()   # reentrant: link k is proven inside its transaction
        if not _readonly:
            check_local(self.path.parent)
        fresh = not self.path.exists() or self.path.stat().st_size == 0
        if _readonly:
            uri = f"{self.path.resolve().as_uri()}?mode=ro"
            self._db = sqlite3.connect(uri, uri=True, isolation_level=None, check_same_thread=False)
        else:
            self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        try:
            self._open(fresh)
        except Exception:
            self._db.close()
            raise

    def _open(self, fresh: bool) -> None:
        db = self._db
        db.execute("PRAGMA trusted_schema = OFF")
        db.execute("PRAGMA foreign_keys = ON")
        if fresh and not self._readonly:
            db.execute("PRAGMA journal_mode = WAL")
            db.execute("BEGIN IMMEDIATE")
            for stmt in SCHEMA.split(";"):
                if stmt.strip():
                    db.execute(stmt)
            db.executemany("INSERT INTO meta (key, value) VALUES (?, ?)",
                           [("format", STORE_FORMAT), ("realm", self.realm), ("pinned", self.pinned),
                            ("fence", "1"), ("frontier", "[]"), ("parts", "0"), ("migration", "")])
            db.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            db.execute("COMMIT")
        app = db.execute("PRAGMA application_id").fetchone()[0]
        ver = db.execute("PRAGMA user_version").fetchone()[0]
        if app != APPLICATION_ID or ver != SCHEMA_VERSION:
            raise StoreRefused(f"{self.path} is not a KeyClerk store of schema {SCHEMA_VERSION} (application id {app}, "
                               f"version {ver})")
        meta = dict(db.execute("SELECT key, value FROM meta").fetchall())
        if meta.get("format") != STORE_FORMAT:
            raise StoreRefused(f"{self.path}: store format {meta.get('format')}, not {STORE_FORMAT}")
        if meta.get("pinned") != self.pinned:
            raise StoreRefused(f"{self.path} is pinned to another records key ({str(meta.get('pinned'))[:16]}...): "
                               "open it with the key it was created with")
        if meta.get("realm") != self.realm:
            raise StoreRefused(f"{self.path} holds realm {meta.get('realm')}, not {self.realm}")
        if not self._readonly:
            db.execute("PRAGMA synchronous = FULL")
            if db.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
                db.execute("PRAGMA journal_mode = WAL")

    # --- transactions -------------------------------------------------------------------------------------------------

    def _write(self, fn):
        if self._readonly:
            raise StoreRefused("a snapshot is read only")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                out = fn(self._db)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
            return out

    def _meta(self, db, key: str) -> str:
        return db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()[0]

    def _frontier(self, db) -> list[tuple[int, bytes]]:
        return [(h, bytes.fromhex(x)) for h, x in json.loads(self._meta(db, "frontier"))]

    def _head(self, db) -> tuple[int, bytes | None]:
        row = db.execute("SELECT seq, hash FROM links ORDER BY seq DESC LIMIT 1").fetchone()
        return (0, None) if row is None else (row[0] + 1, bytes(row[1]))

    # --- write --------------------------------------------------------------------------------------------------------

    def append(self, sealed: dict, side: list[tuple[str, str, dict]] = ()) -> bytes:
        for kind, key, rec in side:
            check_side(kind, key, rec)

        def go(db):
            size, head = self._head(db)
            body, h = L.check_next(sealed, self.pinned, self.realm, size, head, int(self._meta(db, "fence")))
            return self._apply(db, size, body, side, None, lambda: (sealed, h))[1]
        return self._write(go)

    def append_checked(self, body: dict, seal, side: list[tuple[str, str, dict]] = (), check=None) -> tuple[dict, bytes]:
        """An unsigned body applied and checked in one transaction; seal(body) is called only when the checks pass,
        and the sealed link is kept in that same transaction. A refusal rolls it all back, and nothing was signed."""
        for kind, key, rec in side:
            check_side(kind, key, rec)

        def go(db):
            size, head = self._head(db)
            fence = int(self._meta(db, "fence"))
            L.follows(L._body(body), self.realm, size, head, fence)

            def finish():
                sealed = seal(body)
                signed, h = L.check_next(sealed, self.pinned, self.realm, size, head, fence)
                if signed != body:
                    raise StoreRefused("the sealed link is not the body that was checked")
                return sealed, h
            return self._apply(db, size, body, side, check, finish)
        return self._write(go)

    def trial(self, ops: list[dict], fn):
        """fn(view) on the records with ops applied, in a transaction that is always rolled back: a desk judges a change
        on its own replica as the signer will (decision 0022 S5 T9), and nothing of it stays. Ops are checked as a
        link's are; another reader keeps seeing the state before them."""
        L._ops(ops)
        if self._readonly:
            raise StoreRefused("a snapshot is read only")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                size, _ = self._head(self._db)
                self._put_ops(self._db, size, ops)
                return fn(self)
            finally:
                self._db.execute("ROLLBACK")

    def side_put_many(self, items: list[tuple[str, str, dict | None]]) -> None:
        """Side records in one transaction: put each, or delete it when its record is None (a mapping sync)."""
        for kind, key, rec in items:
            check_side(kind, key, rec) if rec is not None else check_side(kind, key)

        def go(db):
            for kind, key, rec in items:
                if rec is None:
                    db.execute("DELETE FROM side WHERE kind = ? AND key = ?", (kind, key))
                else:
                    db.execute("INSERT INTO side (kind, key, body) VALUES (?, ?, ?) ON CONFLICT (kind, key) "
                               "DO UPDATE SET body = excluded.body", (kind, key, E.canonical(rec).decode("utf-8")))
        if items:
            self._write(go)

    def _put_ops(self, db, size: int, ops: list[dict]) -> None:
        for op in ops:
            db.execute("DELETE FROM refs WHERE kind = ? AND key = ?", (op["kind"], op["key"]))
            if op["op"] == "put":
                db.execute("INSERT INTO records (kind, key, seq, body) VALUES (?, ?, ?, ?) ON CONFLICT (kind, key) "
                           "DO UPDATE SET seq = excluded.seq, body = excluded.body",
                           (op["kind"], op["key"], size, E.canonical(op["record"]).decode("utf-8")))
                db.executemany("INSERT INTO refs (kind, field, value, key) VALUES (?, ?, ?, ?)",
                               [(op["kind"], f, v, op["key"]) for f, v in refs_of(op["kind"], op["record"])])
            elif db.execute("DELETE FROM records WHERE kind = ? AND key = ?", (op["kind"], op["key"])).rowcount != 1:
                raise StoreRefused(f"{op['kind']} {op['key']}: deleted, but there is no such record")

    def _apply(self, db, size: int, body: dict, side, check, finish) -> tuple[dict, bytes]:
        """Inside the caller's transaction: the ops and side records, the migration's proof at link k, the check,
        then the link itself; anything raised rolls the transaction back."""
        k = int(self._meta(db, "parts")) if size else L.parts(body)
        L.check_migrate(body, k)
        self._put_ops(db, size, body["change"]["ops"])
        for kind, key, rec in side:                     # in the link's transaction: with it, or not at all
            db.execute("INSERT INTO side (kind, key, body) VALUES (?, ?, ?) ON CONFLICT (kind, key) "
                       "DO UPDATE SET body = excluded.body", (kind, key, E.canonical(rec).decode("utf-8")))
        db.execute("UPDATE meta SET value = ? WHERE key = 'parts'", (str(k),))
        if k and body["seq"] == k:                      # the last migrate link: the signed YAML, by meaning
            from keyclerk.store.replay import prove_migration
            db.execute("UPDATE meta SET value = ? WHERE key = 'migration'", (prove_migration(self, self.pinned),))
        if check is not None:
            check(self)                                 # reads the uncommitted state; a refusal rolls it all back
        sealed, h = finish()
        db.execute("INSERT INTO links (seq, hash, fence, bytes, signature) VALUES (?, ?, ?, ?, ?)",
                   (size, h, body["fence"], E._raw(sealed["bytes"]), sealed["signature"]))
        frontier = merkle.push(self._frontier(db), h)
        db.execute("UPDATE meta SET value = ? WHERE key = 'frontier'", (json.dumps([[x, y.hex()] for x, y in frontier]),))
        db.execute("UPDATE meta SET value = ? WHERE key = 'fence'", (str(body["fence"]),))
        return sealed, h

    def add_checkpoint(self, sealed: dict) -> None:
        def go(db):
            size, head = self._head(db)
            L.check_checkpoint(sealed, self.pinned, self.realm, size, merkle.root(self._frontier(db)), head)
            raw = E._raw(sealed["bytes"])
            row = db.execute("SELECT bytes, signature FROM checkpoints WHERE size = ?", (size,)).fetchone()
            if row is not None and (bytes(row[0]), row[1]) != (raw, sealed["signature"]):
                raise StoreRefused(f"another checkpoint is already kept at {size} links")
            db.execute("INSERT OR IGNORE INTO checkpoints (size, bytes, signature) VALUES (?, ?, ?)",
                       (size, raw, sealed["signature"]))
        self._write(go)

    def side_put(self, kind: str, key: str, record: dict) -> None:
        check_side(kind, key, record)
        self._write(lambda db: db.execute(
            "INSERT INTO side (kind, key, body) VALUES (?, ?, ?) ON CONFLICT (kind, key) DO UPDATE SET body = excluded.body",
            (kind, key, E.canonical(record).decode("utf-8"))))

    def side_delete(self, kind: str, key: str) -> None:
        check_side(kind, key)
        self._write(lambda db: db.execute("DELETE FROM side WHERE kind = ? AND key = ?", (kind, key)))

    def reader(self) -> "SqliteStore":
        """A read-only view of the committed state on a connection of its own: while a write transaction holds a
        change, it still reads the state before it (the write-ahead log gives each reader its own snapshot)."""
        return SqliteStore(self.path, self.pinned, self.realm, _readonly=True)

    def snapshot(self, directory=None) -> "SqliteStore":
        """A read-only copy at this moment, through the online backup API, in its own file (beside the store unless a
        directory is given); closing the snapshot removes the file."""
        fd, tmp = tempfile.mkstemp(prefix=".snapshot-", suffix=".sqlite", dir=directory or self.path.parent)
        os.close(fd)
        try:
            dst = sqlite3.connect(tmp, isolation_level=None)
            try:
                with self._lock:
                    self._db.backup(dst)
                dst.execute("PRAGMA journal_mode = DELETE")     # read only needs no write-ahead log beside it
            finally:
                dst.close()
            snap = SqliteStore(tmp, self.pinned, self.realm, _readonly=True)
        except BaseException:
            os.unlink(tmp)
            raise
        snap._tmp = tmp
        return snap

    def close(self) -> None:
        self._db.close()
        tmp = getattr(self, "_tmp", None)
        if tmp:
            for suffix in ("", "-wal", "-shm", "-journal"):
                try:
                    os.unlink(tmp + suffix)
                except FileNotFoundError:
                    pass

    # --- read ---------------------------------------------------------------------------------------------------------

    def _q(self, sql: str, args=()) -> list:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def size(self) -> int:
        return self._q("SELECT count(*) FROM links")[0][0]

    def migration(self) -> str | None:
        return self._q("SELECT value FROM meta WHERE key = 'migration'")[0][0] or None

    def head(self) -> bytes | None:
        row = self._q("SELECT hash FROM links ORDER BY seq DESC LIMIT 1")
        return bytes(row[0][0]) if row else None

    def root(self) -> bytes:
        with self._lock:
            return merkle.root(self._frontier(self._db))

    def checkpoint(self, size: int | None = None) -> dict | None:
        if size is not None:
            row = self._q("SELECT bytes, signature FROM checkpoints WHERE size = ?", (size,))
        else:
            row = self._q("SELECT bytes, signature FROM checkpoints ORDER BY size DESC LIMIT 1")
        return _sealed(row[0]) if row else None

    def link(self, seq: int) -> dict:
        row = self._q("SELECT bytes, signature FROM links WHERE seq = ?", (seq,))
        if not row:
            raise StoreRefused(f"there is no link {seq}")
        return _sealed(row[0])

    def links(self, start: int = 0, stop: int | None = None) -> Iterator[dict]:
        rows = self._q("SELECT bytes, signature FROM links WHERE seq >= ? AND seq < ? ORDER BY seq",
                       (start, stop if stop is not None else 2 ** 62))
        for r in rows:
            yield _sealed(r)

    def get(self, kind: str, key: str) -> dict | None:
        check_kind(kind)
        row = self._q("SELECT body FROM records WHERE kind = ? AND key = ?", (kind, key))
        return json.loads(row[0][0]) if row else None

    def range(self, kind: str, index: str, lo: str, hi: str | None = None) -> Iterator[tuple[str, dict]]:
        check_kind(kind)
        check_range(index, lo, hi)
        col = COLUMNS[index]
        src = f"records INDEXED BY records_{col}"     # without statistics the planner would scan the kind instead
        if hi is None:
            rows = self._q(f"SELECT key, body FROM {src} WHERE kind = ? AND {col} = ? ORDER BY {col}, key", (kind, lo))
        else:
            rows = self._q(f"SELECT key, body FROM {src} WHERE kind = ? AND {col} >= ? AND {col} < ? ORDER BY {col}, key",
                           (kind, lo, hi))
        for key, body in rows:
            yield key, json.loads(body)

    def find(self, kind: str, field: str, values) -> list[str]:
        check_kind(kind)
        check_ref(field)
        values = sorted(set(values))
        out: set[str] = set()
        for i in range(0, len(values), 500):                 # bounded statements
            chunk = values[i:i + 500]
            out |= {r[0] for r in self._q(
                f"SELECT key FROM refs WHERE kind = ? AND field = ? AND value IN ({','.join('?' * len(chunk))})",
                (kind, field, *chunk))}
        return sorted(out)

    def get_many(self, kind: str, keys) -> dict[str, dict]:
        check_kind(kind)
        keys = sorted(set(keys))
        out: dict[str, dict] = {}
        for i in range(0, len(keys), 500):                   # bounded statements
            chunk = keys[i:i + 500]
            for key, body in self._q(f"SELECT key, body FROM records WHERE kind = ? AND key IN "
                                     f"({','.join('?' * len(chunk))})", (kind, *chunk)):
                out[key] = json.loads(body)
        return out

    def count(self, kind: str) -> int:
        check_kind(kind)
        return self._q("SELECT count(*) FROM records WHERE kind = ?", (kind,))[0][0]

    def scan(self, kind: str) -> Iterator[tuple[str, dict]]:
        check_kind(kind)
        for key, body in self._q("SELECT key, body FROM records WHERE kind = ? ORDER BY key", (kind,)):
            yield key, json.loads(body)

    def side_get(self, kind: str, key: str) -> dict | None:
        check_side(kind, key)
        row = self._q("SELECT body FROM side WHERE kind = ? AND key = ?", (kind, key))
        return json.loads(row[0][0]) if row else None

    def side_scan(self, kind: str) -> Iterator[tuple[str, dict]]:
        check_side(kind, "-")
        for key, body in self._q("SELECT key, body FROM side WHERE kind = ? ORDER BY key", (kind,)):
            yield key, json.loads(body)


def _sealed(row) -> dict:
    import base64
    return {"bytes": base64.b64encode(bytes(row[0])).decode("ascii"), "signature": row[1]}
