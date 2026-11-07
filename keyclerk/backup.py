# SPDX-License-Identifier: EUPL-1.2
"""Backup, its manifest and the restore drill (decisions 0019 points 1 to 4 and 0029, issue 26).

    python -m keyclerk.backup key      --out FILE                    a new manifest key; prints its public key
    python -m keyclerk.backup take     --desk DIR --signer-state DIR --records-key HEX --key FILE --out DIR
    python -m keyclerk.backup shipped  --manifest F --where TEXT --key FILE
    python -m keyclerk.backup erasures --desk DIR --key FILE --out F      the erasure journal, refreshed after an erasure
    python -m keyclerk.backup check    --archive F --manifest F --pin HEX
    python -m keyclerk.backup restore  --archive F --manifest F --pin HEX --records-key HEX --identity FILE --to DIR
                                       --erasures F
    python -m keyclerk.backup drill    --from DIR --pin HEX --records-key HEX --identity FILE [--report FILE]
    python -m keyclerk.backup escrow challenge --manifests DIR --pin HEX --key FILE
    python -m keyclerk.backup escrow answer    --manifests DIR --pin HEX --key FILE --recipient AGE1 (--answer V |
                                               --identity FILE)
    python -m keyclerk.backup hygiene  --manifests DIR --pin HEX      the escrow and rotation checks; exit 1 on a finding

A backup is a consistent snapshot of a desk's directory and of its signer's state, taken while they run: each SQLite
store through the online backup API, every other file as it stands, a log copied up to its last whole line. It leaves
out every key (each *.key file, named in the manifest so a restore says which keys to bring back from escrow; any other
file whose content looks like a key refuses the backup: keys are escrowed apart, never in a data backup), the locks,
the caches, an in-progress restore marker and the replicas earlier resyncs replaced. The copy is verified before it is
written (each change log replayed against the pinned records key, the full check on the signer's, the signer's audit
chain, the YAML store's signature), packed into a tar and encrypted with age to the recipients the configuration lists
(backup.recipients: the custodians' recovery keys and a drill's test key; never one given on a command line). The
manifest names the revision, the head, the archive's hash and size, each member's hash and what was verified, and is
signed by the host's manifest key under its own label. Everything goes through files in a staging directory, so memory
stays small whatever the size of the store.

The shipper, once a copy is off-site, records where and when (shipped): the newest shipped backup is the backup age
metric. A restore checks the manifest before anything else (signed by a pinned key, the archive's size and hash),
decrypts, checks every member against it, verifies again, compares the revision and head with the manifest, and only
then moves the result into place. The desk and the signer it gives start in restore mode (keyclerk/restore.py): no
writes and not ready until a mark is confirmed, and the signer signs nothing at positions it may have lost. A desk is
restored only with an erasure journal at least as new as the backup (decision 0028 point 6): take writes one beside
each manifest, the erasures command refreshes it after an erasure, and what it lists is erased again before the desk
serves. A drill restores the newest good backup into a scratch directory and reports how long
it took: the measured recovery time. A failed drill is an incident.

Hygiene (decision 0019 point 2). The recipients that matter are the configured ones and every retired one a kept
backup (within backup.retention_days) was encrypted to, so older backups stay readable. The escrow check proves each
is still held: escrow challenge encrypts a fresh random value to each, one file per recipient in DIR/escrow; its
custodian decrypts theirs with the standard age tool and escrow answer records the value, or a host holding the
identity (the drill's test key) answers with it; each proof is a line the manifest key signs. hygiene then reports a
recipient whose last proof is older than backup.escrow_check_days (90), and a configured recipient first used more
than backup.rotate_after_days (365) ago: rotate it, by adding the new key to backup.recipients and removing the old one
once the backups encrypted to it have aged out. The gauges keyclerk_backup_escrow_unproven and
keyclerk_backup_recipients_due_rotation count them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from keyclerk import age
from keyclerk import edge as E

FORMAT = "kc-backup-v1"
SHIPPED_FORMAT = "kc-backup-shipped-v1"
LABEL = b"kc-backup-manifest-v1\n"
SHIPPED_LABEL = b"kc-backup-shipped-v1\n"
ERASURES_FORMAT = "kc-erasures-v1"
ERASURES_LABEL = b"kc-erasures-v1\n"
MIN_RECIPIENTS = 2
SQLITE_MAGIC = b"SQLite format 3\x00"
SKIP_SUFFIX = (".lock", ".tmp", "-wal", "-shm", "-journal")
SKIP_NAME = ("restore.json", "fullcheck-previous.sqlite")   # a restore in progress; the full check's rebuildable cache
KEYISH = re.compile(rb"\s*(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{128})\s*")
BLOCK = 1 << 20


class BackupRefused(RuntimeError):
    """Why a backup, a check or a restore did not go ahead, and what to do."""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while b := f.read(BLOCK):
            h.update(b)
    return h.hexdigest()


def load_key(path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path(path).read_text(encoding="utf-8").strip()))


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def new_key(path: Path) -> str:
    """A new manifest key in a file of its own (refusing to overwrite one); its public key, to pin."""
    key = Ed25519PrivateKey.generate()
    with open(path, "x", encoding="utf-8") as f:
        f.write(key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    if os.name != "nt":
        os.chmod(path, 0o600)
    return public_hex(key)


def _policy() -> dict:
    from keyclerk import config
    return (config.current() or {}).get("backup") or {}


def recipients() -> list[str]:
    """The age recipients a backup is encrypted to: backup.recipients, at least two (decision 0029 point 2)."""
    rs = list(dict.fromkeys(r.strip() for r in _policy().get("recipients") or []))
    if len(rs) < MIN_RECIPIENTS:
        raise BackupRefused(f"backup.recipients lists {len(rs)} age recipients; a backup is encrypted to at least "
                            f"{MIN_RECIPIENTS} (two custodians, decision 0019). Add each custodian's recipient, and the "
                            "drill's test key, to the configuration")
    for r in rs:
        try:
            age._recipient(r)
        except age.AgeError as e:
            raise BackupRefused(f"backup.recipients: {r[:12]}... is not an age recipient ({e})") from None
    return rs


# --- taking a snapshot -----------------------------------------------------------------------------------------------

def _skipped(p: Path) -> bool:
    return p.name in SKIP_NAME or p.name.startswith(".snapshot-") or p.name.endswith(SKIP_SUFFIX) or \
        p.name.startswith("audit.jsonl.partial-")


def _keyish(p: Path, head: bytes, size: int) -> bool:
    if size <= 512 and not p.name.endswith((".sha256", ".sig")) and KEYISH.fullmatch(head):   # a hash, a signature
        return True
    return b"PRIVATE KEY-----" in head or b"AGE-SECRET-KEY-1" in head.upper()


def _sqlite_copy(src: Path, dst: Path) -> None:
    """A consistent copy of a SQLite store a process may be writing, through the online backup API."""
    s = sqlite3.connect(f"{src.resolve().as_uri()}?mode=ro", uri=True)
    d = sqlite3.connect(dst)
    try:
        s.backup(d)
        d.execute("PRAGMA journal_mode = DELETE")
    finally:
        d.close()
        s.close()


def _copy(src: Path, dst: Path) -> None:
    """A file as it stands; a log up to its last whole line (a line still being written belongs to the next backup)."""
    with open(src, "rb") as f, open(dst, "wb") as g:
        shutil.copyfileobj(f, g, BLOCK)
    if src.suffix not in (".jsonl", ".log"):
        return
    with open(dst, "r+b") as g:
        end = g.seek(0, os.SEEK_END)
        while end:
            start = max(0, end - BLOCK)
            g.seek(start)
            cut = g.read(end - start).rfind(b"\n")
            if cut >= 0:
                end = start + cut + 1
                break
            end = start
        g.truncate(end)


def _current_replica(root: Path) -> str:
    f = root / "log.current"
    return f.read_text(encoding="utf-8").strip() if f.exists() else "log.db"


def _collect(root: Path, prefix: str, stage: Path, left_out: list[str]) -> list[str]:
    """Copy what a backup holds of root into stage/prefix; the member names."""
    names, current = [], _current_replica(root) if prefix == "desk" else None
    for p in sorted(root.rglob("*")):
        if not p.is_file() or _skipped(p) or "__pycache__" in p.parts:
            continue
        rel = p.relative_to(root).as_posix()
        if p.suffix == ".key":                               # escrowed apart; the manifest names it for the restore
            left_out.append(f"{prefix}/{rel}")
            continue
        with open(p, "rb") as f:
            head = f.read(4096)
        if current and "/" not in rel and rel.startswith("log") and rel.endswith(".db") and rel != current:
            continue                                         # a replica the last resync replaced (0029 point 4)
        if _keyish(p, head, p.stat().st_size):
            raise BackupRefused(f"{p} holds what looks like a key: a backup never carries one (decision 0019: keys are "
                                "escrowed apart, in a password manager and with a second custodian). Name it *.key "
                                "if it is one (a backup leaves those out), or move it out, and take the backup again")
        dst = stage / prefix / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        (_sqlite_copy if head[:16] == SQLITE_MAGIC else _copy)(p, dst)
        names.append(f"{prefix}/{rel}")
    return names


def _db(f: Path, records_key: str):
    from keyclerk.store.sqlite import SqliteStore
    c = sqlite3.connect(f"{f.resolve().as_uri()}?mode=ro", uri=True)
    try:
        realm = dict(c.execute("SELECT key, value FROM meta").fetchall()).get("realm")
    except sqlite3.Error:
        realm = None
    finally:
        c.close()
    return SqliteStore(f, records_key, realm, _readonly=True)


def _is_sqlite(f: Path) -> bool:
    with open(f, "rb") as h:
        return h.read(16) == SQLITE_MAGIC


def verify(stage: Path, names: list[str], records_key: str) -> dict:
    """What the copy in stage proves of itself, or BackupRefused with the reason: every change log replayed against the
    pinned records key, the full check on the signer's, the signer's audit chain, the YAML store's signature."""
    from keyclerk import fullcheck, signer
    from keyclerk.store import replay
    from keyclerk.store.link import StoreRefused
    pub = E.load_public(records_key)
    out: dict = {}
    keys = None                                   # the signer's records-key history's keys, for its audit chain (#41)
    current = f"desk/{(stage / 'desk' / 'log.current').read_text(encoding='utf-8').strip()}" \
        if (stage / "desk" / "log.current").exists() else "desk/log.db"
    for name in sorted(n for n in names if _is_sqlite(stage / n)):
        part = name.split("/", 1)[0]
        if part == "desk" and name != current:
            continue
        try:
            st = _db(stage / name, records_key)
        except StoreRefused as e:
            raise BackupRefused(f"{name}: {e}") from None
        try:
            replay.verify(st, st.pinned, st.realm)    # the store's own history after a rotation (#41)
            if part == "signer" and not isinstance(st.pinned, str):
                keys = [w["key"] for w in st.pinned.doc["keys"]]
            got = {"store": "log", "file": name, "realm": st.realm, "links": st.size(),
                   "head": st.head().hex() if st.head() else None, "revision": replay.revision(st)}
            if part == "signer":
                with tempfile.TemporaryDirectory() as state:
                    r = fullcheck.run(st, Path(state))
                if not r.ok or r.frozen:
                    raise BackupRefused(f"{name}: the full check does not pass ({r.frozen or r.alarms[:1]}): a "
                                        "backup is of a state that passes it. Resolve the finding, then take it")
                got["full_check"] = "passed"
        except StoreRefused as e:
            raise BackupRefused(f"{name} does not verify: {e}. Do not ship it; find why the store is broken") from None
        finally:
            st.close()
        out[part] = got
    if "signer/audit.jsonl" in names:
        with open(stage / "signer" / "audit.jsonl", "rb") as f:
            why, _, n = signer.audit_chain(f, pub, keys)
        if why:
            raise BackupRefused(why)
        out.setdefault("signer", {})["audit_lines"] = n
    if "desk/records.yaml" in names:
        raw = (stage / "desk" / "records.yaml").read_bytes()
        try:
            pub.verify(bytes.fromhex((stage / "desk" / "records.yaml.sig").read_text().strip()), raw)
        except Exception:   # noqa: BLE001 - absent, malformed or another key's
            raise BackupRefused("desk/records.yaml is not signed by the records key, or changed while it was "
                                "copied: take the backup again") from None
        revs = [int(n.rsplit("/", 1)[1][:-5]) for n in names if re.fullmatch(r"desk/revisions/\d+\.yaml", n)]
        out["desk"] = {"store": "yaml", "revision": max(revs, default=None), "head": hashlib.sha256(raw).hexdigest()}
    if not out:
        raise BackupRefused("nothing to back up: give --desk and, where it runs, --signer-state")
    return out


def _main(verified: dict) -> dict:
    return verified["signer"] if "revision" in verified.get("signer", {}) else verified.get("desk", {})


def take(out: Path, records_key: str, key: Ed25519PrivateKey, desk: Path | None = None,
         signer_state: Path | None = None) -> tuple[Path, Path, dict]:
    """A verified, encrypted backup and its signed manifest in out; (archive, manifest, manifest body)."""
    to = recipients()
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="kc-backup-") as tmp:    # private (0700), never in the outbox
        stage, left_out, names = Path(tmp) / "stage", [], []
        stage.mkdir()
        if desk:
            names += _collect(Path(desk), "desk", stage, left_out)
        if signer_state:
            names += _collect(Path(signer_state), "signer", stage, left_out)
        verified = verify(stage, names, records_key)
        main = _main(verified)
        members = [{"path": n, "bytes": (stage / n).stat().st_size, "sha256": _sha_file(stage / n)} for n in sorted(names)]
        tar = Path(tmp) / "backup.tar"
        with tarfile.open(tar, mode="w", format=tarfile.PAX_FORMAT) as t:
            for n in sorted(names):
                info = tarfile.TarInfo(n)
                info.size, info.mode, info.mtime = (stage / n).stat().st_size, 0o600, 0
                with open(stage / n, "rb") as f:
                    t.addfile(info, f)
        taken = _now()
        realm = main.get("realm") or verified.get("desk", {}).get("realm") or "unknown"
        stem = base = f"kc-backup-{realm}-r{main.get('revision') or 0}-{taken.replace(':', '').replace('-', '')}"
        n = 1
        while (out / f"{stem}.tar.age").exists() or (out / f"{stem}.manifest.json").exists():
            n += 1
            stem = f"{base}-{n}"
        archive = out / f"{stem}.tar.age"
        enc = archive.with_name(archive.name + ".tmp")              # only ciphertext is ever written to the outbox
        with open(tar, "rb") as src, open(enc, "wb") as dst:
            age.encrypt_to(src, dst, to)
            dst.flush()
            os.fsync(dst.fileno())
        body = {"format": FORMAT, "realm": realm, "taken_at": taken, "revision": main.get("revision"),
                "head": main.get("head"), "records_key": records_key, "manifest_key": public_hex(key),
                "archive": {"name": archive.name, "bytes": enc.stat().st_size, "sha256": _sha_file(enc)},
                "members": members, "recipients": to, "verified": verified, "keys_left_out": left_out}
        os.replace(enc, archive)
    manifest = out / f"{stem}.manifest.json"
    _write(manifest, _canon({"manifest": body, "signature": key.sign(LABEL + _canon(body)).hex()}) + b"\n")
    if desk:
        write_erasures(Path(desk), key, out / f"{stem}.erasures.json")
    return archive, manifest, body


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


# --- shipping --------------------------------------------------------------------------------------------------------

def shipped(manifest: Path, where: str, key: Ed25519PrivateKey) -> Path:
    """The shipper's signed record that a backup is off-site (decision 0019 point 3), beside its manifest."""
    manifest = Path(manifest)
    if not isinstance(where, str) or not 1 <= len(where) <= 1024 or "\n" in where:
        raise BackupRefused("--where names the off-site copy in one line of at most 1024 characters")
    raw = manifest.read_bytes()
    body = {"format": SHIPPED_FORMAT, "manifest": manifest.name, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "where": where, "at": _now()}
    f = manifest.with_name(manifest.name.removesuffix(".manifest.json") + ".shipped.json")
    _write(f, _canon({"shipped": body, "signature": key.sign(SHIPPED_LABEL + _canon(body)).hex()}) + b"\n")
    return f


def read_shipped(manifest: Path, pins: list[str]) -> dict | None:
    """The shipped record of a manifest when a pinned key signed it for exactly that manifest, else None."""
    f = Path(manifest).with_name(Path(manifest).name.removesuffix(".manifest.json") + ".shipped.json")
    try:
        doc = json.loads(f.read_bytes())
        body, sig = doc["shipped"], bytes.fromhex(doc["signature"])
    except Exception:   # noqa: BLE001 - absent or unreadable: not shipped
        return None
    if body.get("format") != SHIPPED_FORMAT or body.get("manifest_sha256") != _sha_file(Path(manifest)):
        return None
    for pin in pins:
        try:
            E.load_public(pin).verify(sig, SHIPPED_LABEL + _canon(body))
            return body
        except Exception:   # noqa: BLE001 - another key's
            continue
    return None


# --- the erasure journal (decision 0028 point 6) ---------------------------------------------------------------------

def erased_visits(log: Path) -> list[str]:
    """The visit ids a desk's activity log says were erased (ids only: the journal holds no personal data)."""
    out: set[str] = set()
    if not Path(log).exists():
        return []
    with open(log, "rb") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue                                     # a line still being written
            for vid, sha in (e.get("visits") or {}).items() if isinstance(e.get("visits"), dict) else ():
                if sha is None:
                    out.add(vid)
    return sorted(out)


def write_erasures(desk: Path, key: Ed25519PrivateKey, path: Path) -> dict:
    """A signed erasure journal of what desk erased so far, kept and shipped apart from the backups: refresh it after
    every erasure (python -m keyclerk.backup erasures). A restore applies the newest one before the desk serves."""
    body = {"format": ERASURES_FORMAT, "at": _now(), "visits": erased_visits(Path(desk) / "log.jsonl")}
    _write(Path(path), _canon({"erasures": body, "signature": key.sign(ERASURES_LABEL + _canon(body)).hex()}) + b"\n")
    return body


def read_erasures(path: Path, pins: list[str]) -> dict:
    try:
        doc = json.loads(Path(path).read_bytes())
        body, sig = doc["erasures"], bytes.fromhex(doc["signature"])
    except Exception as e:   # noqa: BLE001 - absent or unreadable: refused the same
        raise BackupRefused(f"{path} is not an erasure journal ({type(e).__name__})") from None
    if not isinstance(body, dict) or body.get("format") != ERASURES_FORMAT or not isinstance(body.get("visits"), list):
        raise BackupRefused(f"{path} is not a {ERASURES_FORMAT} journal")
    for pin in pins:
        try:
            E.load_public(pin).verify(sig, ERASURES_LABEL + _canon(body))
            return body
        except Exception:   # noqa: BLE001 - another key's
            continue
    raise BackupRefused(f"{path} is not signed by a pinned manifest key: a forged journal could erase or keep what it "
                        "likes. Use the journal the desk's host wrote")


def newest_erasures(source: Path, pins: list[str]) -> Path | None:
    found = []
    for f in Path(source).glob("*.erasures.json"):
        try:
            found.append((read_erasures(f, pins)["at"], f))
        except BackupRefused:
            continue
    return max(found)[1] if found else None


# --- checking and restoring ------------------------------------------------------------------------------------------

def read_manifest(manifest: Path, pins: list[str]) -> dict:
    """The manifest's body when a pinned manifest key signed it, or BackupRefused."""
    try:
        doc = json.loads(Path(manifest).read_bytes())
        body, sig = doc["manifest"], bytes.fromhex(doc["signature"])
    except Exception as e:   # noqa: BLE001 - unreadable in any way: refused the same
        raise BackupRefused(f"{manifest} is not a backup manifest ({type(e).__name__})") from None
    if not isinstance(body, dict) or body.get("format") != FORMAT:
        raise BackupRefused(f"{manifest} is not a {FORMAT} manifest")
    for pin in pins:
        try:
            E.load_public(pin).verify(sig, LABEL + _canon(body))
            return body
        except Exception:   # noqa: BLE001 - another key's, try the next pin
            continue
    raise BackupRefused(f"{manifest} is not signed by a pinned manifest key: do not restore it. Pin the key of the host "
                        "that took it (--pin), or take the backup from a copy you trust")


def check(archive: Path, manifest: Path, pins: list[str]) -> dict:
    """Decision 0019: the manifest is checked before a restore starts. Its body, or BackupRefused."""
    body = read_manifest(manifest, pins)
    want, size = body["archive"], Path(archive).stat().st_size
    if size != want["bytes"]:
        raise BackupRefused(f"{archive} holds {size} bytes, its manifest says {want['bytes']}: the copy is cut or "
                            "another backup's. Fetch it again, or restore an older backup")
    if _sha_file(Path(archive)) != want["sha256"]:
        raise BackupRefused(f"{archive} does not match its manifest's hash: the copy changed after it was taken. Fetch "
                            "it again, or restore an older backup, and treat the changed copy as an incident")
    return body


def _unpack(archive: Path, ids: list[str], body: dict, work: Path) -> Path:
    """Decrypt and unpack into work/stage, every member checked against the manifest; the stage."""
    tar = work / "backup.tar"
    try:
        with open(archive, "rb") as src, open(tar, "wb") as dst:
            age.decrypt_to(src, dst, ids)
    except age.AgeError as e:
        raise BackupRefused(f"the archive does not decrypt: {e}") from None
    want, seen, stage = {m["path"]: m for m in body["members"]}, set(), work / "stage"
    with tarfile.open(tar, mode="r:") as t:
        for m in t:
            p = PurePosixPath(m.name)
            if not m.isfile() or p.is_absolute() or ".." in p.parts or p.parts[0] not in ("desk", "signer") \
                    or m.name not in want or m.name in seen:
                raise BackupRefused(f"the archive holds {m.name!r}, which is not a file its manifest names")
            f = stage / m.name
            f.parent.mkdir(parents=True, exist_ok=True)
            with t.extractfile(m) as src, open(f, "wb") as dst:
                shutil.copyfileobj(src, dst, BLOCK)
            if f.stat().st_size != want[m.name]["bytes"] or _sha_file(f) != want[m.name]["sha256"]:
                raise BackupRefused(f"{m.name} does not match its manifest")
            seen.add(m.name)
    tar.unlink()
    if seen != set(want):
        raise BackupRefused("the archive's files are not the ones its manifest names")
    return stage


def restore(archive: Path, manifest: Path, pins: list[str], records_key: str, ids: list[str], to: Path,
            erasures: Path | None = None) -> dict:
    """Restore into an empty directory: to/desk and to/signer, both in restore mode. A desk needs the newest erasure
    journal, at least as new as the backup: what was erased since is erased again before the desk serves."""
    from keyclerk import restore as R
    to = Path(to)
    if to.exists() and any(to.iterdir()):
        raise BackupRefused(f"{to} is not empty: a restore writes into an empty directory, never over a store")
    body = check(archive, manifest, pins)
    if body["records_key"] != records_key:
        raise BackupRefused("the backup was taken against another records key than the one pinned (--records-key)")
    journal = None
    if any(m["path"].startswith("desk/") for m in body["members"]):
        if erasures is None:
            raise BackupRefused("a desk is restored only with the erasure journal (decision 0028 point 6): give "
                                "--erasures, the newest *.erasures.json the desk's host wrote and shipped")
        journal = read_erasures(Path(erasures), pins)
        if journal["at"] < body["taken_at"]:
            raise BackupRefused(f"the erasure journal is of {journal['at']}, older than the backup ({body['taken_at']}): "
                                "it may miss what was erased since. Use the newest journal")
    to.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f".{to.name}.restoring-", dir=to.parent))
    try:
        stage = _unpack(Path(archive), ids, body, work)
        verified = verify(stage, [m["path"] for m in body["members"]], records_key)
        main = _main(verified)
        if (main.get("revision"), main.get("head")) != (body["revision"], body["head"]):
            raise BackupRefused("the restored state's revision or head is not its manifest's")
        why = f"restored from {Path(archive).name} (revision {body['revision']})"
        if (stage / "desk").is_dir():
            R.start(stage / "desk", reason=why, erasures=journal["visits"])
        if (stage / "signer").is_dir():
            R.start(stage / "signer", reason=why)            # signs nothing until recover-log or the restore link
        if to.exists():
            to.rmdir()
        os.replace(stage, to)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return {"revision": body["revision"], "head": body["head"], "taken_at": body["taken_at"], "to": str(to),
            "verified": verified, "keys_to_bring_back": body.get("keys_left_out", []),
            "erasures_to_apply": len(journal["visits"]) if journal else 0}


def newest(source: Path, pins: list[str]) -> tuple[Path, Path, dict]:
    """The newest backup in source whose manifest a pinned key signed and whose archive is beside it."""
    found = []
    for m in Path(source).glob("*.manifest.json"):
        try:
            body = read_manifest(m, pins)
        except BackupRefused:
            continue
        a = m.with_name(body["archive"]["name"])
        if a.exists():
            found.append((body["taken_at"], body.get("revision") or 0, a, m, body))
    if not found:
        raise BackupRefused(f"no backup in {source} with a manifest signed by a pinned key")
    *_, a, m, body = max(found, key=lambda x: x[:2])
    return a, m, body


def newest_age(manifests: Path, pins: list[str]) -> float:
    """Seconds since the newest shipped backup (its manifest and its shipped record signed by a pinned key):
    keyclerk_backup_age_seconds. LookupError when there is none, so the gauge is absent and an alert on absence fires."""
    taken = []
    for m in Path(manifests).glob("*.manifest.json"):
        try:
            body = read_manifest(m, pins)
        except BackupRefused:
            continue
        if read_shipped(m, pins):
            taken.append(body["taken_at"])
    if not taken:
        raise LookupError(f"no shipped backup in {manifests} signed by a trusted key")
    at = datetime.strptime(max(taken), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - at).total_seconds())


def last_drill(report: Path) -> dict:
    """The last restore drill's result line; LookupError when no drill ran."""
    lines = Path(report).read_text(encoding="utf-8").splitlines() if Path(report).exists() else []
    if not lines:
        raise LookupError(f"no restore drill in {report}")
    return json.loads(lines[-1])


def drill(source: Path, pins: list[str], records_key: str, ids: list[str], report: Path | None = None) -> dict:
    """Restore the newest good backup into a scratch directory and time it (decision 0019 point 4)."""
    started, result = time.perf_counter(), {"at": _now(), "source": str(source)}
    scratch = Path(tempfile.mkdtemp(prefix="kc-drill-"))
    try:
        a, m, body = newest(source, pins)
        result |= {"archive": a.name, "revision": body["revision"], "taken_at": body["taken_at"]}
        restore(a, m, pins, records_key, ids, scratch / "restored", newest_erasures(source, pins))
        result |= {"ok": True}
    except BackupRefused as e:
        result |= {"ok": False, "why": str(e), "incident": "a failed restore drill is an incident (decision 0019)"}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        result["recovery_seconds"] = round(time.perf_counter() - started, 3)
    if report:
        with open(report, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(result, sort_keys=True) + "\n")
    return result


# --- hygiene: escrow and rotation (decision 0019 point 2) ----------------------------------------------------------

ESCROW_FORMAT = "kc-backup-escrow-v1"
ESCROW_LABEL = b"kc-backup-escrow-v1\n"
CHALLENGE_LABEL = b"kc-backup-escrow-challenge-v1\n"


def _rid(recipient: str) -> str:
    return hashlib.sha256(recipient.encode("ascii")).hexdigest()[:12]


def _ts(s: str) -> datetime:
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def needed_recipients(manifests: Path, pins: list[str], now: datetime | None = None) -> dict[str, dict]:
    """Each recipient that matters: the configured ones and those a kept backup was encrypted to, with when a backup
    first used it and how many kept backups need it."""
    now = now or datetime.now(timezone.utc)
    keep = _policy().get("retention_days")
    try:
        current = recipients()
    except BackupRefused:
        current = [r.strip() for r in _policy().get("recipients") or []]
    out = {r: {"current": True, "first_used": None, "kept_backups": 0} for r in current}
    for m in Path(manifests).glob("*.manifest.json"):
        try:
            body = read_manifest(m, pins)
        except BackupRefused:
            continue
        kept = keep is None or (now - _ts(body["taken_at"])).days <= int(keep)
        for r in body.get("recipients") or []:
            e = out.setdefault(r, {"current": False, "first_used": None, "kept_backups": 0})
            e["first_used"] = min(filter(None, [e["first_used"], body["taken_at"]]))
            e["kept_backups"] += 1 if kept else 0
    return {r: e for r, e in out.items() if e["current"] or e["kept_backups"]}


def _signed_line(key: Ed25519PrivateKey, label: bytes, body: dict) -> bytes:
    return _canon({"body": body, "signature": key.sign(label + _canon(body)).hex()}) + b"\n"


def _verified(raw: bytes, label: bytes, pins: list[str]) -> dict | None:
    try:
        doc = json.loads(raw)
        body, sig = doc["body"], bytes.fromhex(doc["signature"])
    except Exception:   # noqa: BLE001 - unreadable: not a proof
        return None
    for pin in pins:
        try:
            E.load_public(pin).verify(sig, label + _canon(body))
            return body
        except Exception:   # noqa: BLE001 - another key's
            continue
    return None


def escrow_challenge(manifests: Path, pins: list[str], key: Ed25519PrivateKey) -> list[Path]:
    """A fresh random value encrypted to each recipient that matters, and the signed list of their hashes."""
    import secrets
    d = Path(manifests) / "escrow"
    d.mkdir(parents=True, exist_ok=True)
    out, listed = [], []
    for r in sorted(needed_recipients(manifests, pins)):
        value = secrets.token_hex(16)
        f = d / f"{_rid(r)}.challenge.age"
        _write(f, age.encrypt(value.encode("ascii"), [r]))
        listed.append({"recipient": r, "sha256": hashlib.sha256(value.encode("ascii")).hexdigest(), "file": f.name})
        out.append(f)
    _write(d / "challenges.json", _signed_line(key, CHALLENGE_LABEL, {"issued_at": _now(), "challenges": listed}))
    return out


def escrow_answer(manifests: Path, pins: list[str], key: Ed25519PrivateKey, recipient: str, answer: str | None = None,
                  ids: list[str] | None = None) -> dict:
    """Records that the holder of recipient decrypted its challenge: the value they read, or the identity given."""
    d = Path(manifests) / "escrow"
    ch = _verified((d / "challenges.json").read_bytes(), CHALLENGE_LABEL, pins) if (d / "challenges.json").exists() else None
    if ch is None:
        raise BackupRefused("no challenge signed by a pinned manifest key: run escrow challenge first")
    c = next((x for x in ch["challenges"] if x["recipient"] == recipient), None)
    if c is None:
        raise BackupRefused("the challenge names no such recipient")
    if ids is not None:
        try:
            answer = age.decrypt((d / c["file"]).read_bytes(), ids).decode("ascii")
        except Exception:   # noqa: BLE001 - the identity is not this recipient's
            raise BackupRefused("that identity does not open this recipient's challenge") from None
    if not isinstance(answer, str) or hashlib.sha256(answer.strip().encode("ascii")).hexdigest() != c["sha256"]:
        raise BackupRefused("the answer is not the value encrypted to this recipient: its key was not shown")
    body = {"format": ESCROW_FORMAT, "recipient": recipient, "at": _now(), "challenge_issued_at": ch["issued_at"]}
    with open(d / "escrow.jsonl", "ab") as f:
        f.write(_signed_line(key, ESCROW_LABEL, body))
        f.flush()
        os.fsync(f.fileno())
    return body


def hygiene(manifests: Path, pins: list[str], now: datetime | None = None) -> dict:
    """The escrow and rotation checks: each recipient that matters, its last proof, and the findings."""
    now = now or datetime.now(timezone.utc)
    pol = _policy()
    window, rotate = int(pol.get("escrow_check_days", 90)), int(pol.get("rotate_after_days", 365))
    proofs: dict[str, str] = {}
    f = Path(manifests) / "escrow" / "escrow.jsonl"
    for raw in (f.read_bytes().splitlines() if f.exists() else []):
        b = _verified(raw, ESCROW_LABEL, pins)
        if b and b.get("format") == ESCROW_FORMAT:
            proofs[b["recipient"]] = max(proofs.get(b["recipient"], ""), b["at"])
    rows, findings = [], []
    for r, e in sorted(needed_recipients(manifests, pins, now).items()):
        last = proofs.get(r)
        rows.append({"recipient": r, **e, "escrow_proven": last})
        short = f"{r[:16]}..."
        if last is None or (now - _ts(last)).days > window:
            findings.append({"recipient": r, "kind": "escrow_unproven",
                             "why": f"{short}: its key was {'never' if last is None else 'last'} shown"
                                    f"{'' if last is None else ' ' + last}; run escrow challenge and have its custodian "
                                    f"answer (backup.escrow_check_days is {window})"})
        if e["current"] and e["first_used"] and (now - _ts(e["first_used"])).days > rotate:
            findings.append({"recipient": r, "kind": "rotate",
                             "why": f"{short}: in use since {e['first_used']}, past backup.rotate_after_days ({rotate}); "
                                    "add the custodian's new key to backup.recipients, and remove this one once the "
                                    "backups encrypted to it have aged out"})
    return {"at": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "recipients": rows, "findings": findings, "ok": not findings}


# --- command line ----------------------------------------------------------------------------------------------------

def _ids(path: str) -> list[str]:
    ids = age.identities(Path(path).read_text(encoding="utf-8"))
    if not ids:
        raise BackupRefused(f"{path} holds no age identity (AGE-SECRET-KEY-1...)")
    return ids


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m keyclerk.backup", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("key", help="a new manifest key")
    k.add_argument("--out", required=True)
    t = sub.add_parser("take", help="encrypted to backup.recipients in the configuration")
    t.add_argument("--desk")
    t.add_argument("--signer-state")
    t.add_argument("--records-key", required=True, help="the records public key (hex), pinned")
    t.add_argument("--key", required=True, help="this host's manifest key file")
    t.add_argument("--out", required=True)
    j = sub.add_parser("erasures", help="refresh the erasure journal after an erasure; ship it apart from backups")
    j.add_argument("--desk", required=True)
    j.add_argument("--key", required=True, help="this host's manifest key file")
    j.add_argument("--out", required=True)
    s = sub.add_parser("shipped", help="the shipper records that a backup is off-site")
    s.add_argument("--manifest", required=True)
    s.add_argument("--where", required=True, help="where the copy went (bucket and object name), one line")
    s.add_argument("--key", required=True, help="this host's manifest key file")
    for name in ("check", "restore"):
        p = sub.add_parser(name)
        p.add_argument("--archive", required=True)
        p.add_argument("--manifest", required=True)
        p.add_argument("--pin", action="append", required=True, help="a manifest public key (hex) to trust")
        if name == "restore":
            p.add_argument("--records-key", required=True)
            p.add_argument("--identity", required=True, help="an age identity file of a custodian")
            p.add_argument("--to", required=True)
            p.add_argument("--erasures", help="the newest erasure journal (*.erasures.json); needed to restore a desk")
    d = sub.add_parser("drill")
    d.add_argument("--from", dest="source", required=True)
    d.add_argument("--pin", action="append", required=True)
    d.add_argument("--records-key", required=True)
    d.add_argument("--identity", required=True, help="the drill's test identity file")
    d.add_argument("--report", help="append the result as a JSON line")
    es = sub.add_parser("escrow", help="prove the recipients' keys are still held (decision 0019 point 2)")
    es.add_argument("step", choices=("challenge", "answer"))
    es.add_argument("--manifests", required=True)
    es.add_argument("--pin", action="append", required=True)
    es.add_argument("--key", required=True, help="this host's manifest key file")
    es.add_argument("--recipient")
    es.add_argument("--answer", help="the value the custodian read with age -d")
    es.add_argument("--identity", help="an age identity file that opens the challenge (the drill's test key)")
    h = sub.add_parser("hygiene", help="the escrow and rotation checks; exit 1 on a finding")
    h.add_argument("--manifests", required=True)
    h.add_argument("--pin", action="append", required=True)
    a = ap.parse_args(argv)
    try:
        if a.cmd == "escrow":
            if a.step == "challenge":
                for f in escrow_challenge(Path(a.manifests), a.pin, load_key(a.key)):
                    print(f)
            else:
                if not a.recipient or bool(a.answer) == bool(a.identity):
                    raise BackupRefused("answer needs --recipient and one of --answer or --identity")
                print(json.dumps(escrow_answer(Path(a.manifests), a.pin, load_key(a.key), a.recipient, a.answer,
                                               _ids(a.identity) if a.identity else None)))
            return 0
        if a.cmd == "hygiene":
            r = hygiene(Path(a.manifests), a.pin)
            print(json.dumps(r, indent=1))
            return 0 if r["ok"] else 1
        if a.cmd == "key":
            print(new_key(Path(a.out)))
        elif a.cmd == "take":
            if not a.desk and not a.signer_state:
                raise BackupRefused("give --desk, --signer-state or both")
            archive, manifest, body = take(Path(a.out), a.records_key, load_key(a.key),
                                           Path(a.desk) if a.desk else None,
                                           Path(a.signer_state) if a.signer_state else None)
            print(json.dumps({"archive": str(archive), "manifest": str(manifest), "revision": body["revision"],
                              "bytes": body["archive"]["bytes"]}))
        elif a.cmd == "erasures":
            print(json.dumps({"visits": len(write_erasures(Path(a.desk), load_key(a.key), Path(a.out))["visits"])}))
        elif a.cmd == "shipped":
            print(shipped(Path(a.manifest), a.where, load_key(a.key)))
        elif a.cmd == "check":
            body = check(Path(a.archive), Path(a.manifest), a.pin)
            print(json.dumps({"ok": True, "revision": body["revision"], "taken_at": body["taken_at"]}))
        elif a.cmd == "restore":
            print(json.dumps(restore(Path(a.archive), Path(a.manifest), a.pin, a.records_key, _ids(a.identity),
                                     Path(a.to), Path(a.erasures) if a.erasures else None), default=str))
        else:
            r = drill(Path(a.source), a.pin, a.records_key, _ids(a.identity), Path(a.report) if a.report else None)
            print(json.dumps(r))
            return 0 if r["ok"] else 1
    except (BackupRefused, FileExistsError, OSError, ValueError) as e:
        print(f"refused: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
