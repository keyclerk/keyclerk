# SPDX-License-Identifier: EUPL-1.2
"""The desk: the core behind every KeyClerk front end (decision 0005).

People act on group administration here: a deputy adds and removes members, nests groups, creates subgroups and
delegates (part of) what they hold; the root trust owner does the same at the top. Every action is turned into the
record it would add, and the candidate records go through every engine check (the same checks the reconciler runs).
The answer is one of three:
  applied   the checks pass: a new records revision is written, signed and logged; the reconciler applies it next run
  pending   the only thing missing is a key someone else must add (a second key from outside the chain, the security
            officer): the change waits for that approval, and nothing else may complete it
  refused   the checks fail, with every reason in words
Nothing is decided here that the engine does not decide: the desk only finds the delegation an actor acts under and
builds records. Reads are views over the same records (who holds what and why, who manages what and through which
chain), filtered by who asks.

The store is a folder: records.yaml (the current revision) and records.yaml.sig (its detached Ed25519 signature, the
form the reconciler verifies), revisions/ (every revision kept), log.jsonl (one line per change, each carrying the
hash of the line before), pending.json (changes waiting for a key). One process writes it at a time. The log is
appended from a remembered head, read from its tail and verified as it grows, so its length costs nothing per call;
every person's writes are rate-limited (refused attempts included), so nobody can grow it to stop the desk.

Every front end, the bundled one included, reaches this through the HTTP API (keyclerk.api) and its contract
(schema/api.openapi.json); nothing here knows about HTTP.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from keyclerk import delegation as D, guard, records, remedies
from keyclerk import qr as qr_mod

ACTIONS = ("add_member", "include_group", "end_membership", "create_group", "delegate", "end_delegation",
           "appoint_approver", "end_approver",
           "register_visit", "record_entry", "acknowledge_arrival", "confirm_guest", "record_departure",  # decision 0009
           "issue_qr", "issue_badge", "return_badge", "add_attendee", "register_on_site",
           "enrol_edge", "enrol_person_key", "grant_visit_lease", "end_edge_record", "rotate_edge")       # decision 0014
VISIT_ACTIONS = ACTIONS[-15:-5]
EDGE_ACTIONS = ACTIONS[-5:]
KEY_ERRORS = ("second key", "security officer's key", "manager's key")
APPROVERS_SHOWN = 3                  # names in "who can do it"; each is confirmed by a full evaluation (until 0022)
GROUP_ID = re.compile(r"[a-z0-9][a-z0-9-]{1,62}")
PENDING_DAYS = 7
MAX_PENDING = 500                     # changes waiting at once, across everyone
LOG_PAGE = 200
LOG_TAIL_BYTES = 4 * 1024 * 1024      # how much of the log's end a page reads
LOG_LINE_BYTES = 256 * 1024
VISIT_KINDS = (("visits", "visit_id"), ("visit_events", "event_id"), ("badges", "badge_id"))
WRITES_PER_WINDOW, WRITE_WINDOW = 30, 600   # per person: ample for real work, too few to flood the log
FULL_VERIFY_SECONDS = 600


SIGN_OWN = "your own signature: this change is high risk, so you sign it at the broker before it applies"   # decision 0015

class Refusal(Exception):
    """An action refused before the checks, with a reason meant for the person who asked, and the next steps that
    would complete what they set out to do (keyclerk.remedies)."""

    def __init__(self, message: str = "", next_steps: list | None = None):
        super().__init__(message)
        self.next = next_steps or []


class Throttled(Refusal):
    """Too many writes from one person in the window; not logged (that is what it protects)."""


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):      # the records loader refuses aliases, so none are ever written
        return True


def who_name(desk, doc: dict, p: dict) -> str:
    return desk._party_name(doc, p)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(t) -> str | None:
    if t is None:
        return None
    return (t if isinstance(t, datetime) else guard.timestamp(t)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _jsonable(x):
    return json.loads(json.dumps(x, default=lambda o: _iso(o) if isinstance(o, datetime) else str(o)))


# --- the store ----------------------------------------------------------------------------------------------------

def _count_entry(entry: dict) -> None:
    """Decision 0018 H2: every logged change by outcome, every refusal reason by who can resolve it."""
    from keyclerk import metrics
    outcome = str(entry.get("outcome") or "other")
    metrics.inc("keyclerk_changes_total", outcome=outcome)
    if outcome in ("refused", "pending"):
        for r in (entry.get("reasons") or [])[:20]:
            kind = remedies.match(str(r))[2]
            metrics.inc("keyclerk_refusals_total", reason_class=kind if kind in ("approvers", "managers", "root") else "other")


class StoreFault(RuntimeError):
    """The store is in a state the desk will not repair on its own: restore it from a backup."""


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _atomic(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as h:
        h.write(data)
        h.flush()
        os.fsync(h.fileno())
    os.replace(tmp, path)


class DeskFiles:
    """What a desk store keeps in its directory whatever holds the records (decision 0022 S5): the lock of its one
    writer, the activity log (log.jsonl, each line chained to the one before and signed by the records key or the
    checking signer), the pending changes and the view log. A store sets path, _signer, _key, _pub, _wlock, _head,
    _verified and _commit_sig, and gives revision()."""
    VIEW_LOG_MAX = 5_000_000      # bytes; the oldest half is dropped beyond it

    def log_view(self, entry: dict) -> None:
        """Append who looked at whose graph (decision 0009: every look is logged); bounded, never the content."""
        p = self.path / "views.log"
        line = json.dumps(entry, default=str, sort_keys=True) + "\n"
        try:
            if p.exists() and p.stat().st_size > self.VIEW_LOG_MAX:
                keep = p.read_bytes()[-(self.VIEW_LOG_MAX // 2):]
                p.write_bytes(keep[keep.find(b"\n") + 1:])
            with open(p, "a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            pass

    def _hold(self) -> None:
        self._lockf = open(self.path / "desk.lock", "a+b")   # noqa: SIM115 - held for the life of the store
        try:
            if os.name == "nt":
                import msvcrt
                self._lockf.seek(0)
                msvcrt.locking(self._lockf.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._lockf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._lockf.close()
            raise StoreFault("another desk process holds this store: one writer at a time") from None

    def close(self) -> None:
        if not self._lockf.closed:
            self._lockf.close()                               # the operating system drops the lock with the file

    def _signed(self, e: dict) -> bool:
        try:
            self._pub.verify(bytes.fromhex(e["signature"]), e["sha256"].encode())
            return True
        except Exception:   # noqa: BLE001 - absent, malformed or wrong: not signed by this desk
            return False

    def _lines(self, start: int = 0):
        """(end offset, line bytes) of every complete line from start on, streamed."""
        f = self.path / "log.jsonl"
        if not f.exists():
            return
        with f.open("rb") as h:
            h.seek(start)
            pos = start
            while True:
                line = h.readline(LOG_LINE_BYTES + 1)
                if not line.endswith(b"\n"):
                    return                                  # the end, or a line too long: the walk stops here
                pos += len(line)
                yield pos, line

    def _append(self, entry: dict, commit_raw: bytes | None = None) -> dict:
        with self._wlock:
            if self._head is None:
                self._head = (0, "0" * 64)
                for _, line in self._lines():
                    try:
                        e = json.loads(line)
                        self._head = (int(e["seq"]), str(e["sha256"]))
                    except (ValueError, KeyError, TypeError):
                        self._head = (self._head[0] + 1, "broken")   # verify_log names it; the chain stays visibly broken
            seq, prev = self._head
            _count_entry(entry)
            body = {"seq": seq + 1, "at": _iso(_now()), "revision": self.revision(), **_without_visitors(entry), "prev": prev}
            body["sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
            if self._signer is not None:                    # the signer checks a commit before it signs its line
                if commit_raw is not None:
                    out = self._signer.commit(commit_raw.decode("utf-8"), body)
                    body["signature"], self._commit_sig = out["line_signature"], out["records_signature"].encode()
                else:
                    body["signature"] = self._signer.sign_line(body)
            else:
                body["signature"] = self._key.sign(body["sha256"].encode()).hex()
            line = json.dumps(body, sort_keys=True) + "\n"
            if len(line.encode()) > LOG_LINE_BYTES:
                raise Refusal("this change is too large to keep on record")
            with (self.path / "log.jsonl").open("a", encoding="utf-8") as h:
                h.write(line)
                h.flush()
                os.fsync(h.fileno())
            self._head = (seq + 1, body["sha256"])
            return body

    def note(self, entry: dict) -> dict:
        """An activity line the desk signs (decision 0022's DeskStore protocol): refused, pending, an edge event."""
        return self._append(entry)

    def log(self, limit: int = LOG_PAGE) -> list[dict]:
        """The last entries, read from the end of the log, whatever its length."""
        f = self.path / "log.jsonl"
        if not f.exists():
            return []
        size = f.stat().st_size
        with f.open("rb") as h:
            h.seek(max(0, size - LOG_TAIL_BYTES))
            tail = h.read(LOG_TAIL_BYTES)
        lines = tail.split(b"\n")
        if size > LOG_TAIL_BYTES:
            lines = lines[1:]                                   # the first one is cut
        out = []
        for x in lines[-limit - 1:]:
            try:
                e = json.loads(x) if x.strip() else None
            except ValueError:
                e = {"outcome": "unreadable", "reasons": ["a log line does not read"]}
            if isinstance(e, dict):
                e.pop("signature", None)
                out.append(e)
        return out[-limit:]

    def verify_log(self) -> list[str]:
        """Every break in the hash chain of the change log and every line not signed by this desk: the new part each
        call, the whole of it now and then."""
        start, prev, errs, n, full_at = self._verified
        f = self.path / "log.jsonl"
        size = f.stat().st_size if f.exists() else 0
        if size < start or time.monotonic() - full_at > FULL_VERIFY_SECONDS:
            start, prev, errs, n, full_at = 0, "0" * 64, [], 0, time.monotonic()
        errs = list(errs)
        for end, line in self._lines(start):
            n += 1
            try:
                e = json.loads(line)
                signed = self._signed(e)
                e.pop("signature", None)
                sha = e.pop("sha256")
                ok = signed and e["prev"] == prev and hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() == sha
            except (ValueError, KeyError, TypeError, AttributeError):
                ok, sha = False, "broken"
            if not ok:
                errs.append(f"log line {n} does not chain or is not signed by this desk")
            prev, start = sha, end
        self._verified = (start, prev, errs[:100], n, full_at)
        return errs[:100]

    def pending(self) -> dict:
        f = self.path / "pending.json"
        if not f.exists():
            return {}
        try:
            p = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(p, dict):
                return p
        except (ValueError, UnicodeDecodeError):
            pass
        with self._wlock:                                     # changed outside the desk: set aside, on record
            stamp = _now().strftime("%Y%m%dT%H%M%SZ")
            if f.exists():
                os.replace(f, self.path / f"pending.json.corrupt-{stamp}")
            self._append({"action": "recover", "actor": None, "outcome": "recovered",
                          "reasons": ["an unreadable pending file was set aside: the changes it held must be proposed again"]})
        return {}

    def save_pending(self, p: dict) -> None:
        with self._wlock:
            _atomic(self.path / "pending.json", json.dumps(p, sort_keys=True).encode("utf-8"))


class YamlStore(DeskFiles):
    """One desk process per store (a lock file held while it lives). A commit is written ahead: first the revision
    file, then a log line the desk signs (it names the revision and its hash), then the published records and their
    signature. At start, and whenever the published records differ from what the desk last wrote, the store repairs
    what a crash or a stray write can leave, but only towards a revision a signed log line vouches for: a log line cut
    by a crash is set aside, an unreadable pending file is set aside, revision files no log line vouches for are set
    aside, and the vouched revision is published again. Anything else is a StoreFault: the desk does not start."""

    def __init__(self, path: Path, signing_key: Path | None, seed: Path | None = None, signer=None):
        """signing_key: the records key in this process; or signer: the checking signer (decision 0015), which holds
        it in its own process and signs a revision only after its own checks."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
        self.path = Path(path)
        self.key_path = Path(signing_key) if signing_key else None
        (self.path / "revisions").mkdir(parents=True, exist_ok=True)
        self._signer = signer
        if signer is not None:
            self._key = None
            self._pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer.public_key()))
        else:
            self._key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(self.key_path, 200).strip()))
            self._pub = self._key.public_key()
        self._commit_sig: bytes | None = None
        self._wlock = threading.RLock()
        self._hold()
        self._rev, self._sha, self._sig = 0, None, None
        self._parsed: tuple[str, dict] | None = None        # (sha256 of the records, their parse): parse once per change
        self._merged: tuple[str, dict] | None = None        # (records and visits key, the merged document)
        self._visits: dict[str, str] = {}                     # visit id -> sha256 of the file the log vouches for
        self._vparsed: dict[str, dict] = {}                   # sha256 -> the parsed visit file
        (self.path / "visits").mkdir(exist_ok=True)
        self._head: tuple[int, str] | None = None             # (last seq, last sha256) of the log
        self._verified = (0, "0" * 64, [], 0, 0.0)             # (bytes, prev sha, errors, lines, when fully checked)
        self.recovered: list[str] = []
        fresh = not any((self.path / n).exists() for n in ("records.yaml", "log.jsonl")) \
            and not any((self.path / "revisions").glob("*.yaml"))
        if fresh:
            if seed is None:
                raise FileNotFoundError("an empty desk store needs --seed records")
            doc = records.loads(guard.read_bounded(Path(seed)))
            if signer is None:                    # the signer judges a first revision itself; in process, the store does
                from keyclerk.reconcile import check_records
                errors = check_records(doc)
                if errors:
                    raise StoreFault(f"the seed records are refused, nothing was signed: {'; '.join(errors[:3])}")
            self.commit(doc, {"action": "seed", "actor": None, "outcome": "applied"})
        else:
            self._recover()

    # --- signatures -------------------------------------------------------------------------------------------------

    def public_key_hex(self) -> str:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        return self._pub.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    # --- records ----------------------------------------------------------------------------------------------------

    def raw(self) -> bytes:
        raw = guard.read_bounded(self.path / "records.yaml").encode("utf-8")
        if self._sha is not None and (_sha(raw) != self._sha or self._sig_bytes() != self._sig):
            with self._wlock:                                 # changed outside the desk, or a commit is publishing
                raw = guard.read_bounded(self.path / "records.yaml").encode("utf-8")
                if _sha(raw) != self._sha or self._sig_bytes() != self._sig:
                    raw = self._republish("the published records or their signature changed outside the desk")
        return raw

    def _sig_bytes(self) -> bytes | None:
        f = self.path / "records.yaml.sig"
        return f.read_bytes() if f.exists() else None

    def _records(self) -> dict:
        """The signed records alone, parsed once per revision (a parse grows with the records)."""
        raw = self.raw()
        key = _sha(raw)
        cached = self._parsed
        if cached is None or cached[0] != key:
            cached = (key, records.loads(raw.decode("utf-8")))
            self._parsed = cached
        return cached[1]

    def state_key(self) -> str:
        """Changes whenever the records or any visit change."""
        return _sha(self.raw()) + ":" + _sha(json.dumps(sorted(self._visits.items())).encode())

    def legacy_visits(self) -> bool:
        """A store written before 0.16 keeps its visits inside the records; it goes on doing so until it is seeded again."""
        return any(self._records().get(k) for k, _ in VISIT_KINDS)

    def load(self) -> dict:
        """The records with the visits merged in, built once per change and handed out as a copy, so no request can
        change what the next one reads. Visits live in their own files: personal data of visitors is not
        copied into every revision, and a visit is erased after its retention."""
        key = self.state_key()
        cached = self._merged
        if cached is None or cached[0] != key:
            doc = copy.deepcopy(self._records())
            for vid in sorted(self._visits):
                b = self._visit_file(vid)
                doc.setdefault("visits", []).append(b["visit"])
                doc.setdefault("visit_events", []).extend(b.get("visit_events", []))
                doc.setdefault("badges", []).extend(b.get("badges", []))
            cached = (key, doc)
            self._merged = cached
        return copy.deepcopy(cached[1])

    # --- visits -----------------------------------------------------------------------------------------------------

    def _vpath(self, vid: str, sha: str) -> Path:
        return self.path / "visits" / f"{guard.ident(vid, 'visit')}.{sha[:16]}.yaml"

    def _visit_file(self, vid: str) -> dict:
        sha = self._visits[vid]
        if sha not in self._vparsed:
            raw = guard.read_bounded(self._vpath(vid, sha)).encode("utf-8")
            if _sha(raw) != sha:
                raise StoreFault(f"the file of visit {vid}, vouched for by the log, changed: restore from a backup")
            self._vparsed[sha] = records.loads_part(raw.decode("utf-8"))
        return self._vparsed[sha]

    @staticmethod
    def _bundles(doc: dict) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for v in doc.get("visits", []):
            out[v["visit_id"]] = {"visit": v, "visit_events": [], "badges": []}
        for kind in ("visit_events", "badges"):
            for r in doc.get(kind, []):
                if r.get("visit_id") in out:
                    out[r["visit_id"]][kind].append(r)
        return out

    def _write_visits(self, doc: dict) -> dict[str, str | None]:
        """Write the visit files that changed, ahead of the log line that vouches for them: {visit id: new sha256}."""
        changed: dict[str, str | None] = {}
        for vid, b in self._bundles(doc).items():
            if vid in self._visits and b == self._visit_file(vid):
                continue                                      # unchanged: no dump, no write
            raw = yaml.dump(_jsonable_records(b), Dumper=_Dumper, sort_keys=False, allow_unicode=False).encode("utf-8")
            sha = _sha(raw)
            if self._visits.get(vid) != sha:
                records.loads_part(raw.decode("utf-8"))      # what is written must read back through the guard
                _atomic(self._vpath(vid, sha), raw)
                changed[vid] = sha
        return changed

    def _settle_visits(self, changed: dict[str, str | None]) -> None:
        """After the log vouches for the changes: the index follows, and superseded or erased files go."""
        for vid, sha in changed.items():
            old = self._visits.get(vid)
            if sha is None:
                self._visits.pop(vid, None)
            else:
                self._visits[vid] = sha
            if old and old != sha:
                self._vpath(vid, old).unlink(missing_ok=True)
                self._vparsed.pop(old, None)

    def visit_ids(self) -> list[str]:
        return sorted(self._visits)

    scoped_judging = False                    # the desk judges a change on the whole document (decision 0022 S5 T9)

    def judge(self, ops: list[dict]) -> None:
        """Not on this store: every change is judged in full."""
        return None

    def inward(self, value: str) -> str:
        """The records name people by the identity provider's id here: a name is what it says (decision 0028 is the
        change log's)."""
        return value

    def erase_visits(self, vids: list[str], entry: dict) -> dict | None:
        """Erase visits past their retention: their files go, the log keeps one line with the visit ids only."""
        with self._wlock:
            vids = [v for v in vids if v in self._visits]
            if not vids:
                return None
            changed: dict[str, str | None] = {v: None for v in vids}
            body = self._append({**entry, "visits": changed})
            self._settle_visits(changed)
            return body

    def revision(self) -> int:
        return self._rev

    def _publish(self, raw: bytes, sig: bytes | None = None) -> None:
        if sig is None:
            if self._key is None:
                raise StoreFault("the records' signature is missing and only the signer can sign: restore from a backup")
            sig = self._key.sign(raw).hex().encode()
        _atomic(self.path / "records.yaml", raw)              # the records first, then their signature: a reader in
        _atomic(self.path / "records.yaml.sig", sig)          # between sees a mismatch and refuses, never unsigned data
        self._sha, self._sig = _sha(raw), sig

    def _republish(self, why: str) -> bytes:
        f = self.path / "revisions" / f"{self._rev:06d}.yaml"
        raw = f.read_bytes() if f.exists() else b""
        if _sha(raw) != self._sha:
            raise StoreFault(f"revision {self._rev}, vouched for by the log, is missing or changed: restore from a backup")
        sf = f.with_name(f.name + ".sig")                   # kept at commit: publishing again needs no new signature
        self._publish(raw, sf.read_bytes() if sf.exists() else None)
        self._append({"action": "recover", "actor": None, "outcome": "recovered",
                      "reasons": [f"{why}: revision {self._rev} published again"]})
        return raw

    def commit(self, doc: dict, entry: dict, ops: list | None = None, tokens: list | None = None) -> dict:
        """Write a change ahead (a new revision when the records change, the visit files that change), then the log
        line that vouches for all of it, then publish. A store that still keeps visits in its records goes on doing so."""
        with self._wlock:
            changed: dict[str, str | None] = {}
            if self._rev and self.legacy_visits():
                rec = doc
            else:
                rec = {k: v for k, v in doc.items() if k not in dict(VISIT_KINDS)}
                changed = self._write_visits(doc)
            if self._rev:
                same = yaml.dump(_jsonable_records({**rec, "revision": self._rev}), Dumper=_Dumper, sort_keys=False,
                                 allow_unicode=False).encode("utf-8")
                if same == self.raw():                        # only visits changed: no new revision
                    body = self._append({**entry, "visits": changed})
                    self._settle_visits(changed)
                    return body
            n = self._rev + 1
            rec = {**rec, "revision": n}                      # the serial is signed with the records; it only grows
            raw = yaml.dump(_jsonable_records(rec), Dumper=_Dumper, sort_keys=False, allow_unicode=False).encode("utf-8")
            parsed = records.loads(raw.decode("utf-8"))       # what is written must read back through the guard
            rf = self.path / "revisions" / f"{n:06d}.yaml"
            _atomic(rf, raw)
            self._rev = n
            try:
                body = self._append({**entry, "records_sha256": _sha(raw), **({"visits": changed} if changed else {})},
                                    commit_raw=raw if self._signer is not None else None)
            except Exception:
                self._rev = n - 1                             # the signer refused: nothing was committed
                rf.unlink(missing_ok=True)
                raise
            sig = self._commit_sig if self._signer is not None else self._key.sign(raw).hex().encode()
            self._commit_sig = None
            _atomic(rf.with_name(rf.name + ".sig"), sig)
            self._publish(raw, sig)
            self._parsed = (_sha(raw), parsed)               # the next load needs no parse
            self._settle_visits(changed)
            return body

    # --- recovery ---------------------------------------------------------------------------------------------------

    def _recover(self) -> None:
        notes = []
        log = self.path / "log.jsonl"
        if log.exists() and log.stat().st_size:
            with log.open("rb") as h:
                h.seek(-1, os.SEEK_END)
                cut = h.read(1) != b"\n"
            if cut:                                           # a crash in the middle of an append
                data = log.read_bytes()
                keep = data.rfind(b"\n") + 1
                stamp = _now().strftime("%Y%m%dT%H%M%SZ")
                (self.path / f"log.jsonl.partial-{stamp}").write_bytes(data[keep:])
                with log.open("r+b") as h:
                    h.truncate(keep)
                notes.append(f"a log line cut by a crash ({len(data) - keep} bytes) was set aside")
        pend = self.path / "pending.json"
        if pend.exists():
            try:
                p = json.loads(pend.read_text(encoding="utf-8"))
                if not isinstance(p, dict):
                    raise ValueError("not an object")
            except (ValueError, UnicodeDecodeError):
                stamp = _now().strftime("%Y%m%dT%H%M%SZ")
                os.replace(pend, self.path / f"pending.json.corrupt-{stamp}")
                notes.append("an unreadable pending file was set aside: the changes it held must be proposed again")
        last = None
        for _, line in self._lines():
            try:
                e = json.loads(line)
                self._head = (int(e["seq"]), str(e["sha256"]))
            except (ValueError, KeyError, TypeError):
                self._head = ((self._head or (0, ""))[0] + 1, "broken")
                continue
            if e.get("records_sha256") and isinstance(e.get("revision"), int) and self._signed(e):
                last = e
            if isinstance(e.get("visits"), dict) and e["visits"] and self._signed(e):
                for vid, sha in e["visits"].items():
                    if sha is None:
                        self._visits.pop(vid, None)
                    else:
                        self._visits[vid] = sha
        if last is None:
            raise StoreFault("no commit in the log carries this desk's signature: restore the store from a backup")
        n = last["revision"]
        for f in sorted((self.path / "revisions").glob("*.yaml")):
            if f.stem.isdigit() and int(f.stem) > n:          # written ahead, never vouched for: a crash before the log
                (self.path / "revisions" / "aborted").mkdir(exist_ok=True)
                os.replace(f, self.path / "revisions" / "aborted" / f.name)
                notes.append(f"revision file {f.name} was never committed and was set aside")
        self._rev, self._sha = n, last["records_sha256"]
        keep = {self._vpath(v, s).name for v, s in self._visits.items()}
        for f in sorted((self.path / "visits").glob("*.yaml")):
            if f.name not in keep:                            # written ahead and never vouched for, or left by an erasure
                (self.path / "visits" / "aborted").mkdir(exist_ok=True)
                os.replace(f, self.path / "visits" / "aborted" / f.name)
                notes.append(f"visit file {f.name} was never committed and was set aside")
        for v, s in self._visits.items():
            if not self._vpath(v, s).exists():
                raise StoreFault(f"the file of visit {v}, vouched for by the log, is missing: restore from a backup")
        rf = self.path / "records.yaml"
        cur = rf.read_bytes() if rf.exists() else None
        sig_ok = False
        if cur is not None and _sha(cur) == self._sha and self._sig_bytes():
            try:
                self._pub.verify(bytes.fromhex(self._sig_bytes().decode("ascii").strip()), cur)
                sig_ok = True
            except Exception:   # noqa: BLE001
                sig_ok = False
        if sig_ok:
            self._sig = self._sig_bytes()
        else:
            self._republish("the published records or their signature were incomplete or changed")
        if notes:
            self._append({"action": "recover", "actor": None, "outcome": "recovered", "reasons": notes})
        self.recovered = notes


Store = YamlStore                     # the name before the desk had two stores (decision 0022, S5)


def _inward_who(fn):
    """Decision 0028: the person a request is from, as the records name them. Sign-in already resolves a token to the
    internal anchor (oidc resolve); this covers the callers that name themselves by the identity provider's id."""
    import functools

    @functools.wraps(fn)
    def run(self, who, *args, **kwargs):
        a = who.get("anchor") if isinstance(who, dict) else None
        if isinstance(a, str) and a:
            got = self.store.inward(a)
            if got and got != a:
                who = {**who, "anchor": got}
        return fn(self, who, *args, **kwargs)
    return run


def _without_visitors(entry: dict) -> dict:
    """A log line names visits by id only: no names, organisations, purposes or plates, which the log keeps for good
    while a visit is erased after its retention."""
    recs = entry.get("records")
    if not isinstance(recs, dict) or not any(k in recs for k, _ in VISIT_KINDS):
        return entry
    recs = dict(recs)
    vids = set()
    for kind, idf in VISIT_KINDS:
        if kind in recs:
            recs[kind] = [{idf: r.get(idf), "visit_id": r.get("visit_id")} for r in recs[kind] if isinstance(r, dict)]
            vids |= {r["visit_id"] for r in recs[kind] if r.get("visit_id")}
    return {**entry, "records": recs, "summary": f"{entry.get('action')} on {', '.join(sorted(vids)) or 'a visit'}"}


def _jsonable_records(doc: dict) -> dict:
    """Records as written: times as zoned ISO strings (the loader and the schema accept both)."""
    def walk(x):
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v) for v in x]
        if isinstance(x, datetime):
            return _iso(x)
        return x
    return walk(doc)


# --- the desk -----------------------------------------------------------------------------------------------------

class Desk:
    def __init__(self, store: Store, broker_state: Path | None = None, clock=_now, proofs=None,
                 link_key: bytes | None = None, public_base: str | None = None):
        self.store, self.broker_state, self.clock = store, broker_state, clock
        self.link_key, self.public_base = link_key or self._link_key(), (public_base or "").rstrip("/")
        self.proofs = proofs                                  # verifies approval proofs (keyclerk.approvals)
        self.lock = threading.Lock()
        self._bundle_wake = threading.Condition()            # 0026: a commit wakes the edges waiting for a bundle
        self._bundle_gen = 0
        self._long_polls: dict[str, list[dict]] = {}
        self._email_asks: dict[str, deque] = {}           # lease id -> when its address was asked (edge_email)
        self._base: tuple[str, set] | None = None
        self._writes: dict[str, deque] = {}
        self._waiting_cache: dict = {}
        self._counts_cache: dict = {}
        self._approvers_cache: dict = {}

    def _counts_cached(self, doc: dict, approver: str, cid: str, p: dict) -> bool:
        """_counts, remembered for this revision, change, keys given and approver (a view asks it on every load)."""
        key = (self.store.revision(), cid, tuple(p.get("approvals", [])), approver)
        if key not in self._counts_cache:
            if len(self._counts_cache) > 20000:
                self._counts_cache.clear()
            self._counts_cache[key] = self._counts(doc, approver, p)
        return self._counts_cache[key]

    def _link_key(self) -> bytes:
        """The key phone links are signed with: kept in the store, so links outlive a restart (one desk per store)."""
        f = self.store.path / "link.key"
        if not f.exists():
            f.write_text(os.urandom(32).hex(), encoding="utf-8")
            try:
                f.chmod(0o600)
            except OSError:
                pass
        return bytes.fromhex(f.read_text(encoding="utf-8").strip())

    @staticmethod
    def _public(add: dict) -> dict:
        """Records as shown in the log and in answers: approval proofs by their hash, never the tokens (#2)."""
        out = dict(add)
        for kind in ("approval_proofs", "proposal_proofs"):
            if out.get(kind):
                out[kind] = [{"records": p["records"], "by": p["by"],
                              "sha256": hashlib.sha256(str(p.get("token", "")).encode()).hexdigest()} for p in out[kind]]
        return out

    # --- next steps: why it did not happen, and who can make it happen ---------------------------------------------

    def _what(self, doc: dict, recs: dict) -> list[dict]:
        """What a change does, one line per record, in the words an approver checks before signing: the kind, the group
        and its class, the member or delegate, from and until, and the chain it is made under."""
        out = []

        def line(kind, group=None, member=None, start=None, end=None, detail=None, under=None):
            risk = D.effective_risk(doc, group) if group and group in D._groups(doc) else None
            chain = None
            if under == "root":
                chain = "root"
            elif under:
                chain = " < ".join([under] + [x["parent"] for x in D.chain(doc, under)][:-1] + ["root"])
            out.append({"kind": kind, "group": group, "risk": risk, "member": member,
                        "member_name": self._name(doc, member) if member else None,
                        "start": _iso(start) if start else None, "end": _iso(end) if end else None,
                        "detail": detail, "under": chain})
        for m in recs.get("memberships", []):
            mem = m["member"]
            line("membership", m["group"], mem.get("anchor"), m.get("start"), m.get("end"),
                 "the group " + mem["group"] if "group" in mem else "people matched by a rule" if "rule" in mem else None,
                 m.get("under"))
        for d in recs.get("delegations", []):
            line("delegation", d["group"], d["delegate"], d.get("start"), d.get("end"),
                 "powers " + ", ".join(d.get("powers", [])) + ", up to " + str(d.get("max_risk")), d.get("parent"))
        for g in recs.get("groups", []):
            line("new group", g["group_id"], detail="under " + str(g.get("parent")) + ", class " + str(g.get("max_risk")))
        for a in recs.get("approvers", []):
            line("named approver", member=a["anchor"], start=a.get("from"), end=a.get("to"), detail=a.get("reason"))
        for r in recs.get("admin_revocations", []):
            line("end", detail=f"{r.get('mode')} {r.get('id')}: {r.get('reason', '')}".strip(), start=r.get("at"))
        return out[:20]

    def _who(self, doc: dict, anchors) -> list[dict]:
        out, seen = [], set()
        for a in anchors:
            if a and a not in seen:
                seen.add(a)
                out.append({"anchor": a, "name": self._name(doc, a)})
        return out[:50]

    def _approvers(self, doc: dict, recs: dict, given: list, actor: str | None) -> list[str]:
        """Up to APPROVERS_SHOWN people whose approval would complete the change or add a key it still needs (asked of
        the engine), in record order. A cheap pass first (decision 0017): an added approval changes only the change's
        own records, so only they are checked per candidate; the full evaluation (_counts) then confirms each name
        shown. The list is for showing who can do it; whether someone may approve is always their own evaluation."""
        key = (self.store.revision(), json.dumps(recs, sort_keys=True, default=str), tuple(given), actor)
        if key in self._approvers_cache:
            return list(self._approvers_cache[key])
        if len(self._approvers_cache) > 1000:
            self._approvers_cache.clear()
        out = self._approvers_uncached(doc, recs, given, actor)
        self._approvers_cache[key] = list(out)
        return out

    def _approvers_uncached(self, doc: dict, recs: dict, given: list, actor: str | None) -> list[str]:
        p = {"records": recs, "approvals": list(given)}
        candidates = []
        with D.memo():
            for person in (doc.get("persons") or [])[:5000]:
                for a in person["anchors"][:1]:
                    if not ((actor and D.same(doc, a, actor)) or any(D.same(doc, a, g) for g in given)):
                        candidates.append(a)
        before = self._own_key_errors(doc, self._with_approvals(recs, list(given)))
        out = []
        for a in candidates:                   # cheap pass, then the full evaluation, per candidate: stop at the cap
            if before is not None:
                after = self._own_key_errors(doc, self._with_approvals(recs, [*given, a]))
                if not (after is None or not after or before - after):
                    continue
            if self._counts(doc, a, p):
                out.append(a)
                if len(out) >= APPROVERS_SHOWN:
                    break
        return out

    def _own_key_errors(self, doc: dict, add: dict) -> set[str] | None:
        """The key errors of the added records themselves (second key, officer's key, manager's key), with the reason
        tail about keys that do not count removed; None when a kind has no per-record check here (then every candidate
        goes to the full evaluation)."""
        from keyclerk import edge_records, policy_wasm
        per_kind = {"memberships", "delegations", "approvers", "edges", "person_keys", "edge_visit_leases", "edge_rotations"}
        if any(add.get(k) for k in add if k not in per_kind):
            return None
        cand = {**doc}
        for kind, recs in add.items():
            cand[kind] = list(doc.get(kind, [])) + list(recs)
        now = self.clock()
        errs: list[str] = []
        with D.memo():
            for m in add.get("memberships", []):
                errs += D.membership_errors(cand, m) + D.membership_errors(cand, m, at=now)
            for d in add.get("delegations", []):
                errs += D.attenuation_errors(cand, d)
            for x in add.get("approvers", []):
                errs += D.approver_errors(cand, x)
            for e in add.get("edges", []):
                errs += edge_records.edge_errors(cand, e)
            for k in add.get("person_keys", []):
                errs += edge_records.person_key_errors(cand, k)
            if add.get("edge_visit_leases"):
                hours = int(policy_wasm.edge("settings", {})["visit_max_hours"])
                for v in add["edge_visit_leases"]:
                    errs += edge_records.visit_lease_errors(cand, v, hours)
            for r in add.get("edge_rotations", []):
                errs += edge_records.rotation_errors(cand, r)
        return {re.sub(r"; [^;]*? does not count: .*$", "", e) for e in errs if any(k in e for k in KEY_ERRORS)}

    def _managers(self, doc: dict, gid: str | None, power: str, actor: str | None) -> list[str]:
        if not gid or gid not in D._groups(doc):
            return []
        now = self.clock()
        return [a for person in (doc.get("persons") or [])[:500] for a in person["anchors"][:1]
                if not (actor and D.same(doc, a, actor)) and D.authority(doc, a, gid, power, now)]

    def _next(self, doc: dict, actor: str | None, reasons, recs: dict | None = None, given=(), gid: str | None = None,
              sc: dict | None = None) -> list[dict]:
        """For each reason: why, what completes the intent, and who can do it."""
        import re as _re
        from keyclerk import remedies
        steps, seen = [], set()
        root = D.root_at(doc, self.clock())
        first = next((r.get("group") for kind in ("memberships", "delegations") for r in (recs or {}).get(kind, [])), None)
        for reason in list(reasons)[:10]:
            why, do, kind = remedies.match(str(reason))
            if (why, do) in seen:
                continue
            seen.add((why, do))
            m = _re.search(r"power '(\w+)' over (\S+)", str(reason))
            g = m.group(2) if m else (gid or first)
            power = m.group(1) if m else ("includes" if "includ" in str(reason) else "members")
            if kind == "approvers" and recs is not None:
                who = self._approvers(doc, recs, list(given), actor) or []
                if not who:
                    do += (" Nobody in the records can add that key now: the root can appoint a named approver with the"
                           " security officer's key.")
                    who = [root]
            elif kind == "managers":                   # names only for a group the person may see (need to know)
                visible = sc is None or sc.get("all") or g in sc.get("tree", set())
                who = (self._managers(doc, g, power, actor) if visible else []) or [root]
            elif kind == "root":
                who = [root]
            else:
                who = []
            steps.append({"why": why, "do": do, "who": self._who(doc, who)})
        return steps

    def _throttle(self, who: dict) -> None:
        """Called under the lock, before anything is logged."""
        key = str(who.get("sub") or who.get("anchor"))
        now = time.monotonic()
        if len(self._writes) > 10000:
            self._writes = {k: q for k, q in self._writes.items() if q and now - q[-1] < WRITE_WINDOW}
        q = self._writes.setdefault(key, deque())
        while q and now - q[0] > WRITE_WINDOW:
            q.popleft()
        if len(q) >= WRITES_PER_WINDOW:
            raise Throttled(f"too many changes in a short time: at most {WRITES_PER_WINDOW} in {WRITE_WINDOW // 60} minutes")
        q.append(now)

    def _reserved(self) -> dict:
        """The records of changes waiting for a key: their ids are taken, so two of them never share one."""
        out: dict = {}
        for p in self.store.pending().values():
            for kind, recs in (p.get("records") or {}).items():
                out.setdefault(kind, []).extend(recs)
        return out

    def _live_pending(self, now: datetime) -> dict:
        """Pending changes without the expired ones (those are on record as pending in the log already)."""
        pend = self.store.pending()
        live = {k: v for k, v in pend.items() if guard.timestamp(v["at"]) >= now - timedelta(days=PENDING_DAYS)}
        if len(live) != len(pend):
            self.store.save_pending(live)
        return live

    # --- who asks -------------------------------------------------------------------------------------------------

    def _person(self, doc: dict, anchor: str | None) -> dict | None:
        return next((p for p in doc.get("persons", []) if anchor in p["anchors"]), None) if anchor else None

    def _actor(self, doc: dict, who: dict) -> str:
        anchor = who.get("anchor")
        p = self._person(doc, anchor)
        if p is None:
            raise PermissionError("you are signed in, but not as a person these records know")
        return anchor

    def _anchor(self, value, what: str = "anchor") -> str:
        """A person named in a request: checked, then as the records name them (decision 0028: on the change log the
        internal anchor, through the mapping; an account it does not map yet stays as given, and the store gives it an
        anchor of its own when a change names it)."""
        value = guard.anchor(value, what)
        return self.store.inward(value) or value

    def _viewer(self, who: dict) -> bool:
        return "keyclerk-viewer" in (who.get("roles") or [])

    def _may_read(self, doc: dict, who: dict) -> None:
        if not self._viewer(who) and self._person(doc, who.get("anchor")) is None:
            raise PermissionError("you are not a person of this realm and not a viewer")

    def _scope(self, doc: dict, who: dict, now: datetime) -> dict:
        """What this person may look into (need to know). A viewer and the root see everything. Anyone else sees the
        groups they manage or belong to (and the names of the groups above them), the delegations in their own chain
        and below it, and the changes they made, approved, or that touch a group they manage or themselves."""
        a = who.get("anchor")
        if self._viewer(who) or (self._person(doc, a) is not None and D.same(doc, a, D.root_at(doc, now))):
            return {"all": True}
        groups = D._groups(doc)
        manage = {g for g in groups if self._powers(doc, a, g, now)}
        member = {g for g in groups if a and a in D.effective_members(doc, g, now)}
        tree = set(manage | member)
        for g in manage | member:
            tree |= set(D.ancestors(doc, g))
        mine = {d["delegation_id"] for d in doc.get("delegations", []) if D.same(doc, d["delegate"], a)}
        dels = set()
        for d in doc.get("delegations", []):
            ids = {x["delegation_id"] for x in D.chain(doc, d["delegation_id"])}
            if d["delegation_id"] in mine or ids & mine:                    # mine, or below one of mine
                dels.add(d["delegation_id"])
            if d["delegation_id"] in mine:
                dels |= ids                                               # the chain above mine
        return {"all": False, "anchor": a, "manage": manage, "open": manage | member, "tree": tree, "delegations": dels}

    def _sees_entry(self, doc: dict, sc: dict, e: dict) -> bool:
        if sc["all"]:
            return True
        a = sc["anchor"]
        if a and (D.same(doc, a, e.get("actor")) or D.same(doc, a, e.get("approved_by"))):
            return True
        recs = e.get("records") or {}
        ids = {x.get("id") for x in recs.get("admin_revocations", [])}
        touched = {m.get("group") for m in recs.get("memberships", [])} | {d.get("group") for d in recs.get("delegations", [])} \
            | {g.get("parent") for g in recs.get("groups", [])} \
            | {m["group"] for m in doc.get("memberships", []) if m["membership_id"] in ids} \
            | {d["group"] for d in doc.get("delegations", []) if d["delegation_id"] in ids}
        about_me = any(D.same(doc, a, (m.get("member") or {}).get("anchor")) for m in recs.get("memberships", []))
        return bool(touched & sc["manage"]) or about_me

    def _name(self, doc: dict, anchor: str | None) -> str | None:
        p = self._person(doc, anchor)
        return p["person"] if p else None

    # --- checks ---------------------------------------------------------------------------------------------------

    def _errors(self, doc: dict) -> set[str]:
        from keyclerk import metrics
        from keyclerk.reconcile import check_records
        with metrics.timed("keyclerk_check_seconds"):
            return set(check_records(doc))

    def _base_errors(self, doc: dict) -> set[str]:
        h = self.store.state_key()
        if not self._base or self._base[0] != h:
            self._base = (h, self._errors(doc))
        return self._base[1]

    def _commit(self, cand: dict, entry: dict) -> dict:
        """Commit a checked candidate; its errors become the base for the next change, so a write checks the records
        once, not twice."""
        judged = getattr(self, "_judged_ops", None)
        self._judged_ops = None
        if judged is not None and judged[0] is cand:          # the ops the desk judged are the ones proposed
            body = self.store.commit(cand, entry, ops=judged[1], tokens=judged[2])
        else:
            body = self.store.commit(cand, entry)
        checked = getattr(self, "_checked", None)
        if checked is not None and checked[0] is cand:
            self._base = (self.store.state_key(), checked[1])
        self._checked = None
        self._bundles_may_change()
        return body

    def _bundles_may_change(self) -> None:
        """Wake every long-poll (decision 0026): each rebuilds its edge's bundle and answers if what it says changed."""
        with self._bundle_wake:
            self._bundle_gen += 1
            self._bundle_wake.notify_all()

    def _evaluate(self, doc: dict, add: dict) -> tuple[str, list[str], dict]:
        """(outcome, reasons, candidate records) for adding records to doc: applied, pending or refused."""
        cand = copy.deepcopy(doc)
        for kind, recs in add.items():
            cand.setdefault(kind, []).extend(copy.deepcopy(recs))
        new = self._scoped(doc, cand, add) if getattr(self.store, "scoped_judging", False) else None
        if new is not None:                           # judged on what the change reaches (decision 0022 S5 T9)
            self._checked = None
            return self._outcome(sorted(new), cand)
        errs = self._errors(cand)
        self._checked = (cand, errs)                          # if this candidate is committed, it is the next base
        return self._outcome(sorted({e.removesuffix(" (now)") for e in errs - self._base_errors(doc)}), cand)

    @staticmethod
    def _outcome(new: list[str], cand: dict) -> tuple[str, list[str], dict]:
        if not new:
            return "applied", [], cand
        if all(any(k in e for k in KEY_ERRORS) for e in new):
            return "pending", new, cand
        return "refused", new, cand

    def _scoped(self, doc: dict, cand: dict, add: dict) -> set[str] | None:
        """The engine errors a change adds, judged on the subjects it reaches (decision 0022 S5 T9): on the change log's
        replica with the change tried and rolled back, exactly as the checking signer judges it. Visits never reach the
        signer, so a change of visits alone is judged here by the visit checks; a change of visits and records together
        is judged in full. None when the change reaches everyone or is too wide: the full check then judges, as before.
        The signer judges every change again before it signs, so a desk that misjudged gets a refusal, never a link."""
        from keyclerk import metrics, records as R, scope
        from keyclerk.store import link as L
        visit_kinds = {"visits", "visit_events", "badges"}
        ops, visit_ops, tokens = [], [], []
        for kind, recs in add.items():
            field = L.LOG_KINDS.get(kind) or R.KINDS.get(kind)
            for rec in recs:
                if kind in L.PROOF_KINDS:                    # a proof enters the log by its token's digest
                    p = L.proof_record(rec)
                    ops.append({"op": "put", "kind": kind, "key": p["sha256"], "record": p})
                    tokens.append([p["sha256"], str(rec.get("token", ""))])
                    continue
                key = rec.get(field) if field else None
                if not isinstance(key, str):
                    metrics.inc("keyclerk_check_fallback_total", reason="unknown")
                    return None
                (visit_ops if kind in visit_kinds else ops).append({"op": "put", "kind": kind, "key": key, "record": rec})
        with metrics.timed("keyclerk_check_seconds"):
            if visit_ops and ops:
                metrics.inc("keyclerk_check_fallback_total", reason="unknown")
                return None
            if visit_ops:
                from keyclerk import visits

                def norm(errs):
                    return {e.removesuffix(" (now)") for e in errs}
                return norm(visits.check(cand) + scope.touched_schema_errors(cand, visit_ops)) - norm(visits.check(doc))
            from keyclerk.store import migrate as M
            ops = M._json(sorted(ops, key=lambda o: (o["kind"], o["key"])))   # as a link holds them: times as text
            got = self.store.judge(ops)
        if got is not None:
            self._judged_ops = (cand, ops, tokens)            # committed as judged (LogStore.commit)
        return got

    # --- building records -----------------------------------------------------------------------------------------

    def _next_id(self, doc: dict, kind: str, prefix: str, field: str, extra: dict) -> str:
        realm = guard.name(doc["realm"], "realm")
        pat = re.compile(rf"{prefix}-{re.escape(realm)}-(\d+)")
        used = [int(m.group(1)) for x in doc.get(kind, []) + extra.get(kind, [])
                if (m := pat.fullmatch(str(x.get(field, ""))))]
        return f"{prefix}-{realm}-{max(used, default=0) + 1:04d}"

    def _under(self, doc: dict, actor: str, gid: str, power: str, now: datetime) -> str:
        if gid not in D._groups(doc):
            raise Refusal(f"there is no group {gid}")
        under = D.authority(doc, actor, gid, power, now)
        if under is None:
            raise Refusal(f"you hold no delegation that gives the power '{power}' over {gid} now")
        return under

    def _limits(self, doc: dict, under: str) -> dict:
        if under == "root":
            return {"max_risk": "privileged", "max_membership_days": D.R["root_max_membership_days"],
                    "end": None, "depth_left": None, "powers": sorted(D.POWERS), "place": None}
        d = D._delegations(doc)[under]
        return {"max_risk": d["max_risk"], "max_membership_days": d["max_membership_days"], "end": d["end"],
                "depth_left": d["depth_left"], "powers": d["powers"], "place": d.get("place")}

    def _days(self, body: dict, default: int, cap: int = 3650) -> int:
        days = body.get("days", default)
        if not isinstance(days, int) or isinstance(days, bool) or not 1 <= days <= cap:
            raise Refusal(f"days must be a whole number from 1 to {cap}")
        return days

    def _reason(self, body: dict) -> str:
        r = guard.text(body.get("reason", ""), "reason", 300).strip()
        if len(r) < 3:
            raise Refusal("give a reason (at least 3 characters): it is kept in the records")
        return r

    # --- edges (decision 0014) ---------------------------------------------------------------------------------------

    @property
    def edge_store(self):
        from keyclerk.edge_store import EdgeStore
        if getattr(self, "_edge_store", None) is None:
            self._edge_store = EdgeStore(self.store.path)
        return self._edge_store

    @property
    def bundle_key(self):
        """The bundle key: its own file beside the store, separate from the records key (decision 0014)."""
        from keyclerk import edge as E
        if getattr(self, "_bundle_key", None) is None:
            pulled = any(int(self.edge_store.state(d.name).get("serial", 0)) for d in (self.store.path / "edges").glob("*") if d.is_dir())
            self._bundle_key = E.load_or_make_key(self.store.path / "bundle.key", allow_create=not pulled)
        return self._bundle_key

    def edge_key(self) -> dict:
        """The public half of the bundle key, which an edge pins at enrolment (public)."""
        from keyclerk import edge as E
        pub = E.public_hex(self.bundle_key)
        unlock = E.unlock_public(self._unlock_private())
        rf = self.store.path / "bundle-rollover.json"
        return {"key": pub, "key_id": E.key_id(pub), "format": E.BUNDLE_FORMAT, "unlock_key": unlock,
                "unlock_format": E.UNLOCK_CONTEXT,
                "rollover": json.loads(rf.read_text(encoding="utf-8")) if rf.exists() else None,
                "note": "pin this key on the edge only after comparing its key_id with the one the desk's operator reads out"}

    def _edge(self, doc: dict, edge_id: str, now: datetime) -> dict:
        from keyclerk import edge_records
        e = next((x for x in doc.get("edges", []) if x["edge_id"] == edge_id), None)
        if e is None or D._revs(doc, edge_id, now):
            raise LookupError("no enrolled edge by that id")
        return edge_records.current(doc, e, now)

    def edge_public_of(self, edge_id: str) -> str | None:
        """The enrolment key an edge signs with now (an ended edge too, so it can learn it was ended); None if unknown."""
        from keyclerk import edge_records
        doc, now = self.store.load(), self.clock()
        e = next((x for x in doc.get("edges", []) if x["edge_id"] == edge_id), None)
        return edge_records.current(doc, e, now)["enrolment_key"] if e else None

    def edge_ended(self, edge_id: str) -> dict | None:
        """A sealed notice for an ended edge, so its agent tells revocation from an outage (decision 0014c)."""
        from keyclerk import edge as E
        from keyclerk import edge_records
        doc, now = self.store.load(), self.clock()
        r = next((r for r in doc.get("admin_revocations", []) if r["id"] == edge_id and D._ts(r["at"]) <= now), None)
        if r is None:
            return None
        e = next((x for x in doc.get("edges", []) if x["edge_id"] == edge_id), None)
        at = D._ts(r["at"])
        keys = [edge_records.current(doc, e, at)["enrolment_key"]] if e else []    # bound to its keys
        return E.ended_notice(self.bundle_key, edge_id, at, r.get("reason", ""), keys)

    def _unlock_private(self):
        """The desk's P-256 key for phoned unlock (kc-unlock-v2): its own file, 0600, the scalar in hex,
        created before any edge pulled. A kc-unlock-v1 unlock.key beside it is ignored (no migration, 0014d)."""
        from keyclerk import edge as E
        f = self.store.path / "unlock-v2.key"
        if not f.exists():
            fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as h:
                h.write(E.new_unlock_private())
        return E.unlock_private(f.read_text(encoding="utf-8").strip())

    def _emails(self) -> dict:
        """Anchor -> verified e-mail, as the reconciler read it from the broker, so an edge can match a single sign-on login by it."""
        return self._usernames("emails.json")

    def _usernames(self, name: str = "usernames.json") -> dict:
        f = (self.broker_state / name) if self.broker_state else None
        if not f or not f.exists():
            return {}
        try:
            v = guard.load_json_bytes(f.read_bytes(), name, guard.MAX_FILE_BYTES)
            return {str(k): str(x) for k, x in v.items()} if isinstance(v, dict) else {}
        except (guard.InputRejected, ValueError, TypeError, OSError):
            return {}

    def _edge_leases(self, doc: dict, e: dict, now: datetime, horizons: dict, first_seen: dict | None = None) -> list[dict]:
        """Leases for an edge's targets, with ids that stay the same while the grant stays, and a "from"
        that stays too (the desk's clock at bundle time made a lease not yet live on an edge a few seconds
        behind): the earliest start of its direct memberships, or for a derived lease the first time it was issued."""
        from keyclerk import edge as E
        out = []
        seen = first_seen if first_seen is not None else {}
        groups = D._groups(doc)
        for t in e["targets"]:
            for g in groups.values():
                if not any(c.get("entitlement") == t["entitlement"] for c in g.get("carries", [])):
                    continue
                cls = D.effective_risk(doc, g["group_id"])
                for a in sorted(D.effective_members(doc, g["group_id"], now)):
                    direct = [m for m in doc.get("memberships", []) if m["group"] == g["group_id"]
                              and D.same(doc, (m["member"] or {}).get("anchor"), a) and D.membership_status(doc, m, now) == "active"]
                    end = min([D._ts(m["end"]) for m in direct], default=now + timedelta(hours=int(horizons.get(cls, 1))))
                    source = ",".join(sorted(m["membership_id"] for m in direct)) or "derived"
                    lid = "L-" + E.sha256(f"{e['edge_id']}|{t['target']}|{a}|{g['group_id']}|{source}".encode())[:16]
                    start = min([D._ts(m["start"]) for m in direct], default=None)
                    frm = E._iso(start) if start else seen.setdefault(lid, E._iso(now))
                    out.append({"lease_id": lid, "person": a, "target": t["target"], "role": t["role"], "class": cls,
                                "roles": [g["group_id"]], "from": frm, "until": E._iso(end),
                                "target_session_hours": t.get("max_session_hours")})
        return out

    ATTEST_CHALLENGE_MINUTES = 10

    def _ek_trust(self) -> tuple[list[bytes], list[bytes]]:
        """Manufacturer roots and intermediates for EK certificates: configuration, never the edge's word (0016)."""
        from keyclerk import config
        c = config.current().get("edges") or {}
        return [str(x).encode() for x in c.get("ek_roots") or []], [str(x).encode() for x in c.get("ek_intermediates") or []]

    def _tpm(self, e: dict):
        import base64
        from cryptography.hazmat.primitives import serialization
        from keyclerk import attest as A
        t = e.get("tpm")
        if not t:
            return None, None, None
        ek = serialization.load_der_public_key(base64.b64decode(t["ek_public"]))
        return t, ek, A.parse_public(base64.b64decode(t["ak_public"]))

    def edge_attest_challenge(self, edge_id: str) -> dict:
        """Credential activation, step one (decision 0016): check the EK (the officer's pin, and the manufacturer chain
        where there is a certificate), then encrypt a challenge to it, bound to the AK's name."""
        import base64
        from keyclerk import attest as A
        doc, now = self.store.load(), self.clock()
        e = self._edge(doc, edge_id, now)
        t, ek, ak = self._tpm(e)
        if t is None:
            raise Refusal("this edge was enrolled without a TPM: it is a basic edge (decision 0016)")
        roots, inter = self._ek_trust()
        try:
            facts = A.check_ek(ek, t["ek_sha256"], base64.b64decode(t["ek_cert"]) if t.get("ek_cert") else None, roots, inter, at=now)
        except A.AttestError as x:
            self.edge_store.incident(edge_id, {"kind": "attestation_failed", "detail": f"endorsement key: {x}"[:900]}, core=True)
            raise Refusal(f"the TPM's endorsement key does not hold: {x}") from None
        secret = secrets.token_bytes(32)
        idobj, encsec = A.make_credential(A.Public(b"", A.ALG_RSA, A.ALG_SHA256, 0, ek), ak.name, secret)
        self.edge_store.update_state(edge_id, ek_facts=facts, attest_challenge={
            "sha256": hashlib.sha256(secret).hexdigest(), "at": _iso(now), "ak_name": ak.name.hex()})
        b = lambda x: base64.b64encode(x).decode()   # noqa: E731
        return {"edge": edge_id, "id_object": b(idobj), "encrypted_secret": b(encsec),
                "credential": b(A.credential_file(idobj, encsec)),
                "expires_at": _iso(now + timedelta(minutes=self.ATTEST_CHALLENGE_MINUTES))}

    def edge_attest_activate(self, edge_id: str, body: dict) -> dict:
        """Credential activation, step two: only the TPM holding the pinned EK and this AK recovers the challenge."""
        import base64
        import binascii
        import hmac as _hmac
        if not isinstance(body, dict) or set(body) != {"secret"} or not isinstance(body["secret"], str) or len(body["secret"]) > 200:
            raise guard.InputRejected("an activation is {secret}: the recovered challenge, base64")
        now = self.clock()
        ch = self.edge_store.state(edge_id).get("attest_challenge")
        if not ch or guard.timestamp(ch["at"]) < now - timedelta(minutes=self.ATTEST_CHALLENGE_MINUTES):
            raise Refusal("no challenge waits for this edge: ask for one first (GET /edge/attest/challenge)")
        try:
            got = base64.b64decode(body["secret"], validate=True)
        except (binascii.Error, ValueError):
            raise guard.InputRejected("secret: base64") from None
        if not _hmac.compare_digest(hashlib.sha256(got).hexdigest(), ch["sha256"]):
            self.edge_store.update_state(edge_id, attest_challenge=None)
            self.edge_store.incident(edge_id, {"kind": "attestation_failed", "detail": "a wrong answer to the activation "
                                               "challenge: the attestation key is not in the TPM the officer pinned"}, core=True)
            raise Refusal("a wrong answer: the attestation key is not in the TPM the officer pinned; ask for a new challenge")
        self.edge_store.update_state(edge_id, attest_challenge=None, attest_activated={"ak_name": ch["ak_name"], "at": _iso(now)})
        return {"edge": edge_id, "activated": True}

    def _attested(self, e: dict, edge_id: str, quote: str | None, request: tuple | None) -> tuple[str, list[str]]:
        """The profile an edge has proved on this pull: assured only with an activated AK, a quote bound to this signed
        request, and the PCRs the policy names at the baseline the officer signed. Anything less is basic (fails closed)."""
        from keyclerk import attest as A
        from keyclerk import edge as E
        from keyclerk import policy_wasm
        t, _, ak = self._tpm(e)
        st = self.edge_store.state(edge_id)
        if t is None:
            return "basic", ["enrolled without a TPM"]
        act = st.get("attest_activated") or {}
        if act.get("ak_name") != ak.name.hex():
            return "basic", ["the attestation key is not activated (GET /edge/attest/challenge)"]
        if not quote or not request:
            return "basic", ["no quote with this pull (KeyClerk-Quote)"]
        try:
            msg, sig, values = E.parse_quote_header(quote)
            facts = A.verify_quote_values(ak, msg, sig, values, A.quote_nonce(edge_id, int(request[0]), str(request[1])))
        except (A.AttestError, ValueError) as x:
            why = [f"the quote does not hold: {x}"]
        else:
            d = policy_wasm.edge("attestation", {"quote": facts, "baseline": t["pcr_baseline"],
                                                 "ek_certified": bool((st.get("ek_facts") or {}).get("ek_certified"))})
            why = sorted(d["refusals"])
            self.edge_store.update_state(edge_id, last_quote={**facts, "at": _iso(self.clock())})
        if why and why != st.get("attest_refusals"):          # once per new reason, not on every pull
            self.edge_store.incident(edge_id, {"kind": "attestation_failed", "detail": "; ".join(why)[:900]}, core=True)
        self.edge_store.update_state(edge_id, attest_refusals=why, attested="basic" if why else "assured")
        return ("basic", why) if why else ("assured", [])

    LONG_POLL_MAX_WAIT = 55                    # seconds: under common proxy idle timeouts (decision 0026)

    def edge_bundle(self, edge_id: str, serial: str | None = None, quote: str | None = None,
                    request: tuple | None = None, after: str | None = None, wait: str | None = None) -> dict:
        from keyclerk import metrics
        try:
            if wait is not None:
                out = self._long_poll(edge_id, after, wait, quote, request, serial)
            else:
                out = self._edge_bundle(edge_id, serial, quote, request)
        except Exception:
            metrics.inc("keyclerk_edge_pulls_total", result="refused")
            raise
        metrics.inc("keyclerk_edge_pulls_total", result="served")
        return out

    def _long_poll(self, edge_id: str, after: str | None, wait: str, quote, request, serial) -> dict:
        """A pull that waits (decision 0026): answered once this edge's bundle says something other than the bundle
        with serial `after` said, or when the wait ends; either way with a fresh bundle, so a timed-out wait renews the
        edge's offline horizon as a pull does. Answered at once when `after` is not a serial this desk knows, when the
        desk holds its cap of open waits, or when the edge opens more waits than it has nodes (the oldest is answered).
        Time alone wakes nothing: an edge ends a lease by its own `until`."""
        from keyclerk import config
        from keyclerk import edge as E
        if serial is not None:
            raise Refusal("serial asks for a lost bundle again and wait for a new one: send one of them")
        if not (isinstance(wait, str) and wait.isdigit() and int(wait) >= 1):
            raise Refusal("wait: whole seconds from 1")
        seconds = min(int(wait), self.LONG_POLL_MAX_WAIT)
        held = (self.edge_store.state(edge_id).get("digests") or {}).get(str(after)) if after else None
        first = self._edge_bundle(edge_id, None, quote, request)
        if held is None or E.bundle_digest(first) != held:    # unknown serial, or already different: no reason to wait
            return first
        nodes = max(1, len(self._edge(self.store.load(), edge_id, self.clock()).get("nodes") or []))
        cap = int(((config.current() or {}).get("edge") or {}).get("long_poll_max", 256))
        me = {"stop": False}
        with self._bundle_wake:
            if sum(len(v) for v in self._long_polls.values()) >= cap:
                return first                                 # over the cap: a plain pull
            mine = self._long_polls.setdefault(edge_id, [])
            while len(mine) >= nodes:                        # one open wait per node: a reconnect answers the old one
                mine.pop(0)["stop"] = True
            mine.append(me)
            gen = self._bundle_gen
            self._bundle_wake.notify_all()
        deadline = time.monotonic() + seconds
        try:
            while True:
                with self._bundle_wake:
                    while not me["stop"] and self._bundle_gen == gen and time.monotonic() < deadline:
                        self._bundle_wake.wait(deadline - time.monotonic())
                    gen, stop = self._bundle_gen, me["stop"]
                out = self._edge_bundle(edge_id, None, quote, request)
                if stop or time.monotonic() >= deadline or E.bundle_digest(out) != held:
                    return out
        finally:
            with self._bundle_wake:
                waits = self._long_polls.get(edge_id, [])
                if me in waits:
                    waits.remove(me)
                if not waits:
                    self._long_polls.pop(edge_id, None)

    def _edge_bundle(self, edge_id: str, serial: str | None = None, quote: str | None = None,
                     request: tuple | None = None) -> dict:
        """The sealed bundle for one edge (decision 0014 point 3, amendment 0014a): leases inside its ceiling, visit leases,
        revoked visit leases, horizons, the officer-signed ceiling itself and the edge policy with its release manifest.
        The newest bundle is complete: what an edge holds that is not in it has ended. Without a signed ceiling, or with
        an officer who is no longer independent of the core, an edge gets no leases: it fails closed."""
        import json as _json
        from keyclerk import edge as E
        from keyclerk import edge_records
        from keyclerk import policy_wasm
        key = self.bundle_key                       # before any serial moves: the key may be made only before the first pull
        if serial is not None:                      # a retry after a lost answer: the same bundle, no serial burnt
            last = self.edge_store.state(edge_id).get("last_bundle")
            if last and str(self.edge_store.state(edge_id).get("serial")) == str(serial):
                self._edge(self.store.load(), edge_id, self.clock())
                return last
            raise LookupError("no bundle by that serial: pull without one")
        with self.edge_store.lock:
            doc, now = self.store.load(), self.clock()
            e = self._edge(doc, edge_id, now)
            settings = policy_wasm.edge("settings", {})
            horizons = settings["horizons"]
            ceiling, sealed_ceiling = self.edge_store.ceiling(edge_id)
            state = self.edge_store.state(edge_id)
            attested, _ = self._attested(e, edge_id, quote, request)   # proved on this pull, never claimed (0016)
            leases, visits, dropped = [], [], []
            not_independent = edge_records.officer_errors(doc, e, now)
            if not_independent:
                if not state.get("officer_frozen"):
                    self.edge_store.incident(edge_id, {"kind": "officer_not_independent", "detail": not_independent[0][:900]})
                    self.edge_store.update_state(edge_id, officer_frozen=True)
                ceiling, sealed_ceiling = None, None
            elif state.get("officer_frozen"):
                self.edge_store.update_state(edge_id, officer_frozen=False)
            keys = [k for k in doc.get("person_keys", []) if not D._revs(doc, k["key_id"], now)]
            names = self._usernames()
            caps = settings.get("session_max_hours", {})

            def who_fields(anchor):                    # what the agent needs to act for this person (0014b)
                k = next((k for k in keys if D.same(doc, k["anchor"], anchor)), None)
                return {"username": names.get(anchor), "key_id": k["key_id"] if k else None,
                        "public_key": k["public_key"] if k else None}
            if ceiling:
                seen = dict(state.get("lease_first_seen") or {})          # a derived lease keeps its first issue time
                current = self._edge_leases(doc, e, now, horizons, seen)
                self.edge_store.update_state(edge_id, lease_first_seen={x["lease_id"]: seen[x["lease_id"]]
                                                                        for x in current if x["lease_id"] in seen})
                for lease in current:
                    hours = max(1, int((D._ts(lease["until"]) - now).total_seconds() // 3600))
                    d = policy_wasm.ceiling({"ceiling": ceiling, "entry": {"kind": "lease", "person": lease["person"], "roles": lease["roles"],
                                                                           "targets": [lease["target"]], "class": lease["class"], "hours": hours}})
                    if d["allow"]:
                        cap = int(caps.get(lease["class"], 1))
                        if lease.pop("target_session_hours", None):
                            cap = min(cap, int(next(t["max_session_hours"] for t in e["targets"] if t["target"] == lease["target"])))
                        leases.append({**lease, **who_fields(lease["person"]), "email": None,   # fetched by request, 1.3
                                       "max_session_hours": cap})
                    else:
                        lease.pop("target_session_hours", None)
                        dropped.append({"lease_id": lease["lease_id"], "why": sorted(d["refusals"])})
                for v in doc.get("edge_visit_leases", []):
                    if v["edge"] != edge_id or D._revs(doc, v["lease_id"], now) or D._ts(v["until"]) <= now:
                        continue
                    if not any(D.same(doc, k["anchor"], v["person"]) and k.get("ssh_key") == v["ssh_key"] for k in keys):
                        dropped.append({"lease_id": v["lease_id"], "why": ["the person's hardware key was ended"]})
                        continue                       # a lost hardware key ends its visit leases
                    hours = int((D._ts(v["until"]) - D._ts(v["from"])).total_seconds() // 3600)
                    d = policy_wasm.ceiling({"ceiling": ceiling, "entry": {"kind": "visit", "person": v["person"], "targets": v["targets"],
                                                                           "hours": hours, "attested_profile": attested}})
                    if d["allow"]:
                        role = next((t["role"] for t in e["targets"] if t["target"] in v["targets"]), None)
                        visits.append({"lease_id": v["lease_id"], "person": v["person"], "ssh_key": v["ssh_key"], "role": role,
                                       **who_fields(v["person"]),
                                       "targets": v["targets"], "from": E._iso(D._ts(v["from"])), "until": E._iso(D._ts(v["until"]))})
                    else:
                        dropped.append({"lease_id": v["lease_id"], "why": sorted(d["refusals"])})
            revoked = sorted({v["lease_id"] for v in doc.get("edge_visit_leases", []) if v["edge"] == edge_id
                              and D._revs(doc, v["lease_id"], now) and D._ts(v["until"]) > now})
            mods = self._edge_modules()                # by hash only: an agent fetches what it lacks (GET /edge/module)
            release = None
            rf = self.store.path / "policy-release.json"
            if rf.exists():
                release = _json.loads(rf.read_text(encoding="utf-8"))
            policy = {"modules": E.module_refs(mods), "release": release,
                      "entrypoints": ["keyclerk/edge/settings", "keyclerk/edge/admit", "keyclerk/edge/visit_window",
                                    "keyclerk/edge/attestation", "keyclerk/ceiling/decision"]}
            serial = self.edge_store.next_serial(edge_id)
            if state.get("silent"):
                self.edge_store.update_state(edge_id, silent=False)
            for lease in [x for x in leases if x["class"] not in horizons]:    # no horizon, never live
                leases.remove(lease)
                dropped.append({"lease_id": lease["lease_id"], "why": [f"class {lease['class']} has no horizon in edge.rego"]})
            out = E.build_bundle(edge_id, serial, now, horizons, leases, visits, revoked, sealed_ceiling, policy, key,
                                 governed_roles=[t["role"] for t in e["targets"]])   # 0025: the roles its targets map to
            holders = sorted({x["person"] for x in leases + visits})
            digests = dict(list((state.get("digests") or {}).items())[-15:])   # 0026: what recent serials said
            digests[str(serial)] = E.bundle_digest(out)
            self.edge_store.update_state(edge_id, last_dropped=dropped[:100], last_bundle=out, holders=holders, digests=digests,
                                         lease_ids=sorted({x["lease_id"]: x["until"] for x in leases + visits}.items()))
            return out

    EDGE_MODULES = ("edge", "ceiling")

    def _edge_modules(self) -> dict[str, bytes]:
        from keyclerk import policy_wasm
        base = Path(policy_wasm.__file__).resolve().parent / "policy"
        return {name: (base / f"{name}.wasm").read_bytes() for name in self.EDGE_MODULES}

    def edge_module(self, edge_id: str, sha: str) -> dict:
        """A policy module the calling edge's bundle names, by its sha256: fetched once per change, kept by hash
        (inlined, the modules made every pull about 520 KB)."""
        import base64
        from keyclerk import edge as E
        self._edge(self.store.load(), edge_id, self.clock())
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise guard.InputRejected("a module is named by its sha256, 64 lower-case hex characters")
        for name, raw in self._edge_modules().items():
            if E.sha256(raw) == sha:
                return {"name": name, "sha256": sha, "wasm": base64.b64encode(raw).decode("ascii")}
        raise LookupError("no module by that hash on this desk: pull a bundle for the current hashes")

    def _officer_only(self, doc: dict, who: dict, e: dict) -> None:
        if not (who.get("anchor") and D.same(doc, who["anchor"], e["officer"])):
            raise PermissionError("only the edge's officer sets its ceiling")

    def set_ceiling(self, who: dict, edge_id: str, body: dict) -> dict:
        """A ceiling the edge's officer signed with their hardware key (decision 0014 point 4)."""
        from keyclerk import edge as E
        doc, now = self.store.load(), self.clock()
        from keyclerk import edge_records
        e = self._edge(doc, guard.ident(edge_id, "edge"), now)
        self._officer_only(doc, who, e)
        independent = edge_records.officer_errors(doc, e, now)
        if independent:
            raise Refusal(independent[0])
        if not isinstance(body, dict) or set(body) != {"ceiling"} or not isinstance(body["ceiling"], dict):
            raise guard.InputRejected("send {ceiling}: the ceiling sealed with your key (python -m keyclerk.edge_cli seal, "
                                      "kc-edge-ceiling-v2)")
        old, _ = self.edge_store.ceiling(edge_id)
        floor = max(int((old or {}).get("serial", 0)), int(self.edge_store.state(edge_id).get("ceiling_floor", 0))) + 1
        errs, c = E.check_ceiling(edge_id, e["officer_key"], body["ceiling"], floor)
        if errs:
            raise Refusal("; ".join(errs))
        self.edge_store.set_ceiling(edge_id, body["ceiling"])
        self.edge_store.update_state(edge_id, ceiling_floor=c["serial"])
        self._bundles_may_change()
        self.store.note({"change_id": "C-" + secrets.token_hex(6), "action": "set_ceiling", "actor": who.get("anchor"),
                            "summary": f"ceiling {c['serial']} for edge {edge_id}", "records": {},
                            "outcome": "applied", "reasons": []})
        import base64
        return {"edge": edge_id, "serial": c["serial"], "sha256": E.sha256(base64.b64decode(body["ceiling"]["bytes"]))}

    def edge_report(self, edge_id: str, body: dict) -> dict:
        """What the edge applied, its attestation (the hardware profile as policy input) and any drift it saw."""
        if not isinstance(body, dict) or not set(body) <= {"applied_serial", "attestation", "drift"}:
            raise guard.InputRejected("a report is {applied_serial, attestation, drift}")
        att = body.get("attestation") or {}
        if not isinstance(att, dict) or att.get("profile") not in (None, "assured", "basic"):
            raise guard.InputRejected("attestation.profile: assured or basic")
        drift = [guard.text(x, "drift", 300) for x in (body.get("drift") or [])][:50]
        report = {"applied_serial": int(body.get("applied_serial") or 0), "attestation": {k: guard.text(v, k, 200) for k, v in att.items()},
                  "drift": drift, "at": _iso(self.clock()), "attestation_verified": False}   # claimed until quotes are verified
        before = ((self.edge_store.state(edge_id).get("report") or {}).get("attestation") or {}).get("profile")
        if before and before != att.get("profile"):
            self.edge_store.incident(edge_id, {"kind": "attestation_changed", "detail": f"claimed profile {before} became {att.get('profile')}"})
        self.edge_store.update_state(edge_id, report=report, last_report=report["at"])
        if drift:
            self.edge_store.incident(edge_id, {"kind": "drift", "detail": "; ".join(drift)[:900]})
        return {"ok": True}

    def _person_key(self, doc: dict, key_id: str, now: datetime) -> dict:
        k = next((x for x in doc.get("person_keys", []) if x["key_id"] == key_id), None)
        if k is None or D._revs(doc, key_id, now):
            raise Refusal(f"no registered person key {key_id}: without one, nothing can be relayed (no fallback)")
        return k

    def edge_relay(self, edge_id: str, body: dict) -> dict:
        """A ciphertext for one person key, relayed once (decision 0014 point 8). The desk checks the form only."""
        from keyclerk import relay
        doc, now = self.store.load(), self.clock()
        if not isinstance(body, dict) or set(body) != {"key_id", "envelope", "purpose"}:
            raise guard.InputRejected("a relay is {key_id, envelope, purpose}")
        k = self._person_key(doc, guard.ident(body["key_id"], "key"), now)
        try:
            relay.check(body["envelope"])
        except ValueError as e:
            raise guard.InputRejected(f"envelope: {e}") from None
        purpose = guard.text(body["purpose"], "purpose", 120)
        st = self.edge_store.state(edge_id)
        held = {lid: until for lid, until in st.get("lease_ids", [])}
        lid = purpose[len("lease:"):] if purpose.startswith("lease:") else None
        if not lid or lid not in held or not any(D.same(doc, k["anchor"], h) for h in st.get("holders", [])):
            raise Refusal("an edge relays a lease credential only to a holder of that lease in its last bundle (purpose lease:<id>)")
        if body["envelope"]["context"] != purpose:
            raise Refusal("the envelope's context is its purpose: they must match")
        try:
            rid = self.edge_store.relay_put(edge_id, k["anchor"], k["key_id"], body["envelope"], purpose, expires=D._ts(held[lid]))
        except ValueError as e:
            raise Refusal(str(e)) from None
        return {"relay_id": rid}

    def edge_escrow(self, edge_id: str, body: dict) -> dict:
        """A new break-glass value as two ciphertexts, one per custodian; relayed to each, acknowledged signed."""
        from keyclerk import edge as E
        from keyclerk import relay
        doc, now = self.store.load(), self.clock()
        if not isinstance(body, dict) or set(body) != {"system", "item_id", "envelopes"}:
            raise guard.InputRejected("an escrow is {system, item_id, envelopes}")
        envs = body["envelopes"]
        if not isinstance(envs, list) or len(envs) != 2:
            raise guard.InputRejected("exactly two envelopes, one per custodian")
        keys = [self._person_key(doc, guard.ident(x.get("key_id"), "key"), now) for x in envs]
        if D.same(doc, keys[0]["anchor"], keys[1]["anchor"]):
            raise Refusal("two custodians: two different people")
        named = self._edge(doc, edge_id, now).get("custodians") or []
        if not all(any(D.same(doc, k["anchor"], c) for c in named) for k in keys):
            raise Refusal("escrow goes only to the edge's designated custodians (set at enrolment)")
        item_id, system = guard.ident(body["item_id"], "item"), guard.ident(body["system"], "system")
        for x in envs:
            relay.check(x.get("envelope"))
            if x["envelope"]["context"] != f"escrow:{system}:{item_id}":
                raise Refusal(f"each envelope's context is escrow:{system}:{item_id}")
        with self.edge_store.lock:
            if not self.edge_store.relay_room(edge_id, [k["anchor"] for k in keys]):
                raise Refusal("a custodian's inbox from this edge is full: nothing was stored")   # both halves or none
            rids = [self.edge_store.relay_put(edge_id, k["anchor"], k["key_id"], x["envelope"], f"escrow:{system}:{item_id}", keep=True)
                    for x, k in zip(envs, keys, strict=True)]
        digest = E.sha256(E.canonical(envs))
        self.edge_store.escrow_put(edge_id, {"item_id": item_id, "system": system, "sha256": digest, "relay_ids": rids,
                                             "custodians": [k["anchor"] for k in keys], "received": _iso(now)})
        return E.seal(self.bundle_key, {"edge": edge_id, "item_id": item_id, "sha256": digest, "received": _iso(now)},
                      "kc-edge-escrow-ack-v1")

    def edge_incident(self, edge_id: str, body: dict) -> dict:
        from keyclerk.edge_store import INCIDENT_KINDS
        if not isinstance(body, dict) or not set(body) <= {"kind", "system", "at", "detail", "log_sha256"} or body.get("kind") not in INCIDENT_KINDS:
            raise guard.InputRejected(f"an incident is {{kind, system, at, detail, log_sha256}}; kind one of {', '.join(INCIDENT_KINDS)}")
        rec = {k: guard.text(v, k, 900) for k, v in body.items()}
        try:
            out = self.edge_store.incident(edge_id, rec)
        except ValueError as e:
            raise Refusal(str(e)) from None
        self.store.note({"change_id": "C-" + secrets.token_hex(6), "action": "edge_incident", "actor": None,
                            "summary": f"{rec['kind']} on edge {edge_id}" + (f" ({rec['system']})" if rec.get("system") else ""),
                            "records": {}, "outcome": "applied", "reasons": []})
        return {"incident_id": out["incident_id"]}

    def edge_evidence(self, edge_id: str, body: dict) -> dict:
        """Recordings as a hash chain; acknowledged signed up to a sequence (decision 0014 point 10)."""
        from keyclerk import edge as E
        from keyclerk.edge_store import EVIDENCE_BATCH
        if not isinstance(body, dict) or set(body) != {"entries"} or not isinstance(body["entries"], list):
            raise guard.InputRejected("evidence is {entries: [...]}")
        entries = body["entries"][:EVIDENCE_BATCH]
        for x in entries:
            if not isinstance(x, dict) or set(x) != {"seq", "prev", "sha256", "size", "session", "at"}:
                raise guard.InputRejected("an entry is {seq, prev, sha256, size, session, at}")
        try:
            seq, head = self.edge_store.evidence_add(edge_id, entries)
        except ValueError as e:
            head = self.edge_store.state(edge_id).get("evidence_head") or "0" * 64
            if self.edge_store.state(edge_id).get("fork_reported") != head:   # once per head: a fork is an incident
                self.edge_store.incident(edge_id, {"kind": "evidence_fork", "detail": str(e)[:300]}, core=True)
                self.edge_store.update_state(edge_id, fork_reported=head)
            raise Refusal(str(e)) from None
        return E.seal(self.bundle_key, {"edge": edge_id, "up_to_seq": seq, "head": head, "at": _iso(self.clock())},
                      "kc-edge-evidence-ack-v1")

    def carried_lease(self, who: dict, lease_id: str) -> dict:
        """A visit lease the person carries to the edge: sealed for that edge, at most carried_max_hours
        and inside the visit lease's window, with a per-person serial (a newer one replaces an older one)."""
        import time as _time
        from keyclerk import edge as E
        from keyclerk import policy_wasm
        a = who.get("anchor")
        if not isinstance(who.get("auth_time"), (int, float)) or _time.time() - who["auth_time"] > self.RELAY_FRESH_SECONDS:
            raise PermissionError("sign in again first: a carried lease is issued within 10 minutes of a fresh sign-in")
        doc, now = self.store.load(), self.clock()
        v = next((x for x in doc.get("edge_visit_leases", []) if x["lease_id"] == guard.ident(lease_id, "lease")), None)
        if v is None or not a or not D.same(doc, a, v["person"]) or D._revs(doc, v["lease_id"], now):
            raise LookupError("no visit lease of yours by that id")
        if D._ts(v["until"]) <= now:
            raise Refusal("that visit lease has ended")
        e = self._edge(doc, v["edge"], now)
        hours = int(policy_wasm.edge("settings", {})["carried_max_hours"])
        start = max(now, D._ts(v["from"]))
        with self.edge_store.lock:
            st = self.edge_store.state(v["edge"])
            carried = dict(st.get("carried") or {})
            carried[v["person"]] = int(carried.get(v["person"], 0)) + 1
            self.edge_store.update_state(v["edge"], carried=carried)
        role = next((t["role"] for t in e["targets"] if t["target"] in v["targets"]), None)
        body = {"edge": v["edge"], "lease_id": v["lease_id"], "person": v["person"], "username": self._usernames().get(v["person"]),
                "ssh_key": v["ssh_key"], "targets": v["targets"], "role": role, "from": _iso(start),
                "until": _iso(min(D._ts(v["until"]), start + timedelta(hours=hours))), "carried_serial": carried[v["person"]],
                "nonce": secrets.token_hex(8)}
        self.edge_store.incident(v["edge"], {"kind": "carried_lease", "detail": f"{v['lease_id']} carried by {a}"}, core=True)
        return E.seal(self.bundle_key, body, E.CARRIED_FORMAT)

    def phoned_unlock(self, who: dict, edge_id: str, body: dict) -> dict:
        """A code a second person reads to someone on site: only an unlock approver of that edge, never
        the person; within edge.rego's limits; bound to edge, person, key fingerprint, target, nonce and minutes."""
        from keyclerk import edge as E
        from keyclerk import policy_wasm
        doc, now = self.store.load(), self.clock()
        e = self._edge(doc, guard.ident(edge_id, "edge"), now)
        a = who.get("anchor")
        if not isinstance(body, dict) or set(body) != {"person", "target", "key_fingerprint", "nonce", "minutes"}:
            raise guard.InputRejected("send {person, target, key_fingerprint, nonce, minutes}")
        person = self._anchor(body["person"], "person")
        if not a or not any(D.same(doc, a, x) for x in e.get("unlock_approvers", [])):
            raise PermissionError("only an unlock approver of this edge reads an unlock code")
        if D.same(doc, a, person):
            raise Refusal("an unlock approver never unlocks themselves: a second person reads the code")
        if not e.get("unlock_key"):
            raise Refusal("this edge has no unlock key: enrol one first")
        target = guard.ident(body["target"], "target")
        if target not in {t["target"] for t in e["targets"]}:
            raise Refusal(f"{target} is not a target of {edge_id}")
        settings = policy_wasm.edge("settings", {})
        minutes = body["minutes"]
        if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= int(settings["unlock_max_minutes"]):
            raise Refusal(f"minutes: 1 to {settings['unlock_max_minutes']} (edge.rego)")
        fp, nonce = guard.text(body["key_fingerprint"], "key_fingerprint", 120), guard.text(body["nonce"], "nonce", 64)
        with self.edge_store.lock:
            st = self.edge_store.state(edge_id)
            recent = [x for x in st.get("unlocks", []) if x > _iso(now - timedelta(hours=1))]
            if len(recent) >= int(settings["unlock_per_hour"]):
                raise Refusal(f"at most {settings['unlock_per_hour']} unlocks an hour for this edge (edge.rego)")
            self.edge_store.update_state(edge_id, unlocks=recent + [_iso(now)])
        own = self._unlock_private()
        node_id = E.key_id(e["enrolment_key"])                 # kc-unlock-v2 binds the node (one of up to two)
        try:
            code = E.unlock_code(E.unlock_secret(own, E.unlock_public(own), e["unlock_key"], edge_id, node_id),
                                 edge_id, node_id, person, fp, target, nonce, minutes)
        except ValueError as x:
            raise Refusal(f"unlock: {x}") from None
        self.edge_store.incident(edge_id, {"kind": "phoned_unlock", "detail": f"{a} read an unlock for {person} on {target}, "
                                           f"{minutes} min, key {fp[:24]}"}, core=True)
        self.store.note({"change_id": "C-" + secrets.token_hex(6), "action": "phoned_unlock", "actor": a,
                            "summary": f"unlock for {self._name(doc, person) or person} on {edge_id}/{target}", "records": {},
                            "outcome": "applied", "reasons": []})
        return {"code": code, "minutes": minutes, "expires": _iso(now + timedelta(minutes=minutes)), "node": node_id}

    def close_incident(self, who: dict, edge_id: str, incident_id: str, body: dict | None) -> dict:
        doc, now = self.store.load(), self.clock()
        e = self._edge(doc, guard.ident(edge_id, "edge"), now)
        a = who.get("anchor")
        officer = (doc.get("root") or {}).get("officer")
        if not a or not (D.same(doc, a, e["officer"]) or D.same(doc, a, officer)):
            raise PermissionError("the edge's officer or the security officer closes its incidents")
        note = guard.text((body or {}).get("note", ""), "note", 300)
        hit = self.edge_store.close_incident(edge_id, guard.ident(incident_id, "incident"), a, note)
        if hit is None:
            raise LookupError("no such incident")
        return {"incident_id": hit["incident_id"], "closed": hit["closed"]}

    def edge_silence(self) -> list[str]:
        """Edges that stopped pulling for longer than pull_max_hours raise edge_silent once."""
        from keyclerk import policy_wasm
        doc, now = self.store.load(), self.clock()
        limit = timedelta(hours=int(policy_wasm.edge("settings", {})["pull_max_hours"]))
        out = []
        for e in doc.get("edges", []):
            if D._revs(doc, e["edge_id"], now):
                continue
            st = self.edge_store.state(e["edge_id"])
            last = st.get("last_pull")
            if last and now - D._ts(last) > limit and not st.get("silent"):
                self.edge_store.incident(e["edge_id"], {"kind": "edge_silent", "detail": f"no bundle pulled since {last}"}, core=True)
                self.edge_store.update_state(e["edge_id"], silent=True)
                out.append(e["edge_id"])
        return out

    def edge_escrow_status(self, edge_id: str, item_id: str) -> dict:
        """Whether both custodians have opened their halves: only then may the edge forget the value (0014b)."""
        from keyclerk import edge as E
        item = self.edge_store.escrow_get(edge_id, guard.ident(item_id, "item"))
        if item is None:
            raise LookupError("no escrow by that id from this edge")
        done = [self.edge_store.confirmed(r) for r in item.get("relay_ids", [])]
        confirmed = bool(done) and all(done)
        return E.seal(self.bundle_key, {"edge": edge_id, "item_id": item["item_id"], "sha256": item["sha256"],
                                        "confirmed": confirmed, "custodians_confirmed": sum(1 for x in done if x)},
                      "kc-edge-escrow-status-v1")

    EMAIL_PER_LEASE = (6, 60)                     # answers per lease in seconds: a gateway sets a credential, it does not poll

    def edge_email(self, edge_id: str, lease_id: str, request: tuple | None) -> dict:
        """The verified address of a lease's person (decision 0028 point 5, edge protocol 1.3): for a lease in the last
        bundle this edge was served and live now, on an edge whose officer is not frozen; sealed with the bundle key for
        this request's nonce, never cached. The address is not in bundles: an edge fetches it when it sets a gateway
        credential and keeps it nowhere."""
        from keyclerk import edge as E
        lease_id = guard.ident(lease_id, "lease")
        nonce = (request or (None, None))[1]
        if not nonce:
            raise Refusal("the address answers an edge's signed request only")
        state = self.edge_store.state(edge_id)
        if state.get("officer_frozen"):
            raise Refusal("this edge's officer is not independent of the core: it gets no leases, and no addresses")
        last = state.get("last_bundle")
        served = {x.get("lease_id") for x in (E.opened(last).get("leases") or [])} if last else set()
        doc, now = self.store.load(), self.clock()
        e = self._edge(doc, edge_id, now)
        from keyclerk import policy_wasm
        horizons = policy_wasm.edge("settings", {})["horizons"]
        live = next((x for x in self._edge_leases(doc, e, now, horizons) if x["lease_id"] == lease_id), None)
        if live is None or lease_id not in served:
            raise LookupError("no live lease by that id on this edge")
        times = self._email_asks.setdefault(lease_id, deque())
        while times and times[0] < time.monotonic() - self.EMAIL_PER_LEASE[1]:
            times.popleft()
        if len(times) >= self.EMAIL_PER_LEASE[0]:
            raise Throttled("too many address requests for this lease: try again in a minute")
        times.append(time.monotonic())
        return E.email_answer(self.bundle_key, edge_id, lease_id, live["person"], self._emails().get(live["person"]),
                              nonce, now)

    def edge_evidence_head(self, edge_id: str) -> dict:
        from keyclerk import edge as E
        seq, head = self.edge_store.evidence_head(edge_id)
        return E.seal(self.bundle_key, {"edge": edge_id, "up_to_seq": seq, "head": head, "at": _iso(self.clock())},
                      "kc-edge-evidence-ack-v1")

    def edges(self, who: dict) -> list[dict]:
        """Edges with their state, for a viewer, the root, the security officer, or an edge's own officer."""
        from keyclerk import edge as E
        from keyclerk import edge_records
        doc, now = self.store.load(), self.clock()
        a = who.get("anchor")
        sc = self._scope(doc, who, now)
        officer = (doc.get("root") or {}).get("officer")
        out = []
        for e in doc.get("edges", []):
            if not (sc["all"] or (a and (D.same(doc, a, e["officer"]) or D.same(doc, a, officer)))):
                continue
            st = self.edge_store.state(e["edge_id"])
            c, _ = self.edge_store.ceiling(e["edge_id"])
            out.append({"edge_id": e["edge_id"], "name": e.get("name"), "officer": e["officer"], "officer_name": self._name(doc, e["officer"]),
                        "profile": e["profile"], "attested": ((st.get("report") or {}).get("attestation") or {}).get("profile"),
                        "ended": bool(D._revs(doc, e["edge_id"], now)), "targets": [t["target"] for t in e["targets"]],
                        "serial": int(st.get("serial", 0)), "last_pull": st.get("last_pull"), "last_report": st.get("last_report"),
                        "ceiling_serial": (c or {}).get("serial"), "evidence_seq": int(st.get("evidence_seq", 0)),
                        "enrolment_key_id": E.key_id(edge_records.current(doc, e, now)["enrolment_key"]),
                        "incidents": self.edge_store.incidents(e["edge_id"])[-20:], "dropped": st.get("last_dropped", [])[:20],
                        "silent": bool(st.get("silent")), "unlock": bool(e.get("unlock_key")),
                        "unlock_approver": bool(a and any(D.same(doc, a, x) for x in e.get("unlock_approvers", []))),
                        "may_close": bool(a and (D.same(doc, a, e["officer"]) or D.same(doc, a, officer))),
                        "visit_leases": [{"lease_id": v["lease_id"], "person": v["person"], "person_name": self._name(doc, v["person"]),
                                          "targets": v["targets"], "until": _iso(D._ts(v["until"]))}
                                         for v in doc.get("edge_visit_leases", []) if v["edge"] == e["edge_id"]
                                         and not D._revs(doc, v["lease_id"], now) and D._ts(v["until"]) > now]})
        return out

    def relay_list(self, who: dict) -> list[dict]:
        a = who.get("anchor")
        doc = self.store.load()
        return [{"relay_id": x["relay_id"], "edge": x["edge"], "key_id": x["key_id"], "purpose": x["purpose"],
                 "created": x["created"], "expires": x.get("expires"), "taken": x.get("taken")}
                for x in self.edge_store.relay_items() if a and D.same(doc, a, x["anchor"])]

    RELAY_FRESH_SECONDS = 600

    def relay_take(self, who: dict, rid: str) -> dict:
        """The ciphertext, once, to its person, within 10 minutes of a fresh sign-in (decision 0014 point 8)."""
        import time as _time
        a = who.get("anchor")
        if not a:
            raise PermissionError("sign in as yourself to receive what is relayed to you")
        if not isinstance(who.get("auth_time"), (int, float)) or _time.time() - who["auth_time"] > self.RELAY_FRESH_SECONDS:
            raise PermissionError("sign in again first (a fresh sign-in at the broker): a relayed secret is handed over within "
                                  "10 minutes of it")
        doc = self.store.load()
        items = {x["relay_id"]: x for x in self.edge_store.relay_items()}
        x = items.get(guard.ident(rid, "relay"))
        if x is None or not D.same(doc, a, x["anchor"]):
            raise LookupError("nothing by that id waits for you")
        try:
            self._person_key(doc, x["key_id"], self.clock())
        except Refusal:
            raise LookupError("the key it was sent to was ended: it can no longer be opened") from None
        item = self.edge_store.relay_take(x["relay_id"])
        if item is None:
            raise LookupError("already handed over")
        self.store.note({"change_id": "C-" + secrets.token_hex(6), "action": "relay_taken", "actor": a,
                            "summary": f"{item['purpose']} handed over", "records": {}, "outcome": "applied", "reasons": []})
        return {"relay_id": item["relay_id"], "key_id": item["key_id"], "purpose": item["purpose"], "envelope": item["envelope"]}

    def relay_confirm(self, who: dict, rid: str) -> dict:
        """The browser opened it: a credential is deleted; an escrow half is recorded as confirmed (0014b)."""
        a = who.get("anchor")
        doc = self.store.load()
        x = next((i for i in self.edge_store.relay_items() if i["relay_id"] == guard.ident(rid, "relay")), None)
        if x is None or not a or not D.same(doc, a, x["anchor"]) or not x.get("taken"):
            raise LookupError("nothing by that id waits for your confirmation")
        self.edge_store.relay_confirm(x["relay_id"])
        return {"relay_id": x["relay_id"], "confirmed": True}

    def my_visit_leases(self, who: dict) -> list[dict]:
        doc, now = self.store.load(), self.clock()
        a = who.get("anchor")
        return [{"lease_id": v["lease_id"], "edge": v["edge"], "targets": v["targets"], "from": _iso(D._ts(v["from"])),
                 "until": _iso(D._ts(v["until"]))} for v in doc.get("edge_visit_leases", [])
                if a and D.same(doc, a, v["person"]) and not D._revs(doc, v["lease_id"], now) and D._ts(v["until"]) > now]

    def my_keys(self, who: dict) -> list[dict]:
        doc, now = self.store.load(), self.clock()
        a = who.get("anchor")
        return [{"key_id": k["key_id"], "public_key": k["public_key"], "ssh_key": k.get("ssh_key"), "at": _iso(D._ts(k["at"])),
                 "credential_id": k.get("credential_id"),
                 "active": not D._revs(doc, k["key_id"], now)} for k in doc.get("person_keys", []) if a and D.same(doc, a, k["anchor"])]

    @staticmethod
    def _edge_statement(body: dict) -> dict:
        """The multi-signed statement as sent (amendment 0014d): its signatures are checked over its bytes by the
        engine's checks, against what the record holds."""
        st = body.get("statement")
        if not isinstance(st, dict) or set(st) != {"bytes", "signatures"} or not isinstance(st["bytes"], str) \
                or len(st["bytes"]) > 16384 or not isinstance(st["signatures"], list) or not 2 <= len(st["signatures"]) <= 3:
            raise Refusal("statement: the kc-edge-officer-v2 statement, signed by the officer and by the edge "
                          "(python -m keyclerk.edge_cli statement, then cosign with each key)")
        return {"bytes": st["bytes"], "signatures": [{k: str(s.get(k, ""))[:200] for k in ("key", "key_id", "signature")}
                                                     if isinstance(s, dict) else {} for s in st["signatures"]]}

    @staticmethod
    def _unlock_key(v) -> str:
        from keyclerk import edge as E
        try:
            E.load_unlock_public(v)
        except ValueError as x:
            raise Refusal(f"unlock_key: {x}") from None
        return v

    def _build_edge(self, doc: dict, actor: str, body: dict, now: datetime) -> tuple[dict, str]:
        """The records an edge action adds; the engine's checks decide (the officer's or a second key makes them wait)."""
        action = body["action"]
        if action == "enrol_edge":
            eid = body.get("edge_id")
            if not isinstance(eid, str) or not GROUP_ID.fullmatch(eid):
                raise Refusal("an edge id is 2 to 63 lowercase letters, digits and hyphens")
            if any(e["edge_id"] == eid for e in doc.get("edges", [])):
                raise Refusal(f"edge {eid} is enrolled already")
            officer = self._anchor(body.get("officer"), "officer")
            if self._person(doc, officer) is None:
                raise Refusal("the officer is not in the records")
            targets = body.get("targets")
            if not isinstance(targets, list) or not targets or len(targets) > 200:
                raise Refusal("targets: a list of {target, role, entitlement}")
            clean = []
            for x in targets:
                if not isinstance(x, dict) or not {"target", "role", "entitlement"} <= set(x) <= {"target", "role", "entitlement", "max_session_hours"}:
                    raise Refusal("each target is {target, role, entitlement, max_session_hours?}")
                tgt = {"target": guard.ident(x["target"], "target"), "role": guard.ident(x["role"], "role"),
                       "entitlement": guard.ident(x["entitlement"], "entitlement")}
                if x.get("max_session_hours") is not None:
                    if not isinstance(x["max_session_hours"], int) or not 1 <= x["max_session_hours"] <= 24:
                        raise Refusal("max_session_hours: 1 to 24")
                    tgt["max_session_hours"] = x["max_session_hours"]
                clean.append(tgt)
            if body.get("profile") not in ("assured", "basic"):
                raise Refusal("profile: assured or basic (the edge proves it by attestation later)")
            rec = {"edge_id": eid, "enrolment_key": str(body.get("enrolment_key", "")).lower(),
                   "officer": officer, "officer_key": str(body.get("officer_key", "")).lower(), "profile": body["profile"],
                   "statement": self._edge_statement(body), "targets": clean, "by": actor, "approved_by": [], "at": now}
            if body.get("name"):
                rec["name"] = guard.text(body["name"], "name", 120)
            if body.get("unlock_key"):
                rec["unlock_key"] = self._unlock_key(body["unlock_key"])
            if body.get("unlock_approvers"):
                if not isinstance(body["unlock_approvers"], list) or len(body["unlock_approvers"]) > 20:
                    raise Refusal("unlock_approvers: up to twenty people")
                rec["unlock_approvers"] = [self._anchor(c, "approver") for c in body["unlock_approvers"]]
            if body.get("tpm") is not None:                # decision 0016: what the officer pinned on site
                t = body["tpm"]
                if not isinstance(t, dict) or not {"ek_public", "ek_sha256", "ak_public", "pcr_baseline"} <= set(t) \
                        <= {"ek_public", "ek_sha256", "ak_public", "pcr_baseline", "ek_cert"}:
                    raise Refusal("tpm: {ek_public, ek_sha256, ak_public, pcr_baseline, ek_cert?}")
                if body["profile"] != "assured":
                    raise Refusal("a TPM makes sense on an assured edge only")
                rec["tpm"] = {k: (str(v).lower() if k == "ek_sha256" else
                                  {str(p): str(x).lower() for p, x in v.items()} if k == "pcr_baseline" and isinstance(v, dict) else str(v))
                              for k, v in t.items()}
            if body.get("custodians"):
                if not isinstance(body["custodians"], list) or not 2 <= len(body["custodians"]) <= 10:
                    raise Refusal("custodians: two to ten people")
                rec["custodians"] = [self._anchor(c, "custodian") for c in body["custodians"]]
            if body.get("reason"):
                rec["reason"] = self._reason(body)
            return {"edges": [rec]}, f"enrol edge {eid} (officer {self._name(doc, officer)})"
        if action == "enrol_person_key":
            from keyclerk import relay
            try:
                relay.public_key(body.get("public_key"))
            except (ValueError, TypeError) as e:
                raise Refusal(f"public_key: {e}") from None
            if body.get("user_verification") is not True:
                raise Refusal("the authenticator must verify you (a PIN or a fingerprint): user_verification true")
            rec = {"key_id": self._next_id(doc, "person_keys", "K", "key_id", self._reserved()), "anchor": actor,
                   "public_key": body["public_key"], "user_verification": True, "by": actor, "approved_by": [], "at": now}
            for k, n in (("ssh_key", 900), ("credential_id", 400), ("attestation", 40)):
                if body.get(k):
                    rec[k] = guard.text(body[k], k, n).strip()
            return {"person_keys": [rec]}, f"register a hardware key for {self._name(doc, actor)}"
        if action == "grant_visit_lease":
            edge_id = guard.ident(body.get("edge"), "edge")
            person = self._anchor(body.get("person"), "person")
            targets = body.get("targets")
            if not isinstance(targets, list) or not targets or len(targets) > 20:
                raise Refusal("targets: one or more target names on that edge")
            hours = body.get("hours")
            if not isinstance(hours, int) or isinstance(hours, bool) or not 1 <= hours <= 24 * 30:
                raise Refusal("hours: a whole number of hours, 1 or more")
            start = guard.timestamp(body["from"]) if body.get("from") else now
            rec = {"lease_id": self._next_id(doc, "edge_visit_leases", "VL", "lease_id", self._reserved()), "edge": edge_id,
                   "person": person, "ssh_key": guard.text(body.get("ssh_key", ""), "ssh_key", 900).strip(),
                   "targets": [guard.ident(x, "target") for x in targets], "from": start, "until": start + timedelta(hours=hours),
                   "by": actor, "approved_by": []}
            if body.get("reason"):
                rec["reason"] = self._reason(body)
            return {"edge_visit_leases": [rec]}, f"a {hours}-hour visit lease on {edge_id} for {self._name(doc, person)}"
        if action == "rotate_edge":
            eid = guard.ident(body.get("edge_id"), "edge")
            self._edge(doc, eid, now)
            officer = self._anchor(body.get("officer"), "officer")
            rec = {"rotation_id": self._next_id(doc, "edge_rotations", "ER", "rotation_id", self._reserved()), "edge": eid,
                   "enrolment_key": str(body.get("enrolment_key", "")).lower(), "officer": officer,
                   "officer_key": str(body.get("officer_key", "")).lower(), "statement": self._edge_statement(body),
                   "by": actor, "approved_by": [], "at": now}
            if body.get("unlock_key"):
                rec["unlock_key"] = self._unlock_key(body["unlock_key"])
            if body.get("reason"):
                rec["reason"] = self._reason(body)
            return {"edge_rotations": [rec]}, f"rotate the keys of edge {eid}"
        # end_edge_record: an edge, a person key or a visit lease, ended for good
        rid = guard.ident(body.get("id"), "record")
        kinds = {r[k]: (kind, r) for kind, k in (("edges", "edge_id"), ("person_keys", "key_id"), ("edge_visit_leases", "lease_id"))
                 for r in doc.get(kind, [])}
        if rid not in kinds:
            raise Refusal(f"there is no edge, person key or visit lease {rid}")
        kind, r = kinds[rid]
        root, officer = D.root_at(doc, now), (doc.get("root") or {}).get("officer")
        mine = kind == "person_keys" and D.same(doc, actor, r["anchor"]) or kind == "edge_visit_leases" and D.same(doc, actor, r["by"])
        if not (mine or D.same(doc, actor, root) or D.same(doc, actor, officer)):
            raise Refusal("the root, the security officer, or its owner ends it")
        rec = {"id": rid, "at": now, "by": actor, "mode": "retire", "reason": self._reason(body)}
        return {"admin_revocations": [rec]}, f"end {rid}"

    def build(self, doc: dict, actor: str, body: dict, now: datetime) -> tuple[dict, str]:
        """The records an action adds, and a one-line summary of it."""
        action = body.get("action")
        if action not in ACTIONS:
            raise Refusal(f"unknown action; one of {', '.join(ACTIONS)}")
        if action in VISIT_ACTIONS:
            return self._build_visit(doc, actor, body, now)
        if action in EDGE_ACTIONS:
            return self._build_edge(doc, actor, body, now)
        if action in ("add_member", "include_group"):
            gid = guard.ident(body.get("group"), "group")
            power = "members" if action == "add_member" else "includes"
            under = self._under(doc, actor, gid, power, now)
            lim = self._limits(doc, under)
            if action == "add_member":
                member = {"anchor": self._anchor(body.get("anchor"), "anchor")}
                if self._person(doc, member["anchor"]) is None:
                    raise Refusal("that person is not in the records")
                what = f"add {self._name(doc, member['anchor'])} to {gid}"
            else:
                sub = guard.ident(body.get("include"), "included group")
                if sub not in D._groups(doc):
                    raise Refusal(f"there is no group {sub}")
                member = {"group": sub}
                what = f"include {sub} in {gid}"
            days = self._days(body, lim["max_membership_days"])
            if any(m["group"] == gid and m["member"] == member
                   and D.membership_status(doc, m, now) in ("active", "pending", "standby") for m in doc.get("memberships", [])):
                raise Refusal(f"{what}: that membership already holds")
            if any(p["action"] == action and any(r["group"] == gid and r["member"] == member
                                                 for r in p["records"].get("memberships", []))
                   for p in self._live_pending(now).values()):
                raise Refusal(f"{what}: the same change already waits for approval")
            rec = {"membership_id": self._next_id(doc, "memberships", "M", "membership_id", self._reserved()), "group": gid,
                   "member": member, "by": actor, "under": under, "start": now, "end": now + timedelta(days=days)}
            return {"memberships": [rec]}, what
        if action == "end_membership":
            mid = guard.ident(body.get("membership_id"), "membership")
            m = next((x for x in doc.get("memberships", []) if x["membership_id"] == mid), None)
            if m is None:
                raise Refusal(f"there is no membership {mid}")
            if D.membership_status(doc, m, now) not in ("active", "pending", "standby", "invalid"):
                raise Refusal(f"{mid} has already ended")
            power = {"anchor": "members", "group": "includes", "rule": "rules"}[D._kind(m)]
            self._under(doc, actor, m["group"], power, now)
            rec = {"id": mid, "at": now, "by": actor, "mode": "retire", "reason": self._reason(body)}
            return {"admin_revocations": [rec]}, f"end {mid} in {m['group']}"
        if action == "create_group":
            parent = guard.ident(body.get("parent"), "parent group")
            under = self._under(doc, actor, parent, "subgroups", now)
            lim = self._limits(doc, under)
            gid = body.get("group_id")
            if not isinstance(gid, str) or not GROUP_ID.fullmatch(gid):
                raise Refusal("a group id is 2 to 63 lowercase letters, digits and hyphens")
            if gid in D._groups(doc):
                raise Refusal(f"{gid} exists already")
            risk = body.get("max_risk", "low")
            if risk not in D.RISK or D.RISK[risk] > D.RISK[lim["max_risk"]]:
                raise Refusal(f"the class must be one of low, elevated, privileged and not above {lim['max_risk']}")
            rec = {"group_id": gid, "parent": parent, "max_risk": risk, "carries": []}
            place = D._groups(doc)[parent].get("place")
            if place:
                rec["place"] = place
            if body.get("description"):
                rec["description"] = guard.text(body["description"], "description", 300)
            return {"groups": [rec]}, f"create {gid} under {parent}"
        if action == "delegate":
            gid = guard.ident(body.get("group"), "group")
            under = self._under(doc, actor, gid, "delegate", now)
            lim = self._limits(doc, under)
            delegate = self._anchor(body.get("delegate"), "delegate")
            if self._person(doc, delegate) is None:
                raise Refusal("that person is not in the records")
            powers = body.get("powers")
            if not isinstance(powers, list) or not powers or len(powers) > 5 or not set(powers) <= D.POWERS:
                raise Refusal(f"powers: a non-empty list from {', '.join(sorted(D.POWERS))}")
            risk = body.get("max_risk", "low")
            if risk not in D.RISK:
                raise Refusal("max_risk: low, elevated or privileged")
            mdays = self._days({"days": body.get("max_membership_days", lim["max_membership_days"])},
                               lim["max_membership_days"])
            depth_default = 0 if lim["depth_left"] is None else max(lim["depth_left"] - 1, 0)
            depth = body.get("depth_left", depth_default)
            if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 5:
                raise Refusal("depth_left: 0 to 5")
            end = now + timedelta(days=self._days(body, 90, D.R["max_delegation_days"]))
            if lim["end"] is not None:
                end = min(end, guard.timestamp(lim["end"]) if not isinstance(lim["end"], datetime) else lim["end"])
            rec = {"delegation_id": self._next_id(doc, "delegations", "D", "delegation_id", self._reserved()), "delegate": delegate,
                   "group": gid, "powers": sorted(set(powers)), "max_risk": risk, "max_membership_days": mdays,
                   "depth_left": depth, "start": now, "end": end, "by": actor, "parent": under}
            if lim["place"]:
                rec["place"] = lim["place"]
            return {"delegations": [rec]}, f"delegate {', '.join(rec['powers'])} over {gid} to {self._name(doc, delegate)}"
        if action == "appoint_approver":
            if not D.same(doc, actor, D.root_at(doc, now)):
                raise Refusal("only the root trust owner appoints a named approver (with the security officer's key)")
            anchor = self._anchor(body.get("anchor"), "approver")
            if self._person(doc, anchor) is None:
                raise Refusal("that person is not in the records")
            rec = {"approver_id": self._next_id(doc, "approvers", "A", "approver_id", self._reserved()), "anchor": anchor,
                   "appointed_by": actor, "approved_by": [], "from": now,
                   "to": now + timedelta(days=self._days(body, 90, D.R.get("max_approver_days", 365))),
                   "reason": self._reason(body)}
            return {"approvers": [rec]}, f"appoint {self._name(doc, anchor)} as a named approver"
        if action == "end_approver":
            aid = guard.ident(body.get("approver_id"), "appointment")
            a = next((x for x in doc.get("approvers", []) if x["approver_id"] == aid), None)
            if a is None:
                raise Refusal(f"there is no appointment {aid}")
            officer = (doc.get("root") or {}).get("officer")
            if not (D.same(doc, actor, D.root_at(doc, now)) or D.same(doc, actor, officer)):
                raise Refusal("only the root trust owner or the security officer ends an appointment")
            rec = {"id": aid, "at": now, "by": actor, "mode": "retire", "reason": self._reason(body)}
            return {"admin_revocations": [rec]}, f"end {aid} ({self._name(doc, a['anchor'])} as a named approver)"
        # end_delegation
        did = guard.ident(body.get("delegation_id"), "delegation")
        d = D._delegations(doc).get(did)
        if d is None:
            raise Refusal(f"there is no delegation {did}")
        mode = body.get("mode", "retire")
        if mode not in ("retire", "revoke"):
            raise Refusal("mode: retire (orderly) or revoke (for cause)")
        above = {x["delegate"] for x in D.chain(doc, did)[1:]} | {d["by"]}
        is_root = D.same(doc, actor, D.root_at(doc, now))
        if not (is_root or any(D.same(doc, actor, a) for a in above) or (mode == "retire" and D.same(doc, actor, d["delegate"]))):
            raise Refusal("only the root, someone above in its chain, or the deputy (to retire) may end a delegation")
        rec = {"id": did, "at": now, "by": actor, "mode": mode, "reason": self._reason(body)}
        if mode == "revoke":
            rec["from"] = now
        return {"admin_revocations": [rec]}, f"{mode} {did} ({self._name(doc, d['delegate'])} over {d['group']})"

    # --- acting ---------------------------------------------------------------------------------------------------

    def propose(self, who: dict, body: dict) -> dict:
        if not isinstance(body, dict):
            raise Refusal("the request body is a JSON object")
        with self.lock:
            doc, now = self.store.load(), self.clock()
            actor = self._actor(doc, who)
            self._throttle(who)
            try:
                add, what = self.build(doc, actor, body, now)
            except (Refusal, guard.InputRejected) as e:   # an attempt beyond what one holds is on record too
                if isinstance(e, Refusal) and not e.next:
                    e.next = self._next(doc, actor, [str(e)], gid=body.get("group") if isinstance(body.get("group"), str) else None,
                                        sc=self._scope(doc, who, now))
                self.store.note({"change_id": "C-" + secrets.token_hex(6), "action": str(body.get("action"))[:40],
                                    "summary": "attempt refused before the checks", "actor": actor, "records": {},
                                    "outcome": "refused", "reasons": [guard.safe_for_log(e, 300)]})
                raise
            outcome, reasons, cand = self._evaluate(doc, add)
            signs = outcome in ("applied", "pending") and self._needs_proposer(doc, add)
            if signs:                                     # high risk: it waits for the proposer's own signature too
                outcome, reasons = "pending", [*reasons, SIGN_OWN]
            cid = "C-" + secrets.token_hex(6)
            entry = {"change_id": cid, "action": body["action"], "summary": what, "actor": actor,
                     "records": _jsonable(add), "outcome": outcome, "reasons": reasons}
            if outcome == "applied":
                self._commit(cand, entry)
            elif outcome == "refused":
                self.store.note(entry)
            elif outcome == "pending":
                p = self._live_pending(now)
                if len(p) >= MAX_PENDING:
                    raise Refusal(f"{MAX_PENDING} changes already wait for approval: settle some first")
                p[cid] = {**entry, "at": _iso(now), "approvals": [], **({"needs_proposer": True} if signs else {}),
                          "waiting_for": self._approvers(doc, add, [], actor), "waiting_rev": self.store.revision()}
                self.store.save_pending(p)
                self.store.note({**entry, "outcome": "pending"})
            return {"change_id": cid, "outcome": outcome, "summary": what, "reasons": reasons,
                    "records": _jsonable(add), "revision": self.store.revision(),
                    "next": [] if outcome == "applied" else self._next(doc, actor, reasons, add)}

    @staticmethod
    def proofs_required() -> bool:
        from keyclerk import config
        return ((config.current().get("approvals") or {}).get("proofs")) == "required"

    def _needs_proposer(self, doc: dict, add: dict) -> bool:
        """Whether a change is high risk, so its proposer signs it at the broker too (decision 0015, replan D2)."""
        if not self.proofs_required():
            return False
        from keyclerk import approvals, config
        pol = config.current().get("approvals") or {}
        return any(approvals.needs_proposal_proof(doc, kind, r, pol) for kind, _ in approvals.KEYED for r in add.get(kind, []))

    def _sign_own(self, doc: dict, pend: dict, cid: str, p: dict, actor: str, proof: str | None) -> dict:
        """The proposer's own signature on a high-risk change; it applies when no other key is missing."""
        from keyclerk.approvals import KEYED, statement
        if not proof:
            raise Refusal("a high-risk change carries your own signature: sign in again at the broker "
                          "(GET /changes/{id}/statement gives the nonce), then send the ID token as the proof")
        if self.proofs is None:
            raise Refusal("this desk cannot verify proofs")
        items = [(kind, r) for kind, _ in KEYED for r in p["records"].get(kind, [])]
        try:
            self.proofs(proof, statement(doc["realm"], items, actor, purpose="proposal"), actor)
        except guard.InputRejected as e:
            raise Refusal(f"the proof does not fit your change: {e}") from None
        p["proposal_proofs"] = [{"records": self._ids(p["records"]), "by": actor, "token": proof}]
        p["needs_proposer"] = False
        given = p.get("approvals", [])
        add = self._with_approvals(p["records"], given) if given else copy.deepcopy(p["records"])
        if p.get("proofs"):
            add["approval_proofs"] = p["proofs"]
        add["proposal_proofs"] = p["proposal_proofs"]
        outcome, reasons, cand = self._evaluate(doc, add)
        entry = {"change_id": cid, "action": p["action"], "summary": p["summary"], "actor": p["actor"], "signed_by": actor,
                 "records": self._public(add), "outcome": outcome, "reasons": reasons}
        if outcome == "pending":
            p["reasons"] = reasons
            self.store.save_pending(pend)
            self.store.note(entry)
            return {"change_id": cid, "outcome": "pending", "summary": p["summary"], "reasons": reasons,
                    "records": self._public(add), "revision": self.store.revision(),
                    "next": self._next(doc, p["actor"], reasons, p["records"], given)}
        if outcome == "applied":
            self._commit(cand, entry)
        else:
            self.store.note(entry)
        pend.pop(cid)
        self.store.save_pending(pend)
        return {"change_id": cid, "outcome": outcome, "summary": p["summary"], "reasons": reasons,
                "records": self._public(add), "revision": self.store.revision()}

    @staticmethod
    def _ids(recs: dict) -> list[str]:
        from keyclerk.approvals import KEYED
        return [str(r[field]) for kind, field in KEYED for r in recs.get(kind, [])]

    def _statement(self, doc: dict, p: dict, actor: str) -> tuple[str, list[str]]:
        from keyclerk.approvals import KEYED, statement
        items = [(kind, r) for kind, _ in KEYED for r in p["records"].get(kind, [])]
        return statement(doc["realm"], items, actor), self._ids(p["records"])

    def statement(self, who: dict, cid: str) -> dict:
        """What an approver signs: the nonce for a fresh sign-in at the broker (decision 0006)."""
        doc = self.store.load()
        actor = self._actor(doc, who)
        p = self.store.pending().get(guard.ident(cid, "change"))
        sc = self._scope(doc, who, self.clock()) if p else None
        if p is None or not (sc["all"] or self._sees_entry(doc, sc, p) or self._counts(doc, actor, p)):
            raise Refusal("no such change waits for approval")    # the same answer either way: no existence oracle
        nonce, ids = self._statement(doc, p, actor)
        purpose = "approval"
        if p.get("needs_proposer") and D.same(doc, actor, p["actor"]):    # the proposer signs their own change
            from keyclerk.approvals import KEYED, statement
            purpose = "proposal"
            nonce = statement(doc["realm"], [(k, r) for k, _ in KEYED for r in p["records"].get(k, [])], actor, purpose="proposal")
        return {"change_id": cid, "nonce": nonce, "records": ids, "by": actor, "summary": p["summary"],
                "required": self.proofs_required(), "purpose": purpose}

    # --- approving on a phone ------------------------------------------------------------------------------------
    # A short-lived link, signed by this desk, that lets this approver start the same signed approval on another
    # device (a phone): the link only says who may try; the broker's fresh sign-in, stepped up, is the approval.

    PHONE_LINK_SECONDS = 600

    def _link_sig(self, cid: str, anchor: str, exp: int) -> str:
        import base64
        import hmac
        mac = hmac.new(self.link_key, f"phone|{cid}|{anchor}|{exp}".encode(), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()[:32]

    def phone_link(self, who: dict, cid: str) -> dict:
        from urllib.parse import quote, urlencode
        st = self.statement(who, cid)                      # waits, and this person is a known approver
        exp = int(time.time()) + self.PHONE_LINK_SECONDS
        q = urlencode({"for": st["by"], "exp": exp, "sig": self._link_sig(st["change_id"], st["by"], exp)})
        path = f"/approve/{quote(st['change_id'], safe='')}?{q}"
        return {"change_id": st["change_id"], "url": self.public_base + path,
                "qr": f"/approve-qr/{quote(st['change_id'], safe='')}?{q}", "expires_at": _iso(datetime.fromtimestamp(exp, timezone.utc))}

    def phone_link_valid(self, cid: str, anchor: str, exp: str, sig: str) -> bool:
        import hmac
        try:
            e = int(exp)
            guard.ident(cid, "change")
            self._anchor(anchor, "anchor")
        except (ValueError, guard.InputRejected):
            return False
        return time.time() <= e <= time.time() + self.PHONE_LINK_SECONDS + 5 and \
            hmac.compare_digest(self._link_sig(cid, anchor, e), str(sig))

    def preview(self, who: dict, body: dict) -> dict:
        """What propose would answer now, without doing anything: nothing is applied, held or logged. It counts against
        the same per-person limit as a change, so it cannot be used to probe without bound."""
        if not isinstance(body, dict):
            raise Refusal("the request body is a JSON object")
        with self.lock:
            doc, now = self.store.load(), self.clock()
            actor = self._actor(doc, who)
            self._throttle(who)
            try:
                add, what = self.build(doc, actor, body, now)
            except Refusal as e:
                if not e.next:
                    e.next = self._next(doc, actor, [str(e)], gid=body.get("group") if isinstance(body.get("group"), str) else None,
                                        sc=self._scope(doc, who, now))
                raise
            outcome, reasons, _ = self._evaluate(doc, add)
            if outcome in ("applied", "pending") and self._needs_proposer(doc, add):   # as propose would answer
                outcome, reasons = "pending", [*reasons, SIGN_OWN]
            return {"outcome": outcome, "summary": what, "reasons": reasons, "records": _jsonable(add),
                    "revision": self.store.revision(),
                    "next": [] if outcome == "applied" else self._next(doc, actor, reasons, add)}

    def approve(self, who: dict, cid: str, proof: str | None = None) -> dict:
        try:
            return self._approve(who, cid, proof)
        except Refusal as e:
            if not e.next:
                doc = self.store.load()
                p = self.store.pending().get(str(cid))
                actor = who.get("anchor")
                e.next = self._next(doc, actor, [str(e)], p["records"] if p else None, p.get("approvals", []) if p else ())
            raise

    def _approve(self, who: dict, cid: str, proof: str | None = None) -> dict:
        with self.lock:
            doc, now = self.store.load(), self.clock()
            actor = self._actor(doc, who)
            self._throttle(who)
            pend = self.store.pending()
            p = pend.get(guard.ident(cid, "change"))
            if p is None:
                raise Refusal("no such change waits for approval")
            if guard.timestamp(p["at"]) < now - timedelta(days=PENDING_DAYS):
                raise Refusal("this change waited too long and has expired: propose it again")
            if D.same(doc, actor, p["actor"]) and p.get("needs_proposer"):
                return self._sign_own(doc, pend, cid, p, actor, proof)
            if D.same(doc, actor, p["actor"]):
                raise Refusal("you proposed this change: a second key is someone else's")
            given = p.get("approvals", [])
            if any(D.same(doc, actor, a) for a in given):
                raise Refusal("you approved this change already: the key still missing is someone else's")
            proofs = list(p.get("proofs", []))
            if self.proofs_required() or proof:
                if not proof:
                    raise Refusal("an approval is your own signature: sign in again at the broker to approve "
                                  "(GET /changes/{id}/statement gives the nonce), then send the ID token as the proof")
                if self.proofs is None:
                    raise Refusal("this desk cannot verify approval proofs")
                nonce, ids = self._statement(doc, p, actor)
                try:
                    self.proofs(proof, nonce, actor)
                except guard.InputRejected as e:
                    raise Refusal(f"the proof does not fit this approval: {e}") from None
                proofs.append({"records": ids, "by": actor, "token": proof})
            add = self._with_approvals(p["records"], [*given, actor])
            if proofs:
                add["approval_proofs"] = proofs
            if p.get("proposal_proofs"):
                add["proposal_proofs"] = p["proposal_proofs"]
            outcome, reasons, cand = self._evaluate(doc, add)
            if outcome == "applied" and p.get("needs_proposer"):   # every key is in; the proposer has not signed yet
                outcome, reasons = "pending", [SIGN_OWN]
            if outcome == "pending":
                before = set(self._evaluate(doc, self._with_approvals(p["records"], given))[1])
                if not before - set(reasons):
                    raise Refusal("your approval does not count as a key this change needs: " + "; ".join(reasons))
                p["approvals"], p["reasons"] = [*given, actor], reasons     # one key of several: it waits for the rest
                p["proofs"] = proofs
                p["waiting_for"] = self._approvers(doc, p["records"], p["approvals"], p["actor"])
                p["waiting_rev"] = self.store.revision()
                self.store.save_pending(pend)
                self.store.note({"change_id": cid, "action": p["action"], "summary": p["summary"], "actor": p["actor"],
                                    "approved_by": actor, "records": self._public(add), "outcome": "pending", "reasons": reasons})
                return {"change_id": cid, "outcome": "pending", "summary": p["summary"], "reasons": reasons,
                        "records": self._public(add), "revision": self.store.revision(),
                        "next": self._next(doc, p["actor"], reasons, p["records"], p["approvals"])}
            entry = {"change_id": cid, "action": p["action"], "summary": p["summary"], "actor": p["actor"],
                     "approved_by": actor, "records": self._public(add), "outcome": outcome, "reasons": reasons}
            if outcome == "applied":
                self._commit(cand, entry)
            else:
                self.store.note(entry)
            pend.pop(cid)
            self.store.save_pending(pend)
            return {"change_id": cid, "outcome": outcome, "summary": p["summary"], "reasons": reasons,
                    "records": self._public(add), "revision": self.store.revision()}

    @staticmethod
    def _with_approvals(recs: dict, approvers: list[str]) -> dict:
        add = copy.deepcopy(recs)
        for kind in ("memberships", "delegations", "approvers", "badges", "edges", "person_keys", "edge_visit_leases", "edge_rotations"):
            for r in add.get(kind, []):
                r["approved_by"] = sorted(set(r.get("approved_by", [])) | set(approvers))
        return add

    def withdraw(self, who: dict, cid: str) -> dict:
        with self.lock:
            doc = self.store.load()
            actor = self._actor(doc, who)
            self._throttle(who)
            pend = self.store.pending()
            p = pend.get(guard.ident(cid, "change"))
            if p is None:
                raise Refusal("no such change waits for approval")
            if not (D.same(doc, actor, p["actor"]) or D.same(doc, actor, D.root_at(doc, self.clock()))):
                raise Refusal("only who proposed it, or the root, may withdraw a change")
            pend.pop(cid)
            self.store.save_pending(pend)
            self.store.note({"change_id": cid, "action": p["action"], "summary": p["summary"], "actor": actor,
                                "outcome": "withdrawn", "reasons": []})
            return {"change_id": cid, "outcome": "withdrawn", "summary": p["summary"], "reasons": [], "records": {},
                    "revision": self.store.revision()}

    # --- views ----------------------------------------------------------------------------------------------------

    def _powers(self, doc: dict, actor: str | None, gid: str, now: datetime) -> list[str]:
        if not actor:
            return []
        return [p for p in sorted(D.POWERS) if D.authority(doc, actor, gid, p, now)]

    def _observed(self) -> set:
        f = (self.broker_state / "observed.json") if self.broker_state else None
        if not f or not f.exists():
            return set()
        try:
            return {(str(g), str(a)) for g, a in guard.load_json_bytes(f.read_bytes(), "observed", guard.MAX_FILE_BYTES)}
        except (guard.InputRejected, ValueError, TypeError, OSError):
            return set()                                      # unknown, shown as such, never an error page

    def me(self, who: dict) -> dict:
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        a = who.get("anchor")
        p = self._person(doc, a)
        held = [self._delegation_view(doc, d, now, a) for d in doc.get("delegations", []) if p and D.same(doc, d["delegate"], a)]
        manages = [{"group": g["group_id"], "powers": pw} for g in doc.get("groups", [])
                   if (pw := self._powers(doc, a, g["group_id"], now))]
        ents = D.effective_entitlements(doc, a, now) if p else {}
        return {"anchor": a, "name": who.get("name"), "person": p["person"] if p else None, "kind": p["kind"] if p else None,
                "roles": who.get("roles") or [], "viewer": self._viewer(who),
                "root": bool(p) and D.same(doc, a, D.root_at(doc, now)), "realm": doc.get("realm"),
                "revision": self.store.revision(), "delegations": held, "manages": manages,
                "entitlements": [{"entitlement": k, "via": sorted(set(v))} for k, v in sorted(ents.items())],
                "waiting_for_me": sum(1 for c in self.changes(who)["pending"] if c["can_approve"]),
                "guests_waiting": sum(self._visit_summary(doc, v, now, a)["waiting_for_me"] for v in doc.get("visits", [])
                                      if a and (D.same(doc, a, v["host"]) or D.same(doc, a, v["organiser"])))}

    def people(self, who: dict) -> list[dict]:
        doc = self.store.load()
        self._may_read(doc, who)
        sc = self._scope(doc, who, self.clock())
        if not sc["all"] and not sc["manage"]:
            raise PermissionError("the directory is for people who manage a group, a viewer and the root")
        return [{"anchor": a, "person": p["person"], "kind": p["kind"]} for p in doc.get("persons", []) for a in p["anchors"]]

    def groups(self, who: dict) -> list[dict]:
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        sc = self._scope(doc, who, now)
        out = []
        for g in sorted(doc.get("groups", []), key=lambda x: [*reversed(D.ancestors(doc, x["group_id"]))]):
            gid = g["group_id"]
            if not sc["all"] and gid not in sc["tree"]:
                continue
            opened = sc["all"] or gid in sc["open"]
            out.append({"group_id": gid, "parent": g.get("parent"), "depth": len(D.ancestors(doc, gid)) - 1,
                        "max_risk": g["max_risk"], "effective_risk": D.effective_risk(doc, gid), "place": g.get("place"),
                        "description": g.get("description"), "carries": [c["entitlement"] for c in g.get("carries", [])],
                        "members": len(D.effective_members(doc, gid, now)) if opened else 0,
                        "my_powers": self._powers(doc, who.get("anchor"), gid, now)})
        return out

    def group(self, who: dict, gid: str) -> dict:
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        gid = guard.ident(gid, "group")
        g = D._groups(doc).get(gid)
        sc = self._scope(doc, who, now)
        if g is None or not (sc["all"] or gid in sc["open"]):
            raise LookupError(f"there is no group {gid} that you manage or belong to")   # one answer: no existence oracle
        a = who.get("anchor")
        mine = self._powers(doc, a, gid, now)
        obs = self._observed()
        rows = []
        for m in doc.get("memberships", []):
            if m["group"] != gid:
                continue
            kind = D._kind(m)
            power = {"anchor": "members", "group": "includes", "rule": "rules"}[kind]
            status = D.membership_status(doc, m, now)
            rows.append({"membership_id": m["membership_id"], "kind": kind,
                         "member": m["member"].get("anchor") or m["member"].get("group") or m["member"]["rule"]["attribute"],
                         "member_name": self._name(doc, m["member"].get("anchor")), "by": m["by"],
                         "by_name": self._name(doc, m["by"]), "under": m["under"],
                         "chain": [d["delegation_id"] for d in D.chain(doc, m["under"])] + ["root"] if m["under"] != "root" else ["root"],
                         "approved_by": m.get("approved_by", []), "start": _iso(m["start"]), "end": _iso(m["end"]),
                         "status": status, "can_end": power in mine and status in ("active", "pending", "standby", "invalid")})
        members = sorted(D.effective_members(doc, gid, now))
        managers = []
        for d in doc.get("delegations", []):
            if D.covers(doc, d["group"], gid) and D.place_covers(doc, d, gid):
                st = D.chain_status(doc, d["delegation_id"], now)[0]
                managers.append({"anchor": d["delegate"], "name": self._name(doc, d["delegate"]),
                                 "delegation_id": d["delegation_id"], "over": d["group"], "powers": d["powers"],
                                 "status": st, "chain": [x["delegation_id"] for x in D.chain(doc, d["delegation_id"])] + ["root"]})
        root = D.root_at(doc, now)
        return {"group_id": gid, "parent": g.get("parent"), "ancestors": D.ancestors(doc, gid)[1:],
                "children": [x["group_id"] for x in doc.get("groups", []) if x.get("parent") == gid],
                "max_risk": g["max_risk"], "effective_risk": D.effective_risk(doc, gid), "place": g.get("place"),
                "description": g.get("description"), "carries": [c["entitlement"] for c in g.get("carries", [])],
                "included_by": sorted(D._includers(doc, gid)), "memberships": rows,
                "effective_members": [{"anchor": x, "name": self._name(doc, x),
                                       "paths": D.explain(doc, x, gid, now),
                                       "in_broker": (D.GROUP_PREFIX + gid, x) in obs if obs else None} for x in members],
                "managers": [{"anchor": root, "name": self._name(doc, root), "delegation_id": "root", "over": "everything",
                              "powers": sorted(D.POWERS), "status": "ok", "chain": ["root"]}] + managers,
                "my_powers": mine}

    def _delegation_view(self, doc: dict, d: dict, now: datetime, actor: str | None) -> dict:
        st, until = D.chain_status(doc, d["delegation_id"], now)
        above = {x["delegate"] for x in D.chain(doc, d["delegation_id"])[1:]} | {d["by"]}
        can = bool(actor) and st != "dead" and (D.same(doc, actor, D.root_at(doc, now)) or any(D.same(doc, actor, x) for x in above)
                                                or D.same(doc, actor, d["delegate"]))
        return {"delegation_id": d["delegation_id"], "delegate": d["delegate"], "delegate_name": self._name(doc, d["delegate"]),
                "group": d["group"], "powers": d["powers"], "max_risk": d["max_risk"],
                "max_membership_days": d["max_membership_days"], "depth_left": d["depth_left"], "place": d.get("place"),
                "start": _iso(d["start"]), "end": _iso(d["end"]), "by": d["by"], "by_name": self._name(doc, d["by"]),
                "parent": d["parent"], "approved_by": d.get("approved_by", []), "status": st, "grace_until": _iso(until),
                "chain": [x["delegation_id"] for x in D.chain(doc, d["delegation_id"])] + ["root"],
                "can_end": can, "impact": D.impact(doc, d["delegation_id"], now)}

    def delegations(self, who: dict) -> list[dict]:
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        sc = self._scope(doc, who, now)
        return [self._delegation_view(doc, d, now, who.get("anchor")) for d in doc.get("delegations", [])
                if sc["all"] or d["delegation_id"] in sc["delegations"]]

    def person(self, who: dict, anchor: str) -> dict:
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        anchor = self._anchor(anchor, "anchor")
        if not (self._viewer(who) or D.same(doc, who.get("anchor"), anchor)
                or D.same(doc, who.get("anchor"), D.root_at(doc, now))):        # before the lookup: no existence oracle
            raise PermissionError("you may see your own access; a viewer or the root sees everyone's")
        p = self._person(doc, anchor)
        if p is None:
            raise LookupError("that person is not in the records")
        groups = [{"group": g["group_id"], "paths": D.explain(doc, anchor, g["group_id"], now)}
                  for g in doc.get("groups", []) if anchor in D.effective_members(doc, g["group_id"], now)]
        ents = D.effective_entitlements(doc, anchor, now)
        return {"anchor": anchor, "person": p["person"], "kind": p["kind"], "groups": groups,
                "entitlements": [{"entitlement": k, "via": sorted(set(v))} for k, v in sorted(ents.items())],
                "delegations": [self._delegation_view(doc, d, now, who.get("anchor")) for d in doc.get("delegations", [])
                                if D.same(doc, d["delegate"], anchor)]}

    def person_graph(self, who: dict, anchor: str, at: str | None = None) -> dict:
        """One person's graph at a moment (decision 0009): what view.rego lets this viewer see. Every look is logged."""
        from keyclerk import graph, policy_wasm
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        anchor = self._anchor(anchor, "anchor")
        t = now if at in (None, "") else guard.timestamp(at)
        if abs((t - now).total_seconds()) > 5 * 366 * 86400:
            raise Refusal("pick a moment within five years of today")
        g = graph.build(doc, anchor, t)
        sc = self._scope(doc, who, now)
        a = who.get("anchor")
        mine_places = sorted({pl["place_id"] for pl in doc.get("places", [])
                              if any(D.same(doc, a, x) for x in [pl.get("steward"), pl.get("deputy"), *(pl.get("front_office") or [])])}) if a else []
        viewer = {"all": bool(sc["all"]), "self": bool(a) and D.same(doc, a, anchor),
                  "tree": sorted(sc.get("manage", set())), "delegations": sorted(sc.get("delegations", set())),
                  "places": mine_places}
        known = self._person(doc, anchor) is not None
        dec = policy_wasm.view(viewer, g["facts"] if known else {"groups": [], "delegations": [], "places": []},
                               [{"id": n["id"], "kind": n["kind"], "contexts": n["contexts"]} for n in g["nodes"]])
        if not dec["subject"]:                    # the same answer for unknown and not yours: no existence oracle
            raise PermissionError("you may see people in groups you manage, in your chain of delegations or at places "
                                  "you look after; a viewer or the root sees everyone")
        if not known:
            raise LookupError("that person is not in the records")
        keep = set(dec["nodes"])
        nodes = [{k: v for k, v in n.items() if k != "contexts"} for n in g["nodes"] if n["id"] in keep]
        edges = [{k: v for k, v in e.items() if k != "contexts"} for e in g["edges"]
                 if e["source"] in keep and e["target"] in keep]
        self.store.log_view({"at": now, "viewer": a or "viewer-role", "subject": anchor, "moment": t,
                             "nodes": len(nodes)})
        return {"subject": anchor, "at": g["at"], "nodes": nodes, "edges": edges, "marks": g["marks"],
                "realm_sources": graph.realm_sources(doc) if dec["realm"] else None}

    def delegation_tree(self, who: dict, at: str | None = None) -> dict:
        """The delegation tree at a moment (decision 0009): what tree.rego lets this viewer see. A viewer and the root
        see all of it; anyone else what they hold or held, below it and the chain above it. Every look is logged."""
        from keyclerk import graph, policy_wasm
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        t = now if at in (None, "") else guard.timestamp(at)
        if abs((t - now).total_seconds()) > 5 * 366 * 86400:
            raise Refusal("pick a moment within five years of today")
        g = graph.delegation_tree(doc, t)
        a = who.get("anchor")
        held = sorted(d["delegation_id"] for d in doc.get("delegations", []) if a and D.same(doc, a, d["delegate"]))
        dec = policy_wasm.tree({"all": bool(self._scope(doc, who, now)["all"]), "held": held},
                               [{"id": n["id"], "chain": n["chain"]} for n in g["nodes"]])
        keep = set(dec["nodes"])
        nodes = [{k: v for k, v in n.items() if k != "chain"} for n in g["nodes"] if n["id"] in keep]
        edges = [e for e in g["edges"] if e["source"] in keep and e["target"] in keep]
        self.store.log_view({"at": now, "viewer": a or "viewer-role", "subject": "delegation-tree", "moment": t,
                             "nodes": len(nodes)})
        return {"at": g["at"], "nodes": nodes, "edges": edges, "marks": g["marks"], "whole": dec["whole"],
                "held": [d for d in held if d in keep]}

    # --- visits (decision 0009) -----------------------------------------------------------------------------------
    # visits.rego decides who may act, entry at a checkpoint, which timer steps are due and who may see a visit; the
    # desk gathers the facts, builds the records and runs the timer tick.

    def _plate_key(self) -> bytes:
        """The key plates are digested with: kept in the store, never in the records (a plate is not written down)."""
        f = self.store.path / "plate.key"
        if not f.exists():
            f.write_text(os.urandom(32).hex(), encoding="utf-8")
        return bytes.fromhex(f.read_text(encoding="utf-8").strip())

    def _place_staff(self, doc: dict, place: str, anchor: str | None) -> tuple[bool, bool]:
        from keyclerk import visits as V
        return V.place_staff(doc, place, anchor)

    def _badge_key(self) -> bytes:
        """The key badge numbers are digested with: kept in the store, never in the records."""
        f = self.store.path / "badge.key"
        if not f.exists():
            f.write_text(os.urandom(32).hex(), encoding="utf-8")
        return bytes.fromhex(f.read_text(encoding="utf-8").strip())

    def _visit_actor(self, doc: dict, v: dict, anchor: str | None) -> dict:
        from keyclerk import visits as V
        fo, st = self._place_staff(doc, v["place"], anchor)
        people = V.attendees(doc, v)
        return {"anchor": anchor, "is_host": bool(anchor) and D.same(doc, anchor, v["host"]),
                "is_organiser": bool(anchor) and D.same(doc, anchor, v["organiser"]), "front_office": fo, "steward": st,
                "is_party": bool(anchor) and any(D.same(doc, anchor, p.get("anchor")) for p in people),
                "is_escort": bool(anchor) and any(D.same(doc, anchor, x) for x in V.escorts_of(v) + [p.get("escort") for p in people] if x)}

    def _may_act_on_visit(self, doc: dict, action: str, v: dict, actor: str) -> None:
        from keyclerk import policy_wasm
        host = self._person(doc, v["host"]) or {}
        dec = policy_wasm.visits("act", {"action": action, "actor": self._visit_actor(doc, v, actor),
                                         "visit": {"host_kind": host.get("kind")}})
        if not dec["allow"]:
            staff = action in ("record_entry", "record_departure", "issue_badge", "return_badge", "register_on_site")
            byid = {x["place_id"]: x for x in doc.get("places", [])}
            fo = [a for pid in [v["place"], (byid.get(v["place"]) or {}).get("within")] for a in (byid.get(pid) or {}).get("front_office") or []]
            raise Refusal("; ".join(dec["reasons"]), [
                {"why": "the front office of the place does this" if staff
                 else "the host, the organiser or an escort of the visit does this",
                 "do": "ask them to record it on this desk", "who": self._who(doc, fo if staff else [v["host"], v["organiser"]])}])

    def _visit_of(self, doc: dict, body: dict) -> tuple[dict, dict]:
        from keyclerk import visits as V
        v = V.visit(doc, guard.ident(body.get("visit_id"), "visit"))
        if v is None:
            raise Refusal("there is no such visit")
        p = V.party(doc, v, guard.ident(body.get("party"), "party"))
        if p is None:
            raise Refusal(f"{v['visit_id']} has no attendee {body.get('party')}")
        return v, p

    def _visit_event(self, doc: dict, v: dict, p: dict | None, kind: str, actor: str, now: datetime, **extra) -> dict:
        rec = {"event_id": self._next_id(doc, "visit_events", "VE", "event_id", self._reserved()), "visit_id": v["visit_id"],
               "kind": kind, "at": now, "by": actor, **{k: x for k, x in extra.items() if x is not None}}
        if p is not None:
            rec["party"] = p["party"]
        return rec

    def _party_name(self, doc: dict, p: dict) -> str:
        if "anchor" in p:
            return self._name(doc, p["anchor"]) or p["anchor"]
        return p.get("name") or p.get("label") or "unregistered guest"

    def _attendee(self, doc: dict, x, i: int, opens: datetime, closes: datetime) -> dict:
        """One attendee from a request: a registered person (anchor), someone invited by name, or an unregistered
        companion (a label)."""
        if not isinstance(x, dict):
            raise Refusal(f"attendee {i}: an anchor, a name or unregistered with a label")
        if x.get("anchor"):
            a = {"state": "registered", "anchor": self._anchor(x["anchor"], "attendee")}
            if self._person(doc, a["anchor"]) is None:
                raise Refusal(f"attendee {i} is not in the records: invite them by name, or add them as unregistered")
        elif x.get("unregistered"):
            a = {"state": "unregistered", "label": guard.text(x.get("label") or f"companion {i}", "label", 60)}
        elif x.get("name"):
            a = {"state": "invited", "name": guard.text(x["name"], "name", 80)}
        else:
            raise Refusal(f"attendee {i}: an anchor, a name or unregistered with a label")
        if x.get("organisation"):
            a["organisation"] = guard.text(x["organisation"], "organisation", 80)
        if x.get("expected"):
            t = guard.timestamp(x["expected"])
            if not opens <= t < closes:
                raise Refusal(f"attendee {i}: expected inside the visit window")
            a["expected"] = t
        if x.get("escort"):
            a["escort"] = self._anchor(x["escort"], "escort")
            if self._person(doc, a["escort"]) is None:
                raise Refusal(f"attendee {i}: the escort is not in the records")
        kit = []
        for k in (x.get("kit") or [])[:20]:
            c = k.get("count", 1) if isinstance(k, dict) else None
            if not isinstance(c, int) or isinstance(c, bool):
                raise Refusal(f"attendee {i}: kit is a class and a whole number")
            item = {"class": guard.text(k.get("class", ""), "kit class", 40), "count": c}
            if k.get("note"):
                item["note"] = guard.text(k["note"], "note", 80)
            kit.append(item)
        if kit:
            a["kit"] = kit
        return a

    def _build_visit(self, doc: dict, actor: str, body: dict, now: datetime) -> tuple[dict, str]:
        from keyclerk import policy_wasm
        from keyclerk import visits as V
        action = body["action"]
        if action == "register_visit":
            place = guard.text(body.get("place", ""), "place", 120)
            if place not in {p["place_id"] for p in doc.get("places", [])}:
                raise Refusal(f"there is no place {place}")
            host = self._anchor(body.get("host") or actor, "host")
            organiser = self._anchor(body.get("organiser") or actor, "organiser")
            escorts = [self._anchor(x, "escort") for x in (body.get("escorts") or [])[:20]]
            for a, what in [(host, "host"), (organiser, "organiser")] + [(x, "escort") for x in escorts]:
                if self._person(doc, a) is None:
                    raise Refusal(f"the {what} is not in the records")
            start, end = guard.timestamp(body.get("start")), guard.timestamp(body.get("end"))
            if not start < end or end <= now or start > now + timedelta(days=366):
                raise Refusal("the meeting starts before it ends, ends in the future and starts within a year")
            opens, closes = V.window(start, end)
            raw = body.get("attendees")
            if not isinstance(raw, list) or not raw:
                raise Refusal("name who comes: registered people, people invited by name, unregistered companions")
            people = []
            for i, x in enumerate(raw[:V.rules()["max_parties"]], 1):
                people.append({"party": f"P{i}", **self._attendee(doc, x, i, opens, closes)})
            ids = {str(i): a["party"] for i, a in enumerate(people, 1)} | {a["party"]: a["party"] for a in people}
            vehicles = []
            for i, x in enumerate((body.get("vehicles") or [])[:10], 1):
                try:
                    digest, tail = V.plate_digest(self._plate_key(), guard.text(x.get("plate", ""), "plate", 20))
                except ValueError as e:
                    raise Refusal(f"vehicle {i}: a plate has {e}") from None
                rec = {"vehicle": f"K{i}", "plate_digest": digest, "plate_tail": tail}
                if x.get("driver") is not None:
                    rec["driver"] = ids.get(str(x["driver"]), str(x["driver"]))
                for f, n in (("make", 40), ("model", 40), ("colour", 30)):
                    if x.get(f):
                        rec[f] = guard.text(x[f], f, n)
                vehicles.append(rec)
            zones = [guard.text(z, "zone", 120) for z in (body.get("zones") or [])[:10]]
            v = {"visit_id": self._next_id(doc, "visits", "V", "visit_id", self._reserved()), "place": place,
                 "host": host, "organiser": organiser, "purpose": guard.text(body.get("purpose", ""), "purpose", 300),
                 "start": start, "end": end, "opens": opens, "closes": closes, "attendees": people, "by": actor, "at": now}
            if escorts:
                v["escorts"] = escorts
            if zones:
                v["zones"] = zones
            if vehicles:
                v["vehicles"] = vehicles
            dlg = body.get("delegation")
            if isinstance(dlg, dict) and dlg.get("name"):
                v["delegation"] = {"name": guard.text(dlg["name"], "delegation", 80),
                                   **({"organisation": guard.text(dlg["organisation"], "organisation", 80)} if dlg.get("organisation") else {}),
                                   **({"contact": guard.text(dlg["contact"], "contact", 120)} if dlg.get("contact") else {})}
            self._may_act_on_visit(doc, action, v, actor)
            codes, extra = [], {**doc, "visits": doc.get("visits", []) + [v]}
            for p in people:                        # each registered guest gets a code (serial 1), kept as a digest
                if V.registered(p):
                    codes.append(self._visit_event({**extra, "visit_events": extra.get("visit_events", []) + codes}, v, p,
                                                   "qr-issued", actor, now, serial=1, qr=self._code_digest(v, p["party"], 1)))
            add = {"visits": [v]}
            if codes:
                add["visit_events"] = codes
            return add, f"register a visit to {place} hosted by {self._name(doc, host)} ({len(people)} attendees)"
        if action == "return_badge":
            bid = guard.ident(body.get("badge_id"), "badge")
            b = next((x for x in doc.get("badges", []) if x["badge_id"] == bid), None)
            if b is None:
                raise Refusal("there is no such badge")
            v = V.visit(doc, b["visit_id"])
            self._may_act_on_visit(doc, action, v, actor)
            if V.returned(doc, b) is not None:
                raise Refusal("that badge was already returned")
            ev = self._visit_event(doc, v, V.party(doc, v, b["party"]), "badge-returned", actor, now, badge=bid)
            return {"visit_events": [ev]}, f"badge {b['kind']} ...{b['badge_tail']} returned"
        if action == "add_attendee":
            v = V.visit(doc, guard.ident(body.get("visit_id"), "visit"))
            if v is None:
                raise Refusal("there is no such visit")
            self._may_act_on_visit(doc, action, v, actor)
            if V.ended(v, now):
                raise Refusal("the visit has closed")
            if len(V.attendees(doc, v)) >= V.rules()["max_parties"]:
                raise Refusal(f"a visit has at most {V.rules()['max_parties']} attendees")
            a = self._attendee(doc, body.get("attendee"), 1, V._ts(v["opens"]), V._ts(v["closes"]))
            pid = V.next_party(doc, v)
            ev = self._visit_event(doc, v, {"party": pid}, "attendee-added", actor, now, attendee=a)
            add = [ev]
            if V.registered(a):
                code = self._code_digest(v, pid, 1)
                add.append(self._visit_event({**doc, "visit_events": doc.get("visit_events", []) + [ev]}, v, {"party": pid},
                                             "qr-issued", actor, now, serial=1, qr=code))
            return {"visit_events": add}, f"add {self._party_name(doc, a)} to {v['visit_id']}"
        code = None
        if action == "record_entry" and body.get("token"):        # the scanned code names the visit and the attendee
            pl = qr_mod.read(str(body["token"]))
            if pl is None:
                raise Refusal("this is not a KeyClerk visit code")
            body = {**body, "visit_id": pl["v"], "party": pl["p"], "presented": body.get("presented") or "qr"}
            code = str(body["token"])
        v, p = self._visit_of(doc, body)
        self._may_act_on_visit(doc, action, v, actor)
        st = V.state(doc, v, p["party"], now)
        who = self._party_name(doc, p)
        if action == "register_on_site":
            if V.registered(p):
                raise Refusal(f"{who} is registered already")
            anchor = self._anchor(body.get("anchor"), "anchor")
            if self._person(doc, anchor) is None:
                raise Refusal("that person is not in the records yet: they self-register first (a phone at the front "
                              "office will do), then the front office links them here")
            ev = self._visit_event(doc, v, p, "registered-on-site", actor, now, anchor=anchor)
            qr = self._visit_event({**doc, "visit_events": doc.get("visit_events", []) + [ev]}, v, p, "qr-issued", actor,
                                   now, serial=V.qr_serial(doc, v, p["party"]) + 1,
                                   qr=self._code_digest(v, p["party"], V.qr_serial(doc, v, p["party"]) + 1))
            return {"visit_events": [ev, qr]}, f"{who} registered at the front office as {self._name(doc, anchor)}"
        if action == "issue_badge":
            kind = body.get("kind")
            if kind not in V.BADGES:
                raise Refusal("kind: visitor or restricted")
            try:
                digest, tail = V.plate_digest(self._badge_key(), guard.text(body.get("badge", ""), "badge number", 40))
            except ValueError:
                raise Refusal("the badge number as printed on it: 2 to 12 letters and digits") from None
            until = min(V._ts(v["closes"]), guard.timestamp(body["until"]) if body.get("until") else V._ts(v["closes"]))
            b = {"badge_id": self._next_id(doc, "badges", "B", "badge_id", self._reserved()), "visit_id": v["visit_id"],
                 "party": p["party"], "kind": kind, "badge_digest": digest, "badge_tail": tail, "issued_by": actor,
                 "approved_by": [], "from": max(now, V._ts(v["opens"])), "to": until}
            if any(x["kind"] == kind and V.returned(doc, x, now) is None and V._ts(x["to"]) > now
                   for x in V.badges_of(doc, v["visit_id"], p["party"])):
                raise Refusal(f"{who} already holds a {kind} badge: take it back first")
            return {"badges": [b]}, f"a {kind.upper() if kind == 'restricted' else kind} badge ...{tail} for {who}"
        if action == "issue_qr":
            if not V.registered(p):
                raise Refusal("someone without an identity gets no code: they are signed in at the front office")
            if V.ended(v, now):
                raise Refusal("the visit has closed")
            n = V.qr_serial(doc, v, p["party"]) + 1
            ev = self._visit_event(doc, v, p, "qr-issued", actor, now, serial=n, qr=self._code_digest(v, p["party"], n))
            return {"visit_events": [ev]}, f"a new QR code for {who} (the old one stops working)"
        if action == "record_entry":
            presented = body.get("presented", "none")
            if presented not in V.PRESENTED:
                raise Refusal(f"presented: one of {', '.join(V.PRESENTED)}")
            zone = body.get("zone") or None
            if zone is not None and zone not in {z["zone_id"] for z in doc.get("zones", [])}:
                raise Refusal(f"there is no zone {zone}")
            qr = {"required": bool(V.rules()["qr_required"]), "valid": False, "problem": "no code was presented"}
            if code is not None:
                problem = self._code_problem(doc, code, now)
                qr.update(valid=not problem, problem=problem)
            vid_, vdig, vtail = None, None, None              # the vehicle they drive in: announced, or typed at the gate
            if body.get("vehicle_id"):
                vid_ = guard.ident(body["vehicle_id"], "vehicle")
                if not any(k["vehicle"] == vid_ for k in V.vehicles(v)):
                    raise Refusal(f"{v['visit_id']} announced no vehicle {vid_}")
            elif body.get("plate"):
                try:
                    vdig, vtail = V.plate_digest(self._plate_key(), guard.text(body["plate"], "plate", 20))
                except ValueError as e:
                    raise Refusal(f"a plate has {e}") from None
            driving = bool(body.get("vehicle")) or bool(vid_ or vdig)
            if driving and not (vid_ or vdig):                # the vehicle announced with this driver, when there is one
                own = [k["vehicle"] for k in V.vehicles(v) if k.get("driver") == p["party"]]
                vid_ = own[0] if len(own) == 1 else None
            dec = policy_wasm.visits("entry", V.entry_input(doc, v, p["party"], now, zone, presented, driving,
                                                            qr if presented == "qr" else None))
            if not dec["allow"]:
                steps = []
                if dec["front_office"]:
                    steps.append({"why": f"{who} needs " + (f"a {dec['badge']} badge" if dec["badge"] else "to be identified"),
                                  "do": "go to the front office" + (f" for a {dec['badge']} badge" if dec["badge"] else "")
                                  + "; it records the entry again", "who": []})
                raise Refusal(f"{who} may not enter: " + "; ".join(dec["reasons"]), steps)
            first = st["arrived"] is None
            ev = self._visit_event(doc, v, p, "arrived" if first else "entered", actor, now,
                                   checkpoint=guard.text(body["checkpoint"], "checkpoint", 80) if body.get("checkpoint") else None,
                                   zone=zone, presented=presented, vehicle=driving or None, vehicle_id=vid_,
                                   vehicle_digest=vdig, vehicle_tail=vtail,
                                   notify=sorted({v["host"], v["organiser"], *([p["escort"]] if p.get("escort") else [])}) if first else None,
                                   reason="escorted, temporary visitor badge" if dec["escort"] else None)
            return {"visit_events": [ev]}, f"{'arrival' if first else 'entry'} of {who} on {v['visit_id']}"
        if st["arrived"] is None:
            raise Refusal(f"{who} has not arrived yet")
        if action == "acknowledge_arrival":
            if st["acknowledged"]:
                raise Refusal("already acknowledged")
            return {"visit_events": [self._visit_event(doc, v, p, "acknowledged", actor, now)]}, f"acknowledge {who}'s arrival"
        if action == "confirm_guest":
            if st["confirmed"]:
                raise Refusal("already confirmed")
            if st["suspended"] or st["departed"]:
                raise Refusal("too late to confirm: the front office decides what happens next")
            return {"visit_events": [self._visit_event(doc, v, p, "confirmed", actor, now)]}, f"confirm {who} is with the host"
        # record_departure
        if st["departed"]:
            raise Refusal("already left")
        return {"visit_events": [self._visit_event(doc, v, p, "left", actor, now)]}, f"departure of {who} from {v['visit_id']}"

    def _qr(self):
        from keyclerk.qr import QrKey
        if getattr(self, "_qr_key", None) is None:
            self._qr_key = QrKey(self.store.path)
        return self._qr_key

    def _code(self, v: dict, pid: str, serial: int) -> str:
        """A party's code with this serial: signatures are deterministic, so it is made again, never stored."""
        from keyclerk import visits as V
        return self._qr().sign(v["visit_id"], pid, serial, V._epoch(v["closes"]))

    def _code_digest(self, v: dict, pid: str, serial: int) -> str:
        return qr_mod.digest(self._code(v, pid, serial))

    def _code_problem(self, doc: dict, token: str, now: datetime) -> str:
        """Why a code does not count now (online: signature, expiry, the latest serial for a registered party), or ""."""
        from keyclerk import visits as V
        pl, why = qr_mod.verify(self._qr().public, token, int(now.timestamp()))
        if pl is None:
            return why
        v = V.visit(doc, pl["v"])
        p = V.party(doc, v, pl["p"]) if v else None
        if not V.registered(p):
            return "the code names no registered guest of a known visit"
        if pl["n"] != V.qr_serial(doc, v, p["party"], now):
            return "a newer code was issued; this one no longer works"
        return ""

    def visit_qr(self, who: dict, vid: str, pid: str) -> dict:
        """A guest's current QR code, for the guest themselves, the host or the organiser: the code, the link it opens
        and the image. Every look is logged."""
        import base64
        import io
        import segno
        from keyclerk import visits as V
        doc, now = self.store.load(), self.clock()
        actor = self._actor(doc, who)
        v = V.visit(doc, guard.ident(vid, "visit"))
        p = V.party(doc, v, guard.ident(pid, "party")) if v else None
        if v is None or p is None or not self._sees_visit(doc, who, v, now):
            raise PermissionError("you may see the QR code of your own visit, or of a visit you host or organise")
        try:
            self._may_act_on_visit(doc, "issue_qr", v, actor)
        except Refusal:
            raise PermissionError("a guest's code is for the guest themselves, the host and the organiser") from None
        n = V.qr_serial(doc, v, p["party"], now)
        if n == 0:
            raise Refusal("no code was issued for this party", [{"why": "an unregistered passenger gets no code",
                                                                  "do": "they are signed in at the front office", "who": []}])
        token = self._code(v, p["party"], n)
        url = f"{self.public_base}/#/scan/{token}"
        buf = io.BytesIO()
        segno.make(url, error="m").save(buf, kind="svg", scale=5, border=2, dark="#1F0E36", light="#ffffff", xmldecl=False)
        self.store.log_view({"at": now, "viewer": actor, "subject": f"{v['visit_id']}/{p['party']} qr", "moment": now, "nodes": 1})
        return {"visit_id": v["visit_id"], "party": p["party"], "serial": n, "until": _iso(V._ts(v["closes"])),
                "token": token, "url": url, "image": "data:image/svg+xml;base64," + base64.b64encode(buf.getvalue()).decode()}

    def qr_key(self) -> dict:
        """The public half of the QR key, for checkpoints that check codes offline (signature and expiry only)."""
        return self._qr().published()

    def scan(self, token: str) -> dict:
        """What anyone who scans a guest's code with a phone learns: yes or no, and until when; checked online now,
        decided by visits.rego (unescorted). Nothing else: no name, no purpose, no host. Every scan is logged."""
        from keyclerk import policy_wasm
        from keyclerk import visits as V
        doc, now = self.store.load(), self.clock()
        pl = qr_mod.read(token)
        problem = self._code_problem(doc, token, now) if pl else "not a code"
        v = V.visit(doc, pl["v"]) if pl else None
        p = V.party(doc, v, pl["p"]) if v else None
        if v is None or p is None:
            dec = {"unescorted": False, "until": None}
        else:
            st = V.state(doc, v, p["party"], now)
            dec = policy_wasm.visits("unescorted", {
                "now": int(now.timestamp()), "code": {"valid": not problem},
                "visit": {"opens": V._epoch(v["opens"]), "closes": V._epoch(v["closes"])},
                "party": {"registered": V.registered(p), "arrived": st["arrived"] is not None, "suspended": st["suspended"],
                          "departed": st["departed"]}})
        self.store.log_view({"at": now, "viewer": "phone-scan", "subject": f"{pl['v']}/{pl['p']}" if pl else "not a code",
                             "moment": now, "nodes": int(bool(dec["unescorted"]))})
        until = dec.get("until")
        return {"unescorted": bool(dec["unescorted"]), "checked": "online", "at": _iso(now),
                "until": _iso(datetime.fromtimestamp(until, timezone.utc)) if until else None}

    def tick(self) -> list[dict]:
        try:
            self.edge_silence()
        except Exception as e:   # noqa: BLE001 - the visit timers still run
            sys.stderr.write(f"keyclerk.desk: edge silence check: {type(e).__name__}\n")
        return self._tick_visits()

    def _tick_visits(self) -> list[dict]:
        """The visit timers: the steps visits.rego finds due now (a reminder, then a suspension that is flagged for the
        officer), each re-checking its reason; written as events by the engine's own schedule."""
        from keyclerk import policy_wasm
        from keyclerk import visits as V
        with self.lock:
            doc, now = self.store.load(), self.clock()
            self._erase_expired(doc, now)
            doc = self.store.load()
            if not doc.get("visits"):
                return []
            due = policy_wasm.visits("timers", V.timer_input(doc, now))
            if not due:
                return []
            recs = []
            for d in due:
                v = V.visit(doc, d["visit_id"])
                p = V.party(doc, v, d["party"])
                ev = self._visit_event({**doc, "visit_events": doc.get("visit_events", []) + recs}, v, p,
                                       "reminded" if d["step"] == "remind" else "suspended", V.TIMER, now, reason=d["reason"],
                                       notify=sorted({v["host"], v["organiser"]} | ({(doc.get("root") or {}).get("officer")}
                                                                                 if d["step"] == "suspend" else set()) - {None}))
                recs.append(ev)
            add = {"visit_events": recs}
            outcome, reasons, cand = self._evaluate(doc, add)
            entry = {"change_id": "C-" + secrets.token_hex(6), "action": "visit_timer",
                     "summary": "; ".join(f"{r['kind']} {r['party']} on {r['visit_id']}" for r in recs), "actor": V.TIMER,
                     "records": _jsonable(add), "outcome": outcome, "reasons": reasons}
            if outcome == "applied":
                self._commit(cand, entry)
            else:                                   # a reminder or a suspension that did not happen: an alarm
                from keyclerk import metrics
                self.store.note(entry)
                metrics.inc("keyclerk_timer_refused_total")
                print(f"visit timers: refused, {guard.safe_for_log('; '.join(reasons), 300)}", flush=True)
            return recs

    def _sees_visit(self, doc: dict, who: dict, v: dict, now: datetime, sees_all: bool | None = None) -> bool:
        from keyclerk import policy_wasm
        a = who.get("anchor")
        if sees_all is None:
            sees_all = bool(self._scope(doc, who, now)["all"])
        facts = {**self._visit_actor(doc, v, a), "all": sees_all}
        return bool(policy_wasm.visits("see", {"viewer": facts}))

    def _visit_summary(self, doc: dict, v: dict, now: datetime, me: str | None) -> dict:
        from keyclerk import visits as V
        people = V.attendees(doc, v, now)
        states = {p["party"]: V.state(doc, v, p["party"], now) for p in people}
        mine = bool(me) and (D.same(doc, me, v["host"]) or D.same(doc, me, v["organiser"]))
        todo = [p for p, s in states.items() if mine and s["arrived"] and not (s["departed"] or s["suspended"])
                and not (s["acknowledged"] and s["confirmed"])]
        when = "upcoming" if now < V._ts(v["opens"]) else "closed" if V.ended(v, now) else "open"
        return {"visit_id": v["visit_id"], "place": v["place"],
                "place_name": next((p.get("name") for p in doc.get("places", []) if p["place_id"] == v["place"]), None) or v["place"],
                "host": v["host"], "host_name": self._name(doc, v["host"]), "organiser": v["organiser"],
                "organiser_name": self._name(doc, v["organiser"]), "purpose": v["purpose"],
                "start": _iso(V._ts(v["start"])), "end": _iso(V._ts(v["end"])), "opens": _iso(V._ts(v["opens"])),
                "closes": _iso(V._ts(v["closes"])), "when": when,
                "parties": len(people), "unregistered": sum(1 for p in people if not V.registered(p)),
                "arrived": sum(1 for s in states.values() if s["arrived"]),
                "delegation": (v.get("delegation") or {}).get("name"),
                "vehicles": [f"{k.get('colour', '')} {k.get('make', '')} {k.get('model', '')} ...{k['plate_tail']}".strip()
                             for k in v.get("vehicles") or []],
                "suspended": sum(1 for s in states.values() if s["suspended"]), "waiting_for_me": len(todo)}

    def visits(self, who: dict) -> list[dict]:
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        sees_all = bool(self._scope(doc, who, now)["all"])          # once per request, not once per visit
        out = [self._visit_summary(doc, v, now, who.get("anchor")) for v in doc.get("visits", [])
               if self._sees_visit(doc, who, v, now, sees_all)]
        return sorted(out, key=lambda x: x["start"], reverse=True)

    def _erase_expired(self, doc: dict, now: datetime) -> list[str]:
        """Visits closed longer ago than visits.retention_days are erased: their files go, the log keeps their ids."""
        from keyclerk import visits as V
        keep = timedelta(days=int(V.rules()["retention_days"]))
        held = set(self.store.visit_ids())
        old = [v["visit_id"] for v in doc.get("visits", []) if v["visit_id"] in held
               and guard.timestamp(v["closes"]) + keep < now if isinstance(v.get("closes"), str)]
        old += [v["visit_id"] for v in doc.get("visits", []) if v["visit_id"] in held
                and isinstance(v.get("closes"), datetime) and v["closes"] + keep < now]
        if old:
            self.store.erase_visits(sorted(set(old)), {
                "change_id": "C-" + secrets.token_hex(6), "action": "visit_erased", "actor": V.TIMER, "outcome": "applied",
                "summary": f"{len(set(old))} visit(s) erased after {keep.days} days", "records": {}, "reasons": []})
        return sorted(set(old))

    def visit_detail(self, who: dict, vid: str, at: str | None = None) -> dict:
        """One visit at a moment: who comes with what, the timeline, each party's state and what the gate would say
        now, and what this person may do on it. Every look is logged."""
        from keyclerk import policy_wasm
        from keyclerk import visits as V
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        t = now if at in (None, "") else guard.timestamp(at)
        v = V.visit(doc, guard.ident(vid, "visit"))
        if v is None or not self._sees_visit(doc, who, v, now):     # the same answer either way: no existence oracle
            raise PermissionError("you may see visits you host or organise, visits to a place whose front office or "
                                  "steward you are, and your own; a viewer or the root sees all")
        a = who.get("anchor")
        kit = {k["class"]: k["name"] for k in V.rules()["kit_classes"]}
        parties = []
        for p in V.attendees(doc, v, t):
            st = V.state(doc, v, p["party"], t)
            shown = [e["presented"] for e in V.events(doc, v["visit_id"], t) if e.get("party") == p["party"] and e.get("presented")]
            serial = V.qr_serial(doc, v, p["party"], t)               # the preview assumes the guest's current code
            gate = policy_wasm.visits("entry", V.entry_input(doc, v, p["party"], t, None,   # as they last showed, or first time
                                                             shown[-1] if shown else ("qr" if V.registered(p) else "none"), False,
                                                             {"required": bool(V.rules()["qr_required"]), "valid": serial > 0,
                                                              "problem": "" if serial else "no code was issued"}))
            acts = [x for x in ("record_entry", "register_on_site", "issue_badge", "acknowledge_arrival", "confirm_guest",
                                "record_departure")
                    if a and self._person(doc, a) is not None
                    and policy_wasm.visits("act", {"action": x, "actor": self._visit_actor(doc, v, a), "visit": {}})["allow"]
                    and (x in ("record_entry", "issue_badge", "register_on_site") or st["arrived"] is not None)
                    and not (x == "register_on_site" and V.registered(p))
                    and not (x == "issue_badge" and (st["suspended"] or st["departed"]))
                    and not (x == "acknowledge_arrival" and st["acknowledged"])
                    and not (x == "confirm_guest" and (st["confirmed"] or st["suspended"] or st["departed"]))
                    and not (x == "record_departure" and st["departed"])]
            arrival = next((e for e in V.events(doc, v["visit_id"], t) if e.get("party") == p["party"] and e["kind"] == "arrived"), None)
            parties.append({"party": p["party"], "state": p["state"], "registered": V.registered(p),
                            "anchor": p.get("anchor"), "name": self._party_name(doc, p), "organisation": p.get("organisation"),
                            "expected": _iso(V._ts(p["expected"])) if p.get("expected") else None,
                            "escort": self._name(doc, p["escort"]) if p.get("escort") else None,
                            "kit": [{"class": i["class"], "name": kit.get(i["class"], i["class"]), "count": i["count"],
                                     "note": i.get("note")} for i in p.get("kit") or []],
                            "came": None if not arrival else "on foot" if not arrival.get("vehicle")
                            else "vehicle " + arrival["vehicle_id"] if arrival.get("vehicle_id")
                            else "vehicle ..." + arrival["vehicle_tail"] if arrival.get("vehicle_tail") else "a vehicle",
                            "arrived": _iso(st["arrived"]) if st["arrived"] else None,
                            **{k: st[k] for k in ("acknowledged", "confirmed", "suspended", "departed")},
                            "gate": gate, "last_presented": shown[-1] if shown else None, "actions": acts if t == now else [],
                            "qr": V.qr_serial(doc, v, p["party"], t) > 0 and t == now and bool(a)
                            and policy_wasm.visits("act", {"action": "issue_qr", "actor": self._visit_actor(doc, v, a),
                                                           "visit": {}})["allow"]})
        line = []
        for x in V.timeline(doc, v, t):
            item = {k: (_iso(V._ts(val)) if k == "at" else val) for k, val in x.items()
                    if k in ("at", "kind", "party", "text", "by", "checkpoint", "zone", "presented", "vehicle", "notify",
                             "vehicle_id", "vehicle_tail")}
            if "by" in item:
                item["by_name"] = "timer" if item["by"] == V.TIMER else self._name(doc, item["by"])
            line.append(item)
        self.store.log_view({"at": now, "viewer": a or "viewer-role", "subject": v["visit_id"], "moment": t,
                             "nodes": len(parties)})
        return {**self._visit_summary(doc, v, t, a), "at": _iso(t), "zones": v.get("zones") or [],
                "escorts": [self._name(doc, x) or x for x in V.escorts_of(v)], "delegation_detail": v.get("delegation"),
                "may_add": t == now and bool(a) and self._person(doc, a) is not None
                and policy_wasm.visits("act", {"action": "add_attendee", "actor": self._visit_actor(doc, v, a), "visit": {}})["allow"],
                "parties": parties, "vehicles_detail": [{**{k: x.get(k) for k in ("vehicle", "make", "model", "colour", "plate_tail")},
                                                         "driver": next((q["name"] for q in parties if q["party"] == x.get("driver")), None)}
                                                        for x in V.vehicles(v)],
                "kit": [{**i, "with": q["name"]} for q in parties for i in q["kit"]],
                "timeline": line,
                "badges": [{"badge_id": b["badge_id"], "party": b["party"],
                            "holder": next((q["name"] for q in parties if q["party"] == b["party"]), b["party"]),
                            "kind": b["kind"], "tail": b["badge_tail"], "issued_by": self._name(doc, b["issued_by"]),
                            "second": [self._name(doc, x) for x in b.get("approved_by") or []],
                            "from": _iso(V._ts(b["from"])), "to": _iso(V._ts(b["to"])),
                            "returned": _iso(V.returned(doc, b, t)) if V.returned(doc, b, t) else None,
                            "may_return": t == now and V.returned(doc, b, t) is None and bool(a)
                            and policy_wasm.visits("act", {"action": "return_badge", "actor": self._visit_actor(doc, v, a),
                                                           "visit": {}})["allow"]}
                           for b in V.badges_of(doc, v["visit_id"])]}

    def changes(self, who: dict) -> dict:
        doc, now = self.store.load(), self.clock()
        self._may_read(doc, who)
        a = who.get("anchor")
        sc = self._scope(doc, who, now)
        pend, refresh = [], 3
        for cid, p in sorted(self.store.pending().items(), key=lambda kv: kv[1]["at"])[:MAX_PENDING]:
            gave = bool(a) and any(D.same(doc, a, x) for x in p.get("approvals", []))
            if not (sc["all"] or gave or self._sees_entry(doc, sc, p) or (bool(a) and self._counts_cached(doc, a, cid, p))):
                continue
            expired = guard.timestamp(p["at"]) < now - timedelta(days=PENDING_DAYS)
            mine = bool(a) and D.same(doc, a, p["actor"])
            given = bool(a) and any(D.same(doc, a, x) for x in p.get("approvals", []))
            if p.get("waiting_rev") != self.store.revision() and refresh > 0 and self.lock.acquire(blocking=False):
                try:                                       # a few stale answers refreshed per request, never all at once
                    refresh -= 1
                    p["waiting_for"] = self._approvers(doc, p["records"], p.get("approvals", []), p["actor"])
                    p["waiting_rev"] = self.store.revision()
                    stored = self.store.pending()
                    if cid in stored:
                        stored[cid].update(waiting_for=p["waiting_for"], waiting_rev=p["waiting_rev"])
                        self.store.save_pending(stored)
                finally:
                    self.lock.release()
            groups = {r.get("group") for kind in ("memberships", "delegations") for r in p["records"].get(kind, [])}
            waiting = list(p.get("waiting_for") or [])
            shown = sc["all"] or bool(a) and (D.same(doc, a, p["actor"]) or any(D.same(doc, a, x) for x in waiting)
                                              or bool(groups & sc.get("manage", set()))
                                              or self._counts_cached(doc, a, cid, p))    # capped list: ask the engine
            pend.append({"change_id": cid, "summary": p["summary"], "action": p["action"], "actor": p["actor"],
                         "waiting_for": self._who(doc, waiting) if shown else [],
                         "needs": list(dict.fromkeys(remedies.match(r)[0] for r in p["reasons"]))[:5],
                         "actor_name": self._name(doc, p["actor"]), "at": p["at"], "reasons": p["reasons"],
                         "expired": expired, "approvals": p.get("approvals", []),
                         "what": self._what(doc, p["records"]),
                         "approval_names": [self._name(doc, x) for x in p.get("approvals", [])],
                         "can_approve": bool(a) and not mine and not given and not expired and self._counts_cached(doc, a, cid, p),
                         "can_sign": mine and bool(p.get("needs_proposer")) and not expired,
                         "can_withdraw": mine or (bool(a) and D.same(doc, a, D.root_at(doc, now)))})
        log = [{**e, "actor_name": self._name(doc, e.get("actor")), "approver_name": self._name(doc, e.get("approved_by"))}
               for e in reversed(self.store.log()) if self._sees_entry(doc, sc, e)]
        return {"pending": pend, "log": log}

    def _counts(self, doc: dict, approver: str, p: dict) -> bool:
        """Whether this person's approval would complete the change or add one of the keys it still needs."""
        if self._person(doc, approver) is None:
            return False
        given = p.get("approvals", [])
        outcome, reasons, _ = self._evaluate(doc, self._with_approvals(p["records"], [*given, approver]))
        if outcome == "applied":
            return True
        # a key that does not count only adds "...; X does not count: why" to the same reason: that is no progress
        norm = lambda rs: {re.sub(r"; [^;]*? does not count: .*$", "", r) for r in rs}   # noqa: E731
        before = norm(self._evaluate(doc, self._with_approvals(p["records"], given))[1])
        return outcome == "pending" and bool(before - norm(reasons))

    def broker(self, who: dict) -> dict:
        doc = self.store.load()
        self._may_read(doc, who)
        sc = self._scope(doc, who, self.clock())
        if not sc["all"] and not sc["manage"]:
            raise PermissionError("the reconciler's runs are for people who manage a group, a viewer and the root")
        runs, manual = [], []
        f = (self.broker_state / "runs.jsonl") if self.broker_state else None
        if f and f.exists():
            for line in guard.read_bounded(f).splitlines()[-20:]:
                try:
                    r = guard.load_json_bytes(line.encode(), "run")
                except guard.InputRejected:
                    r = {"error": "an unreadable run line"}
                if isinstance(r, dict):
                    for x in r.get("findings") or []:      # memberships added by hand in the broker, and by whom
                        if not (isinstance(x, dict) and x.get("why") == "added by hand in the broker"):
                            continue
                        gid = str(x.get("group", "")).removeprefix(D.GROUP_PREFIX)
                        if sc["all"] or gid in sc["manage"]:
                            manual.append({"at": r.get("at"), "group": str(x.get("group", ""))[:200],
                                           "member": str(x.get("anchor", ""))[:256],
                                           "member_name": self._name(doc, x.get("anchor")),
                                           "by": str(x.get("by_name") or x.get("by_user") or "unknown")[:120],
                                           "client": str(x.get("by_client") or "")[:120]})
                    runs.append({k: (len(v) if isinstance(v, list) else v) for k, v in r.items()
                                 if k in ("at", "applied", "desired", "observed_before", "add", "remove", "findings",
                                          "failed", "refused", "error", "alert", "seconds", "intrusions_removed")})
        return {"revision": self.store.revision(), "observed": len(self._observed()), "runs": list(reversed(runs)),
                "log_intact": not self.store.verify_log(), "manual_changes": list(reversed(manual))[:50]}


for _name, _fn in list(vars(Desk).items()):          # every public method a person calls: who, then the rest
    if callable(_fn) and not _name.startswith("_") and getattr(_fn, "__code__", None)             and _fn.__code__.co_varnames[1:2] == ("who",):
        setattr(Desk, _name, _inward_who(_fn))
