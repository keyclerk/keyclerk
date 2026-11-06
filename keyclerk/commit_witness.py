# SPDX-License-Identifier: EUPL-1.2
"""The commit witness (decision 0031 points 4, 5 and 9): the one witness whose compare-and-swap is the commit point of
a realm in HA mode, and which keeps every committed link, so a standby can always take over.

It is a C2SP witness (keyclerk.witness) and more: for an origin in commit mode it holds the log's links, not only its
newest checkpoint. A commit carries the links the checkpoint adds; the commit witness checks each one as a store
does (signed by the records key, next in sequence, following the head, its fence never lower), recomputes the root
over every link it holds, and only when that root and size are the checkpoint's does it take the checkpoint, persist
links and checkpoint, and countersign. Two signers racing for the same size: one wins, the other is told the size the
witness holds (409). A conflicting tree is refused (422) and kept as evidence. So it is a follower that also referees,
stronger than a consistency proof alone.

    POST /commit                      {"old": size, "links": [sealed link, ...], "note": the checkpoint, signed}
                                      200 the cosignature line; 409 text/x.tlog.size; 422; 403; 404; 400
    GET  /<sha256(origin)>/checkpoint the newest countersigned checkpoint, at once (no lag, unlike C2SP's monitor
                                      endpoint, which may lag an hour)
    GET  /<sha256(origin)>/links?start=N&limit=M   committed links, for a standby or a follower (M at most 500)

    python -m keyclerk.witness serve --commit ...                    the same command, commit mode for every log given
    python -m keyclerk.witness reseed --state DIR --origin O --pin RECORDS_HEX --links FILE --by NAME --reason TEXT
                                      after a loss: the witness starts again from the links in FILE (one sealed
                                      link per line, from the genesis to the newest head the desk saw), each checked;
                                      never from nothing (decision 0031 point 9). Two people confirm the seed out of
                                      band; the reseed is kept in evidence.jsonl.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from keyclerk import witness as W
from keyclerk.store import link as L
from keyclerk.store import merkle
from keyclerk.store import note as N

MAX_COMMIT = 64 * 1024 * 1024
MAX_LINKS = 500


class CommitLog:
    """One origin's links at the commit witness: a file of sealed links, one per line, and in memory the leaf hashes'
    frontier, the head, the fence and the realm."""

    def __init__(self, d: Path, pinned: str):
        self.d, self.pinned = d, pinned
        self.d.mkdir(parents=True, exist_ok=True)
        self.size, self.head, self.fence, self.realm, self.frontier = 0, None, 1, None, []
        self._offsets: list[int] = []

    def load(self, committed: int) -> None:
        """Read the links back, at most `committed` of them: a crash between writing links and the checkpoint leaves
        links beyond it, which were never answered, and they are cut."""
        f = self.d / "links.jsonl"
        if not f.exists():
            return
        keep = 0
        with open(f, "rb") as h:
            for line in h:
                if self.size == committed:
                    break
                self.add(json.loads(line))
                keep += len(line)
                self._offsets.append(keep)
        if keep != f.stat().st_size:
            with open(f, "r+b") as h:
                h.truncate(keep)

    def check(self, links: list) -> tuple[list, int, bytes | None, int, str | None]:
        """The links checked as appends, without changing anything: (frontier, size, head, fence, realm)."""
        frontier, size, head, fence, realm = list(self.frontier), self.size, self.head, self.fence, self.realm
        for sealed in links:
            body, h = L.open_link(sealed, self.pinned)
            realm = realm if realm is not None else body["realm"]
            L.follows(body, realm, size, head, fence)
            frontier, size, head, fence = merkle.push(frontier, h), size + 1, h, body["fence"]
        return frontier, size, head, fence, realm

    def add(self, sealed: dict) -> None:
        self.frontier, self.size, self.head, self.fence, self.realm = self.check([sealed])

    def append(self, links: list, checked: tuple) -> None:
        with open(self.d / "links.jsonl", "ab") as h:
            for sealed in links:
                h.write(json.dumps(sealed, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                self._offsets.append(h.tell())
            h.flush()
            os.fsync(h.fileno())
        self.frontier, self.size, self.head, self.fence, self.realm = checked

    def read(self, start: int, limit: int) -> list[dict]:
        out = []
        with open(self.d / "links.jsonl", "rb") as h:
            h.seek(self._offsets[start - 1] if start else 0)
            for _ in range(min(limit, self.size - start)):
                out.append(json.loads(h.readline()))
        return out


class CommitWitness(W.Witness):
    """A witness in commit mode for every log it is given (decision 0031)."""

    def __init__(self, key, name: str, state: Path, logs: list[str], clock=None):
        super().__init__(key, name, state, logs, **({"clock": clock} if clock else {}))
        self.commits: dict[str, CommitLog] = {}
        for origin, (_, _, pub) in self.logs.items():
            c = CommitLog(self.state / "commit" / W.origin_hash(origin), pub.hex())
            cur = self.latest(origin)
            c.load(cur["size"] if cur else 0)
            self.commits[origin] = c

    def add_checkpoint(self, body: bytes) -> tuple[int, str, bytes]:
        """A commit witness takes checkpoints only with their links (POST /commit): a bare C2SP submission could move
        the head past links it does not hold."""
        return 400, "text/plain; charset=utf-8", b"a commit witness takes POST /commit, with the links\n"

    def commit(self, body: bytes) -> tuple[int, str, bytes]:
        def say(status: int, why: str) -> tuple[int, str, bytes]:
            return status, "text/plain; charset=utf-8", (why + "\n").encode("utf-8")
        if len(body) > MAX_COMMIT:
            return say(400, f"a commit is at most {MAX_COMMIT} bytes")
        try:
            req = json.loads(body)
            old, links, note = req["old"], req["links"], req["note"]
            if not (isinstance(old, int) and not isinstance(old, bool) and old >= 0 and isinstance(links, list)
                    and len(links) <= MAX_LINKS and isinstance(note, str)):
                raise ValueError("a commit is {old, links (at most 500), note}")
            text, sigs = N.split(note)
            origin, size, root = N.parse_checkpoint(text)
        except (ValueError, KeyError, TypeError, N.NoteRefused) as e:
            return say(400, str(e))
        log = self.logs.get(origin)
        if log is None:
            return say(404, "this witness does not witness that log")
        try:
            if N.verify(text, sigs, log) is None:
                return say(403, "no signature of the log's key")
        except N.NoteRefused as e:
            return say(403, str(e))
        c = self.commits[origin]
        own = "".join(f"{N.DASH} {n} {N.b64(raw)}\n" for n, raw in sigs
                      if n == log[0] and raw[:4] == N.key_id(log[0], N.LOG, log[2]))
        with self._lock:
            if old != c.size:
                return 409, W.SIZE_TYPE, f"{c.size}\n".encode("ascii")
            try:
                checked = c.check(links)
            except L.StoreRefused as e:
                self._evidence("inconsistent", origin, old, note)
                return say(422, f"a link does not follow the committed log: {e}")
            if checked[1] != size or merkle.root(checked[0]) != root:
                self._evidence("inconsistent", origin, old, note)
                return say(422, "the checkpoint is not the root and size of the committed log with these links")
            cur = self.latest(origin)
            if not links and cur:                       # a lost answer asked again, or the active's beat: the same
                t = max(int(self.clock()), cur["time"] + 1)   # checkpoint, re-cosigned at a later time, always (0031 p. 7)
            else:
                c.append(links, checked)
                t = max(int(self.clock()), cur["time"] if cur else 0)
            line = N.cosign(text, self.name, self.key, t)
            W._write(self._file(origin), json.dumps({"origin": origin, "size": size, "root": N.b64(root), "time": t,
                                                     "note": text + "\n" + own + line}, sort_keys=True).encode())
        return 200, "text/plain; charset=utf-8", line.encode("utf-8")

    def checkpoint(self, digest: str) -> tuple[int, str, bytes]:
        for origin in self.logs:
            if W.origin_hash(origin) == digest and not (self.latest(origin) or {}).get("note"):
                return 404, "text/plain; charset=utf-8", b"no countersigned checkpoint yet (reseeded)\n"
        return super().checkpoint(digest)

    def links(self, digest: str, start: int, limit: int) -> tuple[int, str, bytes]:
        for origin, c in self.commits.items():
            if W.origin_hash(origin) == digest:
                if not (0 <= start <= c.size and 1 <= limit <= MAX_LINKS):
                    return 400, "text/plain; charset=utf-8", b"start within the log, limit 1 to 500\n"
                return 200, "application/json", json.dumps({"links": c.read(start, limit), "size": c.size}).encode()
        return 404, "text/plain; charset=utf-8", b"no such log\n"


def reseed(state: Path, origin: str, pinned: str, links_file: Path, by: str, reason: str, clock, note: str,
           key=None, name: str | None = None) -> dict:
    """The commit witness starts again from links checked from the genesis (decision 0031 point 9), the witness
    stopped. Its old record of the log is kept beside the evidence."""
    d = Path(state) / "commit" / W.origin_hash(origin)
    c = CommitLog(d.with_name(d.name + ".seed"), pinned)
    links = [json.loads(x) for x in Path(links_file).read_text(encoding="utf-8").splitlines() if x.strip()]
    if not links:
        raise ValueError("a reseed starts from the links of the newest head the desk saw, never from nothing")
    checked = c.check(links)
    root = merkle.root(checked[0])
    try:                                          # the records key's checkpoint of the seed head, checked first
        text, sigs = N.split(note)
        ok = N.parse_checkpoint(text) == (origin, checked[1], root) and \
            N.verify(text, sigs, (origin, N.LOG, bytes.fromhex(pinned))) is not None
    except N.NoteRefused:
        ok = False
    if not ok:
        raise ValueError("the checkpoint is not the records key's, for the seed's size and root")
    c.append(links, checked)
    old = Path(state) / "logs" / f"{W.origin_hash(origin)}.json"
    old.parent.mkdir(parents=True, exist_ok=True)          # a witness seeded before it first ran
    forgot = json.loads(old.read_text(encoding="utf-8")) if old.exists() else None
    if d.exists():
        os.replace(d, d.with_name(d.name + f".before-reseed-{int(clock())}"))
    os.replace(c.d, d)
    own = "".join(f"{N.DASH} {n} {N.b64(raw)}\n" for n, raw in sigs if n == origin)
    t = int(clock())
    line = N.cosign(text, name, key, t) if key is not None else ""      # countersigned now
    W._write(old, json.dumps({"origin": origin, "size": checked[1], "root": N.b64(root), "time": t,
                              "note": text + "\n" + own + line, "reseeded": True}, sort_keys=True).encode())
    with open(Path(state) / "evidence.jsonl", "a", encoding="utf-8", newline="\n") as f:
        f.write(json.dumps({"at": int(clock()), "kind": "reseed", "origin": origin, "by": by, "reason": reason,
                            "size": checked[1], "forgot": forgot}, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())
    return {"origin": origin, "size": checked[1], "root": N.b64(root)}


def http(method: str, url: str, body: bytes | None, timeout: float) -> tuple[int, str, bytes]:
    """The commit witness over HTTP: a page of up to MAX_LINKS whole links is far larger than a witness's note, so its
    answers are read up to MAX_COMMIT (a note-sized cap cut a page of a large realm's links mid-string)."""
    return W.http(method, url, body, timeout, cap=MAX_COMMIT)


class CommitClient:
    """The signer's side of the commit witness: commit, the countersigned checkpoint, and the committed links."""

    def __init__(self, url: str, timeout: float = 10.0, transport=None):
        self.url, self.timeout, self.transport = url.rstrip("/"), timeout, transport or http

    def commit(self, old: int, links: list, note: str) -> tuple[int, str, bytes]:
        body = json.dumps({"old": old, "links": links, "note": note}, separators=(",", ":")).encode()
        return self.transport("POST", self.url + "/commit", body, self.timeout)

    def checkpoint(self, origin: str) -> tuple[int, str, bytes]:
        return self.transport("GET", f"{self.url}/{W.origin_hash(origin)}/checkpoint", None, self.timeout)

    def links(self, origin: str, start: int, limit: int = MAX_LINKS) -> list[dict]:
        status, _, body = self.transport("GET", f"{self.url}/{W.origin_hash(origin)}/links?start={start}&limit={limit}",
                                         None, self.timeout)
        if status != 200:
            raise OSError(f"the commit witness answered {status} for its links")
        return json.loads(body)["links"]


def in_process(witness: CommitWitness):
    """A transport straight into a commit witness, as HTTP would carry it (tests, and a witness in the same process)."""
    import re as _re

    def t(method, url, body, timeout):
        if method == "POST" and url.endswith("/commit"):
            return witness.commit(body)
        m = _re.search(r"/([0-9a-f]{64})/(checkpoint|links)(?:\?start=(\d+)&limit=(\d+))?$", url)
        if m and m.group(2) == "checkpoint":
            return witness.checkpoint(m.group(1))
        if m:
            return witness.links(m.group(1), int(m.group(3)), int(m.group(4)))
        return 404, "text/plain", b""
    return t


def export_seed(signer_state: Path, key, origin: str, out: Path) -> dict:
    """The seed of a commit witness (decision 0031 point 9), from a stopped signer: links.jsonl, every link of its log,
    and checkpoint.note, the records key's checkpoint of them. Refused unless the log names this origin in its ha
    record, so the witness is seeded with the configuration that makes it the commit witness."""
    from keyclerk.signer import Signer
    s = Signer(key, Path(signer_state))             # refused while the signer runs: its state is locked
    try:
        store = s.replica
        if store is None:
            raise ValueError("the signer keeps no change log yet: migrate it first")
        cfg = (store.get("head", "ha") or {}).get("value") or {}
        if cfg.get("origin") != origin:
            raise ValueError(f"the log's ha record does not name origin {origin}: sign the ha record first")
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        with open(out / "links.jsonl", "w", encoding="utf-8", newline="\n") as f:
            for sealed in store.links():
                f.write(json.dumps(sealed, sort_keys=True, separators=(",", ":")) + "\n")
        text = N.checkpoint_text(origin, store.size(), store.root())
        (out / "checkpoint.note").write_text(text + "\n" + N.sign(text, origin, key), encoding="utf-8", newline="\n")
        return {"origin": origin, "size": store.size(), "public_key": s.public_key()}
    finally:
        s.close()


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from keyclerk import guard
    ap = argparse.ArgumentParser(prog="python -m keyclerk.commit_witness")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sd = sub.add_parser("seed", help="export the seed of the commit witness from a stopped signer")
    sd.add_argument("--signer-state", required=True)
    sd.add_argument("--key", required=True, help="the records key file")
    sd.add_argument("--origin", required=True)
    sd.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(a.key), 200).strip()))
    try:
        got = export_seed(Path(a.signer_state), key, a.origin, Path(a.out))
    except ValueError as e:
        raise SystemExit(f"keyclerk.commit_witness: no seed: {e}") from None
    sys.stderr.write(f"keyclerk.commit_witness: seed of {got['origin']} at {got['size']} links in {a.out}; reseed the "
                     f"witness with --pin {got['public_key']}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
