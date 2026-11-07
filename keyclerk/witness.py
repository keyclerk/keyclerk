# SPDX-License-Identifier: EUPL-1.2
"""A witness for the change log, and the signer's side of the witness protocol (c2sp.org/tlog-witness; decision 0022
point 5, decision 0020 G10).

The signer's rollback mark (state/log-mark.json) lives in the state it guards: a signer restored, mark and all, from
an older backup would sign a second history at the positions it lost. A witness is another machine with another owner.
Per log it keeps the newest checkpoint it countersigned, and countersigns a newer one only with a consistency proof
from it. So a restored signer meets a witness that has seen more of its log than it holds, and stops.

    python -m keyclerk.witness serve --key FILE --name NAME --state DIR --log VKEY [--log VKEY ...] --listen HOST:PORT
        POST /add-checkpoint and GET /<sha256(origin), hex>/checkpoint, as the spec says. One witness per state
        directory; the newest checkpoint is on disk (written, synced, renamed) before the answer. A checkpoint the log's
        key signed but that is behind or inconsistent is kept in state/evidence.jsonl: the log's misbehaviour, proven
        by its own key. Plain HTTP on the address given: put TLS or a bastion in front when it leaves the host.
    python -m keyclerk.witness vkey --name NAME (--key FILE | --pub HEX) --type log|cosigner
        the vkey to configure: the signer's records key under the log's origin (type log), on the witness; the
        witness's own key under its name (type cosigner), in the signer's witness.cosigners
    python -m keyclerk.witness reset --state DIR --origin ORIGIN --by NAME --reason TEXT       (the witness stopped)
        after a restore the realm's officers confirmed (decision 0019 point 5): the witness forgets the log's newest
        checkpoint, which it keeps beside the evidence, and the next checkpoint starts the log again. The witness's
        owner does this, never the log's.

Any C2SP witness serves the signer as well (litewitness, the Armored Witness, a public witness network); this one is
small enough to run on a site's own device when the site is cut off (roadmap step 7).

The signer's side (Cosigner.submit) sends the newest checkpoint, signed by the records key, with a consistency proof
from what the witness last countersigned. The witness's 409 (another old size) and 422 (not consistent) answers are not
signed, so on either the signer fetches the witness's checkpoint and checks both its signatures, the records key's and
the witness's. Only then does it call the log rolled back (the witness holds a larger checkpoint the records key
signed) or forked (the witness's checkpoint, at a size this log holds, has another root). Anything less is an error:
the log stays unwitnessed and the next check tries again.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from keyclerk.store import merkle
from keyclerk.store import note as N

MAX_BODY = N.MAX_NOTE + 64 * 64             # a note and at most 63 proof lines
MAX_PROOF = 63
SIZE_TYPE = "text/x.tlog.size"
OLD = re.compile(r"old (0|[1-9][0-9]{0,18})")


def origin_hash(origin: str) -> str:
    return hashlib.sha256(origin.encode("utf-8")).hexdigest()


def request_body(old: int, proof: list[bytes], note: str) -> bytes:
    return (f"old {old}\n" + "".join(N.b64(h) + "\n" for h in proof) + "\n" + note).encode("utf-8")


def parse_request(body: bytes) -> tuple[int, list[bytes], str]:
    if len(body) > MAX_BODY:
        raise N.NoteRefused(f"a request is at most {MAX_BODY} bytes")
    try:
        s = body.decode("utf-8")
    except UnicodeDecodeError:
        raise N.NoteRefused("a request is UTF-8") from None
    first, _, rest = s.partition("\n")
    m = OLD.fullmatch(first)
    if not m:
        raise N.NoteRefused("the first line is old and a decimal size")
    proof = []
    while True:
        line, sep, rest = rest.partition("\n")
        if not sep:
            raise N.NoteRefused("the proof lines end with an empty line")
        if not line:
            break
        h = N.unb64(line)
        if len(h) != 32 or len(proof) == MAX_PROOF:
            raise N.NoteRefused(f"a proof is at most {MAX_PROOF} hashes of 32 bytes")
        proof.append(h)
    return int(m.group(1)), proof, rest


def _write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    if os.name != "nt":
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


class Witness:
    """The witness's state and its two operations; serve() puts them on HTTP."""

    def __init__(self, key: Ed25519PrivateKey, name: str, state: Path, logs: list[str], clock=time.time):
        self.key, self.name, self.state, self.clock = key, N.check_name(name), Path(state), clock
        self.logs: dict[str, tuple[str, int, bytes]] = {}
        for v in logs:
            parsed = N.parse_vkey(v)
            if parsed[1] != N.LOG:
                raise N.NoteRefused(f"a log is configured by its log key (type 0x01), not {v[:60]}")
            self.logs[parsed[0]] = parsed
        (self.state / "logs").mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.vkey = N.vkey(name, N.COSIGNATURE, N.raw_public(key))

    def _file(self, origin: str) -> Path:
        return self.state / "logs" / f"{origin_hash(origin)}.json"

    def latest(self, origin: str) -> dict | None:
        f = self._file(origin)
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None

    def _evidence(self, kind: str, origin: str, old: int, note: str) -> None:
        line = json.dumps({"at": int(self.clock()), "kind": kind, "origin": origin, "old": old, "note": note},
                          sort_keys=True) + "\n"
        with open(self.state / "evidence.jsonl", "a", encoding="utf-8", newline="\n") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def add_checkpoint(self, body: bytes) -> tuple[int, str, bytes]:
        """POST /add-checkpoint: (status, content type, body)."""
        def say(status: int, why: str) -> tuple[int, str, bytes]:
            return status, "text/plain; charset=utf-8", (why + "\n").encode("utf-8")
        try:
            old, proof, note = parse_request(body)
            text, sigs = N.split(note)
            origin, size, root = N.parse_checkpoint(text)
        except N.NoteRefused as e:
            return say(400, str(e))
        log = self.logs.get(origin)
        if log is None:
            return say(404, "this witness does not witness that log")
        try:
            if N.verify(text, sigs, log) is None:
                return say(403, "no signature of the log's key")
        except N.NoteRefused as e:
            return say(403, str(e))
        if old > size:
            return say(400, "the old size is above the checkpoint's")
        own = "".join(f"{N.DASH} {n} {N.b64(raw)}\n" for n, raw in sigs if n == log[0]
                      and raw[:4] == N.key_id(log[0], N.LOG, log[2]))
        with self._lock:
            cur = self.latest(origin)
            have = cur["size"] if cur else 0
            if old != have:
                if size < have:
                    self._evidence("behind", origin, old, note)
                return 409, SIZE_TYPE, f"{have}\n".encode("ascii")
            if old == 0:
                ok = not proof
            elif old == size:
                ok = not proof and N.unb64(cur["root"]) == root
            else:
                ok = merkle.consistent(old, size, N.unb64(cur["root"]), root, proof)
            if not ok:
                self._evidence("inconsistent", origin, old, note)
                return say(422, "the checkpoint is not consistent with the one this witness last countersigned")
            t = max(int(self.clock()), cur["time"] if cur else 0)
            line = N.cosign(text, self.name, self.key, t)
            _write(self._file(origin), json.dumps({"origin": origin, "size": size, "root": N.b64(root), "time": t,
                                                   "note": text + "\n" + own + line}, sort_keys=True).encode())
        return 200, "text/plain; charset=utf-8", line.encode("utf-8")

    def checkpoint(self, digest: str) -> tuple[int, str, bytes]:
        """GET /<sha256(origin)>/checkpoint: the newest countersigned checkpoint, with the log's signature."""
        for origin in self.logs:
            if origin_hash(origin) == digest:
                cur = self.latest(origin)
                if cur:
                    return 200, "text/plain; charset=utf-8", cur["note"].encode("utf-8")
        return 404, "text/plain; charset=utf-8", b"no checkpoint of that log\n"


def serve(w: Witness, host: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _answer(self, status: int, ctype: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):   # noqa: N802 - http.server's name
            n = self.headers.get("Content-Length", "")
            commit = self.path == "/commit" and hasattr(w, "commit")          # a commit witness (decision 0031)
            keys = self.path == "/keys" and hasattr(w, "adopt_keys")           # a newer records-key history (#41)
            if self.path != "/add-checkpoint" and not commit and not keys:
                return self._answer(404, "text/plain", b"not found\n")
            limit = (64 * 1024 * 1024) if commit else MAX_BODY
            if not n.isdigit() or int(n) > limit:
                return self._answer(413 if n.isdigit() else 411, "text/plain", b"a bounded Content-Length\n")
            body = self.rfile.read(int(n))
            self._answer(*(w.commit(body) if commit else w.adopt_keys(body) if keys else w.add_checkpoint(body)))

        def do_GET(self):   # noqa: N802
            m = re.fullmatch(r"/([0-9a-f]{64})/checkpoint", self.path)
            k = re.fullmatch(r"/([0-9a-f]{64})/links\?start=(\d{1,12})&limit=(\d{1,4})", self.path)
            if m:
                return self._answer(*w.checkpoint(m.group(1)))
            if k and hasattr(w, "links"):
                return self._answer(*w.links(k.group(1), int(k.group(2)), int(k.group(3))))
            self._answer(404, "text/plain", b"not found\n")

        def log_message(self, *a):   # the answers say enough; no request log of addresses
            pass
    from keyclerk.httpserve import DualStackHTTPServer
    return DualStackHTTPServer((host, port), Handler)


# --- the signer's side --------------------------------------------------------------------------------------------

def http(method: str, url: str, body: bytes | None, timeout: float, cap: int = MAX_BODY) -> tuple[int, str, bytes]:
    """One request to a witness. An answer longer than cap is refused, never cut and parsed: a cut answer read as
    JSON or as a note fails far from its cause (the commit witness's link pages are larger than a note)."""
    req = urllib.request.Request(url, data=body, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - the configured witness URL
            out = r.status, r.headers.get("Content-Type", ""), r.read(cap + 1)
    except urllib.error.HTTPError as e:
        out = e.code, e.headers.get("Content-Type", ""), e.read(cap + 1)
    if len(out[2]) > cap:
        raise OSError(f"the witness's answer to {method} {url.split('?')[0]} is over {cap} bytes")
    return out


class Cosigner:
    """One witness as the signer sees it: where it answers and its cosigner key."""

    def __init__(self, url: str, vkey: str, timeout: float = 10.0, transport: Callable | None = None):
        self.url, self.timeout = url.rstrip("/"), timeout
        self.key = N.parse_vkey(vkey)
        if self.key[1] != N.COSIGNATURE:
            raise N.NoteRefused(f"a witness is configured by its cosigner key (type 0x04), not {vkey[:60]}")
        self.name = self.key[0]
        self.transport = transport or http

    def _call(self, method: str, path: str, body: bytes | None = None) -> tuple[int, str, bytes]:
        return self.transport(method, self.url + path, body, self.timeout)

    def submit(self, origin: str, log_key: tuple[str, int, bytes], note: str, hashes: Callable[[], list[bytes]],
               old: int) -> dict:
        """The checkpoint note (signed by the records key) sent with a proof from old; returns {"result": cosigned |
        rolled_back | forked | error, "size": what the witness holds when known, "time", "why"}. hashes() gives the
        log's leaf hashes up to the checkpoint's size, read only when a proof or a comparison needs them."""
        text, _ = N.split(note)
        _, size, root = N.parse_checkpoint(text)
        old = old if old <= size else 0       # a size above this log's: ask again, the witness says its own
        trusted = old                         # an unsigned 409 moves the next try only; errors keep this
        try:
            for _ in range(2):
                if old > size:
                    break
                proof = merkle.consistency(hashes()[:size], old) if 0 < old < size else []
                status, ctype, body = self._call("POST", "/add-checkpoint", request_body(old, proof, note))
                if status == 200:
                    t = N.verify(text, N.split(note + body.decode("utf-8"))[1], self.key)
                    if t is None:
                        return {"result": "error", "size": trusted, "why": "the witness answered without its cosignature"}
                    return {"result": "cosigned", "size": size, "time": t}
                if status == 409 and ctype.split(";")[0].strip() == SIZE_TYPE and OLD.fullmatch(
                        "old " + body.decode("ascii", "replace").strip()):
                    old = int(body.strip())
                    continue
                if status == 422:
                    break
                return {"result": "error", "size": trusted, "why": f"the witness answered {status}: "
                        + body[:200].decode("utf-8", "replace").strip()}
            return self._evidence(origin, log_key, text, size, root, hashes, trusted)
        except (OSError, ValueError) as e:
            return {"result": "error", "size": trusted, "why": f"the witness did not answer: {type(e).__name__}: {e}"[:300]}

    def _evidence(self, origin, log_key, text, size, root, hashes, trusted) -> dict:
        """The witness refused or holds another size: its own countersigned checkpoint decides, both signatures
        checked, never its unsigned answer."""
        status, _, body = self._call("GET", f"/{origin_hash(origin)}/checkpoint")
        if status != 200:
            return {"result": "error", "size": trusted, "why": f"the witness refused, and its checkpoint is not served "
                    f"({status})"}
        wtext, sigs = N.split(body.decode("utf-8"))
        o, wsize, wroot = N.parse_checkpoint(wtext)
        if o != origin or N.verify(wtext, sigs, log_key) is None:
            return {"result": "error", "size": trusted, "why": "the witness's checkpoint is not signed by the records key"}
        t = N.verify(wtext, sigs, self.key)
        if t is None:
            return {"result": "error", "size": trusted, "why": "the witness's checkpoint is not countersigned by it"}
        if wsize > size:
            return {"result": "rolled_back", "size": wsize, "time": t,
                    "why": f"witness {self.name} countersigned {wsize} links of this log, signed by the records key, "
                           f"but this replica holds {size}"}
        if merkle.mth(hashes()[:wsize]) != wroot:
            return {"result": "forked", "size": wsize, "time": t,
                    "why": f"witness {self.name} countersigned another history of this log at {wsize} links, signed "
                           "by the records key"}
        if wsize == size:                         # an answer lost on the way: the witness has this very checkpoint
            return {"result": "cosigned", "size": size, "time": t}
        return {"result": "error", "size": wsize, "why": f"the witness refused, but its checkpoint at {wsize} links "
                "agrees with this log: the next check proves from there"}


# --- the command line ---------------------------------------------------------------------------------------------

def _key(path: str) -> Ed25519PrivateKey:
    from keyclerk import guard
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(guard.read_bounded(Path(path), 200).strip()))


def parser() -> argparse.ArgumentParser:
    """The command line, without starting anything: what the deployer contract and the preflight read."""
    ap = argparse.ArgumentParser(prog="python -m keyclerk.witness", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--key", required=True)
    s.add_argument("--name", required=True, help="the witness's cosigner name, e.g. witness.example/kc1")
    s.add_argument("--state", required=True)
    s.add_argument("--log", action="append", required=True, help="a log's vkey (python -m keyclerk.witness vkey)")
    s.add_argument("--listen", default="127.0.0.1:8098")
    s.add_argument("--commit", action="store_true", help="the realm's commit witness: keeps the links (decision 0031)")
    s.add_argument("--trustees", help="with --commit: the trustee set (kc-trustees-v1) this witness pins (#41)")
    s.add_argument("--trustees-since", type=int, default=0,
                   help="with --trustees: the log size from which HA and restore links need trustee signatures")
    s.add_argument("--records-keys", action="append", default=[],
                   help="with --commit: a records-key history (kc-records-keys-v1) of a log, delivered out of band")
    rs = sub.add_parser("reseed", help="a commit witness starts again from checked links, never from nothing")
    rs.add_argument("--state", required=True)
    rs.add_argument("--origin", required=True)
    rs.add_argument("--pin", required=True, help="the records public key (hex)")
    rs.add_argument("--links", required=True, help="one sealed link per line, from the genesis to the seed head")
    rs.add_argument("--by", required=True)
    rs.add_argument("--reason", required=True)
    rs.add_argument("--checkpoint", required=True, help="the records key's checkpoint note of the seed head")
    rs.add_argument("--key", required=True, help="this witness's key, to countersign it")
    rs.add_argument("--name", required=True, help="this witness's cosigner name")
    rs.add_argument("--records-keys", help="the log's records-key history (kc-records-keys-v1), when its key was rotated")
    rs.add_argument("--trustees", help="with --records-keys: the trustee set (kc-trustees-v1) the history holds against")
    v = sub.add_parser("vkey")
    v.add_argument("--name", required=True)
    v.add_argument("--type", choices=("log", "cosigner"), required=True)
    g = v.add_mutually_exclusive_group(required=True)
    g.add_argument("--key")
    g.add_argument("--pub", help="the public key, 64 hex characters (the records public key)")
    r = sub.add_parser("reset")
    r.add_argument("--state", required=True)
    r.add_argument("--origin", required=True)
    r.add_argument("--by", required=True)
    r.add_argument("--reason", required=True)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = parser()
    a = ap.parse_args(argv)
    if a.cmd == "vkey":
        pub = N.raw_public(_key(a.key)) if a.key else bytes.fromhex(a.pub)
        print(N.vkey(a.name, N.LOG if a.type == "log" else N.COSIGNATURE, pub))
        return 0
    from keyclerk.store.sqlite import hold
    from keyclerk.store.link import StoreRefused
    try:
        held = hold(Path(a.state) / "witness.lock", f"another witness holds {a.state}: stop it first")
    except StoreRefused as e:
        raise SystemExit(f"keyclerk.witness: {e}") from None
    if a.cmd == "reseed":
        from keyclerk import commit_witness
        try:
            from keyclerk import records_keys as RK
            hist = RK.KeyHistory(json.loads(Path(a.records_keys).read_text(encoding="utf-8"))) if a.records_keys else None
            ts = json.loads(Path(a.trustees).read_text(encoding="utf-8")) if a.trustees else None
            out = commit_witness.reseed(Path(a.state), a.origin, a.pin, Path(a.links), a.by, a.reason, time.time,
                                        Path(a.checkpoint).read_text(encoding="utf-8"), _key(a.key), a.name,
                                        history=hist, trustees=ts)
        except (ValueError, StoreRefused) as e:
            held.close()
            raise SystemExit(f"keyclerk.witness: not reseeded: {e}") from None
        sys.stderr.write(f"keyclerk.witness: reseeded {out['origin']} at {out['size']} links\n")
        return 0
    if a.cmd == "reset":
        f = Path(a.state) / "logs" / f"{origin_hash(a.origin)}.json"
        if not f.exists():
            raise SystemExit(f"keyclerk.witness: no checkpoint of {a.origin} is kept here")
        line = json.dumps({"at": int(time.time()), "kind": "reset", "origin": a.origin, "by": a.by,
                           "reason": a.reason, "forgot": json.loads(f.read_text(encoding="utf-8"))}, sort_keys=True)
        with open(Path(a.state) / "evidence.jsonl", "a", encoding="utf-8", newline="\n") as out:
            out.write(line + "\n")
            out.flush()
            os.fsync(out.fileno())
        f.unlink()
        sys.stderr.write(f"keyclerk.witness: forgot the newest checkpoint of {a.origin}; kept in evidence.jsonl\n")
        return 0
    if a.commit:
        from keyclerk import commit_witness
        from keyclerk import records_keys as RK
        ts = json.loads(Path(a.trustees).read_text(encoding="utf-8")) if a.trustees else None
        hs = [RK.KeyHistory(json.loads(Path(f).read_text(encoding="utf-8"))) for f in a.records_keys]
        w = commit_witness.CommitWitness(_key(a.key), a.name, Path(a.state), a.log, trustees=ts, histories=hs,
                                         trustees_since=a.trustees_since)
    else:
        w = Witness(_key(a.key), a.name, Path(a.state), a.log)
    host, _, port = a.listen.rpartition(":")
    srv = serve(w, host or "127.0.0.1", int(port))
    sys.stderr.write(f"keyclerk.witness: {w.vkey} witnessing {len(w.logs)} log(s) on {a.listen}\n")
    try:
        srv.serve_forever()
    finally:
        held.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
