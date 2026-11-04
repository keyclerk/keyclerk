# SPDX-License-Identifier: EUPL-1.2
"""Audit events for a SIEM (decision 0018 H4, issue 29): the desk's activity log as OCSF JSON, pulled through a cursor
or sent as syslog over TLS.

The source is the activity log every desk store keeps (log.jsonl): each line is one entry, chained to the one before
and signed by the records key or the checking signer, numbered by seq from 1. So the cursor is a seq, durable with the
log itself: a SIEM reads every event exactly once across a desk restart by asking for the events after the last seq it
holds, and each event carries its line's seq, prev, sha256 and signature and the records revision, so a SIEM's copy
can be checked against the signed history. Only complete lines are served: a line still being written waits.

    GET /audit/events?after=SEQ&limit=N      on the management listener (keyclerk.health), behind siem.reader_token_file,
                                             a token of its own: {events, next, head {seq, sha256}}; N at most 500
    python -m keyclerk.siem forward --store DIR --config FILE [--once]
                                             syslog over TLS (RFC 5424 messages, RFC 5425 octet counting) to
                                             siem.syslog.{host, port}, trusting only siem.syslog.ca_file; resumes from
                                             siem.syslog.cursor_file, which advances only after each message is written
                                             and flushed. Off unless configured; its own process, reading the store's
                                             directory and nothing else.
    python -m keyclerk.siem page --store DIR [--after SEQ] [--limit N]       the same events, for a look by hand

Pseudonymous by default (decision 0018 H3 and H6): a person is person-pseudonym:<site>/<keyed hash>, the key in the
store's directory (siem-pseudonym.key, made on first use, kept apart from the metrics, which name no person). A
reason's text can name people, so an event carries the classes of its reasons, never the text; the change_id leads
back to the desk, where the reader's own rights decide what they see.

OCSF 1.3.0 classes: Group Management (3006) for memberships and groups, User Access Management (3005) for
delegations and leases, Detection Finding (2004) for an edge's incidents, Entity Management (3004) for the rest.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

OCSF_VERSION = "1.3.0"
PAGE_MAX = 500
INDEX_EVERY = 256                                 # a sparse seq -> offset index: a page seeks, it does not rescan
LINE_MAX = 1 << 20
KEY_FILE = "siem-pseudonym.key"

GROUP = {"add_member": 3, "include_group": 3, "end_membership": 4, "create_group": 6}          # 3006 activities
ACCESS = {"delegate": 1, "grant_visit_lease": 1, "end_delegation": 2, "end_approver": 2}       # 3005 activities
FINDING = {"edge_incident", "console_grant"}                                                                    # 2004
CLASS_NAMES = {3006: "Group Management", 3005: "User Access Management", 3004: "Entity Management",
               2004: "Detection Finding"}
STATUS = {"applied": (1, "Success"), "refused": (2, "Failure")}
SEVERITY = {"refused": 2, "recovered": 3, "unreadable": 4}


def _pseudonym_key(store: Path) -> bytes:
    f = store / KEY_FILE
    try:
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return bytes.fromhex(f.read_text(encoding="ascii").strip())
    with os.fdopen(fd, "w", encoding="ascii") as h:
        h.write(os.urandom(32).hex())
        h.flush()
        os.fsync(h.fileno())
    return bytes.fromhex(f.read_text(encoding="ascii").strip())


def _class(action: str) -> tuple[int, int]:
    if action in GROUP:
        return 3006, GROUP[action]
    if action in ACCESS:
        return 3005, ACCESS[action]
    if action in FINDING:
        return 2004, 1
    if action.startswith(("enrol", "create", "add", "seed", "issue")):
        return 3004, 1
    if action.startswith(("end", "remove", "revoke", "erase", "withdraw")) or action.endswith("_erased"):
        return 3004, 4
    return 3004, 3


def to_ocsf(line: dict, seq: int, pseudonym, site: str, version: str) -> dict:
    """One activity line as an OCSF event; the KeyClerk part (chain position, revision) under unmapped.keyclerk."""
    from keyclerk import remedies
    action, outcome = str(line.get("action") or "other"), str(line.get("outcome") or "other")
    cls, act = _class(action)
    status_id, status = STATUS.get(outcome, (99, outcome))
    try:
        t = int(datetime.fromisoformat(str(line["at"]).replace("Z", "+00:00")).timestamp() * 1000)
    except (KeyError, ValueError):
        t = 0
    ev = {"class_uid": cls, "class_name": CLASS_NAMES[cls], "category_uid": cls // 1000, "activity_id": act,
          "type_uid": cls * 100 + act, "time": t, "severity_id": SEVERITY.get(outcome, 1), "status_id": status_id,
          "status": status, "message": f"{action} {outcome}",
          "metadata": {"version": OCSF_VERSION, "uid": f"{site}:{seq}", "sequence": seq, "log_name": "keyclerk-activity",
                       "product": {"name": "KeyClerk", "vendor_name": "KeyClerk", "version": version}}}
    actor = line.get("actor")
    if isinstance(actor, str) and actor:
        ev["actor"] = {"user": {"uid": pseudonym(actor)}}
    if cls == 2004:
        ev["finding_info"] = {"uid": str(line.get("change_id") or f"{site}:{seq}"), "title": str(line.get("summary") or
                                                                                               action)[:200]}
    reasons = line.get("reasons") or []
    ev["unmapped"] = {"keyclerk": {
        "seq": seq, "line_seq": line.get("seq"), "prev": line.get("prev"), "sha256": line.get("sha256"),
        "signature": line.get("signature"), "revision": line.get("revision"), "change_id": line.get("change_id"),
        "action": action, "outcome": outcome,
        "reason_classes": sorted({remedies.match(str(r))[2] for r in reasons if isinstance(reasons, list)})}}
    return ev


class Feed:
    """The activity log of one store directory, read as events after a seq. Read-only: it never writes the log."""

    def __init__(self, store: Path, site: str = "keyclerk"):
        import hashlib
        import hmac
        from keyclerk import __version__
        self.store, self.site, self.version = Path(store), site, __version__
        key = _pseudonym_key(self.store)
        self._pseudonym = lambda a: f"person-pseudonym:{site}/" + hmac.new(key, a.encode(), hashlib.sha256).hexdigest()[:20]
        self._index: dict[int, int] = {0: 0}       # seq of the last line before an offset -> that offset

    def _lines(self, after: int):
        """(seq, line) of the complete lines after seq after, by position: the n-th complete line is seq n."""
        f = self.store / "log.jsonl"
        if not f.exists():
            return
        base = max(k for k in self._index if k <= after)
        with f.open("rb") as h:
            h.seek(self._index[base])
            seq = base
            while True:
                line = h.readline(LINE_MAX + 1)
                if not line.endswith(b"\n"):
                    return                         # the end, or a line still being written: it waits
                seq += 1
                if seq % INDEX_EVERY == 0:
                    self._index[seq] = h.tell()
                if seq > after:
                    yield seq, line

    def entries(self, after: int = 0, limit: int = 100) -> list[tuple[int, dict]]:
        """(seq, the log line) after seq after; an unreadable line reads as such, so the numbering never skips."""
        if not isinstance(after, int) or after < 0 or not 0 < limit <= PAGE_MAX:
            raise ValueError(f"after is a seq from 0, limit 1 to {PAGE_MAX}")
        out = []
        for seq, raw in self._lines(after):
            try:
                line = json.loads(raw)
                line = line if isinstance(line, dict) else {}
            except ValueError:
                line = {"outcome": "unreadable", "action": "other"}
            out.append((seq, line))
            if len(out) == limit:
                break
        return out

    def event(self, seq: int, line: dict) -> dict:
        return to_ocsf(line, seq, self._pseudonym, self.site, self.version)

    def pseudonym(self, anchor: str) -> str:
        return self._pseudonym(anchor)

    def page(self, after: int = 0, limit: int = 100) -> list[dict]:
        return [self.event(seq, line) for seq, line in self.entries(after, limit)]

    def head(self) -> dict:
        top = max(self._index)                     # from the index point before it, so the last line is read
        seq, sha = max([k for k in self._index if k < top] or [0]), None
        for n, raw in self._lines(seq):
            seq = n
            try:
                sha = json.loads(raw).get("sha256")
            except (ValueError, AttributeError):
                sha = None
        return {"seq": seq, "sha256": sha}

    def answer(self, query: str) -> tuple[int, dict]:
        """GET /audit/events?after=SEQ&limit=N: (status, body)."""
        from urllib.parse import parse_qs
        q = parse_qs(query, keep_blank_values=True)
        try:
            after = int(q.get("after", ["0"])[0])
            limit = int(q.get("limit", ["100"])[0])
            events = self.page(after, limit)
        except ValueError as e:
            return 400, {"error": str(e)}
        nxt = events[-1]["metadata"]["sequence"] if events else after
        return 200, {"events": events, "next": nxt, "head": self.head()}


# --- syslog over TLS (RFC 5424, RFC 5425) ---------------------------------------------------------------------------

def syslog_message(ev: dict, hostname: str) -> bytes:
    """One RFC 5424 message, facility log audit (13), framed by its octet count (RFC 5425 section 4.3)."""
    severity = {1: 6, 2: 5, 3: 4, 4: 3}.get(ev["severity_id"], 6)
    ts = datetime.fromtimestamp(ev["time"] / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z" \
        if ev["time"] else "-"
    body = json.dumps(ev, sort_keys=True, separators=(",", ":"))
    msg = f"<{13 * 8 + severity}>1 {ts} {hostname} keyclerk - ocsf-{ev['class_uid']} - {body}".encode("utf-8")
    return str(len(msg)).encode("ascii") + b" " + msg


def _hostname() -> str:
    h = "".join(c for c in socket.gethostname() if 33 <= ord(c) <= 126)[:255]
    return h or "-"


def read_cursor(path: Path) -> int:
    try:
        return int(Path(path).read_text(encoding="ascii").strip() or 0)
    except FileNotFoundError:
        return 0


def write_cursor(path: Path, seq: int) -> None:
    tmp = Path(path).with_name(Path(path).name + ".tmp")
    with open(tmp, "w", encoding="ascii") as h:
        h.write(f"{seq}\n")
        h.flush()
        os.fsync(h.fileno())
    os.replace(tmp, path)


def tls_context(ca_file: str) -> ssl.SSLContext:
    """Trusts the pinned CA and nothing else: no system store."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ca_file)
    return ctx


def close_cleanly(s) -> None:
    """Ends the TLS session with close_notify, then reads until the receiver closes. A socket closed with unread data
    (TLS 1.3 sends session tickets after the handshake) makes the kernel reset the connection, and the receiver drops
    what it had not read yet: events the cursor has already passed, lost for good."""
    if not isinstance(s, ssl.SSLSocket):
        return     # a plain or stand-in connection has no session to end
    try:
        raw = s.unwrap()
    except (OSError, ssl.SSLError, ValueError):
        return     # the receiver closed first or the session is gone: nothing left to drain
    try:
        raw.shutdown(socket.SHUT_WR)
        raw.settimeout(10)
        while raw.recv(65536):
            pass
    except OSError:
        pass


def forward(feed: Feed, cfg: dict, once: bool = False, connect=None) -> int:
    """Sends the events after the cursor, each written and flushed before the cursor moves past it. Returns the seq
    reached. once: drain what is there and return; otherwise poll, reconnecting with a growing pause."""
    cursor_file = Path(cfg.get("cursor_file") or feed.store / "siem-syslog.cursor")
    host, port = cfg["host"], int(cfg.get("port", 6514))
    if connect is None:
        ctx = tls_context(cfg["ca_file"])

        def connect():
            return ctx.wrap_socket(socket.create_connection((host, port), timeout=30),
                                   server_hostname=cfg.get("server_name") or host)
    hostname, pause, seq = _hostname(), 1.0, read_cursor(cursor_file)
    while True:
        try:
            with connect() as s:
                pause = 1.0
                while True:
                    events = feed.page(seq, 100)
                    for ev in events:
                        s.sendall(syslog_message(ev, hostname))
                        seq = ev["metadata"]["sequence"]
                        write_cursor(cursor_file, seq)
                    if not events:
                        if once:
                            close_cleanly(s)
                            return seq
                        time.sleep(2)
        except (OSError, ssl.SSLError) as e:
            if once:
                raise
            sys.stderr.write(f"keyclerk.siem: syslog to {host}:{port} failed ({type(e).__name__}: {e}); retrying in "
                             f"{pause:.0f} s from seq {seq}\n")
            time.sleep(pause)
            pause = min(pause * 2, 60.0)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m keyclerk.siem", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("forward")
    f.add_argument("--store", required=True)
    f.add_argument("--config", required=True)
    f.add_argument("--once", action="store_true", help="send what is there, then exit")
    p = sub.add_parser("page")
    p.add_argument("--store", required=True)
    p.add_argument("--after", type=int, default=0)
    p.add_argument("--limit", type=int, default=50)
    a = ap.parse_args(argv)
    if a.cmd == "page":
        print(json.dumps(Feed(Path(a.store)).page(a.after, a.limit), indent=1))
        return 0
    from keyclerk import config
    cfg = (config.configure(a.config).get("siem") or {}).get("syslog")
    if not cfg:
        raise SystemExit("keyclerk.siem: no siem.syslog in the configuration: syslog is off")
    site = (config.current().get("siem") or {}).get("site", "keyclerk")
    seq = forward(Feed(Path(a.store), site), cfg, once=a.once)
    sys.stderr.write(f"keyclerk.siem: sent up to seq {seq}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
