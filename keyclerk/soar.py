# SPDX-License-Identifier: EUPL-1.2
"""SOAR webhooks (decision 0018 H5, issue 30): chosen events of the desk's activity log, sent signed to each endpoint
the configuration names, off unless configured.

Each event is a CloudEvents 1.0 envelope (id SITE:SEQ, type keyclerk.<noun>.<verb>.v1) whose data is the OCSF event the
SIEM export gives (keyclerk.siem), so a SOAR and a SIEM see the same event under the same id. It is POSTed with the
Standard Webhooks headers (webhook-id, webhook-timestamp, webhook-signature: v1, base64 of HMAC-SHA256 over
"id.timestamp.body" with the endpoint's secret), so a receiver checks it with any Standard Webhooks library and refuses
an old timestamp. Delivery is at least once and in order per endpoint: each keeps its own cursor (a seq of the log),
which moves past an event only once the endpoint answered 2xx, or when the endpoint did not ask for that type. An
endpoint that keeps failing holds its own queue and no other's.

    soar:
      webhooks:
        - url: https://soar.example.org/keyclerk
          secret_file: /etc/keyclerk/soar.secret     # whsec_ and base64, or 24 bytes or more of text
          events: [keyclerk.approval.waiting.v1, keyclerk.change.applied.v1]
          identities: pseudonyms                     # or anchors: the approvers' broker ids, to route reminders
    python -m keyclerk.soar forward --store DIR --config FILE [--once]

Types: keyclerk.change.{applied,refused,pending,withdrawn,expired,recovered}.v1 for changes,
keyclerk.approval.waiting.v1, keyclerk.change.expiring.v1 and keyclerk.approval.escalated.v1 for the reminders (decision
0030 point 2; data.unmapped.keyclerk.approvers names the next approvers, as pseudonyms unless the endpoint is configured
for anchors), keyclerk.edge.incident.v1 and keyclerk.console.grant.v1 for findings, keyclerk.activity.other.v1 for the
rest. A reminder carries no link or code that approves.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from keyclerk import siem

REMINDERS = {"approval_waiting": "keyclerk.approval.waiting.v1", "change_expiring": "keyclerk.change.expiring.v1",
             "approval_escalated": "keyclerk.approval.escalated.v1"}
FINDINGS = {"edge_incident": "keyclerk.edge.incident.v1", "console_grant": "keyclerk.console.grant.v1"}
OUTCOMES = ("applied", "refused", "pending", "withdrawn", "expired", "recovered")
TYPES = tuple(REMINDERS.values()) + tuple(FINDINGS.values()) + tuple(f"keyclerk.change.{o}.v1" for o in OUTCOMES) + (
    "keyclerk.activity.other.v1",)
MAX_SECRET = 4096


def event_type(line: dict) -> str:
    action, outcome = str(line.get("action") or ""), str(line.get("outcome") or "")
    if action in REMINDERS:
        return REMINDERS[action]
    if action in FINDINGS:
        return FINDINGS[action]
    if outcome in OUTCOMES:
        return f"keyclerk.change.{outcome}.v1"
    return "keyclerk.activity.other.v1"


def envelope(feed: siem.Feed, seq: int, line: dict, identities: str = "pseudonyms") -> dict:
    data = feed.event(seq, line)
    if line.get("action") in REMINDERS:
        who = [str(a) for a in (line.get("approvers") or []) if isinstance(a, str)]
        data["unmapped"]["keyclerk"].update({
            "approvers": who if identities == "anchors" else [feed.pseudonym(a) for a in who],
            "waiting_since": line.get("waiting_since"), "ends": line.get("ends")})
    return {"specversion": "1.0", "id": f"{feed.site}:{seq}", "source": f"keyclerk/{feed.site}",
            "type": event_type(line), "time": line.get("at"), "datacontenttype": "application/json", "data": data}


def secret(path: str) -> bytes:
    raw = Path(path).read_text(encoding="utf-8").strip()[:MAX_SECRET]
    key = base64.b64decode(raw[6:], validate=True) if raw.startswith("whsec_") else raw.encode("utf-8")
    if len(key) < 24:
        raise ValueError(f"the webhook secret in {path} is shorter than 24 bytes")
    return key


def sign(key: bytes, msg_id: str, ts: int, body: bytes) -> str:
    """The Standard Webhooks v1 signature: base64(HMAC-SHA256(key, id.timestamp.body))."""
    mac = hmac.new(key, f"{msg_id}.{ts}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(mac).decode("ascii")


def post(url: str, body: bytes, headers: dict, timeout: float = 10.0) -> int:
    req = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": "application/json",
                                                                          "User-Agent": "keyclerk-soar", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:      # noqa: S310 - the configured endpoint
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def cursor_file(feed: siem.Feed, hook: dict) -> Path:
    return Path(hook.get("cursor_file") or feed.store / f"soar-{hashlib.sha256(hook['url'].encode()).hexdigest()[:12]}.cursor")


def deliver(feed: siem.Feed, hook: dict, key: bytes, send=post, clock=time.time) -> tuple[int, str | None]:
    """One pass for one endpoint: the events after its cursor, in order, until the log's end or a failure. Returns the
    seq reached and why it stopped early (None at the end)."""
    cur = cursor_file(feed, hook)
    seq, wanted = siem.read_cursor(cur), set(hook.get("events") or ())
    while True:
        page = feed.entries(seq, 100)
        if not page:
            return seq, None
        for n, line in page:
            if event_type(line) in wanted:
                body = json.dumps(envelope(feed, n, line, hook.get("identities", "pseudonyms")), sort_keys=True,
                                  separators=(",", ":")).encode("utf-8")
                ts, mid = int(clock()), f"{feed.site}:{n}"
                try:
                    status = send(hook["url"], body, {"webhook-id": mid, "webhook-timestamp": str(ts),
                                                      "webhook-signature": sign(key, mid, ts, body)})
                except OSError as e:
                    status, why = 0, f"{type(e).__name__}: {e}"
                if not 200 <= status < 300:
                    siem.write_cursor(cur, seq)
                    return seq, why if status == 0 else f"the endpoint answered {status}"
            seq = n
        siem.write_cursor(cur, seq)


def forward(feed: siem.Feed, hooks: list[dict], once: bool = False, send=post) -> dict:
    """Every endpoint in turn; once: one pass each. Otherwise poll, a failing endpoint waiting longer each time."""
    keys = {h["url"]: secret(h["secret_file"]) for h in hooks}
    pause = {h["url"]: 0.0 for h in hooks}
    due = {h["url"]: 0.0 for h in hooks}
    while True:
        out = {}
        for h in hooks:
            if time.monotonic() < due[h["url"]] and not once:
                continue
            seq, why = deliver(feed, h, keys[h["url"]], send)
            out[h["url"]] = {"seq": seq, "stopped": why}
            if why:
                pause[h["url"]] = min(max(pause[h["url"]] * 2, 1.0), 300.0)
                due[h["url"]] = time.monotonic() + pause[h["url"]]
                sys.stderr.write(f"keyclerk.soar: {h['url']}: {why}; retrying from seq {seq} in "
                                 f"{pause[h['url']]:.0f} s\n")
            else:
                pause[h["url"]] = 0.0
        if once:
            return out
        time.sleep(2)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m keyclerk.soar", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("forward")
    f.add_argument("--store", required=True)
    f.add_argument("--config", required=True)
    f.add_argument("--once", action="store_true", help="one pass for each endpoint, then exit")
    a = ap.parse_args(argv)
    from keyclerk import config
    cfg = config.configure(a.config)
    hooks = ((cfg.get("soar") or {}).get("webhooks")) or []
    if not hooks:
        raise SystemExit("keyclerk.soar: no soar.webhooks in the configuration: webhooks are off")
    out = forward(siem.Feed(Path(a.store), (cfg.get("siem") or {}).get("site", "keyclerk")), hooks, once=a.once)
    sys.stderr.write(json.dumps(out) + "\n")
    return 0 if all(not v["stopped"] for v in out.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
