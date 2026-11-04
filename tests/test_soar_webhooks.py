# SPDX-License-Identifier: EUPL-1.2
"""Issue 30 (decision 0018 H5): chosen events go to each SOAR endpoint as CloudEvents holding the SIEM's OCSF event,
signed per Standard Webhooks, at least once and in order; a failing endpoint holds its own queue and loses nothing."""
import base64
import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from keyclerk import siem, soar
from tests.test_siem import ANCHOR, _note, store  # noqa: F401 - fixture

KEY = b"k" * 32


def _receiver(fail=0):
    got, left = [], [fail]

    class H(BaseHTTPRequestHandler):
        def do_POST(self):   # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            if left[0] > 0:
                left[0] -= 1
                self.send_response(503)
                self.end_headers()
                return
            got.append(({k.lower(): v for k, v in self.headers.items()}, body))
            self.send_response(204)
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, got


def _hook(tmp_path, srv, events, **kw):
    (tmp_path / "secret").write_text("whsec_" + base64.b64encode(KEY).decode())
    return {"url": f"http://127.0.0.1:{srv.server_address[1]}/hook", "secret_file": str(tmp_path / "secret"),
            "events": events, **kw}


def _verified(headers, body):
    """What a receiver does with a Standard Webhooks library."""
    mid, ts = headers["webhook-id"], headers["webhook-timestamp"]
    want = base64.b64encode(hmac.new(KEY, f"{mid}.{ts}.".encode() + body, hashlib.sha256).digest()).decode()
    assert headers["webhook-signature"] == "v1," + want
    return json.loads(body)


def test_chosen_events_arrive_signed_once_and_in_order(store, tmp_path):
    _note(store, 9)
    srv, got = _receiver()
    hook = _hook(tmp_path, srv, ["keyclerk.change.applied.v1"])
    out = soar.forward(siem.Feed(store.path), [hook], once=True)
    _note(store, 3, 9)
    soar.forward(siem.Feed(store.path), [hook], once=True)
    srv.shutdown()
    events = [_verified(h, b) for h, b in got]
    seqs = [int(e["id"].split(":")[1]) for e in events]
    assert seqs == sorted(set(seqs)) and all(e["type"] == "keyclerk.change.applied.v1" for e in events)
    applied = [e for _, e in siem.Feed(store.path).entries(0, 500) if e.get("outcome") == "applied"]
    assert len(events) == len(applied) and out[hook["url"]]["stopped"] is None
    assert events[0]["specversion"] == "1.0" and events[0]["data"]["class_uid"] in (3006, 3004)
    assert ANCHOR not in json.dumps(events)


def test_a_failing_endpoint_retries_from_where_it_stopped(store, tmp_path):
    _note(store, 4)
    srv, got = _receiver(fail=1)
    hook = _hook(tmp_path, srv, list(soar.TYPES))
    first = soar.forward(siem.Feed(store.path), [hook], once=True)[hook["url"]]
    assert first["stopped"] == "the endpoint answered 503" and got == []
    second = soar.forward(siem.Feed(store.path), [hook], once=True)[hook["url"]]
    srv.shutdown()
    assert second["stopped"] is None
    seqs = [int(_verified(h, b)["id"].split(":")[1]) for h, b in got]
    assert seqs == list(range(1, second["seq"] + 1))                   # nothing lost, nothing repeated


def test_reminders_name_approvers_as_pseudonyms_unless_the_endpoint_routes_people(store, tmp_path):
    store.note({"change_id": "C-r", "action": "approval_waiting", "actor": None, "outcome": "reminder", "records": {},
                "reasons": [], "summary": "approval waiting: C-r", "approvers": [ANCHOR], "ends": "2026-11-11T12:00:00Z",
                "waiting_since": "2026-11-04T12:00:00Z"})
    srv, got = _receiver()
    t = ["keyclerk.approval.waiting.v1"]
    soar.forward(siem.Feed(store.path), [_hook(tmp_path, srv, t)], once=True)
    soar.forward(siem.Feed(store.path), [_hook(tmp_path, srv, t, identities="anchors",
                                               cursor_file=str(tmp_path / "routing.cursor"))], once=True)
    srv.shutdown()
    pseud, real = (_verified(h, b)["data"]["unmapped"]["keyclerk"]["approvers"] for h, b in got)
    assert pseud[0].startswith("person-pseudonym:") and real == [ANCHOR]
    assert all("http" not in json.dumps(_verified(h, b)["data"]) for h, b in got)   # no link that approves


def test_the_types_and_secrets_are_checked(tmp_path):
    from keyclerk import config
    (tmp_path / "short").write_text("too short")
    with pytest.raises(ValueError, match="shorter than 24"):
        soar.secret(str(tmp_path / "short"))
    good = {"url": "https://soar.example.org/k", "secret_file": "s", "events": ["keyclerk.change.applied.v1"]}
    base = config.current()
    assert config.validate({**base, "soar": {"webhooks": [good]}}) == []
    for bad in ({**good, "events": ["keyclerk.anything.v1"]}, {**good, "url": "http://soar.example.org/k"}):
        assert config.validate({**base, "soar": {"webhooks": [bad]}})
