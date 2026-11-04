# SPDX-License-Identifier: EUPL-1.2
"""Issue 29 (decision 0018 H4): the desk's activity log as OCSF events for a SIEM. A reader gets every event exactly
once across a desk restart through the seq cursor; syslog over TLS trusts only the pinned CA and resumes from a cursor
that moves only after each message is written; people are pseudonyms and reasons are classes, never text."""
import datetime as dt
import json
import socket
import ssl
import threading
import urllib.error
import urllib.request

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID

from keyclerk import health, siem
from keyclerk.desk import Store
from test_visits import FIXTURES

ANCHOR = "idp:7c1f-ann"


@pytest.fixture
def store(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    s = Store(tmp_path / "store", key, FIXTURES / "records.yaml")
    yield s
    s.close()


def _note(store, n, start=0):
    for i in range(start, start + n):
        store.note({"change_id": f"C-{i}", "action": "add_member" if i % 2 else "end_membership", "actor": ANCHOR,
                    "outcome": "applied" if i % 3 else "refused",
                    "reasons": ["no approver for idp:51aa-eva in group ops"] if i % 3 == 0 else []})


def _all(feed, after=0, limit=7):
    seen = []
    while True:
        page = feed.page(after, limit)
        if not page:
            return seen
        seen += page
        after = page[-1]["metadata"]["sequence"]


def test_a_reader_gets_every_event_once_across_a_restart(store):
    _note(store, 20)
    feed = siem.Feed(store.path)
    first = feed.page(0, 12)
    cursor = first[-1]["metadata"]["sequence"]
    _note(store, 10, 20)
    rest = _all(siem.Feed(store.path), cursor)                         # a new process: only the cursor survives
    seqs = [e["metadata"]["sequence"] for e in first + rest]
    total = feed.head()["seq"]
    assert seqs == list(range(1, total + 1)) and total >= 30           # no gap, no repeat (the seed's lines too)
    assert feed.head()["sha256"] == json.loads((store.path / "log.jsonl").read_text().splitlines()[-1])["sha256"]


def test_each_event_carries_its_chain_position_and_the_records_revision(store):
    _note(store, 3)
    lines = [json.loads(x) for x in (store.path / "log.jsonl").read_text().splitlines()]
    for ev, line in zip(siem.Feed(store.path).page(0, 500), lines, strict=True):
        k = ev["unmapped"]["keyclerk"]
        assert (k["line_seq"], k["prev"], k["sha256"], k["signature"], k["revision"]) == (
            line["seq"], line["prev"], line["sha256"], line["signature"], line["revision"])


def test_people_are_pseudonyms_and_reasons_are_classes(store):
    _note(store, 4)
    events = siem.Feed(store.path).page(0, 500)
    text = json.dumps(events)
    assert ANCHOR not in text and "idp:51aa-eva" not in text and "no approver" not in text
    mine = [e for e in events if e.get("actor")]
    assert mine and all(e["actor"]["user"]["uid"].startswith("person-pseudonym:keyclerk/") for e in mine)
    again = siem.Feed(store.path).page(0, 500)                          # the key is kept: the same pseudonym
    assert [e.get("actor") for e in again] == [e.get("actor") for e in events]
    refused = [e for e in events if e["status_id"] == 2]
    assert refused and all(e["unmapped"]["keyclerk"]["reason_classes"] for e in refused)


def test_events_are_ocsf_classes(store):
    _note(store, 2)
    store.note({"change_id": "C-x", "action": "edge_incident", "actor": None, "outcome": "applied",
                "summary": "drift on plant-a", "reasons": []})
    by_action = {e["unmapped"]["keyclerk"]["action"]: e for e in siem.Feed(store.path).page(0, 500)}
    assert (by_action["add_member"]["class_uid"], by_action["add_member"]["activity_id"]) == (3006, 3)
    assert (by_action["end_membership"]["class_uid"], by_action["end_membership"]["activity_id"]) == (3006, 4)
    inc = by_action["edge_incident"]
    assert inc["class_uid"] == 2004 and inc["finding_info"]["title"] == "drift on plant-a"
    assert all(e["type_uid"] == e["class_uid"] * 100 + e["activity_id"] for e in by_action.values())
    assert all(e["metadata"]["version"] == siem.OCSF_VERSION for e in by_action.values())


def test_a_line_still_being_written_waits(store):
    _note(store, 2)
    n = siem.Feed(store.path).head()["seq"]
    with (store.path / "log.jsonl").open("a", encoding="utf-8") as h:
        h.write('{"seq": 99, "half')
    assert siem.Feed(store.path).head()["seq"] == n and siem.Feed(store.path).page(n, 10) == []


def _get(port, path, token):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_the_pull_api_answers_the_reader_token_only(store):
    _note(store, 5)
    mgmt, reader = "m" * 40, "r" * 40
    srv = health.management_server(("127.0.0.1", 0), None, mgmt, (siem.Feed(store.path), reader))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        code, body = _get(port, "/audit/events?after=2&limit=2", reader)
        assert code == 200 and [e["metadata"]["sequence"] for e in body["events"]] == [3, 4] and body["next"] == 4
        assert _get(port, "/audit/events", mgmt)[0] == 401                # the management token does not read audit
        assert _get(port, "/metrics", reader)[0] == 401                   # nor the reader the metrics
        assert _get(port, "/audit/events?limit=501", reader)[0] == 400
    finally:
        srv.shutdown()
    with pytest.raises(ValueError, match="its own"):
        health.management_server(("127.0.0.1", 0), None, mgmt, (siem.Feed(store.path), mgmt))


# --- syslog over TLS --------------------------------------------------------------------------------------------------

def _ca(tmp_path, name):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    return key, cert


def _leaf(tmp_path, ca_key, ca_cert, tag):
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "siem.test")]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("siem.test")]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    c, k = tmp_path / f"{tag}.crt", tmp_path / f"{tag}.key"
    c.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    k.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, NoEncryption()))
    return c, k


def _receiver(cert, key):
    """A TLS syslog receiver on a free port: collects every message it gets."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    lsock = socket.create_server(("127.0.0.1", 0))
    got: list[bytes] = []

    def run():
        while True:
            try:
                conn, _ = lsock.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as s:
                    buf = b""
                    while chunk := s.recv(65536):
                        buf += chunk
                        while b" " in buf:
                            n, rest = buf.split(b" ", 1)
                            if len(rest) < int(n):
                                break
                            got.append(rest[:int(n)])
                            buf = rest[int(n):]
            except (ssl.SSLError, OSError):
                continue
    threading.Thread(target=run, daemon=True).start()
    return lsock, got


def test_syslog_over_tls_sends_each_event_once_and_resumes_from_the_cursor(store, tmp_path):
    ca_key, ca_cert = _ca(tmp_path, "test ca")
    (tmp_path / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    lsock, got = _receiver(*_leaf(tmp_path, ca_key, ca_cert, "siem"))
    cfg = {"host": "127.0.0.1", "port": lsock.getsockname()[1], "ca_file": str(tmp_path / "ca.pem"),
           "server_name": "siem.test", "cursor_file": str(tmp_path / "cursor")}
    _note(store, 5)
    first = siem.forward(siem.Feed(store.path), cfg, once=True)
    _note(store, 3, 5)
    second = siem.forward(siem.Feed(store.path), cfg, once=True)
    import time
    for _ in range(50):
        if len(got) >= second:
            break
        time.sleep(0.1)
    lsock.close()
    seqs = [json.loads(m.split(b" - ", 2)[-1])["metadata"]["sequence"] for m in got]
    assert seqs == list(range(1, second + 1)) and second == first + 3     # once each, in order, across two runs
    assert siem.read_cursor(tmp_path / "cursor") == second
    assert got[0].startswith(b"<") and b">1 " in got[0][:8]              # RFC 5424, version 1


def test_syslog_refuses_a_receiver_the_pinned_ca_did_not_sign(store, tmp_path):
    ca_key, ca_cert = _ca(tmp_path, "pinned ca")
    (tmp_path / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    other_key, other_cert = _ca(tmp_path, "another ca")
    lsock, got = _receiver(*_leaf(tmp_path, other_key, other_cert, "impostor"))
    cfg = {"host": "127.0.0.1", "port": lsock.getsockname()[1], "ca_file": str(tmp_path / "ca.pem"),
           "server_name": "siem.test", "cursor_file": str(tmp_path / "cursor")}
    _note(store, 3)
    with pytest.raises(ssl.SSLError):
        siem.forward(siem.Feed(store.path), cfg, once=True)
    lsock.close()
    assert got == [] and siem.read_cursor(tmp_path / "cursor") == 0       # nothing sent, the cursor did not move


def test_the_cursor_moves_only_after_a_message_is_written(store, tmp_path):
    _note(store, 4)

    class Breaks:
        def __init__(self):
            self.sent = 0

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def sendall(self, data):
            if self.sent == 2:
                raise OSError("the receiver went away")
            self.sent += 1
    with pytest.raises(OSError):
        siem.forward(siem.Feed(store.path), {"host": "x", "ca_file": str(FIXTURES / "records.yaml"),
                                             "cursor_file": str(tmp_path / "cursor")}, once=True, connect=Breaks)
    assert siem.read_cursor(tmp_path / "cursor") == 2


def test_the_siem_configuration_is_in_the_schema():
    from keyclerk import config
    doc = {**config.current(), "siem": {"reader_token_file": "reader.token",
                                        "syslog": {"host": "siem.example.org", "ca_file": "ca.pem"}}}
    assert config.validate(doc) == []
    assert config.validate({**doc, "siem": {"syslog": {"host": "siem.example.org"}}})       # no CA: refused


def test_pages_past_the_seek_index_points_are_exact(store):
    _note(store, 600)
    feed = siem.Feed(store.path)
    total = feed.head()["seq"]
    assert [e["metadata"]["sequence"] for e in _all(feed, 0, 97)] == list(range(1, total + 1))
    for after in (255, 256, 257, 511, 512, total - 1):                 # from the index, in any order
        page = feed.page(after, 3)
        assert [e["metadata"]["sequence"] for e in page] == list(range(after + 1, min(after + 3, total) + 1))
        assert all(e["unmapped"]["keyclerk"]["line_seq"] == e["metadata"]["sequence"] for e in page)
