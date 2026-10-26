# SPDX-License-Identifier: EUPL-1.2
"""The public scan budget forgets quiet addresses: a full table never refuses everyone for good."""
import threading
from http.server import ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from tests.test_api import FIXTURES, FakeAuth, req  # noqa: F401

from keyclerk import api
from keyclerk.desk import Desk, Store

DIRK = {"sub": "s-dirk", "name": "dirk", "anchor": "idp:44aa-dirk", "roles": [], "csrf": "csrf-dirk"}


class Auth(FakeAuth):
    sessions = {**FakeAuth.sessions, "dirk": DIRK}


def start(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    desk = Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.handler(desk, Auth(), {"desk.test"}, ("other-front-end",), False))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}", desk


from urllib.parse import urlparse



from keyclerk import api


def test_old_addresses_are_forgotten(tmp_path, monkeypatch):
    s, base, desk = start(tmp_path)
    s.shutdown()
    monkeypatch.setattr(desk, "scan", lambda token: {"unescorted": False})
    H = api.handler(desk, Auth(), {"desk.test"}, ("other-front-end",), False)
    h = H.__new__(H)
    h._json = lambda status, obj: status
    clock = [1000.0]
    monkeypatch.setattr(api.time, "monotonic", lambda: clock[0])
    u = urlparse("/api/v1/scan/not-a-code")
    for i in range(10002):
        h.client_address = (f"2001:db8::{i:x}", 0)
        try:
            h._public_visit(u)
        except api.ApiError:
            pass
    clock[0] += 3600                                              # an hour later, a phone never seen before
    h.client_address = ("192.0.2.7", 0)
    try:
        status = h._public_visit(u)
    except api.ApiError as e:
        status = e.status
    assert status == 200, status                                  # FAILS: 429 for good
