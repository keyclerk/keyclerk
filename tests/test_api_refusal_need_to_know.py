# SPDX-License-Identifier: EUPL-1.2
"""An approve refusal names approvers only to someone the pending view would show them to."""
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


import json

import pytest



@pytest.fixture
def srv(tmp_path):
    s, base, desk = start(tmp_path)
    yield base
    s.shutdown()


def test_the_subject_learns_the_approvers_the_view_withholds(srv):
    code, _, out = req(srv, "POST", "/api/v1/changes", {"action": "add_member", "group": "finance",
                                                        "anchor": "idp:44aa-dirk", "days": 30}, cookie="ann", csrf="csrf-ann")
    r = json.loads(out)
    assert r["outcome"] == "pending"
    _, _, out = req(srv, "GET", "/api/v1/changes", cookie="dirk")
    seen = next(c for c in json.loads(out)["pending"] if c["change_id"] == r["change_id"])
    assert seen["waiting_for"] == []                              # holds: the view withholds them from dirk
    code, _, out = req(srv, "POST", f"/api/v1/changes/{r['change_id']}/approve", cookie="dirk", csrf="csrf-dirk")
    assert code == 422
    named = {w["anchor"] for s in json.loads(out)["error"].get("next", []) for w in s.get("who", [])}
    assert named <= {"idp:2b9e-owner"}, named                     # FAILS: bert, eva, finn named
