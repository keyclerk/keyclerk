# SPDX-License-Identifier: EUPL-1.2
"""The API is the contract every front end uses: the server's routes, the bundled front end's calls and every response
are held to schema/api.openapi.json, and the HTTP seam refuses what it must."""
import json
import re
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import api
from keyclerk.desk import Desk, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
UI = Path(api.__file__).resolve().parent / "ui"
C = api.contract()

ANN = {"sub": "s-ann", "name": "ann", "anchor": "idp:7c1f-ann", "roles": [], "csrf": "csrf-ann"}
EVA = {"sub": "s-eva", "name": "eva", "anchor": "idp:55bb-eva", "roles": [], "csrf": "csrf-eva"}
STRANGER = {"sub": "s-x", "name": "x", "anchor": None, "roles": [], "csrf": "csrf-x"}


class FakeAuth:
    """Sessions by cookie value; bearer tokens by value."""
    viewer_role = "keyclerk-viewer"
    sessions = {"ann": ANN, "eva": EVA, "stranger": STRANGER}

    def who(self, cookie):
        return self.sessions.get(cookie)

    def bearer(self, token, clients):
        if token == "good-token" and "other-front-end" in clients:
            return {**EVA, "csrf": None}
        raise ValueError("bad token")


def validate(obj, name):
    jsonschema.Draft202012Validator({"$ref": f"#/components/schemas/{name}", "components": C["components"]}).validate(obj)


@pytest.fixture
def server(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    desk = Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), api.handler(desk, FakeAuth(), {"desk.test"}, ("other-front-end",), False))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", tmp_path
    srv.shutdown()


def req(base, method, path, body=None, cookie=None, csrf=None, headers=None, raw=None, ctype="application/json"):
    h = {"Host": "desk.test", **({"Cookie": f"keyclerk_session={cookie}"} if cookie else {}),
         **({"X-KeyClerk-CSRF": csrf} if csrf else {}), **({"Content-Type": ctype} if method == "POST" else {}), **(headers or {})}
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else (b"{}" if method == "POST" else None))
    try:
        with urllib.request.urlopen(urllib.request.Request(base + path, data=data, method=method, headers=h), timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# --- the contract ---------------------------------------------------------------------------------------------------

def test_the_server_routes_are_exactly_the_contract():
    routes = {(m, p) for m, p, _ in api.ROUTES}
    contract = {(m.upper(), p) for p, ops in C["paths"].items() for m in ops}
    assert routes == contract


def test_the_bundled_front_end_calls_only_the_contract_and_never_builds_html_from_data():
    js = (UI / "app.js").read_text(encoding="utf-8")
    block = js[js.index("const CALLS = {"):js.index("};", js.index("const CALLS = {"))]
    calls = {(m, p) for m, p in re.findall(r'\["(GET|POST)", "([^"]+)"\]', block)}
    contract = {(m.upper(), p) for p, ops in C["paths"].items() for m in ops}
    assert calls and calls <= contract
    assert js.count("fetch(") == 1                                            # one way out: call()
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert bad not in js, bad
    page = (UI / "index.html").read_text(encoding="utf-8")
    assert "<script>" not in page and "style=" not in page                     # nothing inline: the CSP allows none


def test_every_response_matches_the_contract(server):
    base, _ = server
    for path, name in (("/api/v1/me", "Me"), ("/api/v1/groups/office-staff", "GroupDetail"),
                       ("/api/v1/changes", "Changes"), ("/api/v1/broker", "Broker"),
                       ("/api/v1/people/idp:7c1f-ann", "PersonAccess")):
        code, _, body = req(base, "GET", path, cookie="ann")
        assert code == 200, (path, body)
        validate(json.loads(body), name)
    for path, name in (("/api/v1/people", "Person"), ("/api/v1/groups", "Group"), ("/api/v1/delegations", "Delegation")):
        code, _, body = req(base, "GET", path, cookie="ann")
        for item in json.loads(body):
            validate(item, name)
    code, _, body = req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "office-staff",
                                                          "anchor": "idp:66cc-finn", "days": 30}, cookie="ann", csrf="csrf-ann")
    assert code == 200 and json.loads(body)["outcome"] == "applied"
    validate(json.loads(body), "ChangeResult")
    code, _, body = req(base, "GET", "/api/v1/nowhere", cookie="ann")
    assert code == 404
    validate(json.loads(body), "Error")


# --- acting through the API -----------------------------------------------------------------------------------------

def test_a_change_that_needs_a_second_key_waits_and_another_persons_key_completes_it(server):
    base, _ = server
    code, _, body = req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "finance",
                                                          "anchor": "idp:44aa-dirk"}, cookie="ann", csrf="csrf-ann")
    r = json.loads(body)
    assert r["outcome"] == "pending" and "second key" in r["reasons"][0]
    code, _, body = req(base, "POST", f"/api/v1/changes/{r['change_id']}/approve", cookie="ann", csrf="csrf-ann")
    assert code == 422 and "you proposed" in json.loads(body)["error"]["message"]
    code, _, body = req(base, "POST", f"/api/v1/changes/{r['change_id']}/approve", cookie="eva", csrf="csrf-eva")
    assert code == 200 and json.loads(body)["outcome"] == "applied"
    code, _, body = req(base, "GET", "/api/v1/groups/finance", cookie="ann")
    assert "idp:44aa-dirk" in [m["anchor"] for m in json.loads(body)["effective_members"]]


def test_the_engine_refuses_with_reasons_and_powers_are_never_widened(server):
    base, _ = server
    code, _, body = req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "office-staff",
                                                          "anchor": "idp:7c1f-ann"}, cookie="ann", csrf="csrf-ann")
    assert json.loads(body)["outcome"] == "refused" and "added themselves" in json.loads(body)["reasons"][0]
    code, _, body = req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "finance",
                                                          "anchor": "idp:66cc-finn"}, cookie="eva", csrf="csrf-eva")
    assert code == 422 and "no delegation" in json.loads(body)["error"]["message"]


# --- the seam -------------------------------------------------------------------------------------------------------

def test_the_seam_refuses_what_it_must(server):
    base, tmp = server
    add = {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn"}
    assert req(base, "GET", "/api/v1/me")[0] == 401                                       # not signed in
    assert req(base, "GET", "/api/v1/me", cookie="ann", headers={"Host": "evil.example"})[0] == 400
    assert req(base, "POST", "/api/v1/changes", add, cookie="ann")[0] == 403               # no CSRF header
    assert req(base, "POST", "/api/v1/changes", add, cookie="ann", csrf="csrf-eva")[0] == 403
    assert req(base, "POST", "/api/v1/changes", add, cookie="ann", csrf="csrf-ann",
               headers={"Origin": "https://evil.example"})[0] == 403
    assert req(base, "POST", "/api/v1/changes", {**add, "extra": 1}, cookie="ann", csrf="csrf-ann")[0] == 400
    assert req(base, "POST", "/api/v1/changes", add, cookie="ann", csrf="csrf-ann", ctype="text/plain")[0] == 415
    try:                                  # refused before the body is read: a 413, or under load the reset comes first
        assert req(base, "POST", "/api/v1/changes", cookie="ann", csrf="csrf-ann", raw=b"{" * 70000)[0] == 413
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
        pass
    assert req(base, "POST", "/api/v1/changes", cookie="ann", csrf="csrf-ann", raw=b'{"a": NaN}')[0] == 400
    assert req(base, "POST", "/api/v1/changes", {**add, "anchor": "uid:1234"}, cookie="ann", csrf="csrf-ann")[0] == 400
    assert req(base, "GET", "/api/v1/me", cookie="stranger")[0] == 403                     # signed in, not a person here
    assert req(base, "GET", "/api/v1/people/idp:55bb-eva", cookie="ann")[0] == 403         # not her own access
    assert req(base, "PUT", "/api/v1/changes", cookie="ann", csrf="csrf-ann")[0] == 405
    code, headers, _ = req(base, "GET", "/")
    assert code == 200 and "script-src 'self'" in headers["Content-Security-Policy"] and headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_a_front_end_with_its_own_client_uses_bearer_tokens_without_csrf(server):
    base, _ = server
    code, _, body = req(base, "GET", "/api/v1/me", headers={"Authorization": "Bearer good-token"})
    assert code == 200 and json.loads(body)["person"] == "eva" and json.loads(body)["csrf"] is None
    assert req(base, "GET", "/api/v1/me", headers={"Authorization": "Bearer forged"})[0] == 401


def test_the_records_written_are_signed_and_the_log_chains(server):
    base, tmp = server
    req(base, "POST", "/api/v1/changes", {"action": "create_group", "parent": "office", "group_id": "helpdesk"},
        cookie="ann", csrf="csrf-ann")
    store = tmp / "store"
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as K
    key = K.from_private_bytes(bytes.fromhex((tmp / "key").read_text(encoding="utf-8")))
    key.public_key().verify(bytes.fromhex((store / "records.yaml.sig").read_text()), (store / "records.yaml").read_bytes())
    code, _, body = req(base, "GET", "/api/v1/broker", cookie="ann")
    assert json.loads(body)["log_intact"] and json.loads(body)["revision"] == 2
    log = (store / "log.jsonl").read_text(encoding="utf-8").splitlines()
    tampered = json.loads(log[-1])
    tampered["actor"] = "idp:2b9e-owner"
    (store / "log.jsonl").write_text("\n".join(log[:-1] + [json.dumps(tampered, sort_keys=True)]) + "\n", encoding="utf-8")
    assert not json.loads(req(base, "GET", "/api/v1/broker", cookie="ann")[2])["log_intact"]


def test_a_flood_gets_429_in_the_contracts_error_shape(server, monkeypatch):
    from keyclerk import desk as desk_module
    monkeypatch.setattr(desk_module, "WRITES_PER_WINDOW", 2)
    base, _ = server
    codes = [req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "finance", "anchor": "idp:66cc-finn"},
                 cookie="eva", csrf="csrf-eva") for _ in range(3)]
    assert [c[0] for c in codes] == [422, 422, 429]
    body = json.loads(codes[2][2])
    validate(body, "Error")
    assert body["error"]["code"] == "rate_limited"


def test_idle_connections_are_dropped_and_the_number_open_is_bounded(tmp_path, monkeypatch):
    import socket
    import time
    from keyclerk import httpserve
    monkeypatch.setattr(api, "SOCKET_SECONDS", 1)

    def closed(s):
        try:
            return s.recv(64) == b""
        except ConnectionError:
            return True
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(), encoding="utf-8")
    desk = Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"))
    srv = httpserve.Server(("127.0.0.1", 0), api.handler(desk, FakeAuth(), {"desk.test"}, (), False), max_connections=3)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        addr = srv.server_address
        held = [socket.create_connection(addr, timeout=5) for _ in range(3)]
        for s in held:
            s.send(b"GET /api/v1/me HTTP/1.1\r\nHost: desk.test\r\n")     # never finished
        extra = socket.create_connection(addr, timeout=5)
        extra.send(b"GET /api/v1/openapi.json HTTP/1.1\r\nHost: desk.test\r\n\r\n")
        assert closed(extra)                                               # past the bound: closed at once
        time.sleep(2)
        assert all(closed(s) for s in held)                                # silent ones were dropped
        code, _, _ = req(f"http://{addr[0]}:{addr[1]}", "GET", "/api/v1/openapi.json")
        assert code == 200
    finally:
        srv.shutdown()


def test_the_committed_contract_is_what_the_generator_writes():
    import subprocess
    import sys
    root = Path(api.__file__).resolve().parent.parent
    r = subprocess.run([sys.executable, str(root / "tools" / "gen_api_contract.py"), "--check"], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout


def test_a_slow_sender_holds_only_its_own_connection(server):
    import socket
    import time
    base, _ = server
    host, port = base[7:].split(":")
    slow = []
    for _ in range(api.MAX_CONCURRENT + 4):                              # more than there are workers
        s = socket.create_connection((host, int(port)), timeout=5)
        s.send(b"POST /api/v1/changes HTTP/1.1\r\nHost: desk.test\r\nContent-Type: application/json\r\n"
               b"Cookie: keyclerk_session=ann\r\nX-KeyClerk-CSRF: csrf-ann\r\nContent-Length: 500\r\n\r\n{\"ac")
        slow.append(s)
    time.sleep(0.5)
    t0 = time.time()
    code, _, _ = req(base, "GET", "/api/v1/me", cookie="ann")
    # held behind the slow senders it would wait their socket timeout (15 s); a wide bound keeps this true under load
    assert code == 200 and time.time() - t0 < 5
    for s in slow:
        s.close()


def test_one_person_cannot_hold_every_worker(server, monkeypatch):
    import time
    from keyclerk.desk import Desk as RealDesk
    base, _ = server
    real = RealDesk.me

    def slow_me(self, who):
        time.sleep(1)
        return real(self, who)
    monkeypatch.setattr(RealDesk, "me", slow_me)
    out = []
    th = [threading.Thread(target=lambda: out.append(req(base, "GET", "/api/v1/me", cookie="ann")[0]))
          for _ in range(api.PER_PERSON + 3)]
    [t.start() for t in th]
    time.sleep(0.3)
    t0 = time.time()
    other = req(base, "GET", "/api/v1/me", cookie="eva")[0]               # someone else still gets in
    took = time.time() - t0                                               # eva's own request, not the joins after it
    [t.join() for t in th]
    assert other == 200 and took < 1.9
    assert out.count(429) == 3 and out.count(200) == api.PER_PERSON


def test_a_preview_answers_like_a_change_but_writes_nothing_and_counts_against_the_limit(server, monkeypatch):
    from keyclerk import desk as desk_module
    base, tmp = server
    log_before = (tmp / "store" / "log.jsonl").read_bytes()
    code, _, body = req(base, "POST", "/api/v1/changes/preview", {"action": "add_member", "group": "finance",
                                                                  "anchor": "idp:44aa-dirk"}, cookie="ann", csrf="csrf-ann")
    r = json.loads(body)
    assert code == 200 and r["outcome"] == "pending" and "second key" in r["reasons"][0]
    validate(r, "Preview")
    assert (tmp / "store" / "log.jsonl").read_bytes() == log_before and not (tmp / "store" / "pending.json").exists()
    code, _, _ = req(base, "POST", "/api/v1/changes/preview", {"action": "add_member"}, cookie="ann")   # no CSRF
    assert code == 403
    monkeypatch.setattr(desk_module, "WRITES_PER_WINDOW", 1)
    code, _, body = req(base, "POST", "/api/v1/changes/preview", {"action": "add_member", "group": "office-staff",
                                                                  "anchor": "idp:66cc-finn"}, cookie="ann", csrf="csrf-ann")
    assert code == 429


def test_another_site_cannot_sign_you_out(server):
    base, _ = server
    code, _, _ = req(base, "GET", "/logout", headers={"Sec-Fetch-Site": "cross-site"})
    assert code == 403


def test_the_contract_is_served_without_sign_in_and_explains_every_change_field():
    for name, s in C["components"]["schemas"].items():
        if name.startswith("Request_"):
            assert s.get("description"), name
            assert all(v.get("description") for k, v in s["properties"].items() if k != "action"), name
    assert set(C["components"]["schemas"]["Error"]["properties"]["error"]["properties"]["code"]["x-meanings"]) == \
        set(C["components"]["schemas"]["Error"]["properties"]["error"]["properties"]["code"]["enum"])


def test_the_api_page_never_prints_a_secret():
    js = (UI / "app.js").read_text(encoding="utf-8")
    assert "JSON.stringify(redact(obj)" in js and 'k === "csrf"' in js       # every shown result goes through redact
    assert js.count('h("pre"') == 3 and "jsonBlock" in js                    # results (redacted) and two curl blocks
    assert "Bearer $TOKEN" in js and "document.cookie" not in js



def test_an_approval_carries_its_proof_in_a_small_fixed_body(server):
    base, _ = server
    code, _, body = req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "finance",
                                                          "anchor": "idp:44aa-dirk"}, cookie="ann", csrf="csrf-ann")
    cid = json.loads(body)["change_id"]
    code, _, body = req(base, "GET", f"/api/v1/changes/{cid}/statement", cookie="eva")
    st = json.loads(body)
    validate(st, "Statement")
    assert code == 200 and st["by"] == "idp:55bb-eva" and len(st["nonce"]) == 43
    for bad in ({"proof": 5}, {"proof": "x", "more": 1}, ["x"]):
        code, _, _ = req(base, "POST", f"/api/v1/changes/{cid}/approve", bad, cookie="eva", csrf="csrf-eva")
        assert code == 400
    code, _, body = req(base, "POST", f"/api/v1/changes/{cid}/approve", {"proof": "not-a-token"}, cookie="eva", csrf="csrf-eva")
    assert code == 422 and "cannot verify" in json.loads(body)["error"]["message"]     # a proof never passes unchecked


def test_kc64_an_approval_never_starts_from_a_link_or_a_bearer_token(server):
    base, _ = server
    code, _, body = req(base, "GET", "/approve/C-anything", cookie="eva")
    assert code == 404 and b"Approvals page" in body                        # a link alone starts nothing
    code, _, body = req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "finance",
                                                          "anchor": "idp:44aa-dirk"}, cookie="ann", csrf="csrf-ann")
    cid = json.loads(body)["change_id"]
    code, _, _ = req(base, "POST", f"/api/v1/changes/{cid}/approval-sign-in", cookie="eva")            # no CSRF header
    assert code == 403
    code, _, body = req(base, "POST", f"/api/v1/changes/{cid}/approval-sign-in", headers={"Authorization": "Bearer good-token"})
    assert code == 403 and "another front end" in json.loads(body)["error"]["message"]


def test_a_visit_registered_through_the_api_passes_the_contract(server):
    """0.13.1: a request shaped as the desk expects passes the contract (an object schema once required every field)."""
    from datetime import datetime, timedelta, timezone
    base, _ = server
    day = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(days=1)
    iso = lambda t: t.isoformat().replace("+00:00", "Z")   # noqa: E731
    body = {"action": "register_visit", "place": "place:heverlee", "purpose": "contract check",
            "start": iso(day), "end": iso(day + timedelta(hours=1)),
            "attendees": [{"anchor": "ext:3a71-carla", "kit": [{"class": "bag", "count": 1}]},
                          {"name": "someone invited"}, {"unregistered": True, "label": "companion"}],
            "delegation": {"name": "Example Networks"}, "vehicles": [{"plate": "2-XXX-111", "driver": 1}]}
    code, _, out = req(base, "POST", "/api/v1/changes/preview", body, cookie="ann", csrf="csrf-ann")
    assert code == 200, out


def test_odd_methods_and_crowded_queries_get_a_plain_answer(server):
    """Found by fuzzing the contract: TRACE and friends got the HTTP server's HTML 501, and a query with many fields a
    500. Both are the caller's business: a JSON 405 and a 400."""
    base, _ = server
    for method in ("TRACE", "OPTIONS", "HEAD", "PUT", "DELETE", "PATCH"):
        code, _, _ = req(base, method, "/api/v1/me", cookie="ann")
        assert code == 405, method
    code, _, out = req(base, "GET", "/api/v1/people/idp:7c1f-ann/graph?a=1&b=2&c=3&d=4&e=5&f=6", cookie="ann")
    assert code == 400, out


def test_a_credential_that_is_not_understood_never_falls_back_to_the_session(server):
    """Found by fuzzing: an invalid Authorization header beside a valid session cookie was served on the cookie."""
    base, _ = server
    code, _, _ = req(base, "GET", "/api/v1/me", cookie="ann", headers={"Authorization": "Basic Zm9vOmJhcg=="})
    assert code == 401
    code, _, _ = req(base, "GET", "/api/v1/me", cookie="ann", headers={"Authorization": " "})
    assert code == 401                                    # presented, even blank, binds
    for method in ("TRACE", "QUERY", "BREW"):             # any method without a handler: the JSON 405, never a 501
        code, _, _ = req(base, method, "/api/v1/me", cookie="ann")
        assert code == 405, method



def test_a_waiting_change_says_what_it_changes_before_anyone_signs(server):
    """Desk UI slice 3 (desk-upgrade.md C2): the broker's sign-in page does not show the change, so the desk shows it,
    record by record, and the contract describes it."""
    base, _ = server
    code, _, body = req(base, "POST", "/api/v1/changes", {"action": "add_member", "group": "finance",
                                                          "anchor": "idp:44aa-dirk"}, cookie="ann", csrf="csrf-ann")
    cid = json.loads(body)["change_id"]
    code, _, body = req(base, "GET", "/api/v1/changes", cookie="eva")
    c = next(x for x in json.loads(body)["pending"] if x["change_id"] == cid)
    validate(c, "PendingChange")
    line = c["what"][0]
    assert line["kind"] == "membership" and line["group"] == "finance" and line["member"] == "idp:44aa-dirk"
    assert line["member_name"] and line["end"] and line["risk"] in ("low", "elevated", "privileged") and line["under"].endswith("root")
    for e in json.loads(body)["log"]:
        validate(e, "LogEntry")


def test_the_desk_serves_its_icons_from_the_brand(server):
    """The favicon set (brand/build_icons.py) is served as static files, named in the page, and equals the brand's."""
    base, _ = server
    for path, ctype in (("/favicon.svg", "image/svg+xml"), ("/favicon.ico", "image/x-icon"),
                        ("/apple-touch-icon.png", "image/png"), ("/mark-light.svg", "image/svg+xml"),
                        ("/mark-dark.svg", "image/svg+xml")):
        status, headers, body = req(base, "GET", path)
        assert status == 200 and headers["Content-Type"] == ctype, path
        assert body == (UI / path.lstrip("/")).read_bytes()
        name = path.lstrip("/")
        brand = Path(__file__).resolve().parent.parent / "brand" / (
            "mark/keyclerk-" + name if name.startswith("mark-") else "icons/" + name)
        assert body == brand.read_bytes(), f"{path} differs from {brand.name}: copy it after the brand build"
        if path.endswith(".svg"):
            assert b"<style" not in body and b"<script" not in body, f"{path}: no style or script (CSP)"
    page = (UI / "index.html").read_text(encoding="utf-8")
    assert 'href="/favicon.svg"' in page and 'href="/apple-touch-icon.png"' in page
