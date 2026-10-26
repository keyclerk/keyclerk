# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk connectors: every connector passes the contract check; the SCIM connectors
run the real protocol against a small in-process SCIM service provider (users, groups, filters, paging, PATCH of
members) that also answers Keycloak's logout call."""
import hashlib
import hmac
import json
import re
import sys
import threading
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk.connectors.contract import BudgetExceeded, Capabilities, RateBudget, contract_check  # noqa: E402
from keyclerk.connectors.keycloak import KeycloakTarget, ScimTarget, display_name  # noqa: E402
from keyclerk.connectors.physical import OsdpTarget, PacsTarget  # noqa: E402
from keyclerk.connectors.sources import GitPeopleRegister, ScimSource  # noqa: E402
from keyclerk.piam import pacs  # noqa: E402
from keyclerk.piam.core import Allowlist, badge_hash, records_from_leases  # noqa: E402
from keyclerk.piam.osdp_controller import Controller, Door, SimTransport  # noqa: E402

T0 = datetime(2026, 10, 21, 9, 0, tzinfo=timezone.utc)


class Scim:
    """In-memory SCIM data plus Keycloak's logout endpoint."""

    def __init__(self):
        self.users, self.groups, self.logouts, self.roles = {}, {}, [], {}

    def add_user(self, anchor, dept=None, title=None, active=True, modified="2026-10-20T10:00:00Z"):
        uid = str(uuid.uuid4())
        u = {"id": uid, "externalId": anchor, "userName": anchor, "active": active, "meta": {"lastModified": modified}}
        if title:
            u["title"] = title
        if dept:
            u[ScimSource.ENT] = {"department": dept}
        self.users[uid] = u
        return uid


def serve(data: Scim):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=None):
            raw = json.dumps(body).encode() if body is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/scim+json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _list(self, items, q):
            f = q.get("filter", [""])[0]
            m = re.fullmatch(r'([\w.]+) (eq|gt) "([^"]*)"', f)    # linear: no two parts can take the same text
            if m:
                attr, op, val = m.groups()
                get = (lambda x: x.get("meta", {}).get("lastModified", "")) if attr == "meta.lastModified" else (lambda x: x.get(attr))
                items = [x for x in items if (get(x) == val if op == "eq" else (get(x) or "") > val)]
            start, count = int(q.get("startIndex", ["1"])[0]), int(q.get("count", ["100"])[0])
            page = items[start - 1:start - 1 + count]
            return {"totalResults": len(items), "startIndex": start, "itemsPerPage": len(page), "Resources": page}

        def do_GET(self):
            u = urlparse(self.path)
            q = parse_qs(u.query)
            parts = u.path.split("/")
            if "/admin/realms/" in u.path and u.path.endswith("/groups"):          # Keycloak's admin API
                return self._send(200, [{"id": g["id"], "name": g["displayName"], "attributes": g.get("attributes", {})}
                                        for g in data.groups.values()])
            if "/admin/realms/" in u.path and u.path.endswith("/role-mappings"):
                return self._send(200, data.roles.get(parts[-2], {}))
            if "/admin/realms/" in u.path and parts[-2] == "groups":
                g = data.groups.get(parts[-1])
                return self._send(200 if g else 404, {"id": g["id"], "name": g["displayName"], "path": "/" + g["displayName"],
                                                    "attributes": g.get("attributes", {})} if g else None)
            if "/admin/realms/" in u.path and u.path.endswith("/members"):
                g = data.groups.get(parts[-2], {})
                users = [data.users[m["value"]] for m in g.get("members", []) if m["value"] in data.users]
                return self._send(200, [{"id": x["id"], "username": x.get("userName"), "email": x.get("email"),
                                         "emailVerified": x.get("emailVerified"),
                                         "attributes": {"anchor": [x.get("externalId")]}} for x in users])
            if u.path.endswith("/Users"):
                return self._send(200, self._list(list(data.users.values()), q))
            if u.path.endswith("/Groups"):
                return self._send(200, self._list(list(data.groups.values()), q))
            if "/Users/" in u.path:
                x = data.users.get(parts[-1])
                return self._send(200 if x else 404, x)
            self._send(404)

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            if self.path.endswith("/Groups"):
                gid = str(uuid.uuid4())
                data.groups[gid] = {"id": gid, "displayName": body["displayName"], "members": []}
                return self._send(201, data.groups[gid])
            if self.path.endswith("/logout"):
                data.logouts.append(self.path.split("/")[-2])
                return self._send(204)
            self._send(404)

        def do_PUT(self):
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n) or b"{}")
            g = data.groups.get(self.path.split("/")[-1])
            if g is not None:
                g["attributes"] = body.get("attributes", {})
            self._send(204 if g else 404)

        def do_PATCH(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            g = data.groups.get(self.path.split("/")[-1])
            if not g:
                return self._send(404)
            for op in body["Operations"]:
                if op["op"] == "add":
                    for v in op["value"]:
                        if v["value"] not in [m["value"] for m in g["members"]]:
                            g["members"].append({"value": v["value"]})
                else:
                    uid = re.search(r'value eq "(.*)"', op["path"]).group(1)
                    g["members"] = [m for m in g["members"] if m["value"] != uid]
            self._send(204)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


@pytest.fixture()
def scim():
    data = Scim()
    srv, url = serve(data)
    yield data, url
    srv.shutdown()


def test_git_people_register_is_a_read_only_source(tmp_path):
    f = tmp_path / "people.yaml"
    f.write_text("people:\n  - {anchor: op:7a1e-oscar, unit: operator, function: operator}\n  - {anchor: op:former, active: false}\n", encoding="utf-8")
    src = GitPeopleRegister(path=f)
    people = src.read_full()
    assert people["op:7a1e-oscar"]["attributes"] == {"unit": "operator", "function": "operator"} and not people["op:former"]["active"]
    assert contract_check(src, None) == [] and src.validate({"path": tmp_path / "missing.yaml"})


def test_scim_source_pages_filters_and_verifies_events(scim):
    data, url = scim
    for i in range(5):
        data.add_user(f"idp:{i}", dept="finance", title="clerk", modified=f"2026-10-2{i}T10:00:00Z")
    src = ScimSource(base=url, anchor_from="externalId", page=2, webhook_key=b"k")
    full = src.read_full()
    assert len(full) == 5 and full["idp:3"]["attributes"] == {"unit": "finance", "function": "clerk"}
    delta, cursor = src.read_delta("2026-10-22T12:00:00Z")
    assert set(delta) == {"idp:3", "idp:4"} and cursor == "2026-10-24T10:00:00Z"
    raw = b'{"type":"user-changed"}'
    hd = {"webhook-id": "e1", "webhook-timestamp": "1700000000"}
    hd["webhook-signature"] = hmac.new(b"k", b"e1.1700000000." + raw, hashlib.sha256).hexdigest()
    assert src.verify_event(raw, hd) == {"type": "user-changed"}
    assert src.verify_event(raw, {**hd, "webhook-signature": "00"}) is None
    assert src.validate({"base": "http://example.org/scim"})   # plain http only to localhost


def test_keycloak_through_scim_passes_the_contract_and_logs_out_on_removal(scim):
    data, url = scim
    ann, _ = data.add_user("idp:ann"), data.add_user("idp:bert")
    data.groups["own"] = {"id": "own", "displayName": "staff:office", "members": [{"value": ann}]}   # the tenant's group
    kc = KeycloakTarget(keycloak=url, realm="t", base=url + "/scim/v2", admin_token="x")
    kc.base = url   # the fake serves SCIM at its root
    want = {("/grants/tenant-admin@tenant:t", "idp:ann"), ("/leases/active", "idp:bert")}
    assert contract_check(kc, want) == []
    assert data.groups["own"]["members"] == [{"value": ann}]            # never touched: outside the managed prefixes
    kc.apply(kc.plan({("/leases/active", "idp:bert")}, kc.read_full()), "remove-ann", dry_run=False)
    assert kc.read_full() == {("/leases/active", "idp:bert")} and data.logouts == [ann]
    refused = kc.plan({("/staff/office", "idp:bert")}, set())
    assert not refused["add"] and refused["findings"]


def test_a_scim_target_refuses_collisions_and_reports_missing_people(scim):
    data, url = scim
    data.add_user("idp:dup")
    data.add_user("idp:dup")
    t = ScimTarget(base=url)
    r = t.apply({"add": [("/grants/x", "idp:dup")], "remove": []}, "k1", dry_run=False)
    assert "collision" in r["failed"][0]["why"] and not r["added"]            # reported, never applied
    r = t.apply({"add": [("/grants/x", "idp:nobody")], "remove": []}, "k2", dry_run=False)
    assert r["missing_people"] == ["idp:nobody"] and display_name("/grants/x") == "grants:x"


def _badges(end):
    key = b"badge-key"
    leases = [{"lease_id": "L-t-0001", "anchor": "ext:carla", "start": T0 - timedelta(hours=1), "end": end}]
    phys = [{"lease_id": "L-t-0001", "badge": badge_hash(key, b"4471"), "sites": ["heverlee"], "areas": []}]
    return records_from_leases(leases, phys)


def test_the_pacs_target_passes_the_contract_and_stores_the_end_itself():
    sim = pacs.SimulatedPacs(foreign={"staff:1": {"source": "pacs-own", "credential": "x", "levels": [], "activation": T0, "expiry": None}})
    t = PacsTarget(conn=sim, at=T0)
    want = pacs.desired(_badges(T0 + timedelta(days=30)), set())
    assert contract_check(t, want) == [] and t.describe()["expiry_native"]
    assert sim.holders["ext:carla"]["expiry"] == T0 + timedelta(days=30)   # the end lives in the PACS (cut-off safe)
    assert "staff:1" not in sim.holders                                    # the PACS's own cardholders untouched


def test_the_osdp_target_passes_the_contract():
    ctl = Controller([Door("front", "heverlee", "", 1)], Allowlist([]), b"badge-key", SimTransport(), lambda e: None, lambda: T0)
    t = OsdpTarget(controller=ctl)
    want = {"records": frozenset(_badges(T0 + timedelta(days=1))), "revoked": frozenset()}
    assert contract_check(t, want) == []
    assert len(ctl.allowlist.by_badge) == 1


def test_the_rate_budget_bounds_calls():
    clock = [0.0]
    b = RateBudget(2, clock=lambda: clock[0])
    assert b.take() and b.take() and not b.take()
    clock[0] += 30                                   # half a minute refills one call at 2 per minute
    assert b.take()
    src = GitPeopleRegister(caps=Capabilities("source", rate_per_minute=1))
    src.budget = RateBudget(1, clock=lambda: 0.0)
    src.budget.tokens = 0
    with pytest.raises(BudgetExceeded):
        src.read_full()


def test_keycloak_never_touches_lookalike_groups_and_removes_members_without_an_anchor(scim):
    data, url = scim
    ann = data.add_user("idp:ann")
    stray = str(uuid.uuid4())
    data.users[stray] = {"id": stray, "userName": "nobody", "active": True}                  # no anchor
    fid = str(uuid.uuid4())
    data.groups["fake"] = {"id": fid, "displayName": "grants:planted", "members": [{"value": ann}]}
    kc = KeycloakTarget(keycloak=url, realm="t", base=url + "/scim/v2", admin_token="x")
    kc.base = url
    kc.apply(kc.plan({("/grants/tenant-admin@tenant:t", "idp:ann")}, kc.read_full()), "k1", dry_run=False)
    made = next(g for g in data.groups.values() if g["displayName"] == "grants:tenant-admin@tenant:t")
    assert made["attributes"] == {"keyclerk.managed": ["true"]}                              # marked as KeyClerk's
    made["members"].append({"value": stray})
    data.roles[made["id"]] = {"realmMappings": [{"name": "admin"}]}
    have = kc.read_full()
    assert ("/grants/tenant-admin@tenant:t", f"uid:{stray}") in have
    assert any("not created by KeyClerk" in f["why"] for f in kc.findings)                 # the planted group
    assert any("role mappings" in f["why"] for f in kc.findings)
    kc.apply(kc.plan({("/grants/tenant-admin@tenant:t", "idp:ann")}, have), "k2", dry_run=False)
    assert {"value": stray} not in made["members"]
    assert data.groups["fake"]["members"] == [{"value": ann}]                               # never touched


def test_an_injection_shaped_anchor_never_reaches_a_filter(scim):
    data, url = scim
    t = ScimTarget(base=url)
    with pytest.raises(Exception, match="identifier"):
        t.user('idp:x" or userName pr or "a')


def test_a_squatted_group_with_the_managed_name_never_receives_members(scim):
    """A group named like a managed one but not created by KeyClerk is refused on write, not only on read."""
    data, url = scim
    data.add_user("idp:ann")
    sid = str(uuid.uuid4())
    data.groups[sid] = {"id": sid, "displayName": "grants:x", "members": []}                    # no marker
    kc = KeycloakTarget(keycloak=url, realm="t", base=url + "/scim/v2", admin_token="x")
    kc.base = url
    r = kc.apply({"add": [("/grants/x", "idp:ann")], "remove": []}, "k1", dry_run=False)
    assert not r["added"] and "not one KeyClerk created" in r["failed"][0]["why"]
    assert data.groups[sid]["members"] == []


def test_a_failing_add_never_loses_the_removals_and_logouts_before_it(scim):
    """The result of the removals (and their pending logouts) survives an add that fails."""
    data, url = scim
    bert = data.add_user("idp:bert")
    data.add_user("idp:dup")
    data.add_user("idp:dup")
    kc = KeycloakTarget(keycloak=url, realm="t", base=url + "/scim/v2", admin_token="x")
    kc.base = url
    kc.apply({"add": [("/grants/x", "idp:bert")], "remove": []}, "k1", dry_run=False)
    kc.logout = lambda uid: (_ for _ in ()).throw(RuntimeError("broker down"))
    r = kc.apply({"add": [("/grants/x", "idp:dup")], "remove": [("/grants/x", "idp:bert")]}, "k2", dry_run=False)
    assert r["removed"] == [("/grants/x", "idp:bert")] and r["logout_pending"] == [bert]
    assert "collision" in r["failed"][0]["why"]


def test_one_anchor_on_two_people_keeps_neither_in_a_managed_group(scim):
    """A copied anchor never keeps a membership alive."""
    data, url = scim
    data.add_user("idp:ann")
    kc = KeycloakTarget(keycloak=url, realm="t", base=url + "/scim/v2", admin_token="x")
    kc.base = url
    kc.apply({"add": [("/grants/x", "idp:ann")], "remove": []}, "k1", dry_run=False)
    made = next(g for g in data.groups.values() if g["displayName"] == "grants:x")
    mallory = data.add_user("idp:ann")                                                       # the copied anchor
    made["members"].append({"value": mallory})
    have = kc.read_full()
    assert ("/grants/x", "idp:ann") not in have and ("/grants/x", f"uid:{mallory}") in have
    assert any("security incident" in f["why"] for f in kc.findings)


def test_keycloak_reads_usernames_and_only_verified_emails_for_edge_leases(scim):
    """Decision 0014b: an edge's access gateway matches an SSO login by e-mail, so only a verified one is kept."""
    data, url = scim
    ann_mail, bert_mail = "ann" + "@example.test", "bert" + "@example.test"   # built from parts: the leak gate flags any address
    ann, bert = data.add_user("idp:ann"), data.add_user("idp:bert")
    data.users[ann].update(email=ann_mail, emailVerified=True)
    data.users[bert].update(email=bert_mail, emailVerified=False)
    kc = KeycloakTarget(keycloak=url, realm="t", base=url + "/scim/v2", admin_token="x")
    kc.base = url
    want = {("/grants/tenant-admin@tenant:t", "idp:ann"), ("/grants/tenant-admin@tenant:t", "idp:bert")}
    kc.apply(kc.plan(want, kc.read_full()), "k1", dry_run=False)
    kc.read_full()
    assert kc.emails == {"idp:ann": ann_mail}
    assert set(kc.usernames) == {"idp:ann", "idp:bert"}
