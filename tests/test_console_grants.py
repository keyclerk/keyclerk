# SPDX-License-Identifier: EUPL-1.2
"""Decision 0030 point 3 (issue 29): a privileged role granted in the broker outside KeyClerk is a finding, with who
made it, read from the realm's admin events; report-only, nothing is removed. The desk notes each once in its signed
activity log, so it reaches the security officer and the SIEM, and the SIEM event names no person."""
import json
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import siem
from keyclerk.connectors.keycloak import KeycloakTarget
from keyclerk.desk import Desk, Store
from keyclerk.reconcile import State
from test_visits import FIXTURES

UID, GID, ADMIN = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222", \
    "33333333-3333-3333-3333-333333333333"
RM, APP = "44444444-4444-4444-4444-444444444444", "55555555-5555-5555-5555-555555555555"
VIEWER = {"anchor": None, "roles": ["keyclerk-viewer"]}


def _target(events, now_roles=None, fail=False):
    t = KeycloakTarget(realm="example", privileged_roles=("payroll:approve",))
    writes = []

    def admin(path, params=None, method="GET", body=None, write=False):
        if write or method != "GET":
            writes.append(path)
        if path == "/admin-events":
            if fail:
                raise OSError("403")
            return [e for e in events if e["resourceType"] == params["resourceTypes"]]
        if path == f"/users/{ADMIN}":
            return {"username": "mallory"}
        if path == f"/users/{UID}":
            return {"username": "dan"}
        if path == f"/groups/{GID}":
            return {"path": "/contractors"}
        if path == f"/clients/{RM}":
            return {"clientId": "realm-management"}
        if path == f"/clients/{APP}":
            return {"clientId": "payroll"}
        if path.startswith("/users/") and "/role-mappings/" in path:
            return now_roles or []
        raise AssertionError(path)
    t._admin, t.spend = admin, lambda *a: None
    return t, writes


def _ev(t, rtype, path, rep=None):
    return {"time": t, "resourceType": rtype, "operationType": "CREATE", "resourcePath": path,
            "authDetails": {"userId": ADMIN, "clientId": "security-admin-console", "ipAddress": "192.0.2.7"},
            **({"representation": json.dumps(rep)} if rep is not None else {})}


def test_a_privileged_role_granted_by_hand_is_a_finding_with_who_did_it():
    events = [
        _ev(1000, "CLIENT_ROLE_MAPPING", f"users/{UID}/role-mappings/clients/{RM}",
            [{"name": "manage-users", "clientRole": True, "containerId": RM}]),
        _ev(1001, "REALM_ROLE_MAPPING", f"users/{UID}/role-mappings/realm", [{"name": "offline_access"}]),   # not privileged
        _ev(1002, "CLIENT_ROLE_MAPPING", f"groups/{GID}/role-mappings/clients/{APP}",
            [{"name": "approve", "clientRole": True, "containerId": APP}]),                                 # marked high-risk
        _ev(500, "CLIENT_ROLE_MAPPING", f"users/{UID}/role-mappings/clients/{RM}",
            [{"name": "realm-admin", "clientRole": True, "containerId": RM}]),                              # before the cursor
    ]
    t, writes = _target(events)
    found, newest, why = t.console_grants(900)
    assert why is None and newest == 1002 and writes == []                # read only: nothing removed, nothing written
    assert [(f["roles"], f["subject_kind"], f["subject_name"]) for f in found] == [
        (["realm-management:manage-users"], "user", "dan"), (["payroll:approve"], "group", "/contractors")]
    assert all(f["by_name"] == "mallory" and f["by_client"] == "security-admin-console" and f["exact"] for f in found)


def test_without_the_representation_the_roles_are_read_from_the_subject():
    events = [_ev(2000, "CLIENT_ROLE_MAPPING", f"users/{UID}/role-mappings/clients/{RM}")]
    t, _ = _target(events, now_roles=[{"name": "realm-admin", "clientRole": True, "containerId": RM}])
    found, _, _ = t.console_grants(0)
    assert found[0]["roles"] == ["realm-management:realm-admin"] and found[0]["exact"] is False


def test_unreadable_admin_events_say_why_and_find_nothing():
    t, _ = _target([], fail=True)
    found, newest, why = t.console_grants(7)
    assert found == [] and newest == 7 and "view-events" in why


def test_the_reconciler_keeps_its_place_in_the_admin_events(tmp_path):
    st = State(tmp_path / "state", timedelta(minutes=5))
    at = datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc)
    assert st.console_cursor(at) == int((at - timedelta(days=1)).timestamp() * 1000)     # a first run looks back a day
    st.save_console_cursor(1234)
    assert State(tmp_path / "state", timedelta(minutes=5)).console_cursor(at) == 1234


def _desk(tmp_path):
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex())
    state = tmp_path / "broker"
    state.mkdir()
    return Desk(Store(tmp_path / "store", key, FIXTURES / "records.yaml"), broker_state=state), state


def test_the_desk_notes_each_console_grant_once_and_the_siem_names_no_one(tmp_path):
    desk, state = _desk(tmp_path)
    t, _ = _target([_ev(3000, "CLIENT_ROLE_MAPPING", f"users/{UID}/role-mappings/clients/{RM}",
                        [{"name": "manage-users", "clientRole": True, "containerId": RM}])])
    found, _, _ = t.console_grants(0)
    run = {"at": "2026-11-04T12:00:00Z", "console_grants": found}
    (state / "runs.jsonl").write_text(json.dumps(run) + "\n" + json.dumps(run) + "\n")   # seen by two runs
    assert desk.note_console_grants() == 1 and desk.note_console_grants() == 0
    seen = desk.broker(VIEWER)["console_grants"]
    assert len(seen) == 1 and seen[0]["by_name"] == "mallory" and seen[0]["subject_name"] == "dan"
    events = [e for e in siem.Feed(desk.store.path).page(0, 500) if e["unmapped"]["keyclerk"]["action"] == "console_grant"]
    assert len(events) == 1 and events[0]["class_uid"] == 2004
    assert "realm-management:manage-users" in events[0]["finding_info"]["title"]
    text = json.dumps(events)
    assert "mallory" not in text and "dan" not in text and "192.0.2.7" not in text
    desk.store.close()


def test_the_event_id_is_the_key_and_a_client_id_is_named():
    ev = {**_ev(4000, "CLIENT_ROLE_MAPPING", f"users/{UID}/role-mappings/clients/{RM}",
                [{"name": "manage-users", "clientRole": True, "containerId": RM}]), "id": "ev-0001"}
    ev["authDetails"] = {**ev["authDetails"], "clientId": APP}            # Keycloak gives the client's internal id
    t, _ = _target([ev])
    found, _, _ = t.console_grants(0)
    assert found[0]["event"] == "ev-0001" and found[0]["by_client"] == "payroll"
