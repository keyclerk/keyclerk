# SPDX-License-Identifier: EUPL-1.2
"""Grants as code, stage 1: the record checker, the OPA data and the reconciliation plan
pin the accepted invariants of grants as code before any broker is touched."""
import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import grants  # noqa: E402

DEMO = FIXTURES / "records.yaml"
AT = datetime(2026, 10, 21, 9, 0, tzinfo=timezone.utc)


@pytest.fixture()
def doc():
    return yaml.safe_load(DEMO.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def r():
    return grants.rules()


def _one(doc, gid):
    return next(g for g in doc["grants"] if g["grant_id"] == gid)


def test_the_demo_records_pass_the_rule_data(doc, r):
    assert grants.check(doc, r) == []


def test_activation_longer_than_its_role_allows_is_refused(doc, r):
    _one(doc, "G-example-0003")["end"] = "2026-10-21T17:00:00Z"   # 9 h, the rule data allows 8
    assert any("exceeds 8 h" in e for e in grants.check(doc, r))


def test_activation_without_a_covering_eligibility_is_refused(doc, r):
    doc["grants"] = [g for g in doc["grants"] if g["grant_id"] != "G-example-0002"]
    assert any("without an eligibility" in e for e in grants.check(doc, r))


def test_requester_and_grantee_never_approve(doc, r):
    g = _one(doc, "G-example-0001")
    g["approved_by"] = [g["requested_by"]]
    d2 = copy.deepcopy(doc)
    g2 = _one(d2, "G-example-0004")
    g2["approved_by"] = [g2["subject"]["anchor"]]
    assert any("approved their own request" in e for e in grants.check(doc, r))
    assert any("grantee approved their own grant" in e for e in grants.check(d2, r))


def test_planes_never_cross(doc, r):
    g = _one(doc, "G-example-0001")
    g["subject"]["kind"] = "operator"          # a the operator person as tenant administrator
    d2 = copy.deepcopy(doc)
    p = _one(d2, "G-example-0002")
    p.update(role="platform-admin", plane="platform")   # a tenant person with platform privilege
    assert any("planes never cross" in e for e in grants.check(doc, r))
    assert any("planes never cross" in e for e in grants.check(d2, r))


def test_special_and_baseline_roles_are_never_grant_records(doc, r):
    _one(doc, "G-example-0001")["role"] = "security-officer"
    assert any("appointed at a ceremony" in e for e in grants.check(doc, r))


def test_privileged_roles_are_held_on_the_admin_persona(doc, r):
    _one(doc, "G-example-0003")["subject"]["persona"] = "person"
    assert any("admin persona" in e for e in grants.check(doc, r))


def test_a_grant_id_is_never_reused(doc, r):
    dup = copy.deepcopy(_one(doc, "G-example-0005"))
    dup["start"], dup["end"] = "2026-11-01T00:00:00Z", "2026-11-20T00:00:00Z"
    doc["grants"].append(dup)   # a rehire must take a new id, never lift the revocation
    assert any("used twice" in e for e in grants.check(doc, r))


def test_an_envelope_grant_is_never_privileged(doc, r):
    g = _one(doc, "G-example-0003")
    g["origin"] = "envelope"
    assert any("envelope grant" in e for e in grants.check(doc, r))


def test_revoked_grants_are_never_active_and_ship_as_revoked(doc):
    ids = {g["grant_id"] for g in grants.active(doc, AT)}
    assert "G-example-0005" not in ids and {"G-example-0001", "G-example-0003"} <= ids
    data = grants.opa_data(doc)
    assert data["revoked"] == ["G-example-0005"] and "idp:7c1f-ann" in data["by_anchor"]


def test_the_plan_adds_active_grants_removes_ended_and_flags_undeclared(doc):
    state = {
        "/grants/tenant-admin@tenant:example": ["idp:91d0-bert", "idp:ffff-stranger"],
        "/staff/office": ["idp:7c1f-ann"],   # an attribute group from the tenant's IdP: never touched
    }
    p = grants.plan(doc, state, AT)
    added = {(x["group"], x["anchor"]) for x in p["add"]}
    removed = {(x["anchor"], x["why"]) for x in p["remove"]}
    assert ("/grants/tenant-admin@tenant:example", "idp:7c1f-ann") in added
    assert ("/grants/tenant-admin-privileged@tenant:example", "idp:7c1f-ann") in added   # activation in its window
    assert ("idp:91d0-bert", "ended-or-revoked") in removed
    assert ("idp:ffff-stranger", "undeclared") in removed and len(p["findings"]) == 1
    assert all(not x["group"].startswith("/staff/") for x in p["remove"])


def test_eligibility_is_never_a_group_membership(doc):
    p = grants.plan(doc, {}, datetime(2026, 11, 1, tzinfo=timezone.utc))   # eligibility active, no activation
    assert not any("tenant-admin-privileged" in x["group"] for x in p["add"])
