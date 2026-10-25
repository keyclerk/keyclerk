# SPDX-License-Identifier: EUPL-1.2
"""External access leases, stage 1: the lease checker, the lease-group schedule that
drives Keycloak Workflows, the Workflow definitions and the info package pin the accepted rules."""
import copy
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import grants  # noqa: E402
from keyclerk import leases  # noqa: E402

DEMO = FIXTURES / "records.yaml"


@pytest.fixture()
def doc():
    return yaml.safe_load(DEMO.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def xr():
    return leases.rules()


def _lease(doc, lid):
    return next(x for x in doc["leases"] if x["lease_id"] == lid)


def test_the_demo_leases_pass_the_rule_data(doc, xr):
    assert leases.check(doc, xr) == [] and grants.check(doc, grants.rules()) == []


def test_a_lease_never_outlives_its_category_or_the_proof_it_depends_on(doc, xr):
    c = _lease(doc, "L-example-0001")
    c["end"] = "2026-10-28T17:00:00Z"   # one day past the safety certificate's verified expiry
    assert any("expiry_binding" in e for e in leases.check(doc, xr))
    d2 = copy.deepcopy(doc)
    v = _lease(d2, "L-example-0001")
    v["category"] = "visitor"           # 21 days is far past a visitor's one day
    assert any("exceeds 1" in e for e in leases.check(d2, xr))


def test_sponsors_are_tenant_people_and_never_the_resource_owner(doc, xr):
    c = _lease(doc, "L-example-0001")
    c["sponsor"]["kind"] = "external"
    d2 = copy.deepcopy(doc)
    _lease(d2, "L-example-0001")["resource_owner"] = "idp:7c1f-ann"   # the sponsor
    assert any("tenant_people" in e for e in leases.check(doc, xr))
    assert any("also the resource owner" in e for e in leases.check(d2, xr))


def test_a_partner_comes_only_from_a_connected_organisation(doc, xr):
    _lease(doc, "L-example-0002")["issuer"] = "https://idp.unknown.example"
    assert any("connected organisation" in e for e in leases.check(doc, xr))


def test_back_to_back_leases_hit_the_total_and_overlaps_are_refused(doc, xr):
    base = _lease(doc, "L-example-0001")
    for i, (s, e) in enumerate([("2026-01-05", "2026-04-04"), ("2026-04-05", "2026-07-03"), ("2026-07-04", "2026-10-01")]):
        x = copy.deepcopy(base)
        x.update(lease_id=f"L-example-01{i:02d}", start=f"{s}T08:00:00Z", end=f"{e}T08:00:00Z", requested_end=f"{e}T08:00:00Z")
        x["proofs"] = [p for p in x["proofs"] if not p.get("binds_lease")]
        doc["leases"].append(x)
    errs = leases.check(doc, xr)
    assert any("without the security officer" in e for e in errs)   # re-leasing never becomes endless
    d2 = copy.deepcopy(doc)
    _lease(d2, "L-example-0102")["end"] = "2026-10-10T08:00:00Z"   # now overlaps the current lease
    assert any("one lease per person" in e for e in leases.check(d2, xr))


def test_a_grant_under_a_lease_ends_with_it(doc, xr):
    doc["grants"].append({
        "grant_id": "G-example-0100", "subject": {"anchor": "ext:3a71-carla", "kind": "external"},
        "role": "tenant-admin", "plane": "tenant", "class": "functional", "scope": {"level": "tenant", "id": "example"},
        "label_ceiling": "Internal", "justification": {"lease": "L-example-0001"}, "requested_by": "idp:7c1f-ann",
        "approved_by": ["idp:91d0-bert"], "start": "2026-10-06T08:00:00Z", "end": "2026-11-01T00:00:00Z",
        "lease": "L-example-0001"})
    assert any("ends after its lease" in e for e in leases.check(doc, xr))


def test_the_schedule_drives_the_lease_groups(doc, xr):
    s = leases.schedule(doc, xr, datetime(2026, 10, 21, 12, tzinfo=timezone.utc))   # contractor ends 10-27: 6.2 days
    assert "ext:3a71-carla" in s[leases.ACTIVE] and s[leases.ending(7)] == ["ext:3a71-carla"]
    s = leases.schedule(doc, xr, datetime(2026, 10, 27, 9, tzinfo=timezone.utc))
    assert s[leases.ending(1)] == ["ext:3a71-carla"] and s[leases.ending(7)] == []
    s = leases.schedule(doc, xr, datetime(2026, 10, 27, 17, tzinfo=timezone.utc))
    assert "ext:3a71-carla" not in s[leases.ACTIVE]
    p = grants.plan(doc, {leases.ACTIVE: ["ext:3a71-carla"]}, datetime(2026, 10, 28, tzinfo=timezone.utc), leases=s)
    assert {"group": leases.ACTIVE, "anchor": "ext:3a71-carla", "why": "ended-or-revoked", "finding": False} in p["remove"]


def test_workflows_only_react_to_the_lease_groups(xr):
    wf = {w["name"]: w for w in leases.workflows(xr)}
    assert set(wf) == {"lease-reminder-7d", "lease-reminder-1d", "lease-end"}
    end = wf["lease-end"]
    assert end["on"] == f"user-group-membership-removed({leases.ACTIVE})"
    assert [s["uses"] for s in end["steps"]] == ["disable-user", "delete-user"]
    assert end["steps"][1]["after"] == f"{xr['steps']['offboarding']['retention']['account_delete_days']}d"


def test_the_info_package_escapes_requester_text_and_takes_contacts_from_roles(doc):
    ls = _lease(doc, "L-example-0001")
    site = {"name": "<script>x</script> office", "rules": ["Badge visible."], "safety": []}
    out = leases.info_package(ls, site, {"security-desk": "desk, extension 200", "emergency": "112"})
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "2026-10-27 17:00" in out and "desk, extension 200" in out
