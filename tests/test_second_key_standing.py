# SPDX-License-Identifier: EUPL-1.2
"""Second-key standing (decision 0008): one rule, in Rego, compiled to WebAssembly and run in process. Under enforce a
second key needs standing (the security officer, a named approver, or a manager of the group through another chain and
unit), the root never counts, and a favour is never returned within the reciprocity window."""
import copy
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from keyclerk import delegation as D  # noqa: E402
from keyclerk import records  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
ANN, BERT, OWNER, INGRID, OSCAR, KAI, CARLA = ("idp:7c1f-ann", "idp:91d0-bert", "idp:2b9e-owner", "idp:31ee-ingrid",
                                              "op:7a1e-oscar", "idp:bb11-kai", "ext:3a71-carla")


def demo() -> dict:
    return copy.deepcopy(records.load(ROOT / "tests" / "fixtures" / "records.yaml"))


def appoint(doc, anchor, aid="A-1", by=OWNER, keys=(INGRID,), start=NOW - timedelta(days=1), days=90):
    doc.setdefault("approvers", []).append({"approver_id": aid, "anchor": anchor, "appointed_by": by,
                                            "approved_by": list(keys), "from": start.isoformat(),
                                            "to": (start + timedelta(days=days)).isoformat()})


def finance_add(doc, approvers, mid="M-x", by=ANN, start=NOW):
    """Ann adds Bert (a deputy) to finance (elevated): that needs a second key."""
    doc["memberships"].append({"membership_id": mid, "group": "finance", "member": {"anchor": BERT}, "by": by,
                               "under": "D-example-0001", "start": start.isoformat(),
                               "end": (start + timedelta(days=30)).isoformat(), "approved_by": approvers})
    return doc["memberships"][-1]


def key_errors(doc, m):
    return [e for e in D.membership_errors(doc, m, at=NOW) if "second key" in e]


def test_the_compiled_policy_belongs_to_its_source():
    import build_policy
    assert build_policy.check() == []


def test_warn_keeps_todays_rule_and_lists_what_enforce_would_refuse():
    doc = demo()
    with D.standing_mode("warn"):
        assert D.check(doc) == []
        impact = D.standing_impact(doc)
    # the operator's keys on the root's privileged memberships: independent, but no standing yet
    assert {e.split(":")[0] for e in impact} == {"M-example-0006", "M-example-0012", "M-example-0016"}
    assert all("no standing" in e for e in impact)
    appoint(doc, OSCAR)
    with D.standing_mode("warn"):
        assert D.standing_impact(doc) == []                       # appoint first, then enforce changes nothing


def test_under_enforce_a_plain_person_does_not_count_but_the_officer_and_a_named_approver_do():
    doc = demo()
    m = finance_add(doc, [KAI])
    with D.standing_mode("off"):
        assert key_errors(doc, m) == []
    with D.standing_mode("enforce"):
        (err,) = key_errors(doc, m)
        assert f"{KAI} does not count: no standing" in err
        m["approved_by"] = [INGRID]
        assert key_errors(doc, m) == []
        m["approved_by"] = [KAI]
        appoint(doc, KAI)
        assert key_errors(doc, m) == []


def test_an_appointment_needs_the_root_and_the_officers_key_and_ends():
    doc = demo()
    appoint(doc, KAI, aid="A-bad", keys=(BERT,))
    appoint(doc, OWNER, aid="A-root")
    appoint(doc, CARLA, aid="A-ext")
    appoint(doc, KAI, aid="A-long", days=900)
    appoint(doc, KAI, aid="A-by", by=ANN)
    errs = D.check(doc)
    assert any("A-bad: appointing a named approver needs the security officer's key" in e for e in errs)
    assert any("A-root: the root trust owner is never a named approver" in e for e in errs)
    assert any("A-ext: a named approver is a person of the organisation" in e for e in errs)
    assert any("A-long: longer than" in e for e in errs)
    assert any("A-by: a named approver is appointed by the root trust owner" in e for e in errs)
    assert not D.named_approver(doc, KAI, NOW)
    lapsed = demo()
    appoint(lapsed, KAI, days=10, start=NOW - timedelta(days=20))
    assert not D.named_approver(lapsed, KAI, NOW)                 # ran out
    retired = demo()
    appoint(retired, KAI)
    assert D.named_approver(retired, KAI, NOW)
    retired["admin_revocations"].append({"id": "A-1", "at": (NOW - timedelta(hours=1)).isoformat(), "by": OWNER,
                                         "mode": "retire"})
    assert not D.named_approver(retired, KAI, NOW)


def test_the_root_never_counts_even_as_officer():
    doc = demo()
    doc["root"]["officer"] = OWNER
    m = finance_add(doc, [OWNER])
    with D.standing_mode("enforce"):
        (err,) = key_errors(doc, m)
        assert "the root is never a second key" in err


def test_a_sibling_manager_counts_unless_in_the_actors_unit():
    doc = demo()
    doc["delegations"].append({"delegation_id": "D-sib", "delegate": KAI, "group": "office", "powers": ["members"],
                               "max_risk": "elevated", "max_membership_days": 30, "depth_left": 0,
                               "start": "2026-10-02T00:00:00Z", "end": "2027-03-01T00:00:00Z", "by": OWNER,
                               "parent": "root", "approved_by": [INGRID]})
    m = finance_add(doc, [KAI])
    with D.standing_mode("enforce"):
        assert key_errors(doc, m) == []
        for p in doc["persons"]:
            if p["person"] in ("ann", "kai"):
                p["unit"] = "finance-dept"
        (err,) = key_errors(doc, m)
        assert "no standing" in err
        next(p for p in doc["persons"] if p["person"] == "kai")["unit"] = "it-dept"
        assert key_errors(doc, m) == []


def test_a_favour_is_not_returned_within_the_window():
    doc = demo()
    appoint(doc, KAI)
    # Kai earlier made a change that Ann approved; now Kai's key on Ann's change returns the favour
    doc["memberships"].append({"membership_id": "M-favour", "group": "office-staff",
                               "member": {"anchor": "idp:66cc-finn"}, "by": KAI, "under": "root",
                               "start": (NOW - timedelta(days=5)).isoformat(),
                               "end": (NOW + timedelta(days=20)).isoformat(), "approved_by": [ANN]})
    m = finance_add(doc, [KAI])
    with D.standing_mode("enforce"):
        (err,) = key_errors(doc, m)
        assert "returns a favour" in err
    with D.standing_mode("warn"):
        assert key_errors(doc, m) == []


def test_the_rule_is_evaluated_in_process_without_any_server():
    from keyclerk import policy_wasm
    out = policy_wasm.second_key([{"anchor": "x", "kind": "tenant", "actor": False, "member": False, "root": False,
                                   "in_chain": False, "tainted": False, "officer": True, "named": False,
                                   "manager": False, "unit_differs": None, "reciprocal_days_ago": None}],
                                 {"standing": "enforce", "reciprocity_days": 30})
    assert out["counting"] == ["x"]


@pytest.mark.skipif(not shutil.which("opa"), reason="opa CLI not installed")
def test_the_platform_policy_agrees_with_the_engine():
    """delegation.rego (the platform's OPA) builds candidates from opa_data and calls the same rule: parity under
    enforce."""
    doc = demo()
    appoint(doc, KAI)
    cases = [[KAI], [INGRID], [OWNER], [OSCAR], [BERT]]
    with D.standing_mode("enforce"):
        data = {"keyclerk": {"admin_authority": D.opa_data(doc, NOW)}}
        engine = [D.outside_key(doc, c, ANN, BERT, "D-example-0001", NOW, NOW, group="finance") for c in cases]
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "data.json").write_text(json.dumps(data, default=str))
        got = []
        for c in cases:
            inp = {"actor": ANN, "action": "add_member", "group": "finance", "member": BERT, "approvers": c}
            (Path(tmp) / "input.json").write_text(json.dumps(inp))
            out = subprocess.run(["opa", "eval", "-f", "json", "-d", str(ROOT / "keyclerk" / "policy"),
                                  "-d", str(Path(tmp) / "data.json"), "-i", str(Path(tmp) / "input.json"),
                                  "data.keyclerk.delegation.second_key_result.counting"],
                                 capture_output=True, text=True, check=True)
            got.append(json.loads(out.stdout)["result"][0]["expressions"][0]["value"])
    assert got == engine
    assert engine == [[KAI], [INGRID], [], [], []]


def test_through_the_desk_the_root_appoints_and_the_officer_completes_it(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
    from keyclerk.desk import Desk, Refusal, Store
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    desk = Desk(Store(tmp_path / "store", key, ROOT / "tests" / "fixtures" / "records.yaml"))
    w = lambda a: {"anchor": a, "roles": []}   # noqa: E731
    with pytest.raises(Refusal, match="only the root trust owner appoints"):
        desk.propose(w(ANN), {"action": "appoint_approver", "anchor": OSCAR, "reason": "second keys"})
    r = desk.propose(w(OWNER), {"action": "appoint_approver", "anchor": OSCAR, "days": 90, "reason": "second keys"})
    assert r["outcome"] == "pending" and "security officer's key" in r["reasons"][0]
    with pytest.raises(Refusal):
        desk.approve(w(OWNER), r["change_id"])                    # the proposer never adds the key
    assert desk.approve(w(INGRID), r["change_id"])["outcome"] == "applied"
    doc = desk.store.load()
    (a,) = doc["approvers"]
    assert a["anchor"] == OSCAR and a["approved_by"] == [INGRID] and D.named_approver(doc, OSCAR, datetime.now(timezone.utc))
    with D.standing_mode("warn"):
        assert D.standing_impact(doc) == []
    end = desk.propose(w(INGRID), {"action": "end_approver", "approver_id": a["approver_id"], "reason": "rotation"})
    assert end["outcome"] == "applied", end["reasons"]
    assert not D.named_approver(desk.store.load(), OSCAR, datetime.now(timezone.utc) + timedelta(seconds=1))
