# SPDX-License-Identifier: EUPL-1.2
"""Personas, workloads and agents (decision 0011): a sysadmin's daily account stays out of privileged groups, workloads
and agents have owners, an agent has a director and reaches no further than it. Decided by identity.rego, compiled in."""
import copy
from datetime import datetime, timezone
from pathlib import Path

from keyclerk import delegation as D
from keyclerk import records

FIXTURES = Path(__file__).resolve().parent / "fixtures"
AT = datetime(2026, 10, 23, tzinfo=timezone.utc)
ANN, BERT, GINA, KAI, KAI_ADM = "idp:7c1f-ann", "idp:91d0-bert", "idp:77dd-gina", "idp:bb11-kai", "adm:bb11-kai"


def doc():
    d = copy.deepcopy(records.load(FIXTURES / "records.yaml"))
    kai = next(p for p in d["persons"] if p["person"] == "kai")
    kai["anchors"] = [KAI, KAI_ADM]
    kai["personas"] = [{"anchor": KAI, "purpose": "daily"}, {"anchor": KAI_ADM, "purpose": "admin"}]
    d["persons"] += [
        {"person": "ticket-router", "kind": "workload", "anchors": ["spiffe://example/ticket-router"], "owner": KAI},
        {"person": "triage-agent", "kind": "agent", "anchors": ["agent:triage"], "owner": KAI,
         "director": "spiffe://example/ticket-router"},
        {"person": "assistant-gina", "kind": "agent", "anchors": ["agent:assistant-gina"], "owner": GINA, "director": GINA}]
    return d


def member(d, mid, gid, anchor):
    d["memberships"].append({"membership_id": mid, "group": gid, "member": {"anchor": anchor}, "by": "idp:2b9e-owner",
                             "under": "root", "start": "2026-10-01T00:00:00Z", "end": "2027-01-01T00:00:00Z"})


def errors_of(d, mid):
    return [e for e in D.check(d) if e.startswith(mid + ":")]


def test_the_daily_account_stays_out_of_a_privileged_group_and_the_admin_persona_may_join():
    d = doc()
    member(d, "M-t-1", "admins", KAI)
    member(d, "M-t-2", "admins", KAI_ADM)
    assert any("admin persona, not a daily account" in e for e in errors_of(d, "M-t-1"))
    assert not any("admin persona" in e for e in errors_of(d, "M-t-2"))
    assert D.same(d, KAI, KAI_ADM)                      # one person: reviews, separation and leaving count per person


def test_workloads_and_agents_need_owners_and_directors():
    d = doc()
    assert not D.identity_errors(d)
    d["persons"].append({"person": "lost-agent", "kind": "agent", "anchors": ["agent:lost"], "owner": KAI})
    d["persons"].append({"person": "agent-of-agent", "kind": "agent", "anchors": ["agent:x"], "owner": KAI,
                         "director": "agent:triage"})
    d["persons"].append({"person": "orphan", "kind": "workload", "anchors": ["spiffe://example/orphan"]})
    errs = D.identity_errors(d)
    assert any(e.startswith("lost-agent: an agent has a director") for e in errs)
    assert any(e.startswith("agent-of-agent: an agent has a director") for e in errs)
    assert any(e.startswith("orphan: a workload has an owner") for e in errs)


def test_no_workload_or_agent_in_a_privileged_group():
    d = doc()
    member(d, "M-t-3", "admins", "agent:triage")
    member(d, "M-t-4", "office-staff", "spiffe://example/ticket-router")
    assert any("never a member of a privileged group" in e for e in errors_of(d, "M-t-3"))
    assert not any("privileged" in e for e in errors_of(d, "M-t-4"))


def test_an_agent_reaches_no_further_than_its_director():
    d = doc()
    member(d, "M-t-5", "finance", "agent:assistant-gina")       # gina is in finance: her assistant counts there
    member(d, "M-t-6", "office-staff", "agent:assistant-gina")  # gina is not in office-staff: it does not count
    assert "agent:assistant-gina" in D.effective_members(d, "finance", AT)
    assert "agent:assistant-gina" not in D.effective_members(d, "office-staff", AT)
    d["memberships"] = [m for m in d["memberships"] if m["membership_id"] != "M-example-0005"]   # gina leaves finance
    assert "agent:assistant-gina" not in D.effective_members(d, "finance", AT)


# --- decision 0011a, change 1: every effective member, and KeyClerk's own powers, by account -----------------------

import contextlib

from keyclerk import config


@contextlib.contextmanager
def persona_rule(mode):
    cfg = config.current()
    old = cfg.get("identity")
    cfg["identity"] = {**(old or {}), "persona_rule": mode}
    try:
        yield
    finally:
        if old is None:
            cfg.pop("identity", None)
        else:
            cfg["identity"] = old


def test_an_include_already_raises_the_included_group_so_a_daily_account_is_refused_there():
    d = doc()
    member(d, "M-t-7", "office-staff", KAI)
    d["memberships"].append({"membership_id": "M-t-8", "group": "admins", "member": {"group": "office-staff"},
                             "by": "idp:2b9e-owner", "under": "root", "start": "2026-10-01T00:00:00Z",
                             "end": "2027-01-01T00:00:00Z"})
    errs = [e for e in D.check(d) if e.startswith("M-t-7:")]
    assert any("admin persona, not a daily account" in e for e in errs)   # office-staff is privileged by nesting
    assert KAI not in D.effective_members(d, "admins", AT)


def test_rules_never_reach_a_privileged_group_and_enforce_judges_every_effective_member():
    """An adversarial review finding: rules into a privileged group are refused already; enforce also judges every effective
    member, so an account with no stated purpose drops out however it came in (direct, surge or otherwise)."""
    d = doc()
    d["memberships"].append({"membership_id": "M-t-9", "group": "admins", "by": "idp:2b9e-owner", "under": "root",
                             "member": {"rule": {"attribute": "unit", "values": ["it"], "source": "HR source",
                                                 "max_age_hours": 24}},
                             "approved_by": ["idp:31ee-ingrid"], "start": "2026-10-01T00:00:00Z", "end": "2027-01-01T00:00:00Z"})
    assert any("named members only, never a rule" in e for e in D.check(d) if e.startswith("M-t-9:"))
    d = doc()
    kai = next(p for p in d["persons"] if p["person"] == "kai")
    kai["personas"] = []                                                    # no stated purpose on either account
    member(d, "M-t-10", "admins", KAI)
    d["memberships"][-1]["approved_by"] = ["idp:31ee-ingrid"]
    with persona_rule("warn"):
        assert KAI in D.effective_members(d, "admins", AT)                    # warn changes nothing...
        assert any(x["anchor"] == KAI and x["group"] == "admins" for x in D.persona_impact(d, AT))   # ...and says so
    with persona_rule("enforce"):
        assert KAI not in D.effective_members(d, "admins", AT)                # enforce: no admin purpose, no member


def test_keyclerk_powers_are_used_from_the_account_the_role_names_when_enforced():
    d = doc()
    owner = next(p for p in d["persons"] if p["person"] == "owner")
    owner["anchors"] = ["idp:2b9e-owner", "adm:2b9e-owner"]
    owner["personas"] = [{"anchor": "idp:2b9e-owner", "purpose": "daily"}, {"anchor": "adm:2b9e-owner", "purpose": "admin"}]
    with persona_rule("warn"):
        assert D.authority(d, "idp:2b9e-owner", "admins", "members", AT) == "root"
    with persona_rule("enforce"):
        assert D.authority(d, "idp:2b9e-owner", "admins", "members", AT) is None     # the daily account of the root
        assert D.authority(d, "adm:2b9e-owner", "admins", "members", AT) is None     # not the account the role names
        d["root"]["holders"][0]["anchor"] = "adm:2b9e-owner"                          # the root role on the admin persona
        assert D.authority(d, "adm:2b9e-owner", "admins", "members", AT) == "root"
        assert D.authority(d, "adm:2b9e-owner", "office-staff", "members", AT) == "root"


def test_a_second_key_from_a_daily_account_does_not_count_for_a_privileged_group_when_enforced():
    d = doc()
    ingrid = next(p for p in d["persons"] if p["person"] == "ingrid")
    ingrid["personas"] = [{"anchor": ingrid["anchors"][0], "purpose": "daily"}]
    facts = lambda: D.second_key_facts(d, [ingrid["anchors"][0]], "idp:2b9e-owner", KAI_ADM, "root", "admins", AT, AT)   # noqa: E731
    with persona_rule("warn"):
        assert facts()[0]["persona_ok"] is True
    with persona_rule("enforce"):
        assert facts()[0]["persona_ok"] is False



def test_moving_to_the_admin_persona_retires_the_daily_membership_without_failing_the_records():
    """Persons carry no history: once kai's daily account is declared daily, the old membership made with it is not
    judged on that declaration after it is retired (0011a: the move to an admin persona, as a deployment does it)."""
    d = doc()
    member(d, "M-t-1", "admins", KAI)
    d.setdefault("admin_revocations", []).append({"id": "M-t-1", "at": "2026-10-20T00:00:00Z", "by": "idp:2b9e-owner",
                                                 "mode": "retire", "reason": "moved to the admin persona"})
    member(d, "M-t-2", "admins", KAI_ADM)
    assert not any("admin persona" in e for e in errors_of(d, "M-t-1") + errors_of(d, "M-t-2"))
    d["admin_revocations"].pop()                           # not retired: still refused
    assert any("admin persona, not a daily account" in e for e in errors_of(d, "M-t-1"))


def test_without_a_setting_the_persona_rule_is_enforced(monkeypatch):
    """Accepted 2026-10-23: enforce is the default; a deployment that wants warn says so."""
    from keyclerk import config
    cfg = {k: v for k, v in config.current().items() if k != "identity"}
    monkeypatch.setattr(config, "current", lambda: cfg)
    assert D.persona_mode() == "enforce"


def test_a_retired_membership_is_judged_as_made_also_for_its_approvers(monkeypatch):
    """An approval given with a daily account before the move to admin personas still counts for the retired
    membership it approved; a live one is judged by today's rule."""
    from keyclerk import config
    cfg = {**config.current(), "identity": {**(config.current().get("identity") or {}), "persona_rule": "enforce"}}
    monkeypatch.setattr(config, "current", lambda: cfg)
    d = doc()
    member(d, "M-t-1", "admins", KAI_ADM)
    d["memberships"][-1]["approved_by"] = [ANN]                # ann's daily account
    assert any("second key" in e for e in D.check(d) if e.startswith("M-t-1:"))   # live: today's rule
    d.setdefault("admin_revocations", []).append({"id": "M-t-1", "at": "2026-10-20T00:00:00Z", "by": "idp:2b9e-owner",
                                                 "mode": "retire", "reason": "moved"})
    retired = [e for e in D.check(d) if e.startswith("M-t-1:") and "second key" in e]
    assert retired == []                                    # retired: as it was made
