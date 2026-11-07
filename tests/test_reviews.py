# SPDX-License-Identifier: EUPL-1.2
"""Access reviews, derived (0.29, #42): a direct membership is due max_age_months after its start or its newest keep,
lapses grace_days later, and a unit change makes what came with the old unit due at once (the mover's grace)."""
import copy
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from keyclerk import delegation as D
from keyclerk import records
from keyclerk.desk import Desk, Refusal, Store

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ANN, BERT, OWNER = "idp:7c1f-ann", "idp:91d0-bert", "idp:2b9e-owner"
POLICY = {"max_age_months": 1, "grace_days": 7, "from": "2026-10-01T00:00:00Z"}


def t(day: str) -> datetime:
    return datetime.fromisoformat(day + "T12:00:00+00:00").astimezone(timezone.utc)


def doc_with(**extra) -> dict:
    doc = copy.deepcopy(records.load(FIXTURES / "records.yaml"))
    doc.update(extra)
    return doc


def m1(doc: dict) -> dict:
    return next(m for m in doc["memberships"] if m["membership_id"] == "M-example-0001")


def keep(by: str, at: str, source: str = "owner") -> dict:
    return {"decision_id": f"RV-{by[-4:]}{at[:10]}", "membership": "M-example-0001", "decision": "keep", "by": by,
            "at": at, "source": source}


def test_without_a_reviews_setting_nothing_lapses_for_want_of_a_review():
    doc = doc_with()
    assert D.review_due(doc, m1(doc), t("2027-02-01")) is None
    assert D.membership_status(doc, m1(doc), t("2027-02-01")) == "active"


def test_a_membership_is_due_after_max_age_and_lapses_after_the_grace():
    doc = doc_with(reviews=POLICY)
    assert D.membership_status(doc, m1(doc), t("2026-11-05")) == "active"          # due 11-02, inside the grace
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "unreviewed"      # past 11-09


def test_an_owners_keep_restarts_the_clock_and_the_members_own_does_not():
    doc = doc_with(reviews=POLICY, review_decisions=[keep(ANN, "2026-11-05T09:00:00Z")])
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "active"
    assert D.membership_status(doc, m1(doc), t("2026-12-13")) == "unreviewed"
    doc = doc_with(reviews=POLICY, review_decisions=[keep(BERT, "2026-11-05T09:00:00Z")])   # bert is the member
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "unreviewed"


def test_a_parent_keep_counts_only_for_a_named_parent_principal():
    doc = doc_with(reviews=POLICY, review_decisions=[keep("idp:55bb-eva", "2026-11-05T09:00:00Z", "parent")])
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "unreviewed"
    doc["reviews"] = {**POLICY, "parents": ["idp:55bb-eva"]}
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "active"


def test_a_keep_in_the_future_does_not_count_yet():
    doc = doc_with(reviews=POLICY, review_decisions=[keep(ANN, "2026-11-20T09:00:00Z")])
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "unreviewed"


def test_the_movers_grace_makes_what_came_with_the_old_unit_due_at_once():
    doc = doc_with(reviews={**POLICY, "max_age_months": 12})
    bert = next(p for p in doc["persons"] if BERT in p["anchors"])
    bert["unit_since"] = "2026-10-20T00:00:00Z"
    assert D.membership_status(doc, m1(doc), t("2026-10-25")) == "active"          # inside the grace
    assert D.membership_status(doc, m1(doc), t("2026-10-28")) == "unreviewed"
    doc["review_decisions"] = [keep(ANN, "2026-10-26T09:00:00Z")]                  # kept after the move
    assert D.membership_status(doc, m1(doc), t("2026-10-28")) == "active"
    doc["review_decisions"] = [keep(ANN, "2026-10-15T09:00:00Z")]                  # kept before it: does not count
    assert D.membership_status(doc, m1(doc), t("2026-10-28")) == "unreviewed"


def test_months_after_keeps_the_day_where_the_month_has_it():
    assert D._months_after(t("2026-01-31"), 1).day == 28
    assert D._months_after(t("2026-11-30"), 3) == t("2027-02-28")
    assert D._months_after(t("2026-12-15"), 1) == t("2027-01-15")


@pytest.fixture
def rdesk(tmp_path):
    seed = yaml.safe_load((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
    seed["reviews"] = POLICY
    (tmp_path / "seed.yaml").write_text(yaml.safe_dump(seed, sort_keys=False), encoding="utf-8")
    key = tmp_path / "key"
    key.write_text(Ed25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
                   encoding="utf-8")
    d = Desk(Store(tmp_path / "store", key, tmp_path / "seed.yaml"))
    d.clock = lambda: t("2026-11-10")
    return d


def test_the_owner_keeps_a_membership_before_it_lapses_alone(rdesk):
    rdesk.clock = lambda: t("2026-11-05")                 # due 11-02, lapses 11-09: inside the grace
    r = rdesk.propose({"anchor": ANN, "roles": []}, {"action": "review_membership", "membership_id": "M-example-0001",
                                                     "reason": "still on the office team"})
    assert r["outcome"] == "applied", r


def test_a_keep_after_the_lapse_needs_a_second_key(rdesk):
    """0.29 review R4: after the lapse a keep brings access back, so it waits for a second key from someone with the
    members power over the group, as a new membership would."""
    doc = rdesk.store.load()
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "unreviewed"
    r = rdesk.propose({"anchor": ANN, "roles": []}, {"action": "review_membership", "membership_id": "M-example-0001",
                                                     "reason": "still on the office team"})
    assert r["outcome"] == "pending" and "second key" in " ".join(r["reasons"]), r
    doc = rdesk.store.load()
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "unreviewed"
    assert rdesk.approve({"anchor": OWNER, "roles": []}, r["change_id"])["outcome"] == "applied"
    doc = rdesk.store.load()
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "active"
    assert records.guard(doc, {**doc, "review_decisions": []})                     # a decision is never dropped


def test_the_member_cannot_review_their_own_membership(rdesk):
    with pytest.raises(Refusal, match="never the member|may not review"):
        rdesk.propose({"anchor": BERT, "roles": []}, {"action": "review_membership", "membership_id": "M-example-0001",
                                                      "reason": "mine"})


def test_a_keep_by_a_delegate_revoked_for_cause_later_counts_for_nothing():
    """Review R1: ann keeps bert's membership; ann's delegation is later revoked for cause from before the keep."""
    doc = doc_with(reviews=POLICY, review_decisions=[keep(ANN, "2026-11-05T09:00:00Z")])
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) == "active"
    doc["admin_revocations"] = list(doc.get("admin_revocations", [])) + [
        {"id": "D-example-0001", "at": "2026-11-08T00:00:00Z", "by": "idp:2b9e-owner", "mode": "revoke",
         "from": "2026-11-01T00:00:00Z", "reason": "the account was taken over"}]
    assert D.membership_status(doc, m1(doc), t("2026-11-10")) != "active"


def test_a_unit_change_without_unit_since_is_refused_by_the_records_guard():
    """Review R2: nothing wrote unit_since, so the mover's grace never triggered; now a unit change must carry it."""
    old = doc_with()
    new = copy.deepcopy(old)
    bert = next(p for p in new["persons"] if BERT in p["anchors"])
    bert["unit"] = "finance-unit"
    assert any("mover's grace" in e for e in records.guard(old, new))
    bert["unit_since"] = "2026-11-06T00:00:00Z"
    assert not any("unit" in e for e in records.guard(old, new))
    newer = copy.deepcopy(new)
    del next(p for p in newer["persons"] if BERT in p["anchors"])["unit_since"]
    assert any("never goes back" in e for e in records.guard(new, newer))


def test_an_overdue_membership_can_be_ended_and_is_shown(rdesk):
    """0.29 review R5: a membership overdue for review is still a record someone can keep, so it can be ended (the
    group view says so) and the person's graph shows it as overdue instead of hiding it."""
    from keyclerk import graph
    ann = {"anchor": ANN, "roles": []}
    row = next(m for m in rdesk.group(ann, "office-staff")["memberships"] if m["membership_id"] == "M-example-0001")
    assert row["status"] == "unreviewed" and row["can_end"] is True
    g = graph.build(rdesk.store.load(), BERT, t("2026-11-10"))
    e = next(x for x in g["edges"] if x.get("record") == "M-example-0001")
    assert e["status"] == "unreviewed" and e["label"] == "review overdue"
    r = rdesk.propose(ann, {"action": "end_membership", "membership_id": "M-example-0001", "reason": "left the team"})
    assert r["outcome"] == "applied", r


def test_an_overdue_membership_is_not_added_again_to_reset_its_clock(rdesk):
    """0.29 review W6: adding the same person again would start a fresh review clock; it is kept by review or ended."""
    with pytest.raises(Refusal, match="already holds"):
        rdesk.propose({"anchor": ANN, "roles": []}, {"action": "add_member", "group": "office-staff", "anchor": BERT,
                                                     "days": 30, "reason": "again"})


def test_a_keep_is_the_reviewers_own_word_and_dated_at_its_change():
    """0.29 review R3: where approval proofs are required, a keep carries its reviewer's own fresh sign-in (a
    proposer's proof, decision 0015), and the checking signer refuses a keep not dated at the change."""
    from datetime import timedelta

    from keyclerk import approvals
    from keyclerk import edge as E
    from keyclerk.signer import Signer, SignerRefused
    assert approvals.needs_proposal_proof(doc_with(), "review_decisions", keep(ANN, "2026-11-05T12:00:00Z"), {})
    assert not approvals.needs_proposal_proof(doc_with(), "review_decisions", keep(ANN, "2026-11-05T12:00:00Z"),
                                              {"proposer_proof": {"off": True}})   # the deployment's switch still holds

    class St:
        def get(self, kind, key):
            return None
    now = datetime.now(timezone.utc)
    for at, ok in ((now - timedelta(days=3), False), (now + timedelta(hours=1), False), (now, True)):
        op = {"op": "put", "kind": "review_decisions", "key": "RV-1", "record": {**keep(ANN, E._iso(at))}}
        if ok:
            Signer._no_backdated_visits([op], St())
        else:
            with pytest.raises(SignerRefused, match="not dated at this change"):
                Signer._no_backdated_visits([op], St())


def test_w6_the_review_setting_only_tightens_in_place():
    """0.29 review W6: one revision cannot relax access reviews: off, longer, later or with a new parent."""
    old = doc_with(reviews={**POLICY, "parents": ["idp:2b9e-owner"]})
    for change in ({"reviews": None}, {"reviews": {**old["reviews"], "max_age_months": 12}},
                   {"reviews": {**old["reviews"], "grace_days": 90}},
                   {"reviews": {**old["reviews"], "from": "2027-01-01T00:00:00Z"}},
                   {"reviews": {**old["reviews"], "parents": ["idp:2b9e-owner", "idp:7c1f-ann"]}}):
        new = {**old, **change}
        if new["reviews"] is None:
            del new["reviews"]
        assert any(e.startswith("reviews:") for e in records.guard(old, new)), change
    tighter = {**old, "reviews": {**old["reviews"], "grace_days": 3, "parents": []}}
    assert not [e for e in records.guard(old, tighter) if e.startswith("reviews:")]
