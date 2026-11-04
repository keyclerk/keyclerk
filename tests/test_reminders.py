# SPDX-License-Identifier: EUPL-1.2
"""Decision 0030 point 2 (issue 30): approvers are reminded, never handed an action. A pending change gets an
approval_waiting line, then change_expiring and approval_escalated when due, each once, naming the change and its next
approvers and carrying nothing that approves."""
from datetime import timedelta

from keyclerk import guard
from keyclerk.desk import PENDING_DAYS
from tests.test_desk import ANN, BERT, desk  # noqa: F401 - fixture


def _pending(desk):
    r = desk.propose(ANN, {"action": "include_group", "group": "office-staff", "include": "site-wilsele", "days": 30})
    assert r["outcome"] == "pending"
    return r["change_id"], guard.timestamp(desk.store.pending()[r["change_id"]]["at"])


def _at(desk, t):
    desk.clock = lambda: t


def _kinds(lines):
    return [x["action"] for x in lines]


def test_a_pending_change_is_reminded_once_per_step_and_names_its_approvers(desk):
    cid, at = _pending(desk)
    _at(desk, at + timedelta(minutes=1))
    first = desk.remind_pending()
    assert _kinds(first) == ["approval_waiting"] and first[0]["change_id"] == cid
    assert desk.store.inward(BERT["anchor"]) in first[0]["approvers"]    # bert manages the sites subtree
    assert desk.remind_pending() == []                               # once
    _at(desk, at + timedelta(hours=72))
    assert _kinds(desk.remind_pending()) == ["approval_escalated"]
    _at(desk, at + timedelta(days=PENDING_DAYS) - timedelta(hours=2))
    assert _kinds(desk.remind_pending()) == ["change_expiring"]
    assert desk.remind_pending() == []


def test_an_escalation_names_the_root_and_the_officer_too(desk):
    cid, at = _pending(desk)
    _at(desk, at + timedelta(hours=73))
    lines = {x["action"]: x for x in desk.remind_pending()}
    assert set(lines) == {"approval_waiting", "approval_escalated"}
    doc = desk.store.load()
    root = (doc.get("root") or {})
    extra = {x for x in (root.get("officer"), root.get("anchor")) if x}
    assert set(lines["approval_waiting"]["approvers"]) < set(lines["approval_escalated"]["approvers"])
    assert extra & set(lines["approval_escalated"]["approvers"])


def test_a_reminder_carries_nothing_that_approves(desk):
    cid, at = _pending(desk)
    _at(desk, at + timedelta(minutes=1))
    line = desk.remind_pending()[0]
    text = str(line)
    assert "http" not in text and "/approve" not in text and "token" not in text and "qr" not in text
    assert set(line) <= {"seq", "at", "revision", "prev", "sha256", "signature", "change_id", "action", "actor",
                         "outcome", "records", "reasons", "summary", "approvers", "waiting_since", "ends"}


def test_an_expired_or_decided_change_is_not_reminded(desk):
    cid, at = _pending(desk)
    _at(desk, at + timedelta(days=PENDING_DAYS, minutes=1))
    assert desk.remind_pending() == []
    _at(desk, at + timedelta(minutes=1))
    desk.approve(BERT, cid)
    assert desk.remind_pending() == []


def test_the_tick_reminds(desk):
    cid, at = _pending(desk)
    _at(desk, at + timedelta(minutes=1))
    desk.tick()
    assert [e["action"] for e in desk.store.log(20)].count("approval_waiting") == 1
