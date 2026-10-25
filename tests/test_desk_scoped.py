# SPDX-License-Identifier: EUPL-1.2
"""The desk on the change log judges a change on what it reaches (decision 0022 S5 step T9), as the signer does: the
same outcome and the same reasons as the full check, change by change, and the full check whenever the reach is
everyone or too wide."""
import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_signer_replica import FIXTURES

from keyclerk import metrics
from keyclerk.desk import Desk, Refusal
from keyclerk.signer import Signer
from keyclerk.store.log_desk import LogStore

ANN = {"anchor": "idp:7c1f-ann", "roles": []}
EVA = {"anchor": "idp:55bb-eva", "roles": []}
CHANGES = [
    (ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:66cc-finn", "days": 5}),
    (ANN, {"action": "add_member", "group": "office-staff", "anchor": "idp:bb11-kai", "days": 400}),   # past the cap
    (ANN, {"action": "add_member", "group": "office-staff", "anchor": "op:7a1e-oscar", "days": 30}),
    (EVA, {"action": "add_member", "group": "office-staff", "anchor": "idp:ee01-guard", "days": 5}),
]


@pytest.fixture
def desks(tmp_path):
    out = []
    for name in ("scoped", "full"):
        signer = Signer(Ed25519PrivateKey.generate(), tmp_path / f"signer-{name}")
        store = LogStore(tmp_path / f"desk-{name}", signer, FIXTURES / "records.yaml")
        store.scoped_judging = name == "scoped"
        out.append((Desk(store), signer))
    yield out
    for d, s in out:
        d.store.close()
        s.close()


def _outcome(desk, who, body):
    doc = desk.store.load()
    try:
        add, _ = desk.build(doc, desk.store.inward(who["anchor"]) or who["anchor"], copy.deepcopy(body), desk.clock())
    except Refusal as e:
        return ("refused before the checks", str(e))
    outcome, reasons, _ = desk._evaluate(doc, add)
    return outcome, [r.split(": ", 1)[-1] for r in reasons]          # record ids differ between the two desks


def test_scoped_and_full_judging_give_the_same_outcome_change_by_change(desks):
    (scoped, _), (full, _) = desks
    for who, body in CHANGES:
        a, b = _outcome(scoped, who, body), _outcome(full, who, body)
        assert a == b, (body, a, b)
        if a[0] == "applied":                                       # both move on to the same next state
            assert scoped.propose(who, body)["outcome"] == full.propose(who, body)["outcome"] == "applied"


def test_a_plain_change_is_judged_on_its_reach_without_the_full_check(desks, monkeypatch):
    (scoped, _), _ = desks
    called = []
    real = Desk._errors
    monkeypatch.setattr(Desk, "_errors", lambda self, doc: called.append(1) or real(self, doc))
    assert scoped.propose(*CHANGES[0])["outcome"] == "applied"
    assert not called                                  # the desk never ran the full check (the signer judges on its own)


def test_a_change_that_reaches_everyone_falls_back_to_the_full_check(desks, monkeypatch):
    (scoped, _), _ = desks
    from keyclerk import scope
    monkeypatch.setattr(scope, "reach", lambda old, new, ops: scope.Full("group_tree"))
    called = []
    real = Desk._errors
    monkeypatch.setattr(Desk, "_errors", lambda self, doc: called.append(1) or real(self, doc))
    metrics.reset()
    assert scoped.propose(*CHANGES[0])["outcome"] == "applied"
    assert called and 'keyclerk_check_fallback_total{reason="group_tree"} 1' in metrics.render()


def test_the_records_moved_forward_link_by_link_equal_a_full_replay(desks):
    from keyclerk.store import replay as RP
    (scoped, _), _ = desks
    for who, body in CHANGES:
        try:
            scoped.propose(who, body)
        except Refusal:
            pass
        held = scoped.store.load()
        whole = RP.records(scoped.store.store)
        assert {k: v for k, v in held.items() if k not in ("visits", "visit_events", "badges")} == whole
