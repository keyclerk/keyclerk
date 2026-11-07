# SPDX-License-Identifier: EUPL-1.2
"""Issues 50 to 52 (an install walk): the edge command line says what would fail later, before anyone signs or seals."""
from keyclerk import edge_cli as C
from keyclerk.edge_cli import _ceiling_warnings

ANCHOR = "kc:" + "0" * 32


def _statement(capsys, *extra):
    rc = C.main(["statement", "--edge", "edge-a", "--officer", *extra, "--officer-key", "aa" * 32,
                 "--enrolment-key", "bb" * 32])
    return rc, capsys.readouterr()


def test_issue_50_an_officer_that_is_not_an_anchor_is_refused_before_signing(capsys):
    rc, out = _statement(capsys, "alice")
    assert rc == 2 and "no anchor scheme" in out.err and not out.out


def test_issue_50_an_anchor_or_an_account_on_purpose_is_taken(capsys, monkeypatch):
    monkeypatch.setattr(C, "_out", lambda obj: print("signed-out"))
    monkeypatch.setattr(C.E, "officer_statement", lambda *a: {})
    monkeypatch.setattr(C.E, "node", lambda *a: {})
    assert _statement(capsys, ANCHOR)[0] in (0, None)                           # the change log's
    assert _statement(capsys, "op:a1bd8d6c-33f5-4525-a665-5f0ea9236cdb")[0] in (0, None)   # a signed-YAML store's
    assert _statement(capsys, "alice", "--account")[0] in (0, None)


def test_issue_51_a_ceiling_without_persons_says_whom_it_admits():
    assert "admits no one at all" in _ceiling_warnings([], [], ["low"], 24)[0]
    assert "only leases by role (operators) of class low" in _ceiling_warnings([], ["operators"], ["low"], 24)[0]
    assert _ceiling_warnings([ANCHOR], [], ["low"], 24) == []


def test_issue_52_a_ceiling_under_a_day_warns_and_the_default_fits_a_day(capsys, monkeypatch):
    assert "until its last 8 hours" in _ceiling_warnings([ANCHOR], [], ["low"], 8)[0]
    got = []
    monkeypatch.setattr(C, "_out", got.append)
    C.main(["ceiling", "--edge", "edge-a", "--serial", "1", "--persons", ANCHOR, "--targets", "plc-ssh"])
    assert got[0]["max_lease_hours"] == 24 and "warning" not in capsys.readouterr().err
