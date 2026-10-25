# SPDX-License-Identifier: EUPL-1.2
"""Pools and fallback ladders: pools at least twice the need from the roster, a ladder
wherever two people or an escort guard the way to Sensitive or Restricted, and the same step chosen by the Python
reference and by keyclerk/policy/fallback.rego."""
import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import access_paths as A  # noqa: E402
from keyclerk import pools as P  # noqa: E402

G = yaml.safe_load((FIXTURES / "access-paths.yaml").read_text(encoding="utf-8"))
PEOPLE = A.roster(FIXTURES / "records.yaml")

CASES = [   # (ladder, label, band, level, urgent, available) -> step
    (["remote_confirm", "deferred"], "Sensitive", "green", "normal", False, {"site_office": True}, "remote_confirm"),
    (["remote_confirm", "deferred"], "Sensitive", "green", "normal", False, {"site_office": False}, "deferred"),
    (["remote_confirm", "supervised", "deferred"], "Sensitive", "amber", "normal", True,
     {"site_office": False, "remote_watch": True}, "supervised"),
    (["remote_confirm", "supervised", "deferred"], "Sensitive", "amber", "normal", False,
     {"site_office": False, "remote_watch": True}, "deferred"),                        # supervised only when urgent
    (["remote_confirm", "deferred"], "Restricted", "green", "high", False, {"site_office": True}, "deferred"),   # remote ends
    (["remote_confirm", "deferred"], "Restricted", "green", "elevated", False, {"site_office": True}, "remote_confirm"),
    (["deferred", "never"], "Restricted", "green", "normal", True, {"site_office": True}, "deferred"),
    (["remote_confirm", "never"], "Restricted", "green", "normal", False, {"site_office": False}, "never"),     # come back never
    (["remote_confirm", "deferred"], "Internal", "red", "normal", True, {"site_office": True}, "never"),
]


def test_the_demo_pools_and_ladders_are_clean():
    assert P.check(G, PEOPLE) == []


@pytest.mark.parametrize("ladder,label,band,level,urgent,available,want", CASES)
def test_the_reference_ladder(ladder, label, band, level, urgent, available, want):
    assert P.fallback(ladder, label, band, level, urgent, available)["step"] == want


def test_the_rego_ladder_agrees_with_the_reference(tmp_path):
    assert shutil.which("opa"), "opa is pinned in CI (tools/fetch_opa.py) and required locally"
    data = {"keyclerk": {"availability": dict(A.config.current()["availability"])}}
    (tmp_path / "data.json").write_text(json.dumps(data), encoding="utf-8")
    for ladder, label, band, level, urgent, available, want in CASES:
        inp = {"ladder": ladder, "label": label, "band": band, "level": level, "urgent": urgent,
               "available": {"site_office": False, "remote_watch": False, **available}}
        (tmp_path / "input.json").write_text(json.dumps(inp), encoding="utf-8")
        out = subprocess.run(["opa", "eval", "-f", "raw", "-d", str(ROOT / "keyclerk" / "policy" / "fallback.rego"),
                              "-d", str(tmp_path / "data.json"), "-i", str(tmp_path / "input.json"),
                              "data.keyclerk.fallback.step"], capture_output=True, text=True, check=True)
        assert out.stdout.strip().strip('"') == want, (inp, out.stdout)


def test_a_pool_smaller_than_twice_the_need_is_a_finding():
    people = {a: e for a, e in PEOPLE.items() if a not in ("idp:44aa-dirk", "op:7a1e-oscar")}
    errs = P.check(G, people)
    assert any(e.startswith("lockbox-a1-code: two-person pool of 2, needs 4") for e in errs)


def test_a_two_person_checkpoint_on_the_way_to_restricted_declares_a_ladder_that_ends_closed():
    bad = copy.deepcopy(G)
    lb = next(c for c in bad["checkpoints"] if c["checkpoint_id"] == "lockbox-a1-code")
    lb["fallback"] = ["remote_confirm", "supervised"]
    errs = P.check(bad, PEOPLE)
    assert "lockbox-a1-code: fallback steps ['supervised'] are not allowed for Restricted" in errs
    assert "lockbox-a1-code: a Restricted ladder ends in deferred or never" in errs
    lb.pop("fallback")
    assert any(e.startswith("lockbox-a1-code: needs two people or an escort") for e in P.check(bad, PEOPLE))


def test_a_quorum_share_with_one_keeper_is_a_finding():
    bad = copy.deepcopy(G)
    next(k for k in bad["credentials"] if k["credential_id"] == "deposit-box-key")["held_by"] = ["idp:2b9e-owner"]
    assert "deposit-box-open: share deposit-box-key has 1 custodians or stores, needs 2" in P.check(bad, PEOPLE)
