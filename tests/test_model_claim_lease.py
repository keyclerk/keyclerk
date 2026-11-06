# SPDX-License-Identifier: EUPL-1.2
"""Decision 0032 points 30 to 38, version 2: the claim-lease model (docs/specs/ClaimLease.tla) explored exhaustively on
every run, each case at the smallest bounds that reach it: the rule holds under held-back bundles, the protocol's skew,
an adversarial edge clock, reboots, late status lists and desk restores, and each broken assumption breaks the property
it should. Two variants need TLC's bounds (millions of states) and are checked there: docs/specs/ClaimLease-*.cfg."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from model_claim_lease import CASES, Model, broke_as_intended  # noqa: E402


@pytest.mark.parametrize("name", [n for n, (_, _, b) in CASES.items() if b is not None])
def test_the_rule_holds_and_each_broken_assumption_breaks_its_property(name):
    variant, must_break, bounds = CASES[name]
    bad, trace, states = Model(**bounds, variant=variant).run()
    assert states > 50 and not (bad or "").startswith("state limit")
    assert broke_as_intended(bad, must_break), (bad, trace)


def test_the_cases_only_tlc_reaches_are_named_and_have_their_configuration():
    specs = Path(__file__).resolve().parent.parent / "docs" / "specs"
    for name, (variant, _, _bounds) in CASES.items():
        assert (specs / ("ClaimLease.cfg" if variant == "ok" else f"ClaimLease-{variant}.cfg")).exists(), name
