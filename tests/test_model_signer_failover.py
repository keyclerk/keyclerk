# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 point 8 and decision 0033 point 9: the core's failover model with each node's key custodian
(docs/specs/SignerFailover.tla), explored exhaustively at small bounds on every run (one link per signer, two in the
log; two per signer where a custodian must sign twice to break): the design keeps one history and its custodians never
sign a position twice, and each broken assumption yields a counterexample. The larger bounds are TLC's
(docs/specs/SignerFailover.cfg, two links per signer, three in the log: about 53 million distinct states, 16 minutes);
the explorer's limit of 8 million states is passed at two links per signer."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from model_signer_failover import CASES, Model  # noqa: E402


@pytest.mark.parametrize("name", list(CASES))
def test_the_design_holds_and_each_broken_assumption_fails(name):
    flags, must_fail = CASES[name]
    signs = 2 if name == "follow-below-own" else 1        # following below its own size needs a second signature
    bad, trace, states = Model(max_signs=signs, max_len=2, max_msgs=2, **flags).run()
    assert states > 50 and not (bad or "").startswith("state limit")
    assert bool(bad) == must_fail, (bad, trace)
