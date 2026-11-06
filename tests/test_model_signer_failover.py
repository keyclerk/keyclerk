# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 point 8: the core's failover model (docs/specs/SignerFailover.tla), explored exhaustively at small
bounds on every run (one link per signer, two in the log): the design keeps one history, and each broken assumption
yields a counterexample. The larger bounds run with `python tools/model_signer_failover.py --all --max-len 2` (about 2.1 million states)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from model_signer_failover import CASES, Model  # noqa: E402


@pytest.mark.parametrize("name", list(CASES))
def test_the_design_holds_and_each_broken_assumption_fails(name):
    flags, must_fail = CASES[name]
    bad, trace, states = Model(max_signs=1, max_len=2, max_msgs=2, **flags).run()
    assert states > 50 and not (bad or "").startswith("state limit")
    assert bool(bad) == must_fail, (bad, trace)
