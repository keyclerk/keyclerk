# SPDX-License-Identifier: EUPL-1.2
"""A proof whose token was erased is a reason, never an exception (decision 0028)."""
from pathlib import Path

from keyclerk import approvals, guard, records

FIX = Path(__file__).resolve().parent / "fixtures" / "records.yaml"


def _reject(*_):
    raise guard.InputRejected("no")


def test_an_erased_token_is_an_unproven_approval_not_a_crash():
    doc = records.loads(FIX.read_text(encoding="utf-8"))
    kind, rid, rec, by = next(approvals.keys_in(doc))
    doc["approval_proofs"] = [{"records": [rid], "by": by, "sha256": "0" * 64}]     # as replay._token leaves it
    errs = approvals.check(doc, _reject, {})
    assert any(e.startswith(f"{rid}:") for e in errs)
