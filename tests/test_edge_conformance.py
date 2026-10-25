# SPDX-License-Identifier: EUPL-1.2
"""Decision 0014 point 6: the conformance set an edge agent runs too. The modules it names are the compiled policies,
and every case gives its recorded answer; regenerate with tools/gen_edge_conformance.py after changing the Rego."""
import hashlib
import json
from pathlib import Path

from keyclerk import policy_wasm

ROOT = Path(__file__).resolve().parent.parent
SET = json.loads((ROOT / "tests" / "conformance" / "edge.json").read_text(encoding="utf-8"))


def norm(x):
    if isinstance(x, dict):
        return {k: norm(v) for k, v in x.items()}
    if isinstance(x, (list, set, tuple)):
        items = [norm(v) for v in x]
        return sorted(items, key=json.dumps) if isinstance(x, set) or all(isinstance(v, str) for v in items) else items
    return x


def test_the_set_names_the_modules_that_are_shipped():
    for name, sha in SET["modules"].items():
        assert hashlib.sha256((ROOT / "keyclerk" / "policy" / f"{name}.wasm").read_bytes()).hexdigest() == sha, name


def test_every_case_gives_its_recorded_answer():
    assert len(SET["cases"]) >= 15
    for c in SET["cases"]:
        got = policy_wasm.load(c["policy"]).eval(c["entrypoint"], c["input"])
        assert norm(got) == norm(c["expected"]), c["name"]


def test_the_reference_verifier_gives_the_recorded_verdicts():
    """The bytes, pins, state and moment in each case give the same verdict and the same live leases."""
    from datetime import datetime, timezone
    from keyclerk import edge as E
    for c in SET["verifier"]["cases"]:
        errs, applied = E.verify_bundle(c["sealed"], c["pins"], c["state"],
                                        datetime.strptime(c["now"], E.ISO).replace(tzinfo=timezone.utc))
        assert (not errs) == c["expected"]["ok"], (c["name"], errs)
        assert [x["lease_id"] for x in applied.get("leases", [])] == c["expected"]["leases"], c["name"]
        assert [x["lease_id"] for x in applied.get("visit_leases", [])] == c["expected"]["visit_leases"], c["name"]
        assert (applied.get("state") if not errs else None) == c["expected"]["state"], c["name"]
        assert (applied.get("governed_roles") if not errs else None) == c["expected"]["governed_roles"], c["name"]


def test_the_other_families_give_the_recorded_verdicts():
    """Amendment 0014d, kc-unlock-v2, the bound ended notice, modules by hash (keyclerk/edge_conformance.py)."""
    from keyclerk import edge_conformance as EC
    assert EC.failures(SET) == []
    for fam in EC.FAMILIES:
        assert len(SET[fam]["cases"]) >= 3, fam
    assert any(c["expected"]["code"] for c in SET["unlock"]["cases"])
