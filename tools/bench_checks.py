# SPDX-License-Identifier: EUPL-1.2
"""How long the engine checks take for a valid organisation of N people (decision 0017).

The test fixture's people, groups, delegations and rules, plus N generated people. Each gets the fixture's
person-anchored memberships, each starting a few minutes later than its template (inside the template's window, so the
delegation held and the length limit holds) to give every person their own boundaries, as an organisation that hires
over time has. The generated part must add no check errors; the timing is what check_records costs on that revision.

    python tools/bench_checks.py [N ...]          default 100 1000
    python tools/bench_checks.py --json 100       one JSON line per size (for a budget in CI)
"""
from __future__ import annotations

import copy
import json
import sys
import time
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import yaml  # noqa: E402

from keyclerk import config, delegation as D  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


def organisation(n: int) -> dict:
    """The fixture plus n generated people with valid memberships."""
    doc = yaml.safe_load((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
    templates = [m for m in doc.get("memberships", []) if "anchor" in m.get("member", {})]
    deleg = {d["delegation_id"]: d for d in doc.get("delegations", [])}

    def room(m) -> int:
        """Whole days a start can move and stay inside its membership and its delegation (the flood cap is per day)."""
        end = D._ts(m["end"])
        if m["under"] in deleg and deleg[m["under"]].get("end"):
            end = min(end, D._ts(deleg[m["under"]]["end"]))
        for r in doc.get("admin_revocations", []):                  # a revoked delegation holds until its revocation
            if r["id"] == m["under"]:
                end = min(end, D._ts(r["at"]))
        return max(1, min(20, (end - D._ts(m["start"])).days - 1))

    for i in range(n):
        anchor = f"idp:{i:06x}-gen"
        doc["persons"].append({"person": f"gen-{i}", "kind": "tenant", "anchors": [anchor]})
        for j, m in enumerate(templates):
            start = D._ts(m["start"]) + timedelta(days=i % room(m), minutes=1 + (i % 720))
            doc["memberships"].append({**copy.deepcopy(m), "membership_id": f"M-gen-{i}-{j}", "member": {"anchor": anchor},
                                       "start": start})
    return doc


def measure(n: int) -> dict:
    from keyclerk.reconcile import check_records
    base = set(check_records(organisation(0)))
    doc = organisation(n)
    t = time.perf_counter()
    errs = check_records(doc)
    seconds = time.perf_counter() - t
    new = sorted(set(errs) - base)
    return {"people": n, "memberships": len(doc["memberships"]), "seconds": round(seconds, 3),
            "new_errors": len(new), "first_errors": new[:3]}


def bench_config() -> Path:
    """The fixture configuration with the anti-flood limits raised: a real organisation spreads its widenings over
    months; the benchmark puts them in a few days, and the flood rule is not what it measures."""
    import tempfile
    c = yaml.safe_load((FIXTURES / "config.yaml").read_text(encoding="utf-8"))
    for section in c.values():
        if isinstance(section, dict) and "widenings_per_deputy_per_day" in section:
            section["widenings_per_deputy_per_day"] = 1000
            section["widenings_per_subtree_per_day"] = 10000
    out = Path(tempfile.mkdtemp()) / "config.yaml"
    out.write_text(yaml.safe_dump(c), encoding="utf-8")
    return out


def main(argv: list[str]) -> int:
    config.configure(bench_config())
    as_json = "--json" in argv
    sizes = [int(a) for a in argv if a.isdigit()] or [100, 1000]
    for n in sizes:
        r = measure(n)
        if as_json:
            print(json.dumps(r))
        else:
            print(f"{r['people']:6d} people {r['memberships']:7d} memberships  {r['seconds']:8.2f} s  "
                  f"new errors {r['new_errors']} {r['first_errors'][:1]}")
        sys.stdout.flush()
        if r["new_errors"]:
            return 2                            # the generator must stay valid, or the timing means nothing
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
