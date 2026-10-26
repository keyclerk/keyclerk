# SPDX-License-Identifier: EUPL-1.2
"""With no earlier desired set, every anchored removal counts against the cap."""
from datetime import timedelta

from tests.test_reconcile import AT, Broker, FIXTURES, args, doc, write

from keyclerk import reconcile as Rc


def test_a_mass_removal_is_capped_even_when_desired_json_is_gone(tmp_path):
    b = Broker()
    first = Rc.run_once(args(tmp_path, FIXTURES / "records.yaml"), AT, b)
    assert first["applied"] and first["desired"] > 4
    (tmp_path / "state" / "desired.json").write_text("{half", encoding="utf-8")   # damaged: set aside as absent
    d = doc()
    root = d["root"]["holders"][0]["anchor"]
    d.setdefault("admin_revocations", []).extend(
        {"id": m["membership_id"], "at": AT - timedelta(minutes=1), "by": root, "mode": "retire", "reason": "reorganisation"}
        for m in d["memberships"])                                          # every membership retired at once
    run = Rc.run_once(args(tmp_path, write(tmp_path, d, "r2.yaml")), AT, b)
    assert "exceed the cap" in (run.get("refused") or ""), (
        f"{len(run['remove'])} removals applied with no cap (intrusions_removed={run['intrusions_removed']})")
