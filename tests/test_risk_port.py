# SPDX-License-Identifier: EUPL-1.2
"""The risk port for group membership: trust per claim meets the floor of the
group's effective class, acceptances lift at most one band and never to high (FTEF 6.3), and a shortfall leaves the
member dormant instead of dropping them silently."""
import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures"
from keyclerk import delegation as D  # noqa: E402
from keyclerk import records  # noqa: E402
from keyclerk import risk_port as P  # noqa: E402

NOW = datetime(2026, 10, 22, 12, 0, tzinfo=timezone.utc)
SCHEMA = P.config.schema("trust-input")


def trust(identity="low", likeness=None, risk_band="green", acceptances=(), situation="normal", fresh=True):
    until = (NOW + timedelta(days=30 if fresh else -1)).isoformat()
    proof = {"identity": {"band": identity, "method": "tenant_idp", "valid_until": until}}
    if likeness:
        proof["likeness"] = {"band": likeness, "method": "in_person_live_match", "valid_until": until}
    t = {"anchor": "idp:77dd-gina", "source": "keyclerk", "proof": proof, "risk_band": risk_band,
         "situation_level": situation, "acceptances": list(acceptances), "inputs": {"records": "sha256:0", "policy": "sha256:1"}}
    jsonschema.validate(t, SCHEMA)
    return t


def acc(granted="medium", requested_by="idp:77dd-gina", decided_by="idp:31ee-ingrid", situation="normal", days=30):
    return {"acceptance_id": "RA-1", "claim": "identity", "granted_band": granted, "decided_at": (NOW - timedelta(days=1)).isoformat(),
            "until": (NOW + timedelta(days=days - 1)).isoformat(), "decided_by": decided_by, "requested_by": requested_by,
            "situation_level": situation, "residual": 6, "limits": ["no-transit"]}


def test_the_floor_follows_the_effective_class():
    assert P.meets(trust("low"), "low", NOW)["ok"]
    assert not P.meets(trust("low"), "elevated", NOW)["ok"]
    assert P.meets(trust("medium"), "elevated", NOW)["ok"]
    assert not P.meets(trust("high"), "privileged", NOW)["ok"]                       # likeness missing
    assert P.meets(trust("high", "medium"), "privileged", NOW)["ok"]


def test_stale_proof_and_a_red_band_narrow():
    assert not P.meets(trust("medium", fresh=False), "elevated", NOW)["ok"]
    assert not P.meets(trust("high", "medium", risk_band="red"), "privileged", NOW)["ok"]
    assert not P.meets(None, "low", NOW)["ok"]


def test_an_acceptance_lifts_one_band_never_to_high_never_for_privileged():
    r = P.meets(trust("low", acceptances=[acc()]), "elevated", NOW)
    assert r["ok"] and r["accepted"] == ["RA-1"]
    assert not P.meets(trust("none", acceptances=[acc()]), "elevated", NOW)["ok"]     # one band at most
    assert not P.meets(trust("medium", "medium", acceptances=[acc()]), "privileged", NOW)["ok"]


def test_an_acceptance_lapses_on_a_situation_rise_and_is_void_when_self_decided():
    assert not P.meets(trust("low", acceptances=[acc()], situation="high"), "elevated", NOW)["ok"]
    assert not P.meets(trust("low", acceptances=[acc(decided_by="idp:77dd-gina")]), "elevated", NOW)["ok"]
    assert not P.meets(trust("low", acceptances=[acc(days=120)]), "elevated", NOW)["ok"]


def test_a_member_below_the_floor_is_dormant_not_dropped_from_the_record():
    doc = copy.deepcopy(records.load(FIXTURES / "records.yaml"))
    groups = D.carrier_groups(doc, NOW, trusts={"idp:77dd-gina": trust("low")})
    assert "idp:77dd-gina" not in groups["/groups/finance"]                          # finance is elevated
    assert "idp:77dd-gina" in D.effective_members(doc, "finance", NOW)                # still recorded
    active, dormant = P.split({"idp:77dd-gina"}, {"idp:77dd-gina": trust("low")}, "elevated", NOW)
    assert not active and dormant["idp:77dd-gina"] == ["identity trust low, needs medium"]
