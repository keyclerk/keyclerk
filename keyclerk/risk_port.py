# SPDX-License-Identifier: EUPL-1.2
"""The risk port for group membership, shaped on FTEF (ftef-spec 5.3 to 6.8).

A membership gives rights only while its member's trust meets the floor of the group's effective risk class. Trust is
two numbers that never stand in for each other: proof trust per claim, and the person's risk band from
the risk feed. Standalone, KeyClerk computes proof trust from its own proof results; inside a larger platform the same input
comes from the platform's risk and trust ports. Either way the input is keyclerk-trust-input-v1
(schema/trust-input.schema.json), so the source can change without the rule changing.

A shortfall is never silent: the member stays recorded but dormant (no rights) until the trust is there, or a risk
acceptance lifts it. Acceptances follow FTEF 6.3: at most one band above the evidenced band, never to high, never for
a privileged group, only while decided_at <= now < until, not lapsed, the situation level not risen, and not decided
by the person who asked. Accepted trust never feeds anything else (no-transit).
"""
from __future__ import annotations

from datetime import datetime, timedelta


from keyclerk.grants import _ts

from keyclerk import config
BANDS = ["none", "low", "medium", "high"]
RISK_BANDS = ["green", "amber", "red", "black"]


R = config.Section("risk_port")


def _rank(b: str) -> int:
    return BANDS.index(b)


def evidenced(trust: dict, claim: str, at: datetime) -> str:
    p = trust.get("proof", {}).get(claim)
    if not p or at >= _ts(p["valid_until"]):
        return "none"   # decay: a result that is no longer fresh counts as absent
    return p["band"]


def acceptance_lift(trust: dict, a: dict, at: datetime) -> str | None:
    """The band an acceptance grants now, or None when it does not apply (FTEF 6.3)."""
    if a.get("lapsed_at") or not (_ts(a["decided_at"]) <= at < _ts(a["until"])):
        return None
    if a.get("requested_by") and a["requested_by"] == a["decided_by"]:
        return None
    if R["situation_levels"].index(trust.get("situation_level", "normal")) > R["situation_levels"].index(a["situation_level"]):
        return None   # the situation rose above the level the acceptance was decided at: it lapses
    if _ts(a["until"]) - _ts(a["decided_at"]) > timedelta(days=R["acceptance_max_days"]):
        return None
    base = evidenced(trust, a["claim"], at)
    cap = min(_rank(a["granted_band"]), _rank(base) + 1, _rank(R["acceptance_max_band"]))
    return BANDS[cap] if cap > _rank(base) else None


def band(trust: dict, claim: str, at: datetime, accept: bool = True) -> tuple[str, str | None]:
    """(band, acceptance id that lifted it or None)."""
    base = evidenced(trust, claim, at)
    best, by = base, None
    if accept:
        for a in trust.get("acceptances", []):
            if a["claim"] == claim:
                lifted = acceptance_lift(trust, a, at)
                if lifted and _rank(lifted) > _rank(best):
                    best, by = lifted, a["acceptance_id"]
    return best, by


def meets(trust: dict | None, risk: str, at: datetime, level: str = "normal", kind: str = "tenant") -> dict:
    """Whether a member with this trust may use a group of this effective risk class now, and why not. level and kind
    raise the floor: externals from high, everyone at severe."""
    from keyclerk import situation
    if trust is None:
        return {"ok": False, "why": ["no trust input for the person: absent is the strictest value"]}
    why = []
    if trust.get("risk_band", "green") not in R["usable_risk_bands"]:
        why.append(f"risk band {trust['risk_band']}")
    accepted = []
    for claim, floor in R["floor_by_risk"][risk].items():
        floor = BANDS[min(_rank(floor) + situation.floor_raise(kind, level), len(BANDS) - 1)]
        got, acc = band(trust, claim, at, accept=risk not in R["no_acceptance_for"])
        if _rank(got) < _rank(floor):
            why.append(f"{claim} trust {got}, needs {floor}")
        elif acc:
            accepted.append(acc)
    return {"ok": not why, "why": why, "accepted": accepted}


def split(members: set[str], trusts: dict[str, dict], risk: str, at: datetime, level: str = "normal",
          kinds: dict[str, str] | None = None) -> tuple[set[str], dict[str, list[str]]]:
    """(active, dormant with reasons): the members whose trust meets the floor, and the rest."""
    active, dormant = set(), {}
    for a in sorted(members):
        r = meets(trusts.get(a), risk, at, level, (kinds or {}).get(a, "tenant"))
        if r["ok"]:
            active.add(a)
        else:
            dormant[a] = r["why"]
    return active, dormant
