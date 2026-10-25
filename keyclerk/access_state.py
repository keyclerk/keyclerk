# SPDX-License-Identifier: EUPL-1.2
"""Derived access state. Nothing here is stored: every state is a pure function of
the signed records, the time and the evidence, so a lost event or a restart never loses state.

Three axes:
  intent    what the records say: granted, revoked, suspended
  validity  whether the window holds now: pending, valid, ended
  delivery  whether the broker matches (reported by tools/grants.py plan; it never widens)
Effective status follows midPoint's shape with one change: an administrative enable never overrides the end of the
window, because nothing outlives its end.

Clock skew only ever narrows: a widening is judged as if the clock were wrong in the unsafe direction (the grant must
have started at now minus skew and still run at now plus skew), a reduction as if wrong the other way.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from keyclerk.grants import _ts

SKEW = timedelta(seconds=30)    # the clock-drift alarm threshold of the deployment's edge sites
MAX_WAKE = timedelta(hours=1)


def revoked_ids(doc: dict, at: datetime | None = None) -> set[str]:
    """Revoked grant ids. Live (at None): every revocation, whatever its date, because earlier is the safe side.
    Historical (at given, for the timeline): only revocations made by then, so the past is never rewritten."""
    return {r["grant_id"] for r in doc.get("revocations", []) if at is None or _ts(r["at"]) <= at}


def suspended(doc: dict, anchor: str, at: datetime) -> bool:
    """A suspension holds from its start until two different people other than the suspender lift it."""
    for s in doc.get("suspensions", []):
        if s["anchor"] != anchor or _ts(s["at"]) > at:
            continue
        lift = s.get("lifted")
        if not lift or _ts(lift["at"]) > at:
            return True
        lifters = set(lift.get("by", []))
        if len(lifters) < 2 or s["by"] in lifters or anchor in lifters:
            return True
    return False


def grant_state(g: dict, doc: dict, at: datetime, historical: bool = False) -> dict:
    """historical=True answers 'what was true at that moment' for the timeline; decisions use the default."""
    gid, anchor = g["grant_id"], g["subject"]["anchor"]
    start, end = _ts(g["start"]), _ts(g["end"])
    if gid in revoked_ids(doc, at if historical else None):
        intent = "revoked"
    elif suspended(doc, anchor, at):
        intent = "suspended"
    else:
        intent = "granted"
    validity = "pending" if at < start else ("ended" if at >= end else "valid")
    if intent == "revoked":
        effective = "revoked"
    elif validity == "ended":
        effective = "ended"
    elif intent == "suspended":
        effective = "suspended"
    elif validity == "pending":
        effective = "pending"
    else:
        effective = "active"
    return {"grant_id": gid, "intent": intent, "validity": validity, "effective": effective}


def may_widen(g: dict, doc: dict, at: datetime, skew: timedelta = SKEW) -> bool:
    """True only if the grant is active whichever way the clock is wrong by up to skew."""
    return (grant_state(g, doc, at - skew)["effective"] == "active"
            and grant_state(g, doc, at + skew)["effective"] == "active")


def must_reduce(g: dict, doc: dict, at: datetime, skew: timedelta = SKEW) -> bool:
    """True if the grant may no longer be active at any time within skew of now."""
    return not may_widen(g, doc, at, skew)


def effective_grants(doc: dict, at: datetime, skew: timedelta = SKEW) -> list[dict]:
    """The grants a decision or a plan may treat as active now (the skew-safe set)."""
    return [g for g in doc.get("grants", []) if may_widen(g, doc, at, skew)]


def persona_state(doc: dict, anchor: str, persona: str, at: datetime) -> str:
    """An admin persona is active only while an eligibility of the person is effectively active."""
    if persona != "admin":
        raise ValueError("only the admin persona is derived from grants")
    mine = [g for g in doc.get("grants", []) if g["subject"]["anchor"] == anchor and g["class"] == "eligibility"]
    if not mine:
        return "absent"
    if any(may_widen(g, doc, at) for g in mine):
        return "active"
    if any(grant_state(g, doc, at)["effective"] == "pending" for g in mine):
        return "pending"
    return "blocked"


def lease_state(ls: dict, at: datetime, xr: dict) -> str:
    start, end = _ts(ls["start"]), _ts(ls["end"])
    delete_after = timedelta(days=xr["steps"]["offboarding"]["retention"]["account_delete_days"])
    first_reminder = max(xr["steps"]["during"]["reminder_days"])
    if at < start:
        return "approved"
    if at >= end + delete_after:
        return "purged"
    if at >= end:
        return "ended"
    if end - at <= timedelta(days=first_reminder):
        return "ending"
    return "active"


def next_boundary(doc: dict, at: datetime, xr: dict | None = None) -> datetime:
    """When the reconciler must look again: the earliest future start, end, reminder or purge, at most an hour away
    (it sleeps on a monotonic clock and re-checks the wall clock on waking)."""
    cands = []
    for g in doc.get("grants", []):
        cands += [_ts(g["start"]) - SKEW, _ts(g["end"]) - SKEW]
    if xr:
        delete_after = timedelta(days=xr["steps"]["offboarding"]["retention"]["account_delete_days"])
        for ls in doc.get("leases", []):
            end = _ts(ls["end"])
            cands += [_ts(ls["start"]), end, end + delete_after]
            cands += [end - timedelta(days=d) for d in xr["steps"]["during"]["reminder_days"]]
    future = [c for c in cands if c > at]
    return min(future + [at + MAX_WAKE])
