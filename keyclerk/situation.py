# SPDX-License-Identifier: EUPL-1.2
"""Situation levels change access both ways.

An announcement raises or lowers the level of a scope: the tenant, a physical place (tools/places.py; a site, a
building, an outpost) or an org unit. Two levels follow:
- the restriction level counts every valid announcement, registered feeds included; it narrows (visitor categories,
  proof floors, derived attribute rules, rate caps, lease lengths) and is lifted only by a valid lowering;
- the activation level counts only announcements by the officer, a place deputy, a place steward or the on-call rota;
  it switches on what was prepared in peacetime (standby memberships, surge packages), and stays on past
  confirm_hours only when a second person confirms it. A feed can narrow but never widen.
A feed raises at most one step above the people-announced level and never above high; replays, stale records and
bursts are ignored. A lowering is a widening: a second person who did not raise the level approves it, and not
before the minimum dwell. A level never expires by itself; an overdue review escalates. Exercise
announcements never change levels; dry_run shows what they would.

Usage: python -m keyclerk.situation RECORDS.yaml ...     check records that hold situations or surge packages
       python -m keyclerk.situation --dry-run FILE SITUATION_ID    what an exercise announcement would change
"""
from __future__ import annotations

import copy
import sys
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from keyclerk import config
from keyclerk import places as PL
from keyclerk.grants import _ts  # noqa: E402

LEVELS = ["normal", "elevated", "high", "severe"]


R = config.Section("situation")


def rank(level: str) -> int:
    return LEVELS.index(level)


def _key(scope: dict) -> str:
    return "tenant" if scope["kind"] == "tenant" else f"{scope['kind']}:{scope['id']}"


def _announcers(doc: dict, a: dict) -> str | None:
    """Who may announce for this scope: "officer" (the security officer anywhere in the tenant), "deputy" (a place's
    deputy for that place and what is inside it), "steward" (a shared place's steward), "on_call" (raise and confirm
    only, never lower); None otherwise."""
    from keyclerk import delegation as D
    root = doc.get("root") or {}
    if D.same(doc, a["by"], root.get("officer")):
        return "officer"
    if a["scope"]["kind"] == "place":
        for pid in PL.scope_chain(doc, a["scope"]["id"]):   # an outpost's site deputy announces for it
            p = PL._places(doc).get(pid, {})
            if D.same(doc, a["by"], p.get("deputy")):
                return "deputy"
            if D.same(doc, a["by"], p.get("steward")):
                return "steward"
    if any(D.same(doc, a["by"], x) for x in root.get("on_call", [])):
        return "on_call"
    return None


def _feed(doc: dict, source: str) -> dict | None:
    return next((f for f in doc.get("situation_feeds", []) if source == f"feed:{f['feed']}"), None)


def _blank() -> dict:
    return {"restriction": "normal", "people": "normal", "raisers": set(), "since": {}, "raised_at": None,
            "review_by": None, "confirmed": True, "last_feed": None}


def replay(doc: dict, at: datetime, include: str | None = None) -> dict[str, dict]:
    """Per scope key the levels after every valid announcement up to `at`, in time order."""
    from keyclerk import delegation as D
    state: dict[str, dict] = {}
    seen_nonces: set = set()
    for a in sorted(doc.get("situations", []), key=lambda x: (_ts(x["at"]), x["situation_id"])):
        t = _ts(a["at"])
        if t > at or (a.get("exercise") and a["situation_id"] != include):
            continue
        s = state.setdefault(_key(a["scope"]), _blank())
        lvl = rank(a["level"])
        if a["source"].startswith("feed:"):
            f = _feed(doc, a["source"])
            nonce = (a["source"], a.get("nonce"))
            stale = a.get("issued_at") and t - _ts(a["issued_at"]) > timedelta(hours=R["feed"]["max_age_hours"])
            burst = s["last_feed"] and t - s["last_feed"] < timedelta(hours=R["feed"]["min_interval_hours"])
            if f is None or not a.get("nonce") or nonce in seen_nonces or stale or burst:
                continue   # unregistered, replayed, stale or bursting feeds count for nothing
            seen_nonces.add(nonce)
            cap = min(rank(f["max_level"]), rank(s["people"]) + 1, rank(R["feed"]["max_level"]))
            if min(lvl, cap) > rank(s["restriction"]):
                s["restriction"] = LEVELS[min(lvl, cap)]
                s["raisers"].add(a["source"])
                s["raised_at"], s["review_by"], s["last_feed"] = t, a.get("review_by"), t
            continue
        who = _announcers(doc, a)
        if who is None or a["source"] != "officer":
            continue
        cur = rank(s["restriction"])
        if lvl >= cur:
            if lvl > cur:
                s["raisers"], s["raised_at"] = set(), t
            if lvl > rank(s["people"]):
                for L in LEVELS[rank(s["people"]) + 1: lvl + 1]:
                    s["since"][L] = t
                s["confirmed"] = False
                s["confirm_by"] = t + timedelta(hours=R["confirm_hours"])
            elif s["raisers"] and D.person_of(doc, a["by"]) not in s["raisers"]:
                s["confirmed"] = True      # a second person announcing the same level confirms it
            s["restriction"] = a["level"]
            s["people"] = max(s["people"], a["level"], key=rank)
            s["raisers"].add(D.person_of(doc, a["by"]))
            s["review_by"] = a.get("review_by")
            if any(D.person_of(doc, x) not in s["raisers"] for x in a.get("approved_by", [])):
                s["confirmed"] = True
            continue
        second = [x for x in a.get("approved_by", []) if D.person_of(doc, x) not in s["raisers"]
                  and not D.same(doc, x, a["by"])]
        dwell = s["raised_at"] and t - s["raised_at"] < timedelta(hours=R["min_dwell_hours"])
        if who == "on_call" or not second or dwell:
            continue   # a lowering by one person, by a raiser only, by the rota, or within the dwell is ignored
        s["restriction"] = s["people"] = a["level"]
        s["since"] = {L: x for L, x in s["since"].items() if rank(L) <= lvl}
        s["raisers"], s["raised_at"], s["review_by"] = {D.person_of(doc, a["by"])}, t, a.get("review_by")
        s["confirmed"] = True
    return state


def _scope_keys(doc: dict, place: str | None, org: str | None) -> list[str]:
    keys = ["tenant"]
    pid = PL.resolve(doc, place)
    if pid:
        keys += [f"place:{p}" for p in PL.scope_chain(doc, pid)]
    if org:
        keys += [f"org:{o}" for o in PL.org_chain(doc, org)]
    return keys


def levels(doc: dict, place: str | None, at: datetime, org: str | None = None, include: str | None = None) -> dict:
    """{restriction, activation, since}: place facts from the place's scope chain, org facts from the org's
    (places.yaml resolution); an unconfirmed people-raise activates only until its confirm_by."""
    st = replay(doc, at, include)
    restriction, activation, since = "normal", "normal", {}
    for k in _scope_keys(doc, place, org):
        s = st.get(k)
        if not s:
            continue
        restriction = max(restriction, s["restriction"], key=rank)
        act = s["people"]
        if not s["confirmed"] and at >= s.get("confirm_by", at):
            act = "normal"
        activation = max(activation, act, key=rank)
        for L, t in s["since"].items():
            since[L] = min(since.get(L, t), t)
    return {"restriction": restriction, "activation": activation, "since": since}


# --- restrictions ------------------------------------------------------------------------------------------------

def visitor_rule(category: str, level: str) -> str:
    return R["visitors"][level].get(category, "suspended")


def dormant_leases(doc: dict, at: datetime) -> dict[str, str]:
    """lease_id -> why, for running leases whose category a restriction level suspends at any of their places. A
    dormant lease blocks entry only; exits and assembly points stay open."""
    out = {}
    for ls in doc.get("leases", []):
        for ref in ls.get("sites", [None]):
            lvl = levels(doc, ref, at, ls.get("org"))["restriction"]
            if visitor_rule(ls["category"], lvl) == "suspended":
                out[ls["lease_id"]] = f"{ls['category']} suspended at {lvl} ({ref or 'tenant'})"
    return out


def lease_errors(doc: dict) -> list[str]:
    errs = []
    for ls in doc.get("leases", []):
        ref = (ls.get("sites") or [None])[0]
        cap = R["lease_max_days"][levels(doc, ref, _ts(ls["start"]), ls.get("org"))["restriction"]]
        if cap is not None and _ts(ls["end"]) - _ts(ls["start"]) > timedelta(days=cap):
            errs.append(f"{ls['lease_id']}: longer than {cap} days, the cap at the level it started")
    return errs


def floor_raise(kind: str, level: str) -> int:
    return R["floor_raise"]["external" if kind == "external" else "tenant"][level]


def derived_rules_paused(level: str) -> bool:
    return rank(level) >= rank(R["pause_derived_rules_from"])


def rate_factor(level: str) -> float:
    return R["rate_factor"][level]


# --- activations -------------------------------------------------------------------------------------------------

def standby_active(doc: dict, m: dict, place: str | None, at: datetime) -> bool:
    return rank(levels(doc, place, at)["activation"]) >= rank(m["standby_from"])


def _packages(doc: dict) -> dict[str, dict]:
    return {p["package_id"]: p for p in doc.get("surge_packages", [])}


def surge_status(doc: dict, g: dict, at: datetime) -> str:
    """active, pending, ended (its own end, or the level fell) or invalid."""
    if surge_errors(doc, g):
        return "invalid"
    p = _packages(doc)[g["package_id"]]
    if at < _ts(g["at"]):
        return "pending"
    if at >= _ts(g["end"]) or rank(levels(doc, p.get("place"), at)["activation"]) < rank(p["level_min"]):
        return "ended"
    return "active"


def surge_errors(doc: dict, g: dict) -> list[str]:
    from keyclerk import delegation as D
    sid, p = g["surge_id"], _packages(doc).get(g["package_id"])
    if p is None:
        return [f"{sid}: unknown surge package {g['package_id']}"]
    errs, t0 = [], _ts(g["at"])
    lv = levels(doc, p.get("place"), t0)
    if rank(lv["activation"]) < rank(p["level_min"]):
        errs.append(f"{sid}: made while the activation level was {lv['activation']}, below {p['level_min']} (a feed alone never activates)")
    if not D.same(doc, g["by"], p["coordinator"]):
        errs.append(f"{sid}: not made by the package's surge coordinator")
    if D.same(doc, g["by"], (doc.get("root") or {}).get("officer")):
        errs.append(f"{sid}: the surge coordinator is never the officer who raises levels")
    if _ts(g["end"]) - t0 > timedelta(hours=R["surge"]["max_hours"]):
        errs.append(f"{sid}: longer than {R['surge']['max_hours']} hours")
    if D.same(doc, g["anchor"], g["by"]):
        errs.append(f"{sid}: the coordinator granted themselves")
    since = lv["since"].get(p["level_min"])
    episode = [x for x in doc.get("surge_grants", []) if x["package_id"] == p["package_id"] and since
               and since <= _ts(x["at"]) and (_ts(x["at"]), x["surge_id"]) <= (t0, sid)]
    if len(episode) > p["cap"]:
        errs.append(f"{sid}: above the package cap of {p['cap']} for this raised episode")
    total = sum((_ts(x["end"]) - _ts(x["at"]) for x in doc.get("surge_grants", [])
                 if D.same(doc, x["anchor"], g["anchor"]) and (_ts(x["at"]), x["surge_id"]) <= (t0, sid)), timedelta())
    if total > timedelta(days=R["surge"]["max_days_per_person"]):
        errs.append(f"{sid}: {g['anchor']} past {R['surge']['max_days_per_person']} surge days; the normal joiner path applies")
    return errs


def package_errors(doc: dict, p: dict) -> list[str]:
    from keyclerk import delegation as D
    errs = []
    for gid in p["groups"]:
        if D.effective_risk(doc, gid) == "privileged":
            errs.append(f"{p['package_id']}: {gid} is privileged; a surge never touches privileged groups")
    if len([a for a in p.get("approved_by", []) if not D.same(doc, a, p["coordinator"])]) < 2:
        errs.append(f"{p['package_id']}: prepared without two approvers other than the coordinator")
    if levels(doc, p.get("place"), _ts(p["prepared_at"]))["restriction"] != "normal":
        errs.append(f"{p['package_id']}: prepared during a raised level; a surge package is prepared in peacetime")
    return errs


def surge_members(doc: dict, gid: str, at: datetime) -> set[str]:
    return {g["anchor"] for g in doc.get("surge_grants", [])
            if gid in _packages(doc).get(g["package_id"], {}).get("groups", []) and surge_status(doc, g, at) == "active"}


def reviews_due(doc: dict, at: datetime) -> list[dict]:
    out = []
    for g in doc.get("surge_grants", []):
        if surge_status(doc, g, at) == "ended":
            due = _ts(g["end"]) + timedelta(days=R["surge"]["review_days_after_fall"])
            out.append({"item": g["surge_id"], "what": "surge grant review", "due": due.isoformat()})
    for key, s in replay(doc, at).items():
        if s["restriction"] != "normal" and s.get("review_by") and at >= _ts(s["review_by"]):
            out.append({"item": key, "what": f"level {s['restriction']} past its review; escalated to the root and the auditor",
                        "due": str(s["review_by"])})
    return out


def dry_run(doc: dict, exercise_id: str, at: datetime | None = None) -> dict:
    from keyclerk import delegation as D
    ex = next(s for s in doc.get("situations", []) if s["situation_id"] == exercise_id)
    t = at or _ts(ex["at"]) + timedelta(seconds=1)
    real = copy.deepcopy(doc)
    for s in real["situations"]:
        if s["situation_id"] == exercise_id:
            s["exercise"] = False
    place = ex["scope"]["id"] if ex["scope"]["kind"] == "place" else None
    standby = [m["membership_id"] for m in doc.get("memberships", []) if m.get("standby_from")
               and D.membership_status(real, m, t) == "active" and D.membership_status(doc, m, t) == "standby"]
    return {"levels": levels(real, place, t),
            "leases_dormant": sorted(set(dormant_leases(real, t)) - set(dormant_leases(doc, t))),
            "standby_on": standby}


def check(doc: dict) -> list[str]:
    errs = []
    for a in doc.get("situations", []):
        if a["source"] == "officer" and _announcers(doc, a) is None:
            errs.append(f"{a['situation_id']}: announced by someone who may not announce for {_key(a['scope'])}")
        if a["source"].startswith("feed:") and _feed(doc, a["source"]) is None:
            errs.append(f"{a['situation_id']}: unregistered feed {a['source']}")
        if a["scope"]["kind"] == "place":
            if a["scope"]["id"] not in PL._places(doc):
                errs.append(f"{a['situation_id']}: unknown place {a['scope']['id']}")
            elif PL.shared(doc, a["scope"]["id"]) and a["source"] == "officer" and _announcers(doc, a) != "steward":
                errs.append(f"{a['situation_id']}: a shared place's level is announced by its steward")
            elif a["source"] == "officer" and PL.shared_below(doc, a["scope"]["id"]):
                errs.append(f"{a['situation_id']}: would reach shared places {PL.shared_below(doc, a['scope']['id'])}; "
                            "announce on your own places, the steward announces for shared ones")
    errs += lease_errors(doc)
    for p in doc.get("surge_packages", []):
        errs += package_errors(doc, p)
    for g in doc.get("surge_grants", []):
        errs += surge_errors(doc, g)
    return errs


def opa_data(doc: dict, at: datetime) -> dict:
    """data.keyclerk.situation: the levels per place for the bundle (a site holds its last known level, never normal)."""
    out = {"tenant": {k: v for k, v in levels(doc, None, at).items() if k != "since"}}
    for p in doc.get("places", []):
        out[p["place_id"]] = {k: v for k, v in levels(doc, p["place_id"], at).items() if k != "since"}
    return out


def main(argv: list[str]) -> int:
    from keyclerk import records
    if argv[:1] == ["--dry-run"]:
        print(yaml.safe_dump(dry_run(records.load(Path(argv[1])), argv[2]), sort_keys=False), end="")
        return 0
    bad = 0
    for f in [Path(a) for a in argv if not a.startswith("--")]:
        for e in check(records.load(f)):
            print(f"{f}: {e}", file=sys.stderr)
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
