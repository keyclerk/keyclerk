# SPDX-License-Identifier: EUPL-1.2
"""Delegated administration and nested groups.

One root trust owner per tenant delegates the management of group membership to deputies. Every delegation narrows its
parent (attenuation: powers, subtree, risk, membership length, depth and time), so authority is a chain back to the
root role, derived at decision time and never stored. Groups sit in one administrative tree (who manages them); a
group's members come three ways: named people, included groups and attribute rules. The engine flattens all three into
effective members, and only the flat result reaches OPA and Keycloak. Every rule is re-checked now, never
grandfathered.

Records, next to the grants (schema/records.schema.json):
  persons        {person, kind: tenant | external | agent | workload, anchors, personas?, owner?, director?}: one
                 person with several anchors is one person; personas say what each account is for (daily, admin);
                 a workload has an owner, an agent an owner and a director (decision 0011)
  catalogue      entitlements with an owner and a risk class
  sod            conflicting entitlement pairs
  root           {holders: [{anchor, appointed_by, from, to?}], officer}: the root role and who held it when
  groups         {group_id, parent, max_risk (fixed at creation), carries: [{entitlement, by}]}
  delegations    {delegation_id, delegate, group, powers, max_risk, max_membership_days, depth_left, start, end, by,
                  parent ("root" or a delegation id), approved_by?}
  memberships    {membership_id, group, member: {anchor} | {group} | {rule}, by, under, approved_by?, start, end}
  admin_revocations  {id, at, by, mode: retire | revoke, from?, reason}; id may be "root:<anchor>"
  approvers      {approver_id, anchor, appointed_by, approved_by, from, to}: named approvers (decision 0008)

Second keys (decision 0008): keyclerk/policy/second_key.rego decides who counts, compiled to WebAssembly and run in
process (keyclerk.policy_wasm); this module only gathers the facts. Setting delegation.second_key_standing: off and
warn count anyone independent of the actor (warn also lists what enforce would refuse), enforce also needs standing.

Ending: retire is orderly (what was made under it lives on for the grace period, then ends unless re-issued; the
retiring deputy loses every power at once); revoke is for cause (everything below ends, and everything the person made
or approved from the stated compromise time `from` is void, whatever delegation it used). A delegation that
reaches its end counts as retired at its end.

Usage:
  python -m keyclerk.delegation RECORDS.yaml ...                 check records that hold groups
  python -m keyclerk.delegation --explain FILE ANCHOR GROUP      why ANCHOR is in GROUP now
  python -m keyclerk.delegation --impact FILE ID                 what a revocation of ID would end now
  python -m keyclerk.delegation --standing-impact FILE           what enforcing second-key standing would refuse
  python -m keyclerk.delegation --persona-impact FILE            what enforcing the persona rule would change (0011a)
"""
from __future__ import annotations

import contextlib
import contextvars

import sys
from collections import Counter
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from keyclerk import clock, config
from keyclerk.grants import _ts  # noqa: E402

RISK = {"low": 0, "elevated": 1, "privileged": 2}
NAMES = {v: k for k, v in RISK.items()}
POWERS = {"members", "subgroups", "includes", "rules", "delegate"}
GROUP_PREFIX = "/groups/"


R = config.Section("delegation")
ATTRS = config.Section("attributes")


# --- people ------------------------------------------------------------------------------------------------------

def person_of(doc: dict, anchor: str | None) -> str | None:
    store, key = _memo_get("person_index", doc)
    if store is not None:
        index = store.get(key)
        if index is None:                           # the first person listing an anchor wins, as the scan below
            index = {}
            for p in doc.get("persons", []):
                for x in p["anchors"]:
                    index.setdefault(x, p["person"])
            store[key] = index
        return index.get(anchor, anchor)
    for p in doc.get("persons", []):
        if anchor in p["anchors"]:
            return p["person"]
    return anchor


def same(doc: dict, a: str | None, b: str | None) -> bool:
    return a is not None and b is not None and person_of(doc, a) == person_of(doc, b)


IDENTITY_DEFAULTS = {"privileged_needs_admin": True, "machines_in_privileged": False, "persona_rule": "enforce"}


def identity_rules() -> dict:
    """The identity section of the configuration over the defaults (decision 0011)."""
    return {**IDENTITY_DEFAULTS, **(config.current().get("identity") or {})}


def _people_index(doc: dict) -> dict | None:
    """anchor -> the first person record listing it, and the lease holders' anchors; once per memo scope (0017)."""
    store, key = _memo_get("people_records", doc)
    if store is None:
        return None
    if key not in store:
        recs: dict[str, dict] = {}
        for p in doc.get("persons", []):
            for x in p["anchors"]:
                recs.setdefault(x, p)
        store[key] = {"records": recs, "leases": {ls["anchor"] for ls in doc.get("leases", [])}}
    return store[key]


def person_rec(doc: dict, anchor: str | None) -> dict | None:
    if not anchor:
        return None
    ix = _people_index(doc)
    if ix is not None:
        return ix["records"].get(anchor)
    return next((p for p in doc.get("persons", []) if anchor in p["anchors"]), None)


def purpose_of(doc: dict, anchor: str) -> str:
    """What an account is for: daily, admin (or a deployment's own word); unspecified when the person says nothing."""
    p = person_rec(doc, anchor) or {}
    return next((x["purpose"] for x in p.get("personas") or [] if x["anchor"] == anchor), "unspecified")


def membership_input(doc: dict, anchor: str, risk: str) -> dict:
    p = person_rec(doc, anchor) or {}
    director = p.get("director")
    return {"member": {"kind": kind_of(doc, anchor), "purpose": purpose_of(doc, anchor),
                       "director_kind": kind_of(doc, director) if director else ""},
            "group": {"risk": risk}, "settings": identity_rules()}


def identity_errors(doc: dict) -> list[str]:
    """Workloads and agents: an owner who is a person of the organisation, an agent's director (a person or a
    workload, never another agent), personas that name the person's own accounts."""
    errs = []
    for p in doc.get("persons", []):
        who, k = p["person"], p["kind"]
        for x in p.get("personas") or []:
            if x["anchor"] not in p["anchors"]:
                errs.append(f"{who}: a persona names an account that is not theirs ({x['anchor']})")
        if k in ("workload", "agent"):
            if not p.get("owner") or kind_of(doc, p["owner"]) != "tenant":
                errs.append(f"{who}: a {k} has an owner, a person of the organisation")
        if k == "agent":
            if not p.get("director") or kind_of(doc, p["director"]) not in ("tenant", "workload"):
                errs.append(f"{who}: an agent has a director, a person or a workload (never another agent)")
        elif p.get("director"):
            errs.append(f"{who}: only an agent has a director")
    return errs


_PERSONA_OFF: contextvars.ContextVar[bool] = contextvars.ContextVar("keyclerk_persona_off", default=False)


def persona_mode() -> str:
    """off, warn or enforce (decision 0011a, rolled out as 0008); enforce by default since 0.16.1.
    Off while an ended membership is judged as it was made: persons carry no history (see check)."""
    if _PERSONA_OFF.get():
        return "off"
    return identity_rules().get("persona_rule", "enforce")


def actor_errors(doc: dict, actor: str, role_anchor: str, gid: str) -> list[str]:
    """Why this account may not use a power (the root, a delegation naming role_anchor) over gid (identity.rego)."""
    from keyclerk import policy_wasm
    return policy_wasm.identity("actor", {"actor": {"purpose": purpose_of(doc, actor), "exact": actor == role_anchor},
                                          "group": {"risk": effective_risk(doc, gid)}, "settings": identity_rules()})


def persona_impact(doc: dict, at: datetime, people: dict | None = None) -> list[dict]:
    """What enforcing the persona rule would change now: effective members dropped, and powers no longer held."""
    from keyclerk import policy_wasm
    strict = {**identity_rules(), "persona_rule": "enforce"}
    out = []
    for g in doc.get("groups", []):
        gid, risk = g["group_id"], effective_risk(doc, g["group_id"])
        for a in sorted(effective_members(doc, gid, at, people)):
            why = policy_wasm.identity("membership", {**membership_input(doc, a, risk), "settings": strict})
            if why:
                out.append({"group": gid, "anchor": a, "what": "member", "reasons": why})
    root = root_at(doc, at)
    if root and purpose_of(doc, root) != "admin" and any(effective_risk(doc, g["group_id"]) == "privileged"
                                                          for g in doc.get("groups", [])):
        out.append({"group": "(privileged groups)", "anchor": root, "what": "the root",
                    "reasons": ["power over a privileged group is used from an admin persona, not a daily account"]})
    for d in doc.get("delegations", []):
        if chain_status(doc, d["delegation_id"], at)[0] != "ok":
            continue
        risk = effective_risk(doc, d["group"])
        p = person_rec(doc, d["delegate"]) or {"anchors": [d["delegate"]]}
        for a in p["anchors"]:
            why = policy_wasm.identity("actor", {"actor": {"purpose": purpose_of(doc, a), "exact": a == d["delegate"]},
                                                 "group": {"risk": risk}, "settings": strict})
            if why and a == d["delegate"]:
                out.append({"group": d["group"], "anchor": a, "what": "delegation " + d["delegation_id"], "reasons": why})
    return out


def kind_of(doc: dict, anchor: str) -> str:
    """tenant, external, agent or workload; an external lease holder is external; unknown when a persons list exists
    (fail safe)."""
    ix = _people_index(doc)
    if ix is not None:
        if anchor in ix["leases"]:
            return "external"
        rec = ix["records"].get(anchor)
        if rec is not None:
            return rec["kind"]
        return "unknown" if doc.get("persons") else "tenant"
    if anchor in {ls["anchor"] for ls in doc.get("leases", [])}:
        return "external"
    for p in doc.get("persons", []):
        if anchor in p["anchors"]:
            return p["kind"]
    return "unknown" if doc.get("persons") else "tenant"


# --- the root, the tree and the catalogue ------------------------------------------------------------------------

def root_at(doc: dict, t: datetime) -> str | None:
    for h in (doc.get("root") or {}).get("holders", []):
        if _ts(h["from"]) <= t and ("to" not in h or t < _ts(h["to"])):
            return h["anchor"]
    return None


def _groups(doc: dict) -> dict[str, dict]:
    """The groups by id; once per check inside memo() (a realistic organisation's check called this for every
    membership and every ancestor walk: 46,000 memberships times 5,000 groups, minutes per change). Read-only."""
    store, key = _memo_get("groups", doc)
    if store is not None:
        if key not in store:
            store[key] = {g["group_id"]: g for g in doc.get("groups", [])}
        return store[key]
    return {g["group_id"]: g for g in doc.get("groups", [])}


def ancestors(doc: dict, gid: str) -> list[str]:
    gs, out = _groups(doc), []
    while gid in gs and gid not in out:
        out.append(gid)
        gid = gs[gid].get("parent")
    return out


def covers(doc: dict, top: str, gid: str) -> bool:
    return top in ancestors(doc, gid)


def carried_risk(doc: dict, gid: str) -> str:
    """The highest risk class of what the group carries; a gap in the catalogue counts as privileged."""
    cat = {e["entitlement"]: e for e in doc.get("catalogue", [])}
    worst = max([RISK[cat[c["entitlement"]]["risk"]] if c["entitlement"] in cat else 2
                 for c in _groups(doc).get(gid, {}).get("carries", [])] or [0])
    return NAMES[worst]


def _includes(doc: dict, gid: str, exclude: str | None = None) -> list[str]:
    return [m["member"]["group"] for m in doc.get("memberships", [])
            if m["group"] == gid and "group" in m["member"] and m["membership_id"] != exclude]


def _includers(doc: dict, gid: str, extra: tuple = ()) -> set[str]:
    """Every group that includes gid, transitively (extra: a proposed (includer, included) edge)."""
    store, key = _memo_get("include_edges", doc)
    if store is not None:                          # the include edges, once per check (0017)
        if key not in store:
            store[key] = [(m["group"], m["member"]["group"]) for m in doc.get("memberships", []) if "group" in m["member"]]
        edges = store[key] + list(extra)
    else:
        edges = [(m["group"], m["member"]["group"]) for m in doc.get("memberships", []) if "group" in m["member"]]
        edges += list(extra)
    out, todo = set(), [gid]
    while todo:
        x = todo.pop()
        for a, b in edges:
            if b == x and a not in out:
                out.add(a)
                todo.append(a)
    return out


def effective_risk(doc: dict, gid: str) -> str:
    """A group's fixed class, raised by every group that includes it: its members reach their rights."""
    gs = _groups(doc)
    if gid not in gs:
        return "privileged"
    return NAMES[max(RISK[gs[g]["max_risk"]] for g in {gid} | _includers(doc, gid) if g in gs)]


# --- delegations and chains --------------------------------------------------------------------------------------

def _delegations(doc: dict) -> dict[str, dict]:
    return {d["delegation_id"]: d for d in doc.get("delegations", [])}


def chain(doc: dict, did: str) -> list[dict]:
    ds, out, seen = _delegations(doc), [], set()
    while did in ds and did not in seen:
        seen.add(did)
        out.append(ds[did])
        did = ds[did]["parent"]
    return out


def _revs(doc: dict, rid: str, at: datetime) -> list[dict]:
    return [r for r in doc.get("admin_revocations", []) if r["id"] == rid and _ts(r["at"]) <= at]


def compromised_from(doc: dict, anchor: str, at: datetime) -> datetime | None:
    """The earliest compromise time of this person known by `at`: a revoke for cause of one of their delegations or of
    their root holding."""
    times = []
    for r in doc.get("admin_revocations", []):
        if r["mode"] != "revoke" or _ts(r["at"]) > at:
            continue
        rid = r["id"]
        who = rid[5:] if rid.startswith("root:") else (_delegations(doc).get(rid) or {}).get("delegate")
        if same(doc, who, anchor):
            times.append(_ts(r.get("from", r["at"])))
    return min(times) if times else None


def _tainted(doc: dict, anchor: str, made: datetime, at: datetime) -> bool:
    c = compromised_from(doc, anchor, at)
    return c is not None and made >= c


def chain_status(doc: dict, did: str, at: datetime) -> tuple[str, datetime | None]:
    """("ok", None) when every link holds now; ("grace", until) when a link was retired or ran out and the grace
    period runs; ("dead", None) otherwise. Acting needs "ok"; what was made under the chain survives "grace"."""
    if did == "root":
        return ("ok", None)
    links = chain(doc, did)
    if not links or links[-1]["parent"] != "root":
        return ("dead", None)
    grace_until = None
    for d in links:
        if _ts(d["start"]) > at or _tainted(doc, d["by"], _ts(d["start"]), at):
            return ("dead", None)
        revs = _revs(doc, d["delegation_id"], at)
        if any(r["mode"] == "revoke" for r in revs):
            return ("dead", None)
        stop = min([_ts(d["end"])] + [_ts(r["at"]) for r in revs])
        if at >= stop:
            until = stop + timedelta(days=R["retire_grace_days"])
            if at >= until:
                return ("dead", None)
            grace_until = min(grace_until or until, until)
    return ("grace", grace_until) if grace_until else ("ok", None)


def _descendants(doc: dict, did: str) -> list[dict]:
    return [d for d in doc.get("delegations", []) if d["delegation_id"] != did
            and did in [x["delegation_id"] for x in chain(doc, d["delegation_id"])]]


_STANDING: ContextVar[str | None] = ContextVar("second_key_standing", default=None)


def standing_policy() -> dict:
    """The second-key policy data: the rollout mode (off, warn, enforce) and the reciprocity window (decision 0008)."""
    return {"standing": _STANDING.get() or R.get("second_key_standing", "warn"),
            "reciprocity_days": R.get("reciprocity_days", 30)}


def _unit(doc: dict, anchor: str | None) -> str | None:
    for p in doc.get("persons", []):
        if anchor in p["anchors"]:
            return p.get("unit")
    return None


def approver_errors(doc: dict, a: dict) -> list[str]:
    """A named approver is appointed by the root trust owner of the time with the security officer's key, for a limited
    time, and is a person of the organisation other than the root."""
    aid, t0, errs = a["approver_id"], _ts(a["from"]), []
    officer = (doc.get("root") or {}).get("officer")
    if not same(doc, a["appointed_by"], root_at(doc, t0)):
        errs.append(f"{aid}: a named approver is appointed by the root trust owner of that time")
    if not any(same(doc, x, officer) for x in a["approved_by"]):
        errs.append(f"{aid}: appointing a named approver needs the security officer's key")
    if _ts(a["to"]) <= t0:
        errs.append(f"{aid}: ends before it starts")
    elif _ts(a["to"]) - t0 > timedelta(days=R.get("max_approver_days", 365)):
        errs.append(f"{aid}: longer than {R.get('max_approver_days', 365)} days")
    if kind_of(doc, a["anchor"]) != "tenant":
        errs.append(f"{aid}: a named approver is a person of the organisation, never an external or an agent")
    if same(doc, a["anchor"], root_at(doc, t0)):
        errs.append(f"{aid}: the root trust owner is never a named approver (the root is never a second key)")
    return errs


def named_approver(doc: dict, anchor: str, at: datetime) -> bool:
    return any(same(doc, a["anchor"], anchor) and _ts(a["from"]) <= at < _ts(a["to"])
               and not _revs(doc, a["approver_id"], at) and not _tainted(doc, a["appointed_by"], _ts(a["from"]), at)
               and not approver_errors(doc, a) for a in doc.get("approvers", []))


def _manages(doc: dict, anchor: str, gid: str | None, at: datetime) -> bool:
    """Holds a power over the group or a group above it under a delegation whose chain holds. Lighter than authority():
    the delegation's own second keys are not re-derived, so two deputies' approvals can never recurse into each
    other."""
    return gid is not None and any(
        same(doc, d["delegate"], anchor) and covers(doc, d["group"], gid) and place_covers(doc, d, gid)
        and chain_status(doc, d["delegation_id"], at)[0] == "ok" for d in doc.get("delegations", []))


def _reciprocal_days(doc: dict, approver: str, actor: str, made: datetime, exclude: str | None) -> float | None:
    """Days since the actor's key was on a change the approver made (the favour this approval would return), or None."""
    if approver is None or actor is None:
        return None
    store, key = _memo_get("made_by_index", doc)
    if store is not None:                           # records grouped by who made them, built once per check (0017)
        index = store.get(key)
        if index is None:
            index = {}
            for kind, k in (("delegations", "delegation_id"), ("memberships", "membership_id")):
                for r in doc.get(kind, []):
                    if r.get("by") is None:
                        continue
                    index.setdefault(person_of(doc, r["by"]), []).append(
                        (r[k], _ts(r["start"]), {person_of(doc, x) for x in r.get("approved_by", []) if x is not None}))
            store[key] = index
        who = person_of(doc, actor)
        days = [(made - start).total_seconds() / 86400 for rid, start, approved in index.get(person_of(doc, approver), [])
                if rid != exclude and start <= made and who in approved]
        return min(days) if days else None
    days = [(made - _ts(r["start"])).total_seconds() / 86400
            for kind, key in (("delegations", "delegation_id"), ("memberships", "membership_id"))
            for r in doc.get(kind, []) if r[key] != exclude and _ts(r["start"]) <= made and same(doc, r["by"], approver)
            and any(same(doc, x, actor) for x in r.get("approved_by", []))]
    return min(days) if days else None


def second_key_facts(doc: dict, approvers: list[str], actor: str, member: str | None, under: str, group: str | None,
                     made: datetime, at: datetime, exclude: str | None = None) -> list[dict]:
    """The facts keyclerk/policy/second_key.rego decides on, one candidate per approver. Code gathers; the policy
    decides."""
    inside = {person_of(doc, x) for d in (chain(doc, under) if under != "root" else []) for x in (d["by"], d["delegate"])}
    inside |= {person_of(doc, d["delegate"]) for d in (_descendants(doc, under) if under != "root" else [])}
    root, officer, au = root_at(doc, made), (doc.get("root") or {}).get("officer"), _unit(doc, actor)
    out = []
    for a in approvers:
        u = _unit(doc, a)
        out.append({"anchor": a, "kind": kind_of(doc, a), "actor": same(doc, a, actor), "member": same(doc, a, member),
                    "root": same(doc, a, root), "in_chain": person_of(doc, a) in inside,
                    "tainted": _tainted(doc, a, made, at), "officer": same(doc, a, officer),
                    "named": named_approver(doc, a, at), "manager": _manages(doc, a, group, at),   # standing as it stands now
                    "unit_differs": None if not (u and au) else u != au,
                    "reciprocal_days_ago": _reciprocal_days(doc, a, actor, made, exclude),
                    "persona_ok": not (persona_mode() == "enforce" and group in _groups(doc)
                                       and effective_risk(doc, group) == "privileged" and purpose_of(doc, a) != "admin")})
    return out


def second_key_decision(doc: dict, approvers: list[str], actor: str, member: str | None, under: str,
                        group: str | None, made: datetime, at: datetime, exclude: str | None = None,
                        mode: str | None = None) -> dict:
    """keyclerk/policy/second_key.rego, compiled and run in process: counting, with_standing, independent, why_not.
    mode overrides the configured one (the as-made pass checks independence only; standing is judged as things stand)."""
    from keyclerk import policy_wasm
    if not approvers:
        return {"counting": [], "independent": [], "with_standing": [], "why_not": {}}
    pol = standing_policy()
    return policy_wasm.second_key(second_key_facts(doc, approvers, actor, member, under, group, made, at, exclude),
                                  {**pol, "standing": mode or pol["standing"]})


def outside_key(doc: dict, approvers: list[str], actor: str, member: str | None, under: str, made: datetime,
                at: datetime, group: str | None = None, exclude: str | None = None) -> list[str]:
    """Approvers who count as a second key (decision 0008, decided by the policy): independent of the actor (a person of
    the organisation, not the actor, the member or the root, outside the actor's chain, not compromised), and under
    enforce also with standing (the security officer, a named approver, or a manager of the group through another
    chain and unit) and no favour returned within the reciprocity window."""
    return second_key_decision(doc, approvers, actor, member, under, group, made, at, exclude)["counting"]


def _not_counting(sk: dict) -> str:
    """Why the approvals given do not count, for the refusal: '; <anchor> does not count: <reasons>'."""
    return "".join(f"; {a} does not count: {', '.join(r)}" for a, r in sorted(sk.get("why_not", {}).items()))


@contextmanager
def standing_mode(mode: str):
    """Evaluate under another second-key mode (off, warn, enforce) than the configuration's, for impact lists and tests."""
    token = _STANDING.set(mode)
    try:
        yield
    finally:
        _STANDING.reset(token)


def standing_impact(doc: dict) -> list[str]:
    """What enforcing standing would refuse that the current mode accepts: the list warn shows before enforce."""
    now = set(check(doc))
    with standing_mode("enforce"):
        return sorted(set(check(doc)) - now)


def attenuation_errors(doc: dict, d: dict) -> list[str]:
    errs, did, t0 = [], d["delegation_id"], _ts(d["start"])
    if not set(d["powers"]) <= POWERS:
        errs.append(f"{did}: unknown power {sorted(set(d['powers']) - POWERS)}")
    if _ts(d["end"]) - t0 > timedelta(days=R["max_delegation_days"]):
        errs.append(f"{did}: longer than {R['max_delegation_days']} days")
    if kind_of(doc, d["delegate"]) != "tenant":
        errs.append(f"{did}: a deputy is a tenant person, never an external or an agent")
    if same(doc, d["delegate"], d["by"]) or same(doc, d["delegate"], root_at(doc, t0)):
        errs.append(f"{did}: delegated to oneself or to the root trust owner")
    above = chain(doc, d["parent"]) if d["parent"] != "root" else []
    if any(same(doc, d["delegate"], x) for a in above for x in (a["delegate"], a["by"])):
        errs.append(f"{did}: the delegate is already in the chain above (a loop)")
    if d["group"] not in _groups(doc):
        errs.append(f"{did}: unknown group {d['group']}")
    if d["parent"] == "root":
        if not same(doc, d["by"], root_at(doc, t0)):
            errs.append(f"{did}: a root delegation not made by the root trust owner of that time")
        officer = (doc.get("root") or {}).get("officer")
        if RISK[d["max_risk"]] >= 1 and not any(same(doc, a, officer) for a in d.get("approved_by", [])):
            errs.append(f"{did}: an elevated or privileged root delegation needs the security officer's key")
        return errs
    p = _delegations(doc).get(d["parent"])
    if p is None:
        return errs + [f"{did}: unknown parent {d['parent']}"]
    if not same(doc, d["by"], p["delegate"]):
        errs.append(f"{did}: made by someone other than the parent's delegate")
    if "delegate" not in p["powers"] or p["depth_left"] < 1:
        errs.append(f"{did}: the parent may not delegate")
    if not set(d["powers"]) <= set(p["powers"]):
        errs.append(f"{did}: powers wider than the parent's")
    if d["group"] in _groups(doc) and not covers(doc, p["group"], d["group"]):
        errs.append(f"{did}: group outside the parent's subtree")
    if RISK[d["max_risk"]] > RISK[p["max_risk"]]:
        errs.append(f"{did}: max_risk above the parent's")
    if d["max_membership_days"] > p["max_membership_days"]:
        errs.append(f"{did}: max_membership_days above the parent's")
    if p.get("place") and not (d.get("place") and _place_inside(doc, d["place"], p["place"])):
        errs.append(f"{did}: place outside the parent's place")
    if d["depth_left"] >= p["depth_left"]:
        errs.append(f"{did}: depth_left not below the parent's")
    if t0 < _ts(p["start"]) or _ts(d["end"]) > _ts(p["end"]):
        errs.append(f"{did}: outlives or predates its parent")
    if d["max_risk"] == "privileged":
        sk = second_key_decision(doc, d.get("approved_by", []), d["by"], d["delegate"], d["parent"], d["group"], t0, t0,
                                 exclude=did)
        if not sk["counting"]:
            errs.append(f"{did}: delegating privileged groups needs a second key from outside the chain" + _not_counting(sk))
    return errs


def place_covers(doc: dict, d: dict, gid: str) -> bool:
    """A delegation limited to a place covers only groups at that place or inside it (a building's steward
    hands out that building's door groups); a group without a place is logical and outside every place limit."""
    if not d.get("place"):
        return True
    from keyclerk import places as PL
    gp = _groups(doc).get(gid, {}).get("place")
    return bool(gp) and PL.under(doc, gp, d["place"])


def _place_inside(doc: dict, pid: str, top: str) -> bool:
    from keyclerk import places as PL
    return PL.under(doc, pid, top)


def authority(doc: dict, actor: str, gid: str, power: str, at: datetime) -> str | None:
    """The delegation id (or "root") under which actor holds power over gid now; None if none does."""
    if gid not in _groups(doc) or compromised_from(doc, actor, at) is not None:
        return None
    enforcing = persona_mode() == "enforce"          # decision 0011a: KeyClerk's own powers are used by account
    root = root_at(doc, at)
    if same(doc, actor, root) and (not enforcing or not actor_errors(doc, actor, root, gid)):
        return "root"
    risk = RISK[effective_risk(doc, gid)]
    for d in doc.get("delegations", []):
        if enforcing and actor_errors(doc, actor, d["delegate"], gid):
            continue
        if (same(doc, d["delegate"], actor) and power in d["powers"] and covers(doc, d["group"], gid)
                and place_covers(doc, d, gid) and risk <= RISK[d["max_risk"]] and chain_status(doc, d["delegation_id"], at)[0] == "ok"
                and not attenuation_errors(doc, d)):
            return d["delegation_id"]
    return None


# --- memberships -------------------------------------------------------------------------------------------------

def _kind(m: dict) -> str:
    return next(iter(m["member"]))


_MEMO: contextvars.ContextVar[dict | None] = contextvars.ContextVar("keyclerk_delegation_memo", default=None)


@contextlib.contextmanager
def memo():
    """Within one look at unchanging records, fold each membership and group once (an adversarial review found one check folding the
    same memberships tens of thousands of times, each through the compiled policy). Nested scopes share the outer one.
    Every document seen is held until the scope ends, so its id cannot be reused for another document inside it."""
    if _MEMO.get() is not None:
        yield
        return
    token = _MEMO.set({"docs": {}})
    try:
        yield
    finally:
        _MEMO.reset(token)


def _memo_get(kind: str, doc: dict, *key):
    m = _MEMO.get()
    if m is None:
        return None, None
    m["docs"].setdefault(id(doc), doc)
    k = (kind, id(doc), *key)
    return m, k


def membership_status(doc: dict, m: dict, at: datetime) -> str:
    """active, pending, ended, revoked, void (made by or with a compromised person), lapsed (its chain is gone) or
    invalid (it fails the rules as they stand now)."""
    store, key = _memo_get("status", doc, m["membership_id"], at)
    if store is not None and key in store:
        return store[key]
    out = _membership_status(doc, m, at)
    if store is not None:
        store[key] = out
    return out


def _membership_status(doc: dict, m: dict, at: datetime) -> str:
    if _revs(doc, m["membership_id"], at):
        return "revoked"
    t0 = _ts(m["start"])
    if _tainted(doc, m["by"], t0, at):
        return "void"
    if at < t0:
        return "pending"
    st, until = chain_status(doc, m["under"], at)
    if st == "dead" or (until and at >= until):
        return "lapsed"
    if at >= _ts(m["end"]):
        return "ended"
    if membership_errors(doc, m, at=at):
        return "invalid"
    if m.get("standby_from"):
        from keyclerk import situation
        if not situation.standby_active(doc, m, _groups(doc)[m["group"]].get("place"), at):
            return "standby"   # prepared in peacetime, on only while the activation level reaches it
    return "active"


def membership_errors(doc: dict, m: dict, at: datetime | None = None, identity: bool = True) -> list[str]:
    """The rules a membership must meet. at None: as made (the chain held at its start); at given: as things stand
    then (risk, approvals, includes), which is how a later change to a group drops what no longer fits."""
    mid, gid, actor, kind = m["membership_id"], m["group"], m["by"], _kind(m)
    t0 = _ts(m["start"])
    now = at or t0
    if gid not in _groups(doc):
        return [f"{mid}: unknown group {gid}"]
    power = {"anchor": "members", "group": "includes", "rule": "rules"}[kind]
    risk = effective_risk(doc, gid)
    errs = []
    if m["under"] == "root":
        if not same(doc, actor, root_at(doc, t0)):
            errs.append(f"{mid}: made under root by someone who did not hold it then")
        days = R["root_max_membership_days"]
    else:
        d = _delegations(doc).get(m["under"])
        if d is None or not same(doc, d["delegate"], actor):
            return [f"{mid}: not made by the delegate of {m['under']}"]
        if power not in d["powers"] or not covers(doc, d["group"], gid) or not place_covers(doc, d, gid):
            errs.append(f"{mid}: {m['under']} does not give {power} over {gid}")
        if RISK[risk] > RISK[d["max_risk"]]:
            errs.append(f"{mid}: {gid} is {risk}, above what {m['under']} allows")
        if at is None and chain_status(doc, m["under"], t0)[0] != "ok":
            errs.append(f"{mid}: {m['under']} did not hold when it was made")
        if attenuation_errors(doc, d):
            errs.append(f"{mid}: made under an invalid delegation")
        days = d["max_membership_days"]
    if _ts(m["end"]) - t0 > timedelta(days=days):
        errs.append(f"{mid}: longer than {days} days")
    member = m["member"].get("anchor")
    sk = second_key_decision(doc, m.get("approved_by", []), actor, member, m["under"], gid, t0, now, exclude=mid,
                             mode="off" if at is None else None)
    keys = sk["counting"]
    needs_key = risk == "privileged" or (kind == "rule" and risk == "elevated") or (
        member and RISK[risk] >= 1 and any(same(doc, member, d["delegate"]) for d in doc.get("delegations", [])))
    if needs_key and not keys:
        errs.append(f"{mid}: needs a second key from outside the actor's chain ({risk} group)" + _not_counting(sk))
    if kind == "anchor":
        if same(doc, member, actor):
            errs.append(f"{mid}: the actor added themselves")
        if identity:                                     # decision 0011: who may be a member of a group of this class
            from keyclerk import policy_wasm
            errs += [f"{mid}: {r}" for r in policy_wasm.identity("membership", membership_input(doc, member, risk))]
    elif kind == "group":
        errs += _include_errors(doc, m, now)
    else:
        errs += _rule_errors(doc, m, risk)
    return errs


def _include_errors(doc: dict, m: dict, at: datetime) -> list[str]:
    mid, a, b = m["membership_id"], m["group"], m["member"]["group"]
    gs = _groups(doc)
    if b not in gs:
        return [f"{mid}: unknown included group {b}"]
    errs = []
    if "privileged" in (effective_risk(doc, a), gs[b]["max_risk"]):
        errs.append(f"{mid}: a privileged group neither includes nor is included")
    if RISK[gs[b]["max_risk"]] < RISK[effective_risk(doc, a)]:
        errs.append(f"{mid}: {b} is classed below {a}; an included group is classed at least as high")
    t0 = _ts(m["start"])
    second = [x for x in m.get("approved_by", []) if authority(doc, x, b, "members", t0)]
    if not authority(doc, m["by"], b, "members", t0) and not second:
        errs.append(f"{mid}: including {b} needs the members power over {b} too (or its manager's key)")
    if a == b or a in _closure(doc, b, exclude=mid):
        errs.append(f"{mid}: the include closes a cycle")
    for top in {a} | _includers(doc, a):   # the new edge deepens every group above it
        if _depth(doc, top, extra=(a, b), exclude=mid) > R["max_include_depth"]:
            errs.append(f"{mid}: inclusion under {top} deeper than {R['max_include_depth']}")
            break
    if m["by"] in effective_members(doc, b, t0) or any(same(doc, m["by"], x) for x in effective_members(doc, b, t0)):
        errs.append(f"{mid}: the include puts the actor into a group they manage")
    return errs


def _rule_errors(doc: dict, m: dict, risk: str) -> list[str]:
    """An attribute rule hands membership to whoever writes the attribute: its source is an authority over the group
    and is held to the same limits."""
    mid, rule = m["membership_id"], m["member"]["rule"]
    errs = []
    if risk == "privileged":
        errs.append(f"{mid}: a privileged group has named members only, never a rule")
    reg = ATTRS.get(rule["attribute"])
    if reg is None:
        return errs + [f"{mid}: attribute {rule['attribute']} is not in the attribute registry"]
    if reg.get("self_write"):
        errs.append(f"{mid}: {rule['attribute']} is self-writable")
    if rule["source"] not in reg["provided_by"]:
        errs.append(f"{mid}: {rule['source']} is not an authority for {rule['attribute']}")
    if rule["max_age_hours"] > reg["ttl_hours"]:
        errs.append(f"{mid}: max_age_hours above the attribute's ttl ({reg['ttl_hours']})")
    if not reg.get("may_widen"):
        errs.append(f"{mid}: {rule['attribute']} may only narrow, never add members")
    if reg.get("pedigree") != "authoritative" and risk != "low":
        errs.append(f"{mid}: {rule['attribute']} is {reg.get('pedigree', 'unclassified')}; only an authoritative "
                    f"attribute adds members to a {risk} group")
    if reg.get("allowed_values") and not set(rule["values"]) <= set(reg["allowed_values"]):
        errs.append(f"{mid}: values outside the attribute's allowed values")
    return errs


def _closure(doc: dict, gid: str, exclude: str | None = None) -> set[str]:
    seen, todo = set(), [gid]
    while todo:
        for c in _includes(doc, todo.pop(), exclude):
            if c not in seen:
                seen.add(c)
                todo.append(c)
    return seen


def _depth(doc: dict, gid: str, extra: tuple | None = None, exclude: str | None = None,
           seen: frozenset = frozenset()) -> int:
    kids = _includes(doc, gid, exclude) + ([extra[1]] if extra and extra[0] == gid else [])
    kids = [c for c in kids if c not in seen | {gid}]
    return 0 if not kids else 1 + max(_depth(doc, c, extra, exclude, seen | {gid}) for c in kids)


def matches(doc: dict, rule: dict, anchor: str, person: dict, at: datetime) -> bool:
    """A person matches a rule when the attribute comes from the rule's source, is fresh enough, and holds one of the
    values; a missing or stale attribute never matches (absent is the strictest value)."""
    if kind_of(doc, anchor) != "tenant":
        return False
    a = person.get("attributes", {}).get(rule["attribute"])
    return bool(a and a["source"] == rule["source"] and a["value"] in rule["values"]
                and at - _ts(a["at"]) <= timedelta(hours=rule["max_age_hours"]))


def effective_members(doc: dict, gid: str, at: datetime, people: dict | None = None,
                      _seen: frozenset = frozenset()) -> set[str]:
    """Named members, members of included groups and people matched by rules, all active now; suspended people drop
    out. people: {anchor: {"attributes": {name: {value, source, at}}}} from the sources (rules match nobody without it)."""
    store, key = _memo_get("members", doc, gid, at, id(people), _seen)
    if store is not None:
        if people is not None:
            store["docs"].setdefault(id(people), people)
        if key in store:
            return set(store[key])
    out = _effective_members(doc, gid, at, people, _seen)
    if store is not None:
        store[key] = frozenset(out)
    return out


def _effective_members(doc: dict, gid: str, at: datetime, people: dict | None = None,
                       _seen: frozenset = frozenset()) -> set[str]:
    from keyclerk.access_state import suspended
    from keyclerk import situation
    out: set[str] = set()
    paused = bool(doc.get("situations")) and situation.derived_rules_paused(
        situation.levels(doc, _groups(doc).get(gid, {}).get("place"), at)["restriction"])
    for m in doc.get("memberships", []):
        if m["group"] != gid or membership_status(doc, m, at) != "active":
            continue
        k = _kind(m)
        if k == "anchor":
            out.add(m["member"]["anchor"])
        elif k == "group" and m["member"]["group"] not in _seen | {gid}:
            out |= effective_members(doc, m["member"]["group"], at, people, _seen | {gid})
        elif k == "rule":
            if paused and ATTRS.get(m["member"]["rule"]["attribute"], {}).get("pedigree") != "authoritative":
                continue   # a raised level pauses rules on derived attributes
            out |= {a for a, p in (people or {}).items() if matches(doc, m["member"]["rule"], a, p, at)}
    out |= situation.surge_members(doc, gid, at)
    out = {a for a in out if not suspended(doc, a, at)}
    if persona_mode() == "enforce" and out:             # 0011a: every effective member, however they came in
        from keyclerk import policy_wasm
        risk = effective_risk(doc, gid)
        out = {a for a in out if not policy_wasm.identity("membership", membership_input(doc, a, risk))}
    agents = [a for a in out if kind_of(doc, a) == "agent"]
    if agents:                                   # an agent acts on behalf of its director: no further than them (0011)
        from keyclerk import policy_wasm
        for a in agents:
            director = (person_rec(doc, a) or {}).get("director")
            here = bool(director) and any(same(doc, director, b) for b in out if b != a)
            if not policy_wasm.identity("reach", {"kind": "agent", "director_member": here,
                                                  "director_suspended": bool(director) and suspended(doc, director, at)}):
                out.discard(a)
    return out


def _by_group(doc: dict) -> dict[str, list[dict]]:
    """Memberships per group, in record order (once per memo scope)."""
    store, key = _memo_get("by_group", doc)
    if store is not None and key in store:
        return store[key]
    out: dict[str, list[dict]] = {}
    for m in doc.get("memberships", []):
        out.setdefault(m["group"], []).append(m)
    if store is not None:
        store[key] = out
    return out


def member_of(doc: dict, anchor: str, gid: str, at: datetime, people: dict | None = None,
              _seen: frozenset = frozenset()) -> bool:
    """Whether anchor is an effective member of gid at `at`: exactly `anchor in effective_members(doc, gid, at, people)`
    (tests), without expanding the group. The same rules in the same order: named members, included groups and
    rule matches through active memberships, surge members; then suspensions, the persona rule, an agent's director."""
    store, key = _memo_get("member_of", doc, anchor, gid, at, id(people), _seen)
    if store is not None:
        if people is not None:
            store["docs"].setdefault(id(people), people)
        if key in store:
            return store[key]
    out = _member_of(doc, anchor, gid, at, people, _seen)
    if store is not None:
        store[key] = out
    return out


def _member_of(doc: dict, anchor: str, gid: str, at: datetime, people: dict | None, _seen: frozenset) -> bool:
    from keyclerk.access_state import suspended
    from keyclerk import situation
    if suspended(doc, anchor, at):
        return False
    paused = bool(doc.get("situations")) and situation.derived_rules_paused(
        situation.levels(doc, _groups(doc).get(gid, {}).get("place"), at)["restriction"])
    found = False
    for m in _by_group(doc).get(gid, []):
        k = _kind(m)
        if k == "anchor" and m["member"]["anchor"] != anchor:
            continue                                  # cheap filters first; status only for a membership that could bring it
        if k == "group" and m["member"]["group"] in _seen | {gid}:
            continue
        if k == "rule":
            if paused and ATTRS.get(m["member"]["rule"]["attribute"], {}).get("pedigree") != "authoritative":
                continue
            if not (people and anchor in people and matches(doc, m["member"]["rule"], anchor, people[anchor], at)):
                continue
        if membership_status(doc, m, at) != "active":
            continue
        if k == "group" and not member_of(doc, anchor, m["member"]["group"], at, people, _seen | {gid}):
            continue
        found = True
        break
    if not found and anchor not in situation.surge_members(doc, gid, at):
        return False
    if persona_mode() == "enforce":                    # 0011a, as effective_members applies it to every member
        from keyclerk import policy_wasm
        if policy_wasm.identity("membership", membership_input(doc, anchor, effective_risk(doc, gid))):
            return False
    if kind_of(doc, anchor) == "agent":                # 0011: an agent reaches no further than its director
        from keyclerk import policy_wasm
        director = (person_rec(doc, anchor) or {}).get("director")
        here = bool(director) and any(b != anchor and member_of(doc, b, gid, at, people, _seen)
                                      for b in _anchors_of_person(doc, director))
        if not policy_wasm.identity("reach", {"kind": "agent", "director_member": here,
                                              "director_suspended": bool(director) and suspended(doc, director, at)}):
            return False
    return True


def _anchors_of_person(doc: dict, anchor: str) -> list[str]:
    """Every anchor of the person anchor belongs to (anchor itself when no person record lists it)."""
    who = person_of(doc, anchor)
    for p in doc.get("persons", []):
        if p["person"] == who:
            return list(p["anchors"])
    return [anchor]


def sod_timeline(doc: dict, now: datetime, people: dict | None = None, only: set[str] | None = None) -> list[dict]:
    """SoD conflicts along the timeline (decision 0017): at each start time that can bring an SoD entitlement, the
    people that start reaches; at now, everyone. Each conflict once, at the first moment it is seen. only: judge
    these anchors alone (a scoped check, decision 0022 S4); the same conflicts for them as judging everyone."""
    rules = doc.get("sod", [])
    if not rules:
        return []
    named = {e for r in rules for e in r["entitlements"]}
    carriers = [(g["group_id"], [c["entitlement"] for c in g.get("carries", []) if c["entitlement"] in named])
                for g in doc.get("groups", [])]
    carriers = [(g, es) for g, es in carriers if es]
    everyone = {m["member"]["anchor"] for m in doc.get("memberships", []) if "anchor" in m["member"]} | set(people or {})
    starting: dict[datetime, list[dict]] = {}
    for m in doc.get("memberships", []):
        starting.setdefault(_ts(m["start"]), []).append(m)
    seen, out = set(), []

    if only is not None:
        everyone &= only

    def judge(anchors, at):
        for a in sorted(anchors & everyone):
            held: dict[str, list[str]] = {}
            for g, es in carriers:
                if member_of(doc, a, g, at, people):
                    for e in es:
                        held.setdefault(e, []).append(g)
            for rule in rules:
                x, y = rule["entitlements"]
                if x in held and y in held:
                    c = {"anchor": a, "sod": rule["sod_id"], "via": sorted(set(held[x] + held[y]))}
                    k = (a, rule["sod_id"], tuple(c["via"]))
                    if k not in seen:
                        seen.add(k)
                        out.append(c)

    for at in sod_times(doc, now):
        if at == now:
            judge(set(everyone), at)
            continue
        reached: set[str] = set()
        for m in starting.get(at, []):
            k = _kind(m)
            if k == "anchor":
                reached.add(m["member"]["anchor"])
            elif k == "group":
                reached |= effective_members(doc, m["member"]["group"], at, people)
            else:
                reached |= {a for a, pr in (people or {}).items() if matches(doc, m["member"]["rule"], a, pr, at)}
        judge(reached, at)
    return out


def effective_entitlements(doc: dict, anchor: str, at: datetime, people: dict | None = None) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for g in doc.get("groups", []):
        if anchor in effective_members(doc, g["group_id"], at, people):
            for c in g.get("carries", []):
                out.setdefault(c["entitlement"], []).append(g["group_id"])
    return out


def sod_conflicts(doc: dict, at: datetime, people: dict | None = None) -> list[dict]:
    """Conflicts after flattening, so one hidden behind an include or a rule is still found. Only the groups that carry
    an entitlement named in an SoD rule are flattened (decision 0017): the same answer as flattening every person's
    entitlements across all groups (sod_conflicts_reference), without doing that."""
    rules = doc.get("sod", [])
    if not rules:
        return []
    anchors = {m["member"]["anchor"] for m in doc.get("memberships", []) if "anchor" in m["member"]} | set(people or {})
    named = {e for r in rules for e in r["entitlements"]}
    held: dict[str, dict[str, list[str]]] = {}                    # anchor -> entitlement -> groups, in doc order
    for g in doc.get("groups", []):
        carried = [c["entitlement"] for c in g.get("carries", []) if c["entitlement"] in named]
        if not carried:
            continue
        for a in effective_members(doc, g["group_id"], at, people) & anchors:
            for e in carried:
                held.setdefault(a, {}).setdefault(e, []).append(g["group_id"])
    out = []
    for a in sorted(held):
        h = held[a]
        for rule in rules:
            x, y = rule["entitlements"]
            if x in h and y in h:
                out.append({"anchor": a, "sod": rule["sod_id"], "via": sorted(set(h[x] + h[y]))})
    return out


def sod_conflicts_reference(doc: dict, at: datetime, people: dict | None = None) -> list[dict]:
    """The direct form, kept to prove sod_conflicts gives the same answer (tests)."""
    anchors = {m["member"]["anchor"] for m in doc.get("memberships", []) if "anchor" in m["member"]} | set(people or {})
    out = []
    for a in sorted(anchors):
        held = effective_entitlements(doc, a, at, people)
        for rule in doc.get("sod", []):
            x, y = rule["entitlements"]
            if x in held and y in held:
                out.append({"anchor": a, "sod": rule["sod_id"], "via": sorted(set(held[x] + held[y]))})
    return out


def sod_times(doc: dict, now: datetime, every: bool = False) -> list[datetime]:
    """The moments at which a new SoD conflict can appear: the start of a membership whose group, or a group that
    includes it (directly or further up), carries an entitlement an SoD rule names; and now. A start anywhere else
    brings no SoD entitlement to anyone. every: all start times, the previous behaviour (tests)."""
    starts = doc.get("memberships", [])
    if every or not doc.get("sod"):
        return sorted({_ts(m["start"]) for m in starts} | {now}) if (every or doc.get("sod")) else [now]
    named = {e for r in doc["sod"] for e in r["entitlements"]}
    carrying = {g["group_id"] for g in doc.get("groups", []) if any(c["entitlement"] in named for c in g.get("carries", []))}
    included_by: dict[str, set[str]] = {}                          # group -> the groups that include it (any time)
    for m in starts:
        if "group" in m["member"]:
            included_by.setdefault(m["member"]["group"], set()).add(m["group"])
    relevant: dict[str, bool] = {}

    def reaches(gid: str) -> bool:
        if gid not in relevant:
            relevant[gid] = False                                  # cycle guard: assume no until shown
            seen, todo = {gid}, [gid]
            while todo:
                g = todo.pop()
                if g in carrying:
                    relevant[gid] = True
                    break
                for h in included_by.get(g, ()):
                    if h not in seen:
                        seen.add(h)
                        todo.append(h)
        return relevant[gid]
    return sorted({_ts(m["start"]) for m in starts if reaches(m["group"])} | {now})


def explain(doc: dict, anchor: str, gid: str, at: datetime, people: dict | None = None,
            _seen: frozenset = frozenset()) -> list[list[str]]:
    """Every path that puts anchor in gid now (diamonds show as several paths)."""
    paths = []
    for m in doc.get("memberships", []):
        if m["group"] != gid or membership_status(doc, m, at) != "active":
            continue
        links = [d["delegation_id"] for d in chain(doc, m["under"])] if m["under"] != "root" else []
        why = "under " + " < ".join(links + ["root"])
        k = _kind(m)
        if k == "anchor" and m["member"]["anchor"] == anchor:
            paths.append([gid, m["membership_id"], why])
        elif k == "rule" and anchor in (people or {}) and matches(doc, m["member"]["rule"], anchor, people[anchor], at):
            r = m["member"]["rule"]
            paths.append([gid, f"{m['membership_id']} ({r['attribute']} from {r['source']})", why])
        elif k == "group" and m["member"]["group"] not in _seen | {gid}:
            for p in explain(doc, anchor, m["member"]["group"], at, people, _seen | {gid}):
                paths.append([gid] + p)
    return paths


def impact(doc: dict, rid: str, at: datetime) -> dict:
    """What a revocation of a delegation would end now: the delegations below it and what was made under them; shown
    before a retire or revoke is confirmed."""
    below = [d["delegation_id"] for d in _descendants(doc, rid)]
    ids = {rid, *below}
    made = [m["membership_id"] for m in doc.get("memberships", [])
            if m["under"] in ids and membership_status(doc, m, at) == "active"]
    return {"delegations": below, "memberships": made}


# --- the whole record set ----------------------------------------------------------------------------------------

def check(doc: dict, memberships: set[str] | None = None, sod: set[str] | None = None) -> list[str]:
    """Every violation, one line each: the tree, the catalogue, each delegation and membership as made and as things
    stand, the rate caps, and SoD at every change. memberships, sod: judge only these memberships and these anchors'
    separation of duty (a scoped check, decision 0022 S4); everything else is judged whole, on the whole records."""
    errs = identity_errors(doc)
    gs = _groups(doc)
    tops = [g for g in gs.values() if g.get("parent") is None]
    if gs and not (doc.get("root") or {}).get("holders"):
        errs.append("groups without a root trust owner")
    if gs and len(tops) != 1:
        errs.append(f"the tree needs exactly one top group, found {len(tops)}")
    cat = {e["entitlement"]: e for e in doc.get("catalogue", [])}
    for g in gs.values():
        gid = g["group_id"]
        if g.get("parent") is not None and g["parent"] not in gs:
            errs.append(f"{gid}: unknown parent {g['parent']}")
        elif len(tops) == 1 and ancestors(doc, gid)[-1] != tops[0]["group_id"]:
            errs.append(f"{gid}: not under the top group (a loop in the tree)")
        if RISK[carried_risk(doc, gid)] > RISK[g["max_risk"]]:
            errs.append(f"{gid}: carries {carried_risk(doc, gid)} rights above its fixed class {g['max_risk']}")
        for c in g.get("carries", []):
            e = cat.get(c["entitlement"])
            if e is None:
                errs.append(f"{gid}: carries {c['entitlement']}, which is not in the catalogue")
            elif not same(doc, c["by"], e["owner"]):
                errs.append(f"{gid}: {c['entitlement']} set by {c['by']}, not its owner {e['owner']}")
    for d in doc.get("delegations", []):
        errs += attenuation_errors(doc, d)
    for a in doc.get("approvers", []):
        errs += approver_errors(doc, a)
    kids = Counter(d["parent"] for d in doc.get("delegations", []) if d["parent"] != "root")
    errs += [f"{p}: {n} direct delegates, above {R['max_direct_delegates']}" for p, n in kids.items()
             if n > R["max_direct_delegates"]]
    for m in doc.get("memberships", []):
        if memberships is None or m["membership_id"] in memberships:
            errs += membership_check(doc, m)
    errs += _rate_errors(doc)
    for c in sod_timeline(doc, clock.now(), only=sod) if sod is None or sod else []:   # decision 0017: the timeline
        msg = f"SoD {c['sod']}: {c['anchor']} through {', '.join(c['via'])}"
        if msg not in errs:
            errs.append(msg)
    known = set(_delegations(doc)) | {m["membership_id"] for m in doc.get("memberships", [])}
    known |= {a["approver_id"] for a in doc.get("approvers", [])}
    known |= {"root:" + h["anchor"] for h in (doc.get("root") or {}).get("holders", [])}
    known |= {r[k] for kind, k in (("edges", "edge_id"), ("person_keys", "key_id"), ("edge_visit_leases", "lease_id"))
              for r in doc.get(kind, [])}                                 # decision 0014: end_edge_record
    errs += [f"admin revocation of unknown id {r['id']}" for r in doc.get("admin_revocations", []) if r["id"] not in known]
    return list(dict.fromkeys(errs))


def membership_check(doc: dict, m: dict) -> list[str]:
    """One membership's errors as check judges it: as made, and as things stand now when it is invalid now (a scoped
    check judges only the memberships a change reaches, with this, decision 0022 S4)."""
    # persons carry no history, so an ended membership (retired, revoked, expired) is not judged on who its member
    # is declared to be today: it grants nothing, and moving to an admin persona retires the daily one (0011a)
    st = membership_status(doc, m, clock.now())
    if st in ("revoked", "ended", "lapsed", "void"):
        token = _PERSONA_OFF.set(True)                # neither the member nor its approvers by today's personas
        try:
            errs = membership_errors(doc, m, identity=False)
        finally:
            _PERSONA_OFF.reset(token)
    else:
        errs = membership_errors(doc, m)
    if st == "invalid" and not m.get("standby_from"):
        errs += [e + " (now)" for e in membership_errors(doc, m, at=clock.now())]
    return errs


def _top(doc: dict, under: str) -> str:
    return chain(doc, under)[-1]["delegation_id"] if under != "root" and chain(doc, under) else "root"


def _rate_errors(doc: dict) -> list[str]:
    """Widenings per deputy and per subtree per day; delegations count too, so many sub-deputies do not multiply the
    cap."""
    acts = [(m["by"], m["under"], _ts(m["start"]).date()) for m in doc.get("memberships", []) if m["under"] != "root"]
    acts += [(d["by"], d["parent"], _ts(d["start"]).date()) for d in doc.get("delegations", []) if d["parent"] != "root"]
    errs = []
    for (who, day), n in sorted(Counter((person_of(doc, w), day) for w, _, day in acts).items()):
        if n > R["widenings_per_deputy_per_day"]:
            errs.append(f"{who}: {n} widenings on {day}, above {R['widenings_per_deputy_per_day']}")
    for (top, day), n in sorted(Counter((_top(doc, u), day) for _, u, day in acts).items()):
        if n > R["widenings_per_subtree_per_day"]:
            errs.append(f"subtree of {top}: {n} widenings on {day}, above {R['widenings_per_subtree_per_day']}")
    return errs


def revision(doc: dict) -> int:
    """The administrative revision: it only grows with every revocation, so OPA can refuse to decide from a bundle that
    predates the newest one (a zookie)."""
    return len(doc.get("admin_revocations", []))


def opa_data(doc: dict, at: datetime) -> dict:
    """data.keyclerk.delegation for keyclerk/policy/delegation.rego: who may do what over which groups now (authority derived
    here, OPA checks it), each group's effective class, the deputies, today's widenings and the revision."""
    auth: dict[str, list] = {}
    root = root_at(doc, at)
    if root and compromised_from(doc, root, at) is None:
        auth[root] = [{"delegation_id": "root", "powers": sorted(POWERS), "groups": sorted(_groups(doc)),
                       "max_risk": "privileged", "max_membership_days": R["root_max_membership_days"],
                       "chain_people": [root]}]
    for d in doc.get("delegations", []):
        if (chain_status(doc, d["delegation_id"], at)[0] == "ok" and not attenuation_errors(doc, d)
                and compromised_from(doc, d["delegate"], at) is None):
            auth.setdefault(d["delegate"], []).append({
                "delegation_id": d["delegation_id"], "powers": sorted(d["powers"]), "max_risk": d["max_risk"],
                "max_membership_days": d["max_membership_days"],
                "groups": sorted(g for g in _groups(doc) if covers(doc, d["group"], g) and place_covers(doc, d, g)),
                "chain_people": sorted({x for c in chain(doc, d["delegation_id"]) for x in (c["by"], c["delegate"])}
                                       | {x["delegate"] for x in _descendants(doc, d["delegation_id"])})})
    today = Counter(person_of(doc, m["by"]) for m in doc.get("memberships", []) if _ts(m["start"]).date() == at.date())
    return {"authority": auth, "risk": {g: effective_risk(doc, g) for g in sorted(_groups(doc))},
            "deputies": sorted({d["delegate"] for d in doc.get("delegations", [])}),
            "persons": {a: person_of(doc, a) for p in doc.get("persons", []) for a in p["anchors"]},
            "widenings_today": dict(today), "revision": revision(doc),
            "rules": {"widenings_per_deputy_per_day": _cap_now(doc, at)}, "second_key": second_key_data(doc, at)}


def second_key_data(doc: dict, at: datetime) -> dict:
    """The facts delegation.rego needs to build second-key candidates (second_key.rego decides): kinds, units, the
    root, the officer, the named approvers and the compromised people now, and the favours (days since a person's key
    was on another's change)."""
    anchors = {a for p in doc.get("persons", []) for a in p["anchors"]} | {ls["anchor"] for ls in doc.get("leases", [])}
    favours: dict[str, dict] = {}
    for kind in ("delegations", "memberships"):
        for r in doc.get(kind, []):
            if _ts(r["start"]) > at:
                continue
            days = (at - _ts(r["start"])).total_seconds() / 86400
            row = favours.setdefault(person_of(doc, r["by"]), {})
            for x in r.get("approved_by", []):
                row[person_of(doc, x)] = min(days, row.get(person_of(doc, x), days))
    return {"policy": standing_policy(), "root": root_at(doc, at), "officer": (doc.get("root") or {}).get("officer"),
            "kinds": {a: kind_of(doc, a) for a in sorted(anchors)},
            "default_kind": "unknown" if doc.get("persons") else "tenant",
            "units": {a: p["unit"] for p in doc.get("persons", []) if p.get("unit") for a in p["anchors"]},
            "named": sorted({a["anchor"] for a in doc.get("approvers", []) if named_approver(doc, a["anchor"], at)}),
            "tainted": sorted(a for a in anchors if compromised_from(doc, a, at) is not None),
            "favours": favours}


def _cap_now(doc: dict, at: datetime) -> int:
    """The deputy cap shrinks with the tenant's restriction level (situation rate_factor; 0 at severe)."""
    from keyclerk import situation
    return int(R["widenings_per_deputy_per_day"] * situation.rate_factor(situation.levels(doc, None, at)["restriction"]))


def carrier_groups(doc: dict, at: datetime, people: dict | None = None, trusts: dict | None = None) -> dict[str, set[str]]:
    """The flat Keycloak groups the reconciler writes: /groups/<group_id> with the effective members. With trusts
    (keyclerk-trust-input-v1 per anchor), members below the floor of the group's effective class stay out (risk_port)."""
    out = {}
    for g in sorted(_groups(doc)):
        members = effective_members(doc, g, at, people)
        if trusts is not None:
            from keyclerk import risk_port
            from keyclerk import situation
            level = situation.levels(doc, _groups(doc)[g].get("place"), at)["restriction"]
            members, _ = risk_port.split(members, trusts, effective_risk(doc, g), at, level,
                                         {a: kind_of(doc, a) for a in members})
        out[GROUP_PREFIX + g] = members
    return out


def main(argv: list[str]) -> int:
    from keyclerk import records
    now = clock.now()
    if argv[:1] == ["--explain"]:
        paths = explain(records.load(Path(argv[1])), argv[2], argv[3], now)
        print("\n".join(" > ".join(p) for p in paths) or f"{argv[2]} is not in {argv[3]} now")
        return 0
    if argv[:1] == ["--persona-impact"]:
        rows = persona_impact(records.load(Path(argv[1])), clock.now())
        print("\n".join(f"{r['group']}: {r['anchor']} ({r['what']}): {'; '.join(r['reasons'])}" for r in rows)
              or "enforcing the persona rule changes nothing")
        return 0
    if argv[:1] == ["--standing-impact"]:
        print("\n".join(standing_impact(records.load(Path(argv[1])))) or "enforcing standing changes nothing")
        return 0
    if argv[:1] == ["--impact"]:
        print(yaml.safe_dump(impact(records.load(Path(argv[1])), argv[2], now), sort_keys=False), end="")
        return 0
    bad = 0
    for f in [Path(a) for a in argv if not a.startswith("--")]:
        for e in check(records.load(f)):
            print(f"{f}: {e}", file=sys.stderr)
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
