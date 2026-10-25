# SPDX-License-Identifier: EUPL-1.2
"""Pools and fallback ladders.

Pools: every role a checkpoint can need (the second person of a two-person checkpoint, an escort, the custodians of
each quorum share, the site office that confirms remotely) comes from distinct, equally entitled people, at least
pool_factor times what is needed at once, so sick leave, holidays and nights do not stop the work. Counted from the
roster: every person and the entitlements they hold now (tools/access_paths.py _roster).

Fallback ladders: when the normal requirement cannot be met now, the first step of the checkpoint's ladder that the
label, the risk band, the situation level and the urgency allow is taken, and only if that step's own pool is
available (a remote confirmation needs a staffed site office); otherwise the next. The last step for Restricted is
deferral or never, so nothing falls through to free. keyclerk/policy/fallback.rego decides at runtime; this is its
reference implementation, and the tests hold them to the same cases.

Usage: library, run through tools/access_paths.py check.
"""
from __future__ import annotations

from keyclerk import access_paths as A
from keyclerk import config

R = config.Section("availability")
LEVELS = ["normal", "elevated", "high", "severe"]


def _holders(people: dict[str, set[str]], ent: str, persons: dict[str, str] | None = None) -> set[str]:
    return {(persons or {}).get(a, a) for a, ents in people.items() if ent in ents}


def check(g: dict, people: dict[str, set[str]] | None, persons: dict[str, str] | None = None) -> list[str]:
    """Pools at least pool_factor times the need, and a fallback ladder wherever two people or an escort are needed on
    the way to Sensitive or Restricted."""
    from keyclerk import keys as K
    errs = []
    factor = R["pool_factor"]
    creds = K._creds(g)
    for c in A.checkpoints(g):
        label = K.behind(g, c)
        if c.get("two_person") and people is not None and c["requires"] != "possession":
            n = len(_holders(people, c["requires"], persons))
            if n < 2 * factor:
                errs.append(f"{c['checkpoint_id']}: two-person pool of {n}, needs {2 * factor} (pool_factor {factor})")
        if c.get("escort") == "allowed" and people is not None and c["requires"] != "possession":
            n = len(_holders(people, c["requires"], persons))
            if n < factor:
                errs.append(f"{c['checkpoint_id']}: escort pool of {n}, needs {factor}")
        m, ks = A.key_spec(c)
        if m >= 2:
            for k in ks:
                fam = K._family(creds, k)
                keepers = {h for x in fam for h in creds[x].get("held_by", [])} | \
                          {f"store:{creds[x]['stored_in']}" for x in fam if creds[x].get("stored_in")}
                if len(keepers) < factor:
                    errs.append(f"{c['checkpoint_id']}: share {k} has {len(keepers)} custodians or stores, needs {factor}")
        needs_ladder = (c.get("two_person") or c.get("escort") == "allowed") and label in ("Sensitive", "Restricted")
        ladder = c.get("fallback")
        if needs_ladder and not ladder:
            errs.append(f"{c['checkpoint_id']}: needs two people or an escort on the way to {label} and declares no fallback ladder")
        if ladder and label:
            allowed = R["allowed_steps"][label]
            bad = [s for s in ladder if s not in allowed]
            if bad:
                errs.append(f"{c['checkpoint_id']}: fallback steps {bad} are not allowed for {label}")
            if label == "Restricted" and ladder[-1] not in ("deferred", "never"):
                errs.append(f"{c['checkpoint_id']}: a Restricted ladder ends in deferred or never")
    if people is not None:
        office = _holders(people, R["site_office_entitlement"], persons)
        if any("remote_confirm" in (c.get("fallback") or []) for c in A.checkpoints(g)) and len(office) < factor:
            errs.append(f"site office pool of {len(office)}, needs {factor} for remote confirmations")
    return errs


def fallback(ladder: list[str], label: str, band: str, level: str, urgent: bool, available: dict) -> dict:
    """The step taken when the normal requirement cannot be met now; available: {"site_office": bool,
    "remote_watch": bool}. Mirrors keyclerk/policy/fallback.rego."""
    if band in ("red", "black"):
        return {"step": "never", "why": f"risk band {band}"}
    if level not in LEVELS or label not in R["allowed_steps"]:
        return {"step": "never", "why": "unknown label or level"}
    allowed = set(R["allowed_steps"][label])
    until = R["remote_steps_until_level"].get(label)
    if until not in LEVELS or LEVELS.index(level) > LEVELS.index(until):   # missing data closes remote steps (never fail open)
        allowed -= {"remote_confirm", "supervised"}
    for step in ladder:
        if step not in allowed:
            continue
        if step == "remote_confirm" and not available.get("site_office"):
            continue
        if step == "supervised" and not (available.get("remote_watch") and (urgent or label == "Internal")):
            continue
        return {"step": step, "obligations": R["steps"][step]["obligations"]}
    return {"step": "deferred" if label != "Restricted" or "deferred" in ladder else "never", "why": "no step available"}
