# SPDX-License-Identifier: EUPL-1.2
"""Places: where things are, physical and logical, one model for access, levels and paths.

Physical places form one tree by `within`: region, campus, site, building, floor, space (a room, cage, aisle,
hallway, yard; its `type` says which). Regions, campuses, buildings and spaces may nest in their own kind (a wing in a
building, a cage in a room). Anything below site level sits under a site or an outpost. An outpost (an antenna site, a
remote cabinet, a pumping station) is a physical place of its own that `belongs_to` the site that runs it: it shares
that site's levels, deputy and administration through scope_chain, which every administrative check uses.
Zones (security, fire, HVAC) are overlays: sets of places that may span floors and buildings. Doors are not
places: they are checkpoints between two places. Org units form one tree by `parent` and
`occupies` physical places at or below site level. A place is shared when it, or a place containing it, is
marked shared or has a steward, unless the steward assigned it to one tenant. Retired ids never return.

Usage: python -m keyclerk.places RECORDS.yaml ...      check records that hold places
"""
from __future__ import annotations

import sys
from pathlib import Path


from keyclerk import config

P = config.Section("places")


def _kinds() -> list[str]:
    return P["kinds"]          # outermost first


def _nest_same() -> set[str]:
    return set(P["nest_same_kind"])


def _site_level() -> int:
    return _kinds().index("site")


def _places(doc: dict) -> dict[str, dict]:
    return {p["place_id"]: p for p in doc.get("places", [])}


def _orgs(doc: dict) -> dict[str, dict]:
    return {o["org_id"]: o for o in doc.get("org_units", [])}


def _depth(kind: str) -> int:
    return _site_level() if kind == "outpost" else _kinds().index(kind)


def within_chain(doc: dict, pid: str) -> list[str]:
    """pid and every place containing it, innermost first (stops on a loop, which check() reports)."""
    ps, out = _places(doc), []
    while pid in ps and pid not in out:
        out.append(pid)
        pid = ps[pid].get("within")
    return out


def scope_chain(doc: dict, pid: str) -> list[str]:
    """Every place whose level, deputy or rules reach pid: its containers, and for an outpost (or anything inside
    one) the site it belongs to with that site's containers."""
    ps, out, todo = _places(doc), [], [pid]
    while todo:
        for x in within_chain(doc, todo.pop(0)):
            if x not in out:
                out.append(x)
                owner = ps[x].get("belongs_to")
                if owner and owner not in out:
                    todo.append(owner)
    return out


def org_chain(doc: dict, oid: str) -> list[str]:
    os_, out = _orgs(doc), []
    while oid in os_ and oid not in out:
        out.append(oid)
        oid = os_[oid].get("parent")
    return out


def inside(doc: dict, pid: str, top: str) -> bool:
    """Geographically inside (within only)."""
    return top in within_chain(doc, pid)


def under(doc: dict, pid: str, top: str) -> bool:
    """Administratively under: inside, or run from (outposts); used by deputies, stewards and place limits."""
    return top in scope_chain(doc, pid)


def places_of_org(doc: dict, oid: str) -> set[str]:
    tops = {p for o in doc.get("org_units", []) if oid in org_chain(doc, o["org_id"]) for p in o.get("occupies", [])}
    return {p for p in _places(doc) if any(inside(doc, p, t) for t in tops)}


def orgs_at(doc: dict, pid: str) -> set[str]:
    chain = set(within_chain(doc, pid))
    return {o["org_id"] for o in doc.get("org_units", [])
            for p in o.get("occupies", []) if p in chain or inside(doc, p, pid)}


def resolve(doc: dict, ref: str | None) -> str | None:
    """A place id from a place id or a host id (a host is placed at a place); None stays None."""
    if ref is None or ref in _places(doc):
        return ref
    for p in doc.get("places", []):
        if ref in p.get("hosts", []):
            return p["place_id"]
    return None


def shared(doc: dict, pid: str) -> bool:
    """Shared when this place or one containing it is marked shared or has a steward, unless an inner place on the way
    was assigned to one tenant by the steward."""
    ps = _places(doc)
    for x in within_chain(doc, pid):
        p = ps[x]
        if p.get("assigned_to"):
            return False
        if p.get("shared") or p.get("steward"):
            return True
    return False


def shared_below(doc: dict, pid: str) -> list[str]:
    """Shared places inside pid (excluding pid): a tenant's place-scoped level would reach them."""
    return [x for x in _places(doc) if x != pid and inside(doc, x, pid) and shared(doc, x) and not shared(doc, pid)]


def check(doc: dict) -> list[str]:
    errs = []
    ps, os_ = _places(doc), _orgs(doc)
    retired = set(doc.get("retired_places", []))
    if len(ps) != len(doc.get("places", [])):
        errs.append("a place id appears twice")
    errs += [f"{pid}: a retired place id is never reused" for pid in ps if pid in retired]
    for p in ps.values():
        pid, kind = p["place_id"], p["kind"]
        if kind not in _kinds() and kind != "outpost":
            errs.append(f"{pid}: unknown kind {kind}")
            continue
        up = p.get("within")
        if up is not None:
            if up not in ps:
                errs.append(f"{pid}: within unknown place {up}")
            elif _depth(ps[up]["kind"]) > _depth(kind) or (ps[up]["kind"] == kind and kind not in _nest_same()) or \
                    (ps[up]["kind"] != kind and _depth(ps[up]["kind"]) == _depth(kind)):
                errs.append(f"{pid}: a {kind} cannot be within a {ps[up]['kind']}")
            elif up in within_chain(doc, up)[1:] or pid in within_chain(doc, up):
                errs.append(f"{pid}: a loop in within")
        if _depth(kind) > _site_level() and not any(ps[x]["kind"] in ("site", "outpost") for x in within_chain(doc, pid)[1:]):
            errs.append(f"{pid}: a {kind} sits under a site or an outpost")
        owner = p.get("belongs_to")
        if owner is not None:
            if kind != "outpost":
                errs.append(f"{pid}: only an outpost belongs to a site; a {kind} is within one")
            elif owner not in ps or ps[owner]["kind"] != "site":
                errs.append(f"{pid}: belongs to {owner}, which is not a site")
            elif inside(doc, owner, pid) or inside(doc, pid, owner):
                errs.append(f"{pid}: an outpost is never inside the site it belongs to, nor contains it")
        if kind == "outpost" and owner is None:
            errs.append(f"{pid}: an outpost names the site it belongs to")
        if p.get("deputy") and kind not in ("site", "outpost"):
            errs.append(f"{pid}: a deputy is named on a site or an outpost")
        if p.get("assigned_to") and not any(ps[x].get("steward") for x in within_chain(doc, pid)):
            errs.append(f"{pid}: assigned to a tenant, but no steward above it assigns places")
    for z in doc.get("zones", []):
        errs += [f"{z['zone_id']}: unknown member place {m}" for m in z["members"] if m not in ps]
    for o in os_.values():
        if o.get("parent") is not None and o["parent"] not in os_:
            errs.append(f"{o['org_id']}: unknown parent {o['parent']}")
        for pl in o.get("occupies", []):
            if pl not in ps:
                errs.append(f"{o['org_id']}: occupies unknown place {pl}")
            elif _depth(ps[pl]["kind"]) < _site_level():
                errs.append(f"{o['org_id']}: occupies {pl}, above site level")
    hosts = [i for p in ps.values() for i in p.get("hosts", [])]
    errs += [f"host {i} placed twice" for i in set(hosts) if hosts.count(i) > 1]
    return errs


def main(argv: list[str]) -> int:
    from keyclerk import records
    bad = 0
    for f in [Path(a) for a in argv if not a.startswith("--")]:
        for e in check(records.load(f)):
            print(f"{f}: {e}", file=sys.stderr)
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
