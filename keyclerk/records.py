# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk records, one file each.

A realm's records live in a directory:
  realm.yaml                       realm, home, connected_organisations
  grants/<grant_id>.yaml           one grant
  revocations/<grant_id>.yaml      one revocation, named by the grant it revokes; never changed once written
  leases/<lease_id>.yaml           one external access lease
  suspensions/<id>.yaml            one suspension of a person, lifted only by two people
One file per record keeps concurrent merge requests from touching the same file (research H). The loader returns the
same document shape as a single records file, so grants and leases work on
either.

Usage:
  python tools/records.py split FILE DIR        write a single-file realm as one file per record
  python tools/records.py guard OLD_DIR NEW_DIR refuse a new head that drops or changes a revocation
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

KINDS = {"grants": "grant_id", "revocations": "grant_id", "leases": "lease_id", "suspensions": "suspension_id",
         "catalogue": "entitlement", "sod": "sod_id", "groups": "group_id", "delegations": "delegation_id",
         "memberships": "membership_id", "admin_revocations": "revocation_key",   # delegated administration
         "situations": "situation_id", "surge_packages": "package_id", "surge_grants": "surge_id",   # situation levels
         "approvers": "approver_id",                                                                 # decision 0008
         "visits": "visit_id", "visit_events": "event_id", "badges": "badge_id",                      # decision 0009
         "accounts": "anchor",                                                                        # decision 0028
         "edges": "edge_id", "person_keys": "key_id", "edge_visit_leases": "lease_id",                 # decision 0014
         "edge_rotations": "rotation_id"}
OPTIONAL = ("accounts", "leases", "catalogue", "sod", "groups", "delegations", "memberships", "admin_revocations", "situations",
            "surge_packages", "surge_grants", "approvers", "visits", "visit_events", "badges",
            "edges", "person_keys", "edge_visit_leases", "edge_rotations")
HEAD = ("realm", "home", "connected_organisations", "root", "persons", "places", "org_units", "zones", "retired_places",
        "situation_feeds", "revision", "approval_proofs", "proposal_proofs")   # every top-level kind is in HEAD or KINDS (a test holds it)


class _Plain(yaml.SafeDumper):
    """The safe dumper without anchors and aliases: a value used twice in memory (one `now` for two fields) is written
    twice, because the loader refuses YAML anchors (guard)."""

    def ignore_aliases(self, data):
        return True


def _key(kind: str, rec: dict) -> str:
    """The file name of a record; an administrative revocation is keyed by its id and mode (a retire may be followed
    by a revoke of the same id)."""
    return f"{rec['id']}.{rec['mode']}" if kind == "admin_revocations" else rec[KINDS[kind]]


def _y(p: Path):
    """Every records file through the guard: bounded, no YAML aliases, bounded depth and strings."""
    from keyclerk import guard
    doc = guard.load_yaml(p)
    if doc is not None and not isinstance(doc, dict):
        raise guard.InputRejected(f"{p.name} is not a mapping")
    return doc


ID_FIELDS = {"grant_id", "anchor", "lease_id", "suspension_id", "entitlement", "sod_id", "group_id", "delegation_id",
             "membership_id", "situation_id", "package_id", "surge_id", "place_id", "org_id", "zone_id", "requested_by",
             "by", "delegate", "parent", "group", "under", "coordinator", "realm", "home", "role"}
ANCHOR_FIELDS = {"anchor", "requested_by", "by", "delegate", "coordinator"}
TIME_FIELDS = {"start", "end", "at", "from", "to", "decided_at", "until", "valid_until", "issued_at", "review_by",
               "prepared_at", "valid_from", "requested_end", "checked_at",
               "expiry", "contract_end", "opens", "closes", "expected"}   # every date-time in the records schema (a test holds it)


# --- where a person's anchor sits in the records (decision 0028 point 1) --------------------------------------------
# The one table of every place a record names a person by anchor. The internal-anchor migration re-keys exactly these
# paths, and a test holds the table to the schema and to real records, so a new anchor field cannot be missed.
# Path syntax: "a" a field, "a.b" a field of an object, "a[]" each item of a list, "a[].b" a field of each item.
ANCHOR_PATHS: dict[str, tuple[str, ...]] = {
    "root": ("officer", "holders[].anchor", "holders[].appointed_by", "on_call[]"),
    "persons": ("anchors[]", "personas[].anchor", "owner", "director"),
    "grants": ("subject.anchor", "requested_by", "approved_by[]"),
    "revocations": ("by",),
    "leases": ("anchor", "sponsor.anchor", "resource_owner", "approved_by[]", "proofs[].checker"),
    "accounts": ("anchor",),
    "catalogue": ("owner",),
    "connected_organisations": ("contact",),
    "groups": ("carries[].by",),
    "delegations": ("delegate", "by", "approved_by[]"),
    "memberships": ("member.anchor", "by", "approved_by[]"),
    "admin_revocations": ("by",),
    "suspensions": ("anchor", "by", "lifted.by[]"),
    "approvers": ("anchor", "appointed_by", "approved_by[]"),
    "situations": ("by", "approved_by[]"),
    "surge_packages": ("coordinator", "approved_by[]"),
    "surge_grants": ("anchor", "by"),
    "places": ("deputy", "steward", "front_office[]"),        # hosts[] are machine host names, not people
    "approval_proofs": ("by",),
    "proposal_proofs": ("by",),
    "edges": ("officer", "by", "approved_by[]", "custodians[]", "unlock_approvers[]"),
    "person_keys": ("anchor", "by", "approved_by[]"),
    "edge_visit_leases": ("person", "by", "approved_by[]"),
    "edge_rotations": ("officer", "by", "approved_by[]"),
    # side kinds (outside the log, erasable): re-keyed too, so a visit never names a person by their provider id
    "visits": ("host", "organiser", "escorts[]", "by", "attendees[].anchor", "attendees[].escort", "parties[].anchor"),
    "visit_events": ("by", "anchor", "attendee.anchor", "attendee.escort"),
    "badges": ("issued_by", "approved_by[]"),
}


def _at(node, parts: list[str]):
    """The values at a path inside one record."""
    if not parts:
        yield node
        return
    head, rest = parts[0], parts[1:]
    many = head.endswith("[]")
    key = head[:-2] if many else head
    if not isinstance(node, dict) or key not in node:
        return
    v = node[key]
    for item in (v if many and isinstance(v, list) else [] if many else [v]):
        yield from _at(item, rest)


def anchor_values(kind: str, rec: dict):
    """(path, value) for every anchor a record of this kind holds, by ANCHOR_PATHS."""
    for path in ANCHOR_PATHS.get(kind, ()):
        for v in _at(rec, path.replace("[].", "[] ").replace(".", " ").split()):
            if isinstance(v, str) and v:
                yield path, v


def schema(log_backed: bool = False) -> dict:
    """The records schema. log_backed: without the whole-document caps on how many records a kind holds (maxItems on
    the top-level arrays), which bound one YAML file read whole; a store that keeps one record per row bounds each change
    instead (decision 0022, amendment of S4)."""
    from keyclerk import config
    s = config.schema("records")
    if not log_backed:
        return s
    props = {k: ({x: y for x, y in v.items() if x != "maxItems"} if isinstance(v, dict) and v.get("type") == "array" else v)
             for k, v in s["properties"].items()}
    return {**s, "properties": props}


def validate(doc: dict, log_backed: bool = False) -> list[str]:
    """Everything a records document must be before any rule looks at it: the records schema, identifiers in the
    narrow identifier set, and every time with an explicit zone (a naive time is refused, never read as UTC).
    log_backed: the schema without its whole-document caps (records schema())."""
    import json
    from datetime import date, datetime
    import jsonschema
    from keyclerk import guard
    errs = [f"schema: {e.message[:200]} at {'/'.join(map(str, e.path))}"
            for e in jsonschema.Draft202012Validator(schema(log_backed)).iter_errors(
                json.loads(json.dumps(doc, default=str)))][:50]

    def walk(node, path):
        if isinstance(node, dict):
            for k, v in node.items():
                p = f"{path}/{k}"
                if k in TIME_FIELDS and v is not None:
                    if isinstance(v, datetime) and v.tzinfo is None:
                        errs.append(f"{p}: time without a zone")
                    elif isinstance(v, date) and not isinstance(v, datetime) and k not in ("review_by",):
                        errs.append(f"{p}: a date where a time with a zone is needed")
                    elif isinstance(v, str):
                        try:
                            guard.timestamp(v, p)
                        except guard.InputRejected as e:
                            errs.append(str(e))
                elif k in ID_FIELDS and isinstance(v, str) and v not in ("root",):
                    try:
                        (guard.anchor if k in ANCHOR_FIELDS else guard.ident)(v, p)
                    except guard.InputRejected as e:
                        errs.append(str(e))
                elif k == "anchors" and isinstance(v, list):   # list items are anchors too
                    for i, a in enumerate(v):
                        try:
                            guard.anchor(a, f"{p}/{i}")
                        except guard.InputRejected as e:
                            errs.append(str(e))
                walk(v, p)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}/{i}")
    walk(doc, "")
    return errs


def loads(text: str) -> dict:
    """A realm document from the exact text of one file (the bytes a signature was checked over)."""
    from keyclerk import guard
    doc = guard.load_yaml_text(text)
    if not isinstance(doc, dict):
        raise guard.InputRejected("records are not a mapping")
    doc.setdefault("suspensions", [])
    return doc


def loads_part(text: str) -> dict:
    """A part of the records kept in its own file (one visit with its events and badges), read through the same guard."""
    from keyclerk import guard
    doc = guard.load_yaml_text(text)
    if not isinstance(doc, dict):
        raise guard.InputRejected("a records part is not a mapping")
    return doc


def load(path: Path) -> dict:
    """A realm document from a single file or a records directory."""
    path = Path(path)
    if path.is_file():
        doc = _y(path)
        doc.setdefault("suspensions", [])
        return doc
    head = _y(path / "realm.yaml") or {}
    doc = {"realm": head["realm"], "connected_organisations": head.get("connected_organisations", [])}
    if head.get("home") is not None:              # a missing home stays missing (the schema refuses a null one)
        doc["home"] = head["home"]
    for k in HEAD[3:]:
        if head.get(k):
            doc[k] = head[k]
    for kind, key in KINDS.items():
        items = []
        for f in sorted((path / kind).glob("*.yaml")) if (path / kind).is_dir() else []:
            rec = _y(f)
            if _key(kind, rec) != f.stem:
                raise ValueError(f"{f}: file name and {key} differ")
            items.append(rec)
        doc[kind] = items
    if not doc["connected_organisations"]:
        doc.pop("connected_organisations")
    for kind in OPTIONAL:
        if not doc[kind]:
            doc.pop(kind)
    return doc


def split(doc: dict, out: Path) -> None:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    head = {k: doc[k] for k in HEAD if k in doc}
    (out / "realm.yaml").write_text(yaml.dump(head, Dumper=_Plain, sort_keys=False), encoding="utf-8", newline="\n")
    for kind in KINDS:
        for rec in doc.get(kind, []):
            d = out / kind
            d.mkdir(exist_ok=True)
            (d / f"{_key(kind, rec)}.yaml").write_text(yaml.dump(rec, Dumper=_Plain, sort_keys=False, default_flow_style=False),
                                                encoding="utf-8", newline="\n")


def canonical(doc):
    """The same records with every time as one UTC ISO string, so a time written as a YAML timestamp and the same
    time written as text compare equal (the history guard compares meaning, not spelling)."""
    from datetime import date, datetime, timezone
    from keyclerk import guard as G

    def walk(x, key=None):
        if isinstance(x, dict):
            return {k: walk(v, k) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v, key) for v in x]
        if key in TIME_FIELDS and isinstance(x, (str, datetime)) and not (isinstance(x, date) and not isinstance(x, datetime)):
            try:
                return G.timestamp(x).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            except G.InputRejected:
                return x
        return x
    return walk(doc)


KIND_IDS = {"grants": "grant_id", "revocations": "grant_id", "leases": "lease_id", "suspensions": "suspension_id",
             "sod": "sod_id", "groups": "group_id", "delegations": "delegation_id", "memberships": "membership_id",
             "persons": "person", "situations": "situation_id", "surge_packages": "package_id", "surge_grants": "surge_id",
             "places": "place_id", "org_units": "org_id", "zones": "zone_id", "approvers": "approver_id",
             "visits": "visit_id", "visit_events": "event_id", "badges": "badge_id"}


def duplicate_ids(doc: dict) -> list[str]:
    """Every identifier used twice within its kind: one id, one record (two records under one id make every later
    reference to it ambiguous)."""
    errs = []
    for kind, field in KIND_IDS.items():
        seen: set = set()
        for r in doc.get(kind) or []:
            v = r.get(field) if isinstance(r, dict) else None
            if v is None:
                continue
            if v in seen:
                errs.append(f"{v}: used by more than one of the {kind}")
            seen.add(v)
    return errs


def guard(old: dict, new: dict) -> list[str]:
    """Why a new head may not replace the old one: revocations only ever grow and never change, and a revoked grant
    id never returns as a new grant. Times are compared by meaning (canonical)."""
    old, new = canonical(old), canonical(new)
    errs = []
    old_rev = {r["grant_id"]: r for r in old.get("revocations", [])}
    new_rev = {r["grant_id"]: r for r in new.get("revocations", [])}
    for gid, r in old_rev.items():
        if gid not in new_rev:
            errs.append(f"{gid}: revocation dropped")
        elif new_rev[gid] != r:
            errs.append(f"{gid}: revocation changed")
    old_grants = {g["grant_id"]: g for g in old.get("grants", [])}
    for g in new.get("grants", []):
        gid = g["grant_id"]
        if gid in old_rev and gid in old_grants and g != old_grants[gid]:
            errs.append(f"{gid}: a revoked grant was changed")
        if gid in old_rev and gid not in old_grants:
            errs.append(f"{gid}: a revoked grant id was reused")
    errs += _guard_admin(old, new)
    old_s = {s["suspension_id"]: s for s in old.get("suspensions") or []}
    new_s = {s["suspension_id"]: s for s in new.get("suspensions") or []}
    for sid, s in old_s.items():                          # suspensions only grow; the only change is a lift, once
        n = new_s.get(sid)
        if n is None:
            errs.append(f"{sid}: suspension dropped")
        elif {k: v for k, v in n.items() if k != "lifted"} != {k: v for k, v in s.items() if k != "lifted"}:
            errs.append(f"{sid}: suspension changed")
        elif s.get("lifted") and n.get("lifted") != s["lifted"]:
            errs.append(f"{sid}: a lift changed")
    for kind in ("approval_proofs", "proposal_proofs"):
        new_p = {json.dumps(p, sort_keys=True) for p in new.get(kind) or []}
        for p in old.get(kind) or []:                     # proofs only grow
            if json.dumps(p, sort_keys=True) not in new_p:
                errs.append(f"{'an approval' if kind == 'approval_proofs' else 'a proposal'} proof was dropped or changed")
                break
    if isinstance(old.get("revision"), int) and not (isinstance(new.get("revision"), int) and new["revision"] >= old["revision"]):
        errs.append(f"revision {new.get('revision')} after revision {old['revision']}: the serial only grows")
    return errs


def _guard_admin(old: dict, new: dict) -> list[str]:
    """Section 23: administrative revocations only grow and never change; a delegation or membership is never deleted
    (it ends by time or revocation), and once retired or revoked it never changes again."""
    errs = []
    new_ar = {_key("admin_revocations", r): r for r in new.get("admin_revocations", [])}
    for k, r in {_key("admin_revocations", r): r for r in old.get("admin_revocations", [])}.items():
        if k not in new_ar:
            errs.append(f"{k}: administrative revocation dropped")
        elif new_ar[k] != r:
            errs.append(f"{k}: administrative revocation changed")
    for kind, key in (("visits", "visit_id"), ("visit_events", "event_id"), ("badges", "badge_id")):  # a visit, what happened
        now = {r[key]: r for r in new.get(kind, [])}                                # are never deleted or rewritten
        for r in old.get(kind, []):
            if r[key] not in now:
                errs.append(f"{r[key]}: {kind[:-1].replace('_', ' ')} record deleted")
            elif now[r[key]] != r:
                errs.append(f"{r[key]}: {kind[:-1].replace('_', ' ')} record changed")
    ended = {r["id"] for r in old.get("admin_revocations", [])}
    for kind, key in (("delegations", "delegation_id"), ("memberships", "membership_id"), ("approvers", "approver_id")):
        now = {r[key]: r for r in new.get(kind, [])}
        for r in old.get(kind, []):
            if r[key] not in now:
                errs.append(f"{r[key]}: {kind[:-1]} record deleted")
            elif r[key] in ended and now[r[key]] != r:
                errs.append(f"{r[key]}: changed after it was retired or revoked")
    return errs


def main(argv: list[str]) -> int:
    if argv[:1] == ["split"]:
        split(load(Path(argv[1])), Path(argv[2]))
        return 0
    if argv[:1] == ["guard"]:
        errs = guard(load(Path(argv[1])), load(Path(argv[2])))
        for e in errs:
            print(e, file=sys.stderr)
        return 1 if errs else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
