# SPDX-License-Identifier: EUPL-1.2
"""Grants as code: grant records are checked against the configuration (roles and grant_limits), turned into OPA data
for the local PDP, and reconciled against the broker's grant groups.

The reconciler is the only writer of grant groups: a membership the records do not hold is removed and is a
finding; an ended or revoked grant is removed; attribute groups (from the tenant's IdP) are never touched. Nothing here
reads the broker: the plan is computed from a state the caller supplies, and applying it is a separate, gated step.

Usage:
  python -m keyclerk.grants records.yaml ...                  check records
  python -m keyclerk.grants --opa-data records.yaml           print the OPA data document
  python -m keyclerk.grants --plan records.yaml state.json    print the reconciliation plan for a broker state
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import yaml

from keyclerk import clock, config

GROUP_PREFIX = "/grants/"
MANAGED = (GROUP_PREFIX, "/leases/", "/groups/")   # lease groups (leases.schedule) and delegated groups (delegation) are written by the same reconciler
REVIEW_PERIOD = timedelta(days=92)   # glossary.review_period: the quarterly access review


def _ts(v) -> datetime:
    d = v if isinstance(v, datetime) else datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def rules() -> dict:
    """The roles and grant limits of the current configuration."""
    c = config.current()
    return {"roles": c["roles"], **c["grant_limits"]}


def load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _planes(role: dict) -> list[str]:
    p = role["plane"]
    return p if isinstance(p, list) else [p]


def records_schema(log_backed: bool) -> dict:
    from keyclerk import records
    return records.schema(log_backed)


def check(doc: dict, r: dict, schema: bool = True, log_backed: bool = False) -> list[str]:
    """Every violation of the rule data, as one line each. Empty means the records may be applied. schema False: the
    records are known to meet the schema already (a scoped check validates the records a change touches, 0022 S4)."""
    errs = []
    if schema:
        errs = [f"schema: {e.message} at {'/'.join(map(str, e.path))}"
                for e in jsonschema.Draft202012Validator(records_schema(log_backed)).iter_errors(
                    json.loads(json.dumps(doc, default=str)))]
    if errs:
        return errs
    seen: set[str] = set()
    by_id = {g["grant_id"]: g for g in doc["grants"]}
    for g in doc["grants"]:
        gid, role_name = g["grant_id"], g["role"]
        if gid in seen:
            errs.append(f"{gid}: grant id used twice (ids are never reused)")
        seen.add(gid)
        role = r["roles"].get(role_name)
        if role is None:
            errs.append(f"{gid}: unknown role {role_name}")
            continue
        if role["class"] in ("special", "baseline"):
            errs.append(f"{gid}: {role_name} is {role['class']}: {'appointed at a ceremony' if role['class'] == 'special' else 'from attribute rules'}, never a grant record")
            continue
        if g["plane"] not in _planes(role):
            errs.append(f"{gid}: plane {g['plane']} is not a plane of {role_name}")
        want = "eligibility" if role["class"] == "activation" and g["class"] == "eligibility" else role["class"]
        if g["class"] != want:
            errs.append(f"{gid}: class {g['class']} does not match {role_name} ({role['class']})")
        kind = g["subject"]["kind"]
        if kind not in r["subject_kinds"]:
            errs.append(f"{gid}: subject kind {kind} is not in the configuration's subject_kinds")
        if g["scope"]["level"] not in r["scope_levels"]:
            errs.append(f"{gid}: scope level {g['scope']['level']} is not in the configuration's scope_levels")
        op = r["operator_kind"]
        if g["plane"] == "tenant" and kind == op and role_name not in r["operator_tenant_roles"]:
            errs.append(f"{gid}: an operator person holds a tenant role outside operator_tenant_roles (planes never cross)")
        if g["plane"] in ("infrastructure", "platform") and kind != op and role_name not in r["tenant_infrastructure_roles"]:
            errs.append(f"{gid}: a {kind} person holds an {g['plane']} role (planes never cross)")
        if kind == "external" and g["class"] in ("eligibility", "activation") and g["plane"] != "tenant":
            errs.append(f"{gid}: an external never holds infrastructure or platform privilege")
        start, end = _ts(g["start"]), _ts(g["end"])
        if end <= start:
            errs.append(f"{gid}: end is not after start")
        hours = (end - start).total_seconds() / 3600
        if g["class"] == "activation":
            cap = r["activation_max_hours"].get(role_name)
            if cap is None:
                errs.append(f"{gid}: no activation lifetime for {role_name} in the rule data")
            elif hours > cap:
                errs.append(f"{gid}: activation of {hours:g} h exceeds {cap} h for {role_name}")
            if not _eligible(g, doc["grants"]):
                errs.append(f"{gid}: activation without an eligibility for {role_name} at that scope covering it")
        elif g["class"] == "eligibility":
            if end - start > REVIEW_PERIOD:
                errs.append(f"{gid}: eligibility longer than the review period")
            need = 2 if g["plane"] in ("infrastructure", "platform") else 1
            if len(set(g["approved_by"])) < need and not (r["phase_one"] and g["plane"] != "tenant"):
                errs.append(f"{gid}: eligibility needs {need} distinct approvers")
        elif g["class"] == "functional":
            cap = r["functional_max_hours"].get(role_name)
            if cap is not None and hours > cap:
                errs.append(f"{gid}: functional grant of {hours:g} h exceeds {cap} h for {role_name}")
        people = set(g["approved_by"])
        if g["requested_by"] in people:
            errs.append(f"{gid}: the requester approved their own request")
        if g["subject"]["anchor"] in people:
            errs.append(f"{gid}: the grantee approved their own grant")
        if g["class"] in ("eligibility", "activation") and g["subject"].get("persona", "person") != "admin":
            errs.append(f"{gid}: privileged roles are held on the admin persona")
        if g.get("origin") == "envelope" and g["class"] != "functional" and role_name != "tenant-user":
            errs.append(f"{gid}: an envelope grant is a baseline or functional tenant role only")
    for rv in doc["revocations"]:
        if rv["grant_id"] not in by_id:
            errs.append(f"revocation of unknown grant {rv['grant_id']}")
    return errs


def _eligible(act: dict, grants: list[dict]) -> bool:
    a0, a1 = _ts(act["start"]), _ts(act["end"])
    return any(e["class"] == "eligibility" and e["role"] == act["role"] and e["scope"] == act["scope"]
               and e["subject"]["anchor"] == act["subject"]["anchor"]
               and _ts(e["start"]) <= a0 and a1 <= _ts(e["end"]) for e in grants)


def revoked(doc: dict) -> set[str]:
    return {rv["grant_id"] for rv in doc["revocations"]}


def active(doc: dict, at: datetime) -> list[dict]:
    gone = revoked(doc)
    return [g for g in doc["grants"] if g["grant_id"] not in gone and _ts(g["start"]) <= at < _ts(g["end"])]


def group_of(g: dict) -> str:
    return f"{GROUP_PREFIX}{g['role']}@{g['scope']['level']}:{g['scope']['id']}"


def opa_data(doc: dict) -> dict:
    """data.keyclerk.grants: grants keyed by anchor (never the broker's local sub), plus the revoked ids."""
    by_anchor: dict[str, list] = {}
    for g in doc["grants"]:
        by_anchor.setdefault(g["subject"]["anchor"], []).append({
            "grant_id": g["grant_id"], "role": g["role"], "plane": g["plane"], "class": g["class"], "scope": g["scope"],
            "label_ceiling": g["label_ceiling"], "start": _ts(g["start"]).isoformat(), "end": _ts(g["end"]).isoformat(),
            "persona": g["subject"].get("persona", "person")})
    return {"realm": doc["realm"], "by_anchor": by_anchor, "revoked": sorted(revoked(doc))}


def plan(doc: dict, state: dict, at: datetime, leases: dict | None = None, people: dict | None = None,
         trusts: dict | None = None) -> dict:
    """Reconciliation plan for one realm. state: {group path: [anchor, ...]} for the broker's groups.
    Eligibilities are data only, never a membership; only groups under MANAGED prefixes are touched. leases: the lease
    group memberships of tools/leases.py schedule."""
    from keyclerk.access_state import effective_grants   # skew-safe and suspension-aware
    want: dict[str, set] = {k: set(v) for k, v in (leases or {}).items()}
    if doc.get("situations") and leases:
        from keyclerk.situation import dormant_leases   # a suspended category's leases go dormant, not ended
        asleep = {ls["anchor"] for ls in doc.get("leases", []) if ls["lease_id"] in dormant_leases(doc, at)}
        want = {k: (v - asleep if k == "/leases/active" else v) for k, v in want.items()}
    if doc.get("groups"):
        from keyclerk.delegation import carrier_groups   # flattened, never nested in Keycloak
        want.update(carrier_groups(doc, at, people, trusts))
    for g in effective_grants(doc, at):
        if g["class"] in ("functional", "activation"):
            want.setdefault(group_of(g), set()).add(g["subject"]["anchor"])
    known = {(group_of(g), g["subject"]["anchor"]) for g in doc["grants"]}
    known |= {(grp, ls["anchor"]) for ls in doc.get("leases", []) for grp in (leases or {})}
    known |= {("/groups/" + m["group"], m["member"]["anchor"]) for m in doc.get("memberships", []) if "anchor" in m["member"]}
    add, remove = [], []
    for grp, members in sorted(want.items()):
        for a in sorted(members - set(state.get(grp, []))):
            add.append({"group": grp, "anchor": a})
    for grp, members in sorted(state.items()):
        if not grp.startswith(MANAGED):
            continue   # attribute groups belong to the tenant's IdP (group_roles.attribute_groups)
        for a in sorted(set(members) - want.get(grp, set())):
            why = "ended-or-revoked" if (grp, a) in known else "undeclared"
            remove.append({"group": grp, "anchor": a, "why": why, "finding": why == "undeclared"})
    return {"realm": doc["realm"], "at": at.isoformat(), "add": add, "remove": remove,
            "findings": [x for x in remove if x["finding"]]}


def main(argv: list[str]) -> int:
    r = rules()
    if argv[:1] == ["--opa-data"]:
        print(json.dumps(opa_data(load(Path(argv[1]))), indent=1))
        return 0
    if argv[:1] == ["--plan"]:
        state = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
        print(json.dumps(plan(load(Path(argv[1])), state, clock.now()), indent=1))
        return 0
    files = [Path(a) for a in argv if not a.startswith("--")]
    bad = 0
    for f in files:
        for e in check(load(f), r):
            print(f"{f}: {e}", file=sys.stderr)
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
