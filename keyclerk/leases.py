# SPDX-License-Identifier: EUPL-1.2
"""External access leases, stage 1: lease records next to the grant records are checked
against the external_access section of the configuration, scheduled into lease groups, and turned into
Keycloak Workflow definitions and an info package.

Keycloak Workflows react to events, groups, attributes and fixed delays; none compares a per-person end date. So the
lease engine keeps the clock: it places each external in /leases/active, /leases/ending-<n>d or nothing, and the
reconciler (tools/grants.py plan) writes those memberships like grant groups. The Workflows only react: a reminder when
a person joins an ending group, a block when they leave /leases/active, a delete after the retention delay.

Usage:
  python -m keyclerk.leases records.yaml ...            check records that hold leases
  python -m keyclerk.leases --workflows                 print the Keycloak Workflow definitions (YAML)
  python -m keyclerk.leases --info LEASE_ID FILE        render the info package of one lease (site-info.yaml beside it)
"""
from __future__ import annotations

import html
import sys
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from keyclerk import config, grants

ACTIVE = "/leases/active"


def ending(days: int) -> str:
    return f"/leases/ending-{days}d"


def rules() -> dict:
    """The external_access section of the current configuration."""
    return config.current()["external_access"]


def _ts(v) -> datetime:
    return grants._ts(v)


def _days(a: datetime, b: datetime) -> float:
    return (b - a).total_seconds() / 86400


def check(doc: dict, xr: dict) -> list[str]:
    """Every violation of the external_access rules for the leases in one record file."""
    errs: list[str] = []
    leases = doc.get("leases", [])
    orgs = {o["issuer"]: o for o in doc.get("connected_organisations", [])}
    by_id = {}
    for ls in leases:
        lid, cat = ls["lease_id"], ls["category"]
        if lid in by_id:
            errs.append(f"{lid}: lease id used twice")
        by_id[lid] = ls
        start, end = _ts(ls["start"]), _ts(ls["end"])
        cap = xr["categories"][cat]["max_days"]
        if _days(start, end) > cap:
            errs.append(f"{lid}: {cat} lease of {_days(start, end):g} days exceeds {cap}")
        bound = [_ts(ls["requested_end"]), start + timedelta(days=cap)]
        if "contract_end" in ls:
            bound.append(_ts(ls["contract_end"]))
        bound += [_ts(p["expiry"]) for p in ls["proofs"] if p.get("binds_lease") and "expiry" in p]
        if end > min(bound):
            errs.append(f"{lid}: lease ends after the earliest of its request, category, contract and proof expiry (expiry_binding)")
        sp = ls["sponsor"]
        if sp["kind"] != "tenant":
            errs.append(f"{lid}: the sponsor is a {sp['kind']} person; a sponsor comes from tenant_people")
        if sp["anchor"] == ls["anchor"]:
            errs.append(f"{lid}: a person sponsors themself")
        if cat != "visitor":
            owner = ls.get("resource_owner")
            if not owner:
                errs.append(f"{lid}: a {cat} lease names a resource owner")
            elif owner == sp["anchor"]:
                errs.append(f"{lid}: the sponsor is also the resource owner")
            elif not {sp["anchor"], owner} <= set(ls["approved_by"]):
                errs.append(f"{lid}: a {cat} lease needs the sponsor and the resource owner as approvers")
            if ls.get("label_ceiling", "Internal") != "Internal":
                if all(p["checker"] == sp["anchor"] for p in ls["proofs"]):
                    errs.append(f"{lid}: for Sensitive and above the proof checker is not the sponsor")
                if not any(a.startswith("officer:") for a in ls["approved_by"]):
                    errs.append(f"{lid}: a Sensitive or Restricted lease needs the tenant's security officer")
        if ls["anchor"] in ls["approved_by"]:
            errs.append(f"{lid}: the external approved their own lease")
        if cat == "partner":
            org = orgs.get(ls.get("issuer", ""))
            if org is None or org.get("refused"):
                errs.append(f"{lid}: a partner comes only from a connected organisation")
        if not ls["proofs"]:
            errs.append(f"{lid}: no proof was checked")
    # grants under a lease end with it and belong to its person; a visitor holds no grant record
    for g in doc.get("grants", []):
        lid = g.get("lease")
        if lid is None:
            if g["subject"]["kind"] == "external":
                errs.append(f"{g['grant_id']}: an external's grant carries its lease")
            continue
        ls = by_id.get(lid)
        if ls is None:
            errs.append(f"{g['grant_id']}: unknown lease {lid}")
            continue
        if g["subject"]["anchor"] != ls["anchor"]:
            errs.append(f"{g['grant_id']}: the grant's person is not the lease's person")
        if _ts(g["end"]) > _ts(ls["end"]):
            errs.append(f"{g['grant_id']}: ends after its lease")
        if ls["category"] == "visitor":
            errs.append(f"{g['grant_id']}: a visitor holds the guest network and a badge only, never a grant record")
    # one lease per person at a time, and totals per identity in the window
    per_person: dict[str, list] = {}
    for ls in leases:
        per_person.setdefault(ls["identity_hash"], []).append(ls)
    tot = xr["totals"]
    for ls_list in per_person.values():
        ls_list.sort(key=lambda x: _ts(x["start"]))
        for a, b in zip(ls_list, ls_list[1:], strict=False):   # each lease with the next
            if _ts(b["start"]) < _ts(a["end"]):
                errs.append(f"{b['lease_id']}: overlaps {a['lease_id']}: one lease per person per tenant at a time")
        for ls in ls_list:
            if ls.get("officer_approved_total"):
                continue
            w0 = _ts(ls["end"]) - timedelta(days=tot["window_days"])
            used = sum(_days(max(_ts(x["start"]), w0), _ts(x["end"])) for x in ls_list
                       if _ts(x["end"]) > w0 and _ts(x["start"]) <= _ts(ls["start"]))
            cap = tot["visitor_max_days"] if ls["category"] == "visitor" else tot["max_days"]
            if used > cap:
                errs.append(f"{ls['lease_id']}: {used:g} lease days in {tot['window_days']} days exceeds {cap} without the security officer")
    return errs


def schedule(doc: dict, xr: dict, at: datetime) -> dict:
    """Lease group memberships at a moment: {group: [anchor]} for the reconciler."""
    reminders = sorted(xr["steps"]["during"]["reminder_days"])
    want: dict[str, list] = {ACTIVE: []}
    for d in reminders:
        want[ending(d)] = []
    for ls in doc.get("leases", []):
        start, end = _ts(ls["start"]), _ts(ls["end"])
        if not (start <= at < end):
            continue
        want[ACTIVE].append(ls["anchor"])
        left = _days(at, end)
        hit = [d for d in reminders if left <= d]
        if hit:
            want[ending(min(hit))].append(ls["anchor"])
    return {k: sorted(v) for k, v in want.items()}


def workflows(xr: dict) -> list[dict]:
    """Keycloak Workflow definitions (26.8 YAML shape): they react to the lease groups the engine maintains."""
    delete_after = xr["steps"]["offboarding"]["retention"]["account_delete_days"]
    out = []
    for d in sorted(xr["steps"]["during"]["reminder_days"], reverse=True):
        out.append({
            "name": f"lease-reminder-{d}d",
            "on": f"user-group-membership-added({ending(d)})",
            "steps": [{"uses": "notify-user", "with": {"message": (
                f"<p>Your access to ${{realm.displayName}} ends in {d} day{'s' if d != 1 else ''}. "
                "Ask your sponsor if you need an extension.</p>")}}],
        })
    out.append({
        "name": "lease-end",
        "on": f"user-group-membership-removed({ACTIVE})",
        "steps": [
            {"uses": "disable-user"},
            {"uses": "delete-user", "after": f"{delete_after}d"},
        ],
    })
    return out


def info_package(ls: dict, site: dict, roles: dict) -> str:
    """Markdown info package for one lease. Contacts come from the role register, never free text; every value
    that a requester could have supplied is escaped."""
    esc = html.escape
    who = {r: roles[r] for r in ("sponsor", "security-desk", "emergency") if r in roles}
    lines = [
        f"# Welcome to {esc(site['name'])}",
        "",
        f"Your access ends on {_ts(ls['end']).strftime('%Y-%m-%d %H:%M')} UTC. Everything ends then: sign-in, network, badge.",
        "",
        "## Who to call",
    ]
    lines += [f"- {k.replace('-', ' ')}: {esc(v)}" for k, v in who.items()]
    lines += ["", "## House rules"] + [f"- {esc(x)}" for x in site.get("rules", [])]
    lines += ["", "## Safety"] + [f"- {esc(x)}" for x in site.get("safety", [])]
    lines += ["", "## Report a security event", f"- {esc(roles.get('security-desk', 'the security desk'))}, at once.",
              "", "## Your personal data",
              "- We keep the facts of the checks we made, never copies of your documents.",
              "- Your account is blocked when your access ends and deleted after the retention period.", ""]
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    xr = rules()
    if argv[:1] == ["--workflows"]:
        print(yaml.safe_dump_all(workflows(xr), sort_keys=False), end="")
        return 0
    if argv[:1] == ["--info"]:
        doc = grants.load(Path(argv[2]))
        site_file = Path(argv[2]).with_name("site-info.yaml")
        site = yaml.safe_load(site_file.read_text(encoding="utf-8"))
        ls = next(x for x in doc["leases"] if x["lease_id"] == argv[1])
        print(info_package(ls, site["site"], site["contacts"]))
        return 0
    bad = 0
    for f in [Path(a) for a in argv if not a.startswith("--")]:
        for e in check(grants.load(f), xr):
            print(f"{f}: {e}", file=sys.stderr)
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
