# SPDX-License-Identifier: EUPL-1.2
"""What an edge may hold, derived from the records alone (decision 0021): its leases, visit leases and revoked visit
leases at a moment, inside the ceiling its officer signed.

Pure: no desk state, no key. The desk builds a bundle with it; the checking signer derives the same from its own replica
before it seals one, so a taken-over desk cannot put a lease in a bundle that the records do not hold.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from keyclerk import delegation as D


def leases(doc: dict, e: dict, now: datetime, horizons: dict, first_seen: dict | None = None) -> list[dict]:
    """Leases for an edge's targets, with ids that stay the same while the grant stays, and a "from"
    that stays too (the desk's clock at bundle time made a lease not yet live on an edge a few seconds
    behind): the earliest start of its direct memberships, or for a derived lease the first time it was issued."""
    from keyclerk import edge as E
    out = []
    seen = first_seen if first_seen is not None else {}
    groups = D._groups(doc)
    for t in e["targets"]:
        for g in groups.values():
            if not any(c.get("entitlement") == t["entitlement"] for c in g.get("carries", [])):
                continue
            cls = D.effective_risk(doc, g["group_id"])
            for a in sorted(D.effective_members(doc, g["group_id"], now)):
                direct = [m for m in doc.get("memberships", []) if m["group"] == g["group_id"]
                          and D.same(doc, (m["member"] or {}).get("anchor"), a) and D.membership_status(doc, m, now) == "active"]
                end = min([D._ts(m["end"]) for m in direct], default=now + timedelta(hours=int(horizons.get(cls, 1))))
                source = ",".join(sorted(m["membership_id"] for m in direct)) or "derived"
                lid = "L-" + E.sha256(f"{e['edge_id']}|{t['target']}|{a}|{g['group_id']}|{source}".encode())[:16]
                start = min([D._ts(m["start"]) for m in direct], default=None)
                frm = E._iso(start) if start else seen.setdefault(lid, E._iso(now))
                out.append({"lease_id": lid, "person": a, "target": t["target"], "role": t["role"], "class": cls,
                            "roles": [g["group_id"]], "from": frm, "until": E._iso(end),
                            "target_session_hours": t.get("max_session_hours")})
    return out


def _since(doc: dict, gid: str, person: str, now: datetime, seen: frozenset = frozenset()) -> datetime | None:
    """Since when the records make this person a member of this group: the earliest start of a direct membership, or
    through an included group the later of the inclusion's start and the person's start there (0.29 review X4). The
    same on every edge, from the records alone; None only for access by rules, which carry no start."""
    best = None
    for m in doc.get("memberships", []):
        if m["group"] != gid or D.membership_status(doc, m, now) != "active":
            continue
        member = m.get("member") or {}
        if member.get("anchor") and D.same(doc, member["anchor"], person):
            t = D._ts(m["start"])
        elif member.get("group") and member["group"] not in seen | {gid}:
            inner = _since(doc, member["group"], person, now, seen | {gid})
            t = max(D._ts(m["start"]), inner) if inner else None
        else:
            continue
        if t is not None and (best is None or t < best):
            best = t
    return best


def _holdings(doc: dict, e: dict, now: datetime, horizons: dict) -> list[tuple]:
    """(person, lease id, from, until, stable start or None) for everything an edge would carry now, before its
    ceiling: the derived leases and the live visit leases."""
    out = []
    for lease in leases(doc, e, now, horizons):
        starts = [t for g in lease["roles"] if (t := _since(doc, g, lease["person"], now)) is not None]
        out.append((lease["person"], lease["lease_id"], D._ts(lease["from"]), D._ts(lease["until"]),
                    min(starts) if starts else None))
    for v in doc.get("edge_visit_leases", []):
        if v["edge"] == e["edge_id"] and not D._revs(doc, v["lease_id"], now) and D._ts(v["until"]) > now:
            out.append((v["person"], v["lease_id"], D._ts(v["from"]), D._ts(v["until"]), D._ts(v["from"])))
    return out


def excluded(doc: dict, e: dict, now: datetime, horizons: dict) -> dict[str, str]:
    """Lease ids this edge must not carry because the same person holds an overlapping entry on another edge of a live
    exclusion: of two, the one with the earlier stable start stays, then the edge listed first, then the lower id. Each
    edge computes the same answer from the same records, so exactly one of them carries it."""
    out = {}
    edges = {x["edge_id"]: x for x in doc.get("edges", [])}
    for x in doc.get("edge_exclusions", []):
        if e["edge_id"] not in x["edges"] or D._revs(doc, x["exclusion_id"], now):
            continue
        rank = {eid: i for i, eid in enumerate(x["edges"])}
        far = datetime.max.replace(tzinfo=now.tzinfo)
        hold = {eid: _holdings(doc, edges[eid], now, horizons) for eid in x["edges"] if eid in edges}
        for p, lid, t0, t1, st in hold.get(e["edge_id"], []):
            key = (st or far, rank[e["edge_id"]], lid)
            for other, rows in hold.items():
                if other == e["edge_id"]:
                    continue
                for q, olid, o0, o1, ost in rows:
                    if D.same(doc, p, q) and t0 < o1 and o0 < t1 and (ost or far, rank[other], olid) < key:
                        out[lid] = f"cross-edge exclusion {x['exclusion_id']}: the person holds {other} at the same time"
    return out


def entries(doc: dict, e: dict, now: datetime, settings: dict, ceiling: dict | None, attested: str | None,
            names: dict, first_seen: dict | None = None) -> dict:
    """Everything a bundle carries for one edge besides its policy: {"leases", "visits", "revoked", "dropped"}.
    Without a ceiling an edge gets no leases and no visit leases: it fails closed. names: anchor -> bastion username."""
    from keyclerk import edge as E
    from keyclerk import policy_wasm
    horizons = settings["horizons"]
    out, visits, dropped = [], [], []
    keys = [k for k in doc.get("person_keys", []) if not D._revs(doc, k["key_id"], now)]
    caps = settings.get("session_max_hours", {})

    def who_fields(anchor):                    # what the agent needs to act for this person (0014b)
        k = next((k for k in keys if D.same(doc, k["anchor"], anchor)), None)
        return {"username": names.get(anchor), "key_id": k["key_id"] if k else None,
                "public_key": k["public_key"] if k else None}
    if ceiling:
        for lease in leases(doc, e, now, horizons, first_seen):
            hours = E.ceiling_hours(now, D._ts(lease["until"]))
            d = policy_wasm.ceiling({"ceiling": ceiling, "entry": {"kind": "lease", "person": lease["person"], "roles": lease["roles"],
                                                                   "targets": [lease["target"]], "class": lease["class"], "hours": hours}})
            if d["allow"]:
                cap = int(caps.get(lease["class"], 1))
                if lease.pop("target_session_hours", None):
                    cap = min(cap, int(next(t["max_session_hours"] for t in e["targets"] if t["target"] == lease["target"])))
                out.append({**lease, **who_fields(lease["person"]), "email": None,   # fetched by request, 1.3
                            "max_session_hours": cap})
            else:
                lease.pop("target_session_hours", None)
                dropped.append({"lease_id": lease["lease_id"], "why": sorted(d["refusals"])})
        for v in doc.get("edge_visit_leases", []):
            if v["edge"] != e["edge_id"] or D._revs(doc, v["lease_id"], now) or D._ts(v["until"]) <= now:
                continue
            if not any(D.same(doc, k["anchor"], v["person"]) and k.get("ssh_key") == v["ssh_key"] for k in keys):
                dropped.append({"lease_id": v["lease_id"], "why": ["the person's hardware key was ended"]})
                continue                       # a lost hardware key ends its visit leases
            hours = E.ceiling_hours(D._ts(v["from"]), D._ts(v["until"]))
            d = policy_wasm.ceiling({"ceiling": ceiling, "entry": {"kind": "visit", "person": v["person"], "targets": v["targets"],
                                                                   "hours": hours, "attested_profile": attested}})
            if d["allow"]:
                role = next((t["role"] for t in e["targets"] if t["target"] in v["targets"]), None)
                visits.append({"lease_id": v["lease_id"], "person": v["person"], "ssh_key": v["ssh_key"], "role": role,
                               **who_fields(v["person"]),
                               "targets": v["targets"], "from": E._iso(D._ts(v["from"])), "until": E._iso(D._ts(v["until"]))})
            else:
                dropped.append({"lease_id": v["lease_id"], "why": sorted(d["refusals"])})
    if doc.get("edge_exclusions"):                 # 0.29: one person, one edge of an exclusion at a time
        gone = excluded(doc, e, now, horizons)
        for kept in (out, visits):
            for x in [x for x in kept if x["lease_id"] in gone]:
                kept.remove(x)
                dropped.append({"lease_id": x["lease_id"], "why": [gone[x["lease_id"]]]})
    revoked = sorted({v["lease_id"] for v in doc.get("edge_visit_leases", []) if v["edge"] == e["edge_id"]
                      and D._revs(doc, v["lease_id"], now) and D._ts(v["until"]) > now})
    for lease in [x for x in out if x["class"] not in horizons]:    # no horizon, never live
        out.remove(lease)
        dropped.append({"lease_id": lease["lease_id"], "why": [f"class {lease['class']} has no horizon in edge.rego"]})
    return {"leases": out, "visits": visits, "revoked": revoked, "dropped": dropped}
