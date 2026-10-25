# SPDX-License-Identifier: EUPL-1.2
"""One person's graph at a moment: how their accounts, groups, delegations, places and the people around them connect
(decision 0009, D7). Back and forward in time: `at` may be any past or future instant, and `marks` are the moments
around it where something in the graph starts or ends, so a view can step to the previous or next change.

Code gathers; keyclerk/policy/view.rego decides what the viewer may see (need to know), compiled in like every rule.
Nodes and edges carry contexts (the group, delegation or place they belong to) for that decision.

Node kinds: subject (the person), account (one anchor, by identity source), person (someone connected), group,
scope (a top-level part of the group tree, drawn as a box), place.
Edge kinds: account (subject to account), member, manages, delegated, approved, steward, deputy, front_office, host,
lease, approver (a named approver appointment), within (place in place).
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta

from keyclerk import config
from keyclerk import delegation as D
from keyclerk.grants import _ts

SOURCES = config.Section()


def source_of(anchor: str) -> dict:
    """The identity source an anchor comes from, by its prefix (configuration identity_sources); unknown otherwise."""
    for s in SOURCES.get("identity_sources", None) or []:
        if ("prefix" in s and anchor.startswith(s["prefix"])) or ("pattern" in s and re.fullmatch(s["pattern"], anchor)):
            sid = s.get("id") or s.get("prefix", s["name"]).rstrip(":").lower().replace(" ", "-")
            return {"id": sid, "name": s["name"], "kind": s.get("kind", "oidc")}
    head = anchor.split(":", 1)[0] if ":" in anchor else "unknown"
    return {"id": head, "name": head, "kind": "unknown"}


def _iso(t) -> str | None:
    return _ts(t).isoformat().replace("+00:00", "Z") if t is not None else None


def _person_rec(doc: dict, anchor: str) -> dict | None:
    return next((p for p in doc.get("persons", []) if anchor in p["anchors"]), None)


def _scope_of(doc: dict, gid: str) -> str | None:
    """The top-level part of the tree a group sits in (the child of the top group), drawn as a box."""
    anc = D.ancestors(doc, gid)
    return anc[-2] if len(anc) >= 2 else None


def build(doc: dict, anchor: str, at: datetime) -> dict:
    """{subject, nodes, edges, marks, facts}: facts feed the view policy; nothing is filtered here."""
    p = _person_rec(doc, anchor)
    anchors = p["anchors"] if p else [anchor]
    me = anchors[0]
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    times: set[str] = set()

    def node(nid: str, kind: str, label: str, contexts: list | None = None, **data) -> str:
        n = nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label, "contexts": [], **data})
        for c in contexts or []:
            if c not in n["contexts"]:
                n["contexts"].append(c)
        return nid

    def other(a: str, contexts: list) -> str:
        if D.same(doc, a, me):
            return "subject"
        q = _person_rec(doc, a)
        return node("person:" + (q["person"] if q else a), "person", q["person"] if q else a, contexts,
                    anchor=a, person_kind=(q or {}).get("kind"))

    def edge(kind: str, src: str, dst: str, contexts: list, label: str = "", start=None, end=None, status=None, **data):
        for t in (start, end):
            if t is not None:
                times.add(_iso(t))
        edges.append({"id": f"e{len(edges)}", "kind": kind, "source": src, "target": dst, "label": label,
                      "from": _iso(start), "to": _iso(end), "status": status, "contexts": contexts, **data})

    root, officer = D.root_at(doc, at), (doc.get("root") or {}).get("officer")
    roles = [r for r, yes in (("root", any(D.same(doc, a, root) for a in anchors)),
                              ("security officer", any(D.same(doc, a, officer) for a in anchors)),
                              ("named approver", any(D.named_approver(doc, a, at) for a in anchors))) if yes]
    node("subject", "subject", p["person"] if p else anchor, [], anchor=me, person_kind=(p or {}).get("kind", "unknown"),
         unit=(p or {}).get("unit"), roles=roles, last_seen=None)
    for a in anchors:
        src = source_of(a)
        node("account:" + a, "account", a, [], source=src, purpose=D.purpose_of(doc, a))
        edge("account", "subject", "account:" + a, [], src["name"])

    def group_node(gid: str) -> str:
        g = D._groups(doc).get(gid, {})
        sc = _scope_of(doc, gid)
        if sc and sc != gid:
            node("scope:" + sc, "scope", sc, [{"group": sc}])
        return node("group:" + gid, "group", gid, [{"group": gid}], parent=("scope:" + sc) if sc and sc != gid else None,
                    risk=D.effective_risk(doc, gid), place=g.get("place"))

    # memberships: every group the person is in at `at`, and the records that put or will put them there
    groups = []
    for gid in sorted(D._groups(doc)):
        ctx = [{"group": gid}]
        held = any(a in D.effective_members(doc, gid, at) for a in anchors)
        recs = [m for m in doc.get("memberships", []) if m["group"] == gid and (m["member"].get("anchor") in anchors)]
        for m in recs:
            times.update({_iso(m["start"]), _iso(m["end"])})
        if not held and not any(_ts(m["start"]) > at for m in recs):
            continue
        groups.append(gid)
        paths = [x for a in anchors for x in D.explain(doc, a, gid, at)]
        direct = [m for m in recs if _ts(m["start"]) <= at < _ts(m["end"])]
        upcoming = [m for m in recs if _ts(m["start"]) > at]
        m = (direct or upcoming or [None])[0]
        edge("member", "subject", group_node(gid), ctx, "member" if held else "from " + _iso(m["start"])[:10],
             m["start"] if m else None, m["end"] if m else None, ("active" if held else "pending"),
             via=[" > ".join(x) for x in paths][:5], record=m["membership_id"] if m else None)
        for a in (m or {}).get("approved_by", []):
            edge("approved", other(a, ctx), "group:" + gid, ctx, "approved", m["start"], m["end"])
        if m:
            edge("added", other(m["by"], ctx), "group:" + gid, ctx, "added", m["start"], m["end"])

    # delegations held and made
    dels = []
    for d in doc.get("delegations", []):
        did, gid = d["delegation_id"], d["group"]
        st = D.chain_status(doc, did, at)[0]
        ended = st == "dead" or at >= _ts(d["end"])
        times.update({_iso(d["start"]), _iso(d["end"])})
        ctx = [{"delegation": did}, {"group": gid}]
        if any(D.same(doc, a, d["delegate"]) for a in anchors) and not (ended and at > _ts(d["end"])):
            dels.append(did)
            edge("manages", "subject", group_node(gid), ctx, ", ".join(d["powers"]), d["start"], d["end"],
                 "pending" if at < _ts(d["start"]) else st, record=did, depth_left=d["depth_left"], max_risk=d["max_risk"])
            edge("delegated", other(d["by"], ctx), "subject", ctx, "delegated " + gid, d["start"], d["end"], st, record=did)
        elif any(D.same(doc, a, d["by"]) for a in anchors) and not ended:
            dels.append(did)
            edge("delegated", "subject", other(d["delegate"], ctx), ctx, "delegated " + gid, d["start"], d["end"], st,
                 record=did)

    # named approver appointments
    for ap in doc.get("approvers", []):
        if any(D.same(doc, a, ap["anchor"]) for a in anchors):
            times.update({_iso(ap["from"]), _iso(ap["to"])})
            ok = D.named_approver(doc, ap["anchor"], at)
            edge("approver", other(ap["appointed_by"], []), "subject", [], "appointed approver", ap["from"], ap["to"],
                 "active" if ok else ("pending" if at < _ts(ap["from"]) else "ended"), record=ap["approver_id"])

    # workloads and agents (decision 0011): who owns them, who directs an agent; and whom this person owns or directs
    if p:
        if p.get("owner"):
            edge("owns", other(p["owner"], []), "subject", [], "owns")
        if p.get("director"):
            edge("directs", other(p["director"], []), "subject", [], "directs")
    for q in doc.get("persons", []):
        if q is p:
            continue
        for rel in ("owner", "director"):
            if q.get(rel) and any(D.same(doc, a, q[rel]) for a in anchors):
                edge("owns" if rel == "owner" else "directs", "subject", other(q["anchors"][0], []), [],
                     "owns" if rel == "owner" else "directs")

    # places: roles, and leases (a lease names hosts; a place lists the hosts it holds)
    places = []
    by_host = {h: pl["place_id"] for pl in doc.get("places", []) for h in pl.get("hosts") or []}

    def place_node(pid: str) -> str:
        pl = next((x for x in doc.get("places", []) if x["place_id"] == pid), {})
        par = pl.get("within")
        if par:
            place_node(par)
        return node("place:" + pid, "place", pl.get("name") or pid, [{"place": pid}],
                    parent=None, place_kind=pl.get("kind"), within=("place:" + par) if par else None)

    for pl in doc.get("places", []):
        pid = pl["place_id"]
        for role in ("steward", "deputy"):
            if pl.get(role) and any(D.same(doc, a, pl[role]) for a in anchors):
                places.append(pid)
                edge(role, "subject", place_node(pid), [{"place": pid}], role, pl.get("valid_from"), pl.get("valid_until"))
        for a in pl.get("front_office") or []:
            if any(D.same(doc, x, a) for x in anchors):
                places.append(pid)
                edge("front_office", "subject", place_node(pid), [{"place": pid}], "front office")
    for ls in doc.get("leases", []):
        if not any(D.same(doc, a, ls["anchor"]) for a in anchors):
            continue
        times.update({_iso(ls["start"]), _iso(ls["end"])})
        st = "pending" if at < _ts(ls["start"]) else ("active" if at < _ts(ls["end"]) else "ended")
        for host in ls.get("sites", []):
            pid = by_host.get(host)
            if pid:
                places.append(pid)
                edge("lease", "subject", place_node(pid), [{"place": pid}], ls.get("category", "lease"), ls["start"],
                     ls["end"], st, record=ls["lease_id"])
        sp = (ls.get("sponsor") or {}).get("anchor")
        if sp:
            edge("sponsor", other(sp, [{"place": by_host.get(h)} for h in ls.get("sites", []) if by_host.get(h)]),
                 "subject", [{"place": by_host.get(h)} for h in ls.get("sites", []) if by_host.get(h)], "sponsors",
                 ls["start"], ls["end"], st, record=ls["lease_id"])
    for pid in list(nodes):
        n = nodes[pid]
        if n["kind"] == "place" and n.get("within") in nodes:
            edges.append({"id": f"e{len(edges)}", "kind": "within", "source": pid, "target": n["within"], "label": "in",
                          "from": None, "to": None, "status": None, "contexts": n["contexts"]})

    stamp = _iso(at)
    marks = sorted(t for t in times if t)
    return {"subject": anchor, "at": stamp, "nodes": list(nodes.values()), "edges": edges,
            "marks": {"before": [t for t in marks if t < stamp][-20:], "after": [t for t in marks if t > stamp][:20]},
            "facts": {"groups": groups, "delegations": dels, "places": sorted(set(places))}}


def realm_sources(doc: dict) -> list[dict]:
    """Which identity sources the realm's people come through, with counts (persons, accounts)."""
    out: dict[str, dict] = {}
    for p in doc.get("persons", []):
        seen = set()
        for a in p["anchors"]:
            s = source_of(a)
            row = out.setdefault(s["id"], {**s, "persons": 0, "accounts": 0})
            row["accounts"] += 1
            if s["id"] not in seen:
                row["persons"] += 1
                seen.add(s["id"])
    return sorted(out.values(), key=lambda r: -r["accounts"])


RECENT_DAYS = 30          # an ended delegation stays in the tree this long after it stopped, drawn as ended


def _tree_status(doc: dict, d: dict, at: datetime) -> tuple[str, str | None]:
    """pending, active, grace (until), ended (its own end or retirement), revoked, or dead (a link above it broke)."""
    did = d["delegation_id"]
    if at < _ts(d["start"]):
        return "pending", None
    own = D._revs(doc, did, at)
    if any(r["mode"] == "revoke" for r in own):
        return "revoked", None
    st, until = D.chain_status(doc, did, at)
    if st == "ok":
        return "active", None
    if st == "grace":
        return "grace", _iso(until)
    stop = min([_ts(d["end"])] + [_ts(r["at"]) for r in own])
    return ("ended" if at >= stop else "dead"), None


def delegation_tree(doc: dict, at: datetime) -> dict:
    """The whole delegation tree at a moment (decision 0009, section 8: what was handed on, to whom, how deep, until
    when): {at, nodes, edges, marks}. Each node carries its chain up to the root for keyclerk/policy/tree.rego, which
    decides what the viewer may see; nothing is filtered here except delegations that stopped long before `at`."""
    name = lambda a: (_person_rec(doc, a) or {}).get("person") or a          # noqa: E731
    root = D.root_at(doc, at)
    nodes = [{"id": "root", "kind": "root", "label": name(root) if root else "no root holder", "anchor": root,
              "chain": ["root"], "parent": None, "status": "active" if root else "dead"}]
    edges, times = [], set()
    used = Counter(m["under"] for m in doc.get("memberships", []) if m.get("under")
                   and _ts(m["start"]) <= at < _ts(m["end"]))
    for d in doc.get("delegations", []):
        did = d["delegation_id"]
        revs = D._revs(doc, did, datetime.max.replace(tzinfo=at.tzinfo))
        grace = timedelta(days=D.R["retire_grace_days"])
        times.update({_iso(d["start"]), _iso(d["end"]), _iso(_ts(d["end"]) + grace)} | {_iso(r["at"]) for r in revs}
                     | {_iso(_ts(r["at"]) + grace) for r in revs if r["mode"] == "retire"})
        stop = min([_ts(d["end"])] + [_ts(r["at"]) for r in revs if _ts(r["at"]) <= at])
        if stop < at - timedelta(days=RECENT_DAYS):
            continue
        status, until = _tree_status(doc, d, at)
        chain = [x["delegation_id"] for x in D.chain(doc, did)] + ["root"]
        nodes.append({"id": did, "kind": "delegation", "label": name(d["delegate"]), "anchor": d["delegate"],
                      "by": name(d["by"]), "group": d["group"], "powers": d["powers"], "max_risk": d["max_risk"],
                      "max_membership_days": d.get("max_membership_days"), "depth": len(chain) - 1,
                      "depth_left": d["depth_left"], "from": _iso(d["start"]), "to": _iso(d["end"]), "status": status,
                      "grace_until": until, "in_use": used.get(did, 0), "chain": chain, "parent": d["parent"]})
    ids = {n["id"] for n in nodes}
    for n in nodes[1:]:
        if n["parent"] in ids:
            edges.append({"id": "t:" + n["id"], "source": n["parent"], "target": n["id"], "status": n["status"]})
    stamp = _iso(at)
    marks = sorted(t for t in times if t)
    return {"at": stamp, "nodes": nodes, "edges": edges,
            "marks": {"before": [t for t in marks if t < stamp][-20:], "after": [t for t in marks if t > stamp][:20]}}
