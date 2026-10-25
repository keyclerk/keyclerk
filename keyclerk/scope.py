"""What a change reaches (decision 0022 S4): the subjects whose engine errors a change can alter.

An engine error belongs to one subject: a record (by its id), or a relation (an anchor's separation of duty, a rate
bucket, the group tree, an unknown id an administrative revocation names). subject_of(error, doc) says which.
reach(old, new, ops) is computed by the engine from the ops, never by the caller: every touched record in its old and
its new version, followed through what judging a subject reads. It answers a set of subjects (a subject ending in ":*"
covers its whole family), or Full(reason) when a change reaches everyone or the reach cannot be computed; a full
check then runs. Soundness, the property tests/test_scope.py holds on generated organisations and random changes:
every subject whose errors differ between the old and the new state, judged at one moment, is inside the reach.

Reach is deliberately coarse where precision would be fragile; the background full check (decision 0022 S4)
compares, and a subject found outside the reach freezes signing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from keyclerk import records as R

FULL_KINDS = {"places": "places", "zones": "places", "org_units": "places", "situations": "situations",
              "surge_packages": "situations", "surge_grants": "situations", "sod": "sod", "catalogue": "catalogue",
              "head": "head"}
REASONS = ("head", "places", "situations", "sod", "catalogue", "group_tree", "schema", "root", "bound", "unknown",
           "forced", "config")   # the metric's reason label values (keyclerk.metrics.VALUES)
EDGE_KINDS = ("edges", "person_keys", "edge_rotations", "edge_visit_leases")
VISIT_KINDS = ("visits", "visit_events", "badges")


class Wide(Exception):
    """The working set cannot serve a reach within its bounds: the change is judged in full (reason "bound")."""


@dataclass(frozen=True)
class Full:
    """A change the scoped check does not judge: the full check runs. reason is one of REASONS (a bounded metric label)."""
    reason: str


# --- errors to subjects ---------------------------------------------------------------------------------------------

_SOD = re.compile(r"SoD [^:]+: (\S+) through ")
_RATE = re.compile(r"(.+): \d+ widenings on (\S+), above ")
_SUBTREE = re.compile(r"subtree of (.+): \d+ widenings on (\S+), above ")
_UNKNOWN_REV = re.compile(r"admin revocation of unknown id (.+)$")
_UNKNOWN_GRANT = re.compile(r"revocation of unknown grant (.+)$")
_PATH = re.compile(r"(?:schema: .* at |^/?)([a-z_]+)/(\d+)(?:/|:|$)")
TREE = ("groups without a root trust owner", "the tree needs exactly one top group")
PLACES = ("a place id appears twice", "host ")


def subject_of(error: str, doc: dict) -> str:
    """The subject an error belongs to: a record id, or sod:<anchor>, rate:<person>:<day>, subtree:<top>:<day>,
    adminrev:<id>, tree, places; a schema or field error by the record its path names."""
    e = error.removesuffix(" (now)")
    if m := _SOD.match(e):
        return f"sod:{m.group(1)}"
    if m := _SUBTREE.match(e):
        return f"subtree:{m.group(1)}:{m.group(2)}"
    if m := _RATE.match(e):
        return f"rate:{m.group(1)}:{m.group(2)}"
    if m := _UNKNOWN_REV.match(e):
        return f"adminrev:{m.group(1)}"
    if m := _UNKNOWN_GRANT.match(e):
        return m.group(1)                       # the grant id the revocation names
    if e.startswith(TREE):
        return "tree"
    if e.startswith(PLACES):
        return "places"
    if e.startswith("schema: ") or e.startswith("/"):
        m = _PATH.search(e)
        if m and m.group(1) in doc and isinstance(doc[m.group(1)], list) and int(m.group(2)) < len(doc[m.group(1)]):
            return _id_of(m.group(1), doc[m.group(1)][int(m.group(2))])
        return "schema"
    head = e.split(": ", 1)[0]
    return head.split("/", 1)[0]


def _id_of(kind: str, rec) -> str:
    if not isinstance(rec, dict):
        return "schema"
    if kind == "admin_revocations":
        return f"adminrev-record:{rec.get('id')}.{rec.get('mode')}"
    field = R.KINDS.get(kind) or R.KIND_IDS.get(kind)
    return str(rec.get(field)) if field and rec.get(field) is not None else "schema"


def covered(subject: str, reach: set[str]) -> bool:
    if subject in reach:
        return True
    parts = subject.split(":")
    return any(":".join(parts[:i]) + ":*" in reach for i in range(1, len(parts)))


# --- what reach reads, behind one index -------------------------------------------------------------------------------

SMALL_KINDS = ("groups", "catalogue", "sod", "delegations", "admin_revocations", "approvers", "places", "zones",
               "org_units", "situations", "surge_packages", "surge_grants", "suspensions", "edges", "person_keys",
               "edge_rotations", "edge_visit_leases", "visits", "visit_events", "badges")


def norm(v):
    """A value as the store holds it: times as UTC text, dates as ISO text (YAML parses them into objects)."""
    from datetime import date, datetime
    if isinstance(v, datetime):
        from keyclerk import edge as E
        return E._iso(v)
    if isinstance(v, date):
        return v.isoformat()
    return v


class Ix:
    """What reach reads of one state, the old or the new: the small kinds whole, the large ones (persons,
    memberships, grants, revocations, leases) by the fields the store indexes (store.refs_of). DocIx answers from a
    document by scanning; keyclerk.store.working.StoreIx from a store by its refs index; the two agree by
    construction, and tests/test_working.py holds it."""

    def __init__(self):
        from keyclerk import delegation as D
        self.D = D
        self.groups = {g["group_id"]: g for g in self.small("groups")}
        self.dels = {d["delegation_id"]: d for d in self.small("delegations")}
        self._people: dict[str, tuple[str, set[str]]] = {}

    # to implement: small(kind), head(field), where(kind, field, values), get(kind, key), records_order_key

    def small(self, kind: str) -> list[dict]:
        raise NotImplementedError

    def head(self, field: str):
        raise NotImplementedError

    def where(self, kind: str, field: str, values) -> list[dict]:
        raise NotImplementedError

    def get(self, kind: str, key: str):
        raise NotImplementedError

    def mems(self, field: str, values) -> list[dict]:
        return self.where("memberships", field, values)

    def mems_both(self, f1: str, v1, f2: str, v2) -> list[dict]:
        """The memberships whose f1 holds one of v1 and whose f2 holds one of v2."""
        from keyclerk.store import refs_of
        want = {(f2, norm(v)) for v in v2}
        return [m for m in self.mems(f1, v1) if set(refs_of("memberships", {k: norm(v) for k, v in m.items()})) & want]

    def includes(self) -> list[dict]:
        return self.mems("member.group", list(self.groups))

    def rule_mems(self) -> list[dict]:
        return self.mems("member.rule", ["yes"])

    def ids(self, kind: str) -> set[str]:
        field = R.KINDS.get(kind)
        return {str(r.get(field)) for r in self.small(kind) if field}

    def _person_of(self, a) -> tuple[str, set[str]]:
        """(the person an anchor belongs to, all their anchors): the first person listing it, in key order."""
        if a not in self._people:
            ps = sorted(self.where("persons", "anchors", [a]), key=lambda p: p["person"]) if isinstance(a, str) else []
            self._people[a] = (ps[0]["person"], set(ps[0].get("anchors", []))) if ps else (a, set())
        return self._people[a]

    def person(self, a):
        return self._person_of(a)[0]

    def anchors_of(self, a) -> set[str]:
        """Every anchor of the person an anchor belongs to (the anchor itself when no person lists it)."""
        return set(self._person_of(a)[1]) | {a}

    def descendants(self, did: str) -> set[str]:
        out, todo = set(), [did]
        while todo:
            x = todo.pop()
            for d in self.dels.values():
                if d["parent"] == x and d["delegation_id"] not in out:
                    out.add(d["delegation_id"])
                    todo.append(d["delegation_id"])
        return out

    def ancestors(self, did: str) -> set[str]:
        out, x = set(), self.dels.get(did, {}).get("parent")
        while x in self.dels and x not in out:
            out.add(x)
            x = self.dels[x]["parent"]
        return out

    def top(self, did: str) -> str:
        if did == "root" or did not in self.dels:
            return did
        x, seen = did, set()
        while self.dels.get(x, {}).get("parent", "root") != "root" and x not in seen:
            seen.add(x)
            x = self.dels[x]["parent"]
        return x

    def include_edges(self) -> list[tuple[str, str]]:
        if not hasattr(self, "_edges"):
            self._edges = [(m["group"], m["member"]["group"]) for m in self.includes()]
        return self._edges

    def up(self, gids: set[str]) -> set[str]:
        """The groups and every group that includes one of them, transitively (their effective members follow)."""
        edges, out, todo = self.include_edges(), set(gids), list(gids)
        while todo:
            x = todo.pop()
            for a, b in edges:
                if b == x and a not in out:
                    out.add(a)
                    todo.append(a)
        return out

    def down(self, gids: set[str]) -> set[str]:
        """The groups and every group one of them includes, transitively (their effective risk follows)."""
        edges, out, todo = self.include_edges(), set(gids), list(gids)
        while todo:
            x = todo.pop()
            for a, b in edges:
                if a == x and b not in out:
                    out.add(b)
                    todo.append(b)
        return out

    def subtree(self, gid: str) -> set[str]:
        out, todo = {gid}, [gid]
        while todo:
            x = todo.pop()
            for g in self.groups.values():
                if g.get("parent") == x and g["group_id"] not in out:
                    out.add(g["group_id"])
                    todo.append(g["group_id"])
        return out

    def carriers(self) -> set[str]:
        named = {e for r in self.small("sod") for e in r["entitlements"]}
        return {g for g, x in self.groups.items() if any(c["entitlement"] in named for c in x.get("carries", []))}

    def agents_of(self, anchors: set[str]) -> set[str]:
        """The anchors of agents directed (or workloads owned) by a person of these anchors."""
        persons = {self.person(a) for a in anchors}
        every = set().union(*(self.anchors_of(a) for a in anchors)) if anchors else set()
        out = set()
        for p in self.where("persons", "director", every) + self.where("persons", "owner", every):
            if p.get("kind") in ("agent", "workload") and (self.person(p.get("director")) in persons
                                                          or self.person(p.get("owner")) in persons):
                out |= set(p.get("anchors", []))
        return out


class DocIx(Ix):
    """The index over a whole document, by scanning: what reach did before the working set, kept as the reference."""

    def __init__(self, doc: dict):
        from keyclerk.store import refs_of
        self.doc = doc
        self._refs = {}
        for kind in ("persons", "memberships", "grants", "revocations", "leases"):
            rows = []
            for r in doc.get(kind) or []:
                n = {k: norm(v) if not isinstance(v, dict) else {a: norm(b) for a, b in v.items()} for k, v in r.items()}
                rows.append((set(refs_of(kind, n)), r))
            self._refs[kind] = rows
        super().__init__()

    def small(self, kind: str) -> list[dict]:
        return list(self.doc.get(kind) or [])

    def head(self, field: str):
        return self.doc.get(field)

    def where(self, kind: str, field: str, values) -> list[dict]:
        want = {(field, norm(v)) for v in values}
        if kind in self._refs:
            return [r for refs, r in self._refs[kind] if refs & want]
        from keyclerk.store import refs_of
        return [r for r in self.doc.get(kind) or [] if set(refs_of(kind, r)) & want]

    def get(self, kind: str, key: str):
        from keyclerk.store import link as L
        if not hasattr(self, "_keys"):
            self._keys: dict[str, dict] = {}
        if kind not in self._keys:
            ix = {}
            for r in self.doc.get(kind) or []:
                try:
                    ix.setdefault(L.record_key(kind, r), r)
                except Exception:   # noqa: BLE001 - a record without its id is a schema matter
                    continue
            self._keys[kind] = ix
        return self._keys[kind].get(key)

    def _person_of(self, a) -> tuple[str, set[str]]:
        """As the engine's person_of: the first person listing the anchor, in the document's order."""
        if a not in self._people:
            p = next((p for p in self.doc.get("persons") or [] if a in p.get("anchors", [])), None)
            self._people[a] = (p["person"], set(p.get("anchors", []))) if p else (a, set())
        return self._people[a]


def _people_fields(rec: dict) -> set[str]:
    """Every anchor a record names in a person field."""
    out = set()
    for k in ("by", "delegate", "anchor", "appointed_by", "requested_by", "owner", "director", "coordinator", "host",
              "organiser"):
        v = rec.get(k)
        if isinstance(v, str):
            out.add(v)
    for k in ("approved_by", "anchors"):
        out |= {x for x in rec.get(k) or [] if isinstance(x, str)}
    for k in ("member", "subject", "sponsor"):
        v = rec.get(k)
        if isinstance(v, dict) and isinstance(v.get("anchor"), str):
            out.add(v["anchor"])
    return out


PEOPLE_REFS = {"memberships": ("member.anchor", "by", "approved_by"),
               "grants": ("subject.anchor", "requested_by", "approved_by"),
               "leases": ("anchor", "sponsor.anchor", "approved_by", "requested_by")}


# --- reach -----------------------------------------------------------------------------------------------------------

def _get(doc: dict, kind: str, key: str):
    from keyclerk.store import link as L
    if kind == "head":
        return None
    for r in doc.get(kind) or []:
        try:
            if L.record_key(kind, r) == key:
                return r
        except Exception:   # noqa: BLE001 - a record without its id is a schema matter
            continue
    return None


def touched_schema_errors(new: dict, ops: list[dict]) -> list[str]:
    """records.validate for the touched records only: each in a document of its own."""
    errs = []
    realm = new.get("realm") if isinstance(new, dict) else new.head("realm")
    base = {"realm": realm, "grants": [], "revocations": [], "suspensions": []}
    for op in ops:
        if op["op"] != "put" or op["kind"] == "head":
            continue
        rec = op["record"]
        if op["kind"] in ("approval_proofs", "proposal_proofs") and set(rec) == {"records", "by", "sha256"}:
            rec = {"records": rec["records"], "by": rec["by"], "token": rec["sha256"]}   # the schema's shape; the
        errs += R.validate({**base, op["kind"]: [rec]})                                  # signer bounds the token itself
    return errs


def reach(old, new, ops: list[dict]) -> set[str] | Full:
    """The subjects a change reaches. old and new are documents or Ix indexes (a store's, through the working set)."""
    kinds = {op["kind"] for op in ops}
    for k in kinds:
        if k in FULL_KINDS:
            return Full(FULL_KINDS[k])
    if touched_schema_errors(new, ops):          # the old state meets the schema: every record in it was validated
        return Full("schema")                    # when a change touched it (the background check verifies the whole)
    try:
        return _reach(tuple(x if isinstance(x, Ix) else DocIx(x) for x in (old, new)), ops)
    except Wide:
        return Full("bound")


def _reach(ix, ops):
    out: set[str] = set()
    groups_changed: set[str] = set()      # groups whose effective members may change
    anchors: set[str] = set()             # anchors whose separation of duty may change
    persons_touched: set[str] = set()     # anchors of touched persons, suspensions, leases
    for op in ops:
        kind, key = op["kind"], op["key"]
        out.add(key)
        out.add(f"adminrev:{key}")
        if kind == "groups":                     # a new, removed, moved or top group: the tree and every cover
            a, b = ix[0].get(kind, key), ix[1].get(kind, key)
            if a is None or b is None or a.get("parent") != b.get("parent") or a.get("parent") is None:
                return Full("group_tree")
        for x in ix:
            rec = x.get(kind, key)
            if rec is None:
                continue
            res = _one(kind, rec, x, out, groups_changed, anchors, persons_touched)
            if isinstance(res, Full):
                return res
    if persons_touched:
        for x in ix:
            every = set().union(*(x.anchors_of(a) for a in persons_touched))
            persons_touched |= every
        r = _persons(ix, persons_touched, out, groups_changed, anchors)
        if isinstance(r, Full):
            return r
    _propagate(ix, out, groups_changed, anchors)
    for x in ix:                                  # small kinds that read groups' effective risk and members: always
        for kind in ("situations", "surge_packages", "surge_grants"):
            out |= x.ids(kind)
    return out


def _mids(recs) -> set[str]:
    return {m["membership_id"] for m in recs}


def _one(kind, rec, x: Ix, out, groups_changed, anchors, persons_touched):
    if kind == "groups":
        gid = rec["group_id"]
        out.update({gid, "tree"})
        out |= {g for g, y in x.groups.items() if y.get("parent") == gid}
        down = x.down({gid})
        groups_changed |= x.up({gid}) | down
        out |= _mids(x.mems("group", down)) | _mids(x.mems("member.group", down))
        out |= {d["delegation_id"] for d in x.dels.values() if d["group"] in x.subtree(gid)}
        out.add("sod:*")                        # risk and carries reach every holder through the persona rule
    elif kind == "delegations":
        did = rec["delegation_id"]
        hit = {did} | x.descendants(did)
        out |= hit
        out |= {rec["parent"]} if rec["parent"] != "root" else set()
        under = x.mems("under", hit)
        out |= _mids(under)
        groups_changed |= {m["group"] for m in under}
        anchors |= {m["member"]["anchor"] for m in under if "anchor" in m["member"]}
        who = x.anchors_of(rec["delegate"]) | x.anchors_of(rec["by"])
        cover = x.subtree(rec["group"]) if rec["group"] in x.groups else set(x.groups)
        for m in x.mems("approved_by", who) + x.mems("by", who):   # second key: named, manager, in the chain; authority
            if (set(m.get("approved_by") or []) & who and (m["group"] in cover or m["under"] in x.ancestors(did) | hit)) \
                    or m["by"] in who:
                out.add(m["membership_id"])
        for d in x.dels.values():
            if set(d.get("approved_by") or []) & who or d["by"] in who:
                out.add(d["delegation_id"])
        deputy = x.anchors_of(rec["delegate"])           # a member who is a deputy anywhere needs a second key
        out |= _mids(x.mems("member.anchor", deputy))
        out |= _reciprocal(x, rec)
        out |= _rates(x, rec)
        for top in {x.top(did), x.top(rec["parent"])}:   # the subtree buckets of its top, before and after a move
            out.add(f"subtree:{top}:*")
        out |= {f"subtree:{x.top(d)}:*" for d in hit}
        for r in x.small("admin_revocations"):
            if r["id"] in hit and r["mode"] == "revoke":
                persons_touched.add(rec["delegate"])     # a compromised delegate: taint follows the person
    elif kind == "memberships":
        mid = rec["membership_id"]
        out.add(mid)
        groups_changed.add(rec["group"])
        if "anchor" in rec["member"]:
            anchors.add(rec["member"]["anchor"])
        if "group" in rec["member"]:
            b = rec["member"]["group"]
            down = x.down({b})
            groups_changed |= down
            out |= _mids(x.includes())                                   # cycles, depth: every include
            out |= _mids(x.mems("group", down))                          # effective risk below
            out.add("sod:*")
        if "rule" in rec["member"]:
            out.add("sod:*")
        out |= _reciprocal(x, rec)
        out |= _rates(x, rec)
        anchors |= {m["member"]["anchor"] for m in x.mems("start", [norm(rec["start"])]) if "anchor" in m["member"]}
    elif kind == "approvers":
        out.add(rec["approver_id"])
        who = x.anchors_of(rec["anchor"]) | x.anchors_of(rec["appointed_by"])
        out |= _mids(x.mems("approved_by", who))
        out |= {d["delegation_id"] for d in x.dels.values() if set(d.get("approved_by") or []) & who}
        out |= {e for k in EDGE_KINDS for e in x.ids(k)}
    elif kind == "admin_revocations":
        rid = rec["id"]
        out.add(f"adminrev:{rid}")
        if rid.startswith("root:"):
            return Full("root")
        if rid in x.dels:
            res = _one("delegations", x.dels[rid], x, out, groups_changed, anchors, persons_touched)
            if isinstance(res, Full):
                return res
            if rec["mode"] == "revoke":
                persons_touched.add(x.dels[rid]["delegate"])
        m = x.get("memberships", rid)
        if m is not None:
            _one("memberships", m, x, out, groups_changed, anchors, persons_touched)
        for a in x.small("approvers"):
            if a["approver_id"] == rid:
                _one("approvers", a, x, out, groups_changed, anchors, persons_touched)
        out |= {e for k in EDGE_KINDS for e in x.ids(k)}
    elif kind == "persons":
        persons_touched |= set(rec.get("anchors", []))
        same = x.get("persons", rec["person"])
        persons_touched |= set((same or {}).get("anchors", []))
        out.add(rec["person"])
    elif kind == "suspensions":
        persons_touched.add(rec["anchor"])
        out.add(rec["suspension_id"])
    elif kind == "leases":
        persons_touched.add(rec["anchor"])
        if rec.get("identity_hash"):
            out |= {ls["lease_id"] for ls in x.where("leases", "identity_hash", [rec["identity_hash"]])}
        out |= {g["grant_id"] for g in x.where("grants", "lease", [rec["lease_id"]])}
    elif kind == "grants":
        s, role, scope = rec["subject"].get("anchor"), rec["role"], rec.get("scope")
        out |= {g["grant_id"] for g in x.where("grants", "subject.anchor", [s]) if g["role"] == role
                and g.get("scope") == scope}
        out |= {rv["grant_id"] for rv in x.where("revocations", "grant_id", [rec["grant_id"]])}
        if rec.get("lease"):
            out.add(rec["lease"])
    elif kind == "revocations":
        out.add(rec["grant_id"])
    elif kind in EDGE_KINDS:
        out |= {e for k in EDGE_KINDS for e in x.ids(k)}
    elif kind in VISIT_KINDS:
        out |= {e for k in VISIT_KINDS for e in x.ids(k)}
    elif kind in ("approval_proofs", "proposal_proofs"):
        pass                                     # proofs are judged by the signer's approvals check, not the engine
    else:
        return Full("unknown")
    return None


def _reciprocal(x: Ix, rec: dict) -> set[str]:
    """A record by X with Y in approved_by: the records by Y with X in approved_by, started at or after it."""
    if not rec.get("by"):
        return set()
    by = x.anchors_of(rec["by"])
    approvers = set().union(*(x.anchors_of(a) for a in rec.get("approved_by") or [] if a))
    out = {m["membership_id"] for m in x.mems("by", approvers) if set(m.get("approved_by") or []) & by}
    out |= {d["delegation_id"] for d in x.dels.values() if d.get("by") in approvers and set(d.get("approved_by") or []) & by}
    return out


def _rates(x: Ix, rec: dict) -> set[str]:
    from keyclerk.delegation import _ts
    try:
        day = _ts(rec["start"]).date()
    except Exception:   # noqa: BLE001 - an unreadable time is a schema matter, judged there
        return {"rate:*", "subtree:*"}
    under = rec.get("under", rec.get("parent"))
    return {f"rate:{x.person(rec['by'])}:{day}", f"subtree:{x.top(under)}:{day}"}


def _persons(ix, touched: set[str], out, groups_changed, anchors):
    """A touched person (or suspension, or lease of an anchor) reaches every subject that names one of its anchors."""
    for x in ix:
        root = x.head("root") or {}
        if touched & ({h.get("anchor") for h in root.get("holders", [])} | {root.get("officer")}):
            return Full("root")
        agents = x.agents_of(touched)
        every = touched | agents
        anchors |= every
        for p in x.where("persons", "anchors", every) + x.where("persons", "owner", every) \
                + x.where("persons", "director", every):
            out.add(p["person"])
        for kind, fields in PEOPLE_REFS.items():
            for f in fields:
                for r in x.where(kind, f, every):
                    out.add(str(r[R.KINDS[kind]]))
                    if kind == "memberships":
                        groups_changed.add(r["group"])
        for kind in ("delegations", "approvers", "person_keys", "suspensions"):
            for r in x.small(kind):
                if _people_fields(r) & every:
                    out.add(str(r[R.KINDS[kind]]))
        out |= _mids(x.rule_mems())                                   # a rule can match them anywhere
        out |= {f"rate:{x.person(a)}:*" for a in every}
        out |= {e for k in EDGE_KINDS for e in x.ids(k)}
        out |= {e for k in VISIT_KINDS for e in x.ids(k)}
        for d in x.dels.values():                 # a deputy's kind and personas: everything under their delegations
            if _people_fields(d) & every:
                hit = {d["delegation_id"]} | x.descendants(d["delegation_id"])
                out |= hit
                out |= _mids(x.mems("under", hit))
    return None


def _propagate(ix, out, groups_changed, anchors):
    """To a fixpoint: a re-judged delegation reaches what was made under it and below it; a re-judged membership can
    change status, so its group's effective members move, and with them the includes above that group and the
    separation of duty of everyone who moved.

    An include reached only because its included group's members moved is re-judged, but its own status reads that
    group's members in one place only (whether its actor is among them: "the include puts the actor into a group they
    manage"), so it moves its members' separation of duty only once its actor's anchors have moved."""
    done: list[set[str]] = [set(), set()]
    by_members: set[str] = set()     # includes in out only through the members of the group they take in (both sides)
    while True:
        before = (len(out), len(anchors))
        for i, x in enumerate(ix):
            for d in list(x.dels):
                if d in out:
                    hit = {d} | x.descendants(d)
                    under = _mids(x.mems("under", hit))
                    by_members -= under
                    out |= hit | under
            for key in sorted(out - done[i]):
                m = x.get("memberships", key) if ":" not in key else None
                if m is None:
                    done[i].add(key)
                    continue
                if "group" in m["member"] and key in by_members and not (x.anchors_of(m["by"]) & anchors):
                    continue                     # judged again, but its status does not move (yet)
                done[i].add(key)
                groups_changed.add(m["group"])
                if "anchor" in m["member"]:
                    anchors.add(m["member"]["anchor"])
                elif "group" in m["member"]:
                    anchors |= {y["member"]["anchor"] for y in x.mems("group", x.down({m["member"]["group"]}))
                                if "anchor" in y["member"]}
            up = x.up(groups_changed)
            for m in x.includes():
                if m["member"]["group"] in up and m["membership_id"] not in out:
                    out.add(m["membership_id"])
                    by_members.add(m["membership_id"])
        if (len(out), len(anchors)) == before:
            break
    for x in ix:
        if x.up(groups_changed) & x.carriers() or "sod:*" in out:
            members = anchors | x.agents_of(anchors)
            out |= {f"sod:{a}" for a in members}


# --- the scoped judgement ----------------------------------------------------------------------------------------------

def scoped_errors(doc: dict, reach: set[str]) -> list[str]:
    """The engine errors of the subjects in reach, judged by today's check code: the expensive parts (the schema over
    the whole document, every membership, separation of duty for everyone) only for the reached subjects, the cheap
    ones whole and then kept to the reach. Exactly the full check's errors whose subject is in reach (the equivalence
    tests in tests/test_scope.py), provided the records already meet the schema (a scoped check validates the records
    a change touches: touched_schema_errors) and their keys are their ids (the store's guarantee)."""
    from keyclerk import clock, delegation as D, edge_records, grants, leases, places, situation
    with clock.fixed(), D.memo():
        errs: list[str] = []
        errs += grants.check(doc, grants.rules(), schema=False)
        if doc.get("leases"):
            errs += leases.check(doc, leases.rules())
        if doc.get("groups"):
            errs += _delegation(doc, reach)
        if doc.get("places"):
            errs += places.check(doc)
        if doc.get("situations") or doc.get("surge_packages"):
            errs += situation.check(doc)
        if doc.get("visits") or doc.get("visit_events") or doc.get("badges"):
            from keyclerk import visits
            errs += visits.check(doc)
        if doc.get("edges") or doc.get("person_keys") or doc.get("edge_visit_leases") or doc.get("edge_rotations"):
            errs += edge_records.check(doc)
        return [e for e in errs if covered(subject_of(e, doc), reach)]


def _delegation(doc: dict, reach: set[str]) -> list[str]:
    """delegation.check itself, on the whole records, judging only the reached memberships and anchors' separation of
    duty (the two parts that grow with the organisation); every other part is judged whole and kept to the reach."""
    from keyclerk import delegation as D
    sod = None if "sod:*" in reach else {s[4:] for s in reach if s.startswith("sod:")}
    return D.check(doc, memberships={m["membership_id"] for m in doc.get("memberships", []) if m["membership_id"] in reach},
                   sod=sod)


BOUND = 0.2       # a reach above this share of the records is judged in full (decision 0022 S4: measured, a start)


def bounded(r, doc: dict):
    """The reach, or Full("bound") when it names more than BOUND of the records (the full check is then no dearer)."""
    if isinstance(r, Full):
        return r
    total = sum(len(v) for v in doc.values() if isinstance(v, list))
    named = sum(1 for x in r if not x.endswith("*") and ":" not in x)
    return Full("bound") if total and named > BOUND * total else r


def guard_errors(old: dict, new: dict, ops: list[dict]) -> list[str]:
    """records.guard for a change, over the records it touches: an untouched record is the same in both states, so it
    can only matter through a touched one, and what it matters through is brought along (a touched grant's
    revocation, a touched record's administrative revocations, the revision). Exactly records.guard(old, new) (a test
    holds it)."""
    keys: dict[str, set[str]] = {}
    for op in ops:
        keys.setdefault(op["kind"], set()).add(op["key"])

    def part(doc: dict) -> dict:
        from keyclerk.store import link as L
        out: dict = {"revision": doc.get("revision")} if "revision" in doc else {}
        for kind, ks in keys.items():
            if kind == "head":
                continue
            out[kind] = [r for r in doc.get(kind) or [] if _key_or_none(L, kind, r) in ks]
        grants = keys.get("grants", set()) | keys.get("revocations", set())
        out["revocations"] = [r for r in doc.get("revocations") or [] if r["grant_id"] in grants]
        out["grants"] = [g for g in doc.get("grants") or [] if g["grant_id"] in grants]
        ids = set().union(*(keys.get(k, set()) for k in ("delegations", "memberships", "approvers")))
        ids |= {k.rsplit(".", 1)[0] for k in keys.get("admin_revocations", set())}
        out["admin_revocations"] = [r for r in doc.get("admin_revocations") or [] if r["id"] in ids]
        return out
    return R.guard(part(old), part(new))


def _key_or_none(L, kind, rec):
    try:
        return L.record_key(kind, rec)
    except Exception:   # noqa: BLE001 - a record without its id: never one a change touched
        return None
