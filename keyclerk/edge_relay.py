# SPDX-License-Identifier: EUPL-1.2
"""Relays and the site key (decision 0027, edge protocol 1.5): the reference an edge implementation conforms to.

A relay sits between the desk and the edges of a site's subtree. It can tighten, never grant:

    kc-edge-relay-v1     the relay certificate, multi-signed by the edges' officer with their hardware key (the same
                         envelope as kc-edge-officer-v2, signed by exactly that key):
                         {format, officer_key, relay_key, edges [ids], operations [op], serial, issued, expires}
    kc-edge-tighten-v1   a tightening, sealed by the relay key:
                         {format, cert_sha256, edge, parent_serial, counter, signed_at, ops [{op, ...}]}
    kc-edge-site-v1      a statement by the site's physical key and a node, multi-signed by both:
                         {format, purpose: provisional | promotion, edge, site_key, node_key, at, reason}

Operations: revoke_lease {lease_id}, end_lease {lease_id, until}, cut_sessions {lease_id | "*"}, suspend_edge {},
rollback_release {serial}, hold_release {}. No operation adds a lease, widens a window, lifts a suspension or ends an
edge: a parent bundle lifts a suspension, and only the officer's ended notice ends an edge, so a stolen relay key cannot
force a re-enrolment.

The edge checks the chain from its pinned officer key through the certificate to the tightening (verify_tighten):
the certificate names this edge and the operation, has not expired in the edge's trusted time (its newest signed time,
and its clock), and was issued no later than that; the tightening names this certificate by the hash of its bytes, this
edge, the serial of the parent bundle the edge applied (a newer parent bundle supersedes every tightening made against
an older one), and a counter above the last one this edge applied from that relay key. Each operation must narrow the
edge's current state: a lease it holds, an end before the lease's own, a release older than the current and no lower
than the edge's release floor. Anything else is refused whole. A tightening lapses with its certificate.

The site key (verify_site) signs with the new node's key, for one purpose each: provisional (a replacement that runs on
the dead edge's cached bundle until the officer confirms or ends it) and promotion (a node of a high-availability edge
made active by hand, as the last resort, decision 0031). The purpose is inside the signed bytes, so a statement made
for one never serves as the other.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from keyclerk import edge as E

RELAY_FORMAT = "kc-edge-relay-v1"
TIGHTEN_FORMAT = "kc-edge-tighten-v1"
SITE_FORMAT = "kc-edge-site-v1"                  # a provisional replacement
SITE_FORMAT_V2 = "kc-edge-site-v2"               # edge protocol 1.6: a promotion, with not_after
SITE_MAX_HOURS = 24                              # a promotion statement's longest life: it promotes once, soon
OPERATIONS = ("revoke_lease", "end_lease", "cut_sessions", "suspend_edge", "rollback_release", "hold_release")
SITE_PURPOSES = ("provisional", "promotion")
MAX_DAYS = 31                                    # a relay certificate's life: short, so a lost key lapses soon
MAX_EDGES = 500
MAX_OPS = 200
CERT_FIELDS = {"format", "officer_key", "relay_key", "edges", "operations", "serial", "issued", "expires"}
TIGHTEN_FIELDS = {"format", "key_id", "cert_sha256", "edge", "parent_serial", "counter", "signed_at", "ops"}
SITE_FIELDS = {"format", "purpose", "edge", "site_key", "node_key", "at", "reason"}
SITE_FIELDS_V2 = SITE_FIELDS | {"not_after"}


def site_format(purpose: str) -> str:
    """The format a site statement of this purpose is signed under: a promotion is kc-edge-site-v2 from 1.6."""
    return SITE_FORMAT_V2 if purpose == "promotion" else SITE_FORMAT


def relay_certificate(officer_key: str, relay_key: str, edges: list[str], operations: list[str], serial: int,
                      issued: datetime, expires: datetime) -> dict:
    """The object the officer signs (E.cosign with RELAY_FORMAT)."""
    return {"format": RELAY_FORMAT, "officer_key": officer_key, "relay_key": relay_key, "edges": sorted(set(edges)),
            "operations": sorted(set(operations)), "serial": serial, "issued": E._iso(issued), "expires": E._iso(expires)}


def tightening(cert: dict, edge: str, parent_serial: int, counter: int, ops: list[dict], signed_at: datetime) -> dict:
    """The object the relay seals (E.seal with TIGHTEN_FORMAT); cert is the sealed certificate."""
    return {"format": TIGHTEN_FORMAT, "cert_sha256": E.sha256(E._raw(cert["bytes"])), "edge": edge,
            "parent_serial": parent_serial, "counter": counter, "signed_at": E._iso(signed_at), "ops": ops}


def site_statement(purpose: str, edge: str, site_key: str, node_key: str, at: datetime, reason: str,
                   not_after: datetime | None = None) -> dict:
    """The object the site key and the node both sign (E.cosign with site_format(purpose)). A promotion
    (kc-edge-site-v2, edge protocol 1.6) carries not_after, at most SITE_MAX_HOURS after at (the default): a statement
    found later cannot promote the node again."""
    if purpose not in SITE_PURPOSES:
        raise ValueError(f"purpose: {' or '.join(SITE_PURPOSES)}")
    base = {"format": SITE_FORMAT, "purpose": purpose, "edge": edge, "site_key": site_key, "node_key": node_key,
            "at": E._iso(at), "reason": reason}
    if purpose != "promotion":
        return base
    return {**base, "format": SITE_FORMAT_V2, "not_after": E._iso(not_after or at + timedelta(hours=SITE_MAX_HOURS))}


def _cert(sealed: dict, officer_key: str) -> dict:
    c = E.unseal_multi(sealed, [officer_key], RELAY_FORMAT)
    if set(c) != CERT_FIELDS:
        raise ValueError(f"a relay certificate is exactly {{{', '.join(sorted(CERT_FIELDS))}}}")
    if c["officer_key"] != officer_key or not E.HEX64.fullmatch(str(c["relay_key"])):
        raise ValueError("the certificate names the pinned officer and a 64-hex relay key")
    if (not isinstance(c["edges"], list) or not 1 <= len(c["edges"]) <= MAX_EDGES
            or not all(isinstance(x, str) and x for x in c["edges"]) or len(set(c["edges"])) != len(c["edges"])):
        raise ValueError(f"edges: 1 to {MAX_EDGES} edge ids, each once (a list, never a pattern)")
    if (not isinstance(c["operations"], list) or not c["operations"] or not set(c["operations"]) <= set(OPERATIONS)
            or len(set(c["operations"])) != len(c["operations"])):
        raise ValueError(f"operations: some of {', '.join(OPERATIONS)}, each once")
    if not E._whole(c["serial"], 1):
        raise ValueError("serial: a whole number from 1")
    issued, expires = E._ts(c["issued"]), E._ts(c["expires"])
    if not issued < expires <= issued + timedelta(days=MAX_DAYS):
        raise ValueError(f"a relay certificate lives at most {MAX_DAYS} days, from issued to expires")
    return c


def _narrowing(op: dict, applied: dict, release: dict | None) -> str | None:
    """Why op would not narrow the edge's current state, or None."""
    kind = op.get("op")
    leases = {x["lease_id"]: x for x in [*applied.get("leases", []), *applied.get("visit_leases", [])]}
    args = {k for k in op if k != "op"}
    if kind in ("revoke_lease", "end_lease", "cut_sessions"):
        lid = op.get("lease_id")
        if kind == "cut_sessions" and lid == "*":
            return None if args == {"lease_id"} else "cut_sessions takes {lease_id} only"
        if lid not in leases:
            return f"{kind}: {str(lid)[:60]} is no lease this edge holds"
        if kind == "end_lease":
            if args != {"lease_id", "until"}:
                return "end_lease takes {lease_id, until}"
            try:
                until = E._ts(op["until"])
            except ValueError as e:
                return f"end_lease: {e}"
            if until >= E._ts(leases[lid]["until"]):
                return f"end_lease: {lid} already ends at {leases[lid]['until']}: a relay only ends it earlier"
            return None
        return None if args == {"lease_id"} else f"{kind} takes {{lease_id}} only"
    if kind in ("suspend_edge", "hold_release"):
        return None if not args else f"{kind} takes nothing"
    if kind == "rollback_release":
        if args != {"serial"} or not E._whole(op.get("serial"), 1):
            return "rollback_release takes {serial}"
        if release is None:
            return "rollback_release: this edge holds no signed release"
        if not int(release.get("floor", 0)) <= op["serial"] < int(release["serial"]):
            return (f"rollback_release: release {op['serial']} is not below the current {release['serial']} and at or "
                    f"above the floor {release.get('floor', 0)}")
        return None
    return f"{str(kind)[:40]} is no relay operation"


def verify_tighten(cert: dict, sealed: dict, pins: dict, state: dict, applied: dict, now: datetime,
                   release: dict | None = None) -> tuple[list[str], dict]:
    """A tightening against the edge's current state. pins: {edge, officer_key}; state: {serial (the parent bundle
    applied), newest (the newest signed time), relay_counters {relay_key: counter}}; applied: the verified bundle's
    {leases, visit_leases}; release: {serial, floor} of the signed release the edge runs, if any. Returns (errors,
    effect); the caller applies the effect and stores effect["state"] only when there are no errors."""
    try:
        c = _cert(cert, pins["officer_key"])
        t = E.unseal(sealed, c["relay_key"], TIGHTEN_FORMAT)
    except (ValueError, KeyError, TypeError) as e:
        return [str(e)], {}
    errs = []
    if set(t) != TIGHTEN_FIELDS:
        return [f"a tightening is exactly {{{', '.join(sorted(TIGHTEN_FIELDS))}}}"], {}
    trusted = max(now, E._ts(state["newest"])) if state.get("newest") else now
    if pins["edge"] not in c["edges"]:
        errs.append("the certificate does not name this edge")
    if trusted >= E._ts(c["expires"]):
        errs.append("the relay certificate has expired in this edge's trusted time")
    if t["cert_sha256"] != E.sha256(E._raw(cert["bytes"])):
        errs.append("the tightening names another certificate")
    if t["edge"] != pins["edge"]:
        errs.append("a tightening for another edge")
    if not E._whole(t["parent_serial"], 1) or t["parent_serial"] != int(state.get("serial", 0)):
        errs.append(f"made against bundle {t['parent_serial']}, but this edge applied {state.get('serial', 0)}: a newer "
                    "parent bundle supersedes it" if E._whole(t["parent_serial"], 1) else "parent_serial: a whole number")
    last = int((state.get("relay_counters") or {}).get(c["relay_key"], 0))
    if not E._whole(t["counter"], 1) or t["counter"] <= last:
        errs.append(f"counter {t['counter']} is not above {last}, the last this edge applied from this relay: a replay")
    try:
        at = E._ts(t["signed_at"])
        if at > now + timedelta(seconds=E.SKEW) or at < E._ts(c["issued"]):
            errs.append("signed_at is in the future or before the certificate was issued")
    except ValueError as e:
        errs.append(f"signed_at: {e}")
    ops = t["ops"]
    if not isinstance(ops, list) or not 1 <= len(ops) <= MAX_OPS or not all(isinstance(o, dict) for o in ops):
        return errs + [f"ops: 1 to {MAX_OPS} operations"], {}
    for o in ops:
        if o.get("op") not in c["operations"]:
            errs.append(f"{str(o.get('op'))[:40]}: the certificate does not allow it")
            continue
        why = _narrowing(o, applied, release)
        if why:
            errs.append(why)
    if errs:
        return errs, {}
    effect = {"revoked": sorted({o["lease_id"] for o in ops if o["op"] == "revoke_lease"}),
              "ends": {o["lease_id"]: o["until"] for o in ops if o["op"] == "end_lease"},
              "cut_sessions": sorted({o["lease_id"] for o in ops if o["op"] == "cut_sessions"}),
              "suspended": any(o["op"] == "suspend_edge" for o in ops),
              "hold_release": any(o["op"] == "hold_release" for o in ops),
              "rollback_release": min((o["serial"] for o in ops if o["op"] == "rollback_release"), default=None),
              "lapses": c["expires"],
              "state": {"relay_counters": {**(state.get("relay_counters") or {}), c["relay_key"]: t["counter"]}}}
    return [], effect


def verify_site(sealed: dict, site_key: str, edge: str, purpose: str, now: datetime | None = None) -> dict:
    """A site statement for this edge and this purpose, signed by exactly the pinned site key and the node it names;
    ValueError otherwise. A promotion is kc-edge-site-v2 (edge protocol 1.6): its not_after is after its at and at
    most SITE_MAX_HOURS later, and with now, not passed."""
    if purpose not in SITE_PURPOSES:
        raise ValueError(f"purpose: {' or '.join(SITE_PURPOSES)}")
    body = E.opened(sealed) if isinstance(sealed, dict) and "bytes" in sealed else None
    node = (body or {}).get("node_key")
    if not isinstance(node, str) or not E.HEX64.fullmatch(node):
        raise ValueError("a site statement names the node's 64-hex enrolment key")
    fmt = site_format(purpose)
    if (body or {}).get("format") != fmt:
        if purpose == "promotion":
            raise ValueError("a promotion is kc-edge-site-v2 (edge protocol 1.6), with not_after: a statement without "
                             "one could promote the node again")
        raise ValueError(f"a statement for {purpose} is {fmt}")
    fields = SITE_FIELDS_V2 if fmt == SITE_FORMAT_V2 else SITE_FIELDS
    st = E.unseal_multi(sealed, [site_key, node], fmt)
    if set(st) != fields or st["site_key"] != site_key:
        raise ValueError(f"a site statement is exactly {{{', '.join(sorted(fields))}}}, naming the pinned site key")
    if st["purpose"] != purpose:
        raise ValueError(f"a statement for {st['purpose']} is not one for {purpose}")
    if st["edge"] != edge:
        raise ValueError("a site statement for another edge")
    at = E._ts(st["at"])
    if not isinstance(st["reason"], str) or not 3 <= len(st["reason"]) <= 300:
        raise ValueError("reason: 3 to 300 characters")
    if fmt == SITE_FORMAT_V2:
        na = E._ts(st["not_after"])
        if not at < na <= at + timedelta(hours=SITE_MAX_HOURS):
            raise ValueError(f"not_after: after at, and at most {SITE_MAX_HOURS} hours later")
        if now is not None and now > na:
            raise ValueError(f"the promotion statement expired at {st['not_after']}")
    return st


def cert_sha256(cert: dict) -> str:
    return hashlib.sha256(E._raw(cert["bytes"])).hexdigest()
