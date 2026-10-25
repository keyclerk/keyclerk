# SPDX-License-Identifier: EUPL-1.2
"""Approvals as signatures the desk cannot make (decision 0006).

A key someone adds to a change (a second key, a manager's key, the security officer's key, a lift of a suspension) is
an entry in approved_by or lifted.by. Written by the desk alone, such an entry would rest on the desk's one signing
key: whoever held that key could write any approval. So every approval carries a proof the broker signs: the approver
signs in again (a fresh authentication) with the OIDC nonce set to the statement below, and the broker's ID token,
carrying that nonce, the approver's anchor and the time of the sign-in, is kept in the records (approval_proofs). The
reconciler verifies every proof against the broker's own keys before it applies a revision; an approval without a
valid proof refuses the revision. Approvals made before proofs existed (records reviewed elsewhere, such as in git)
are accepted only when the deployment pins them, record by record, in approvals.accepted_without_proof.

The statement names the realm, the approver and the records the approval covers, without their approval lists, so
everyone who approves the same change signs the same records. A proof fits only the records and the person it names.

What a proof does not cover: a desk compromised while it serves its pages could show an approver one change and ask
the broker to sign another, since the broker's sign-in page does not show the change.

The proposer (decision 0015, replan D2): a high-risk record (a membership of an elevated or privileged group, a
delegation, anything a root holder makes; the classes are policy, approvals.proposer_proof) carries its proposer's own
proof too, a fresh sign-in whose nonce is the proposal statement (proposal_proofs). The checking signer verifies it for
every record a revision adds or widens; records made before stay as they were.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import urllib.request
from pathlib import Path

from keyclerk import guard, records
from keyclerk.oidc import rs256

KEYED = (("memberships", "membership_id"), ("delegations", "delegation_id"), ("grants", "grant_id"),
         ("approvers", "approver_id"), ("badges", "badge_id"),
         ("edges", "edge_id"), ("person_keys", "key_id"), ("edge_visit_leases", "lease_id"),   # decision 0014: every kind
         ("edge_rotations", "rotation_id"))                    # the desk adds approved_by to (Desk._with_approvals)
MAX_ARCHIVED_KEYS = 64


def _bare(kind: str, rec: dict) -> dict:
    if kind == "suspensions":
        return {**{k: v for k, v in rec.items() if k != "lifted"}, "lift": True}
    return {k: v for k, v in rec.items() if k != "approved_by"}


def statement(realm: str, items: list[tuple[str, dict]], by: str, purpose: str = "approval") -> str:
    """The nonce an approval (or, purpose "proposal", a proposal) by `by` of these records must carry:
    base64url(sha256(canonical statement)). The purpose is part of what is signed: one never stands for the other."""
    recs = sorted(([kind, records.canonical(_bare(kind, rec))] for kind, rec in items),
                  key=lambda x: json.dumps(x, sort_keys=True, default=str))
    if purpose not in ("approval", "proposal"):
        raise ValueError("purpose is approval or proposal")
    body = json.dumps({f"keyclerk-{purpose}": 1, "realm": realm, "by": by, "records": recs},
                      sort_keys=True, separators=(",", ":"), default=str)
    return base64.urlsafe_b64encode(hashlib.sha256(body.encode()).digest()).rstrip(b"=").decode()


def record_index(doc: dict) -> tuple[dict[str, tuple[str, dict]], set[str]]:
    """Records by id, and the ids used by more than one kind of record (an approval on those cannot be told apart)."""
    out, twice = {}, set()
    for kind, field in KEYED + (("suspensions", "suspension_id"),):
        for r in doc.get(kind) or []:
            rid = str(r.get(field))
            if rid in out and out[rid][0] != kind:
                twice.add(rid)
            out[rid] = (kind, r)
    return out, twice


def record_hash(kind: str, rec: dict) -> str:
    """What a pinned approval is bound to: the record as approved, without its approval list."""
    body = json.dumps([kind, records.canonical(_bare(kind, rec))], sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(body.encode()).hexdigest()


def keys_in(doc: dict):
    """(kind, record id, record, approver) for every approval key in the records."""
    for kind, field in KEYED:
        for r in doc.get(kind) or []:
            for a in r.get("approved_by") or []:
                yield kind, str(r[field]), r, a
    for s in doc.get("suspensions") or []:
        for a in (s.get("lifted") or {}).get("by") or []:
            yield "suspensions", str(s["suspension_id"]), s, a


def check(doc: dict, verify, policy: dict) -> list[str]:
    """Every approval key without a valid proof (empty: every approval is the approver's own)."""
    allowed = {(str(x["record"]), str(x["by"])): x.get("sha256") for x in policy.get("accepted_without_proof") or []}
    index, twice = record_index(doc)
    proofs: dict[tuple[str, str], list[dict]] = {}
    for p in doc.get("approval_proofs") or []:
        for rid in p.get("records") or []:
            proofs.setdefault((str(rid), str(p.get("by"))), []).append(p)
    errs = []
    for kind, rid, rec, by in keys_in(doc):
        if rid in twice:
            errs.append(f"{rid}: the id is used by two kinds of record, so its approvals cannot be told apart")
            continue
        if (rid, by) in allowed and allowed[(rid, by)] == record_hash(kind, rec):
            continue                                    # pinned, and the record is still the one that was approved
        why = "no proof"
        for p in proofs.get((rid, by), []):
            items = [index[str(x)] for x in p["records"] if str(x) in index]
            if len(items) != len(p["records"]):
                why = "the proof names a record that is not in these records"
                continue
            try:
                verify(p["token"], statement(doc["realm"], items, by), by)
                break
            except guard.InputRejected as e:
                why = str(e)
        else:
            if (rid, by) in allowed:
                why = "pinned, but the record changed since it was approved"
            errs.append(f"{rid}: the approval by {by} has no valid proof ({guard.safe_for_log(why, 120)})")
    return errs


PIN_HINT = ("approvals made before proofs were required are kept by pinning them, after review, in "
            "approvals.accepted_without_proof (python -m keyclerk.approvals pin RECORDS prints the entries)")


def pins(doc: dict) -> list[dict]:
    """Every approval key in the records as an approvals.accepted_without_proof entry (record, by, sha256), for the
    deployment to review and pin when it switches proofs on. A pin holds only while the record is unchanged."""
    return [{"record": rid, "by": by, "sha256": record_hash(kind, rec)} for kind, rid, rec, by in keys_in(doc)]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    ap = argparse.ArgumentParser(prog="keyclerk.approvals", description=(
        "pin RECORDS: print approvals.accepted_without_proof entries for every approval key in RECORDS (a records file "
        "or directory). Review each before you pin it: a pin accepts that approval without a proof, for that exact "
        "record. Use it once, when a deployment switches approvals.proofs to required."))
    sub = ap.add_subparsers(dest="cmd", required=True)
    pp = sub.add_parser("pin")
    pp.add_argument("records")
    a = ap.parse_args(argv)
    doc = records.load(Path(a.records))
    entries = pins(doc)
    sys.stdout.write("# approvals made before proofs were required: review, then put under approvals: in the "
                     "deployment's configuration\n")
    sys.stdout.write(json.dumps({"accepted_without_proof": entries}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# --- the proposer's own proof (decision 0015, replan D2) --------------------------------------------------------------

PROPOSER_DEFAULT = {"classes": ["elevated", "privileged"], "delegations": True, "root": True}


def proposer_policy(policy: dict) -> dict:
    return {**PROPOSER_DEFAULT, **((policy or {}).get("proposer_proof") or {})}


def proposer_of(rec: dict) -> str:
    return str(rec.get("by") or rec.get("requested_by") or "")


def needs_proposal_proof(doc: dict, kind: str, rec: dict, policy: dict) -> bool:
    """Whether this record is high risk: its proposer signs it, not only the desk."""
    from keyclerk import delegation as D
    pol = proposer_policy(policy)
    if pol.get("off"):
        return False
    if kind == "delegations" and pol.get("delegations"):
        return True
    if kind == "memberships" and D.effective_risk(doc, str(rec.get("group"))) in set(pol.get("classes") or []):
        return True
    if pol.get("root"):
        holders = {str(h.get("anchor")) for h in ((doc.get("root") or {}).get("holders") or [])}
        if proposer_of(rec) in holders:
            return True
    return False


def _without_end(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if k != "end"}


def widened(old: dict, new: dict):
    """(kind, id, record) for every record a revision adds, or changes other than ending it sooner or adding keys."""
    for kind, field in KEYED:
        before = {str(r.get(field)): r for r in old.get(kind) or []}
        for r in new.get(kind) or []:
            rid = str(r.get(field))
            o = before.get(rid)
            if o is None:
                yield kind, rid, r
                continue
            a, b = _bare(kind, o), _bare(kind, r)
            if a == b:
                continue
            if _without_end(a) == _without_end(b) and a.get("end") is not None and b.get("end") is not None and b["end"] <= a["end"]:
                continue                                  # ended sooner: taking away needs no second signature
            yield kind, rid, r


def check_proposals(old: dict, new: dict, verify, policy: dict) -> list[str]:
    """Every high-risk record this revision adds or widens without its proposer's own valid proof."""
    index, _ = record_index(new)
    proofs: dict[tuple[str, str], list[dict]] = {}
    for p in new.get("proposal_proofs") or []:
        for rid in p.get("records") or []:
            proofs.setdefault((str(rid), str(p.get("by"))), []).append(p)
    errs = []
    for kind, rid, rec in widened(old, new):
        if not needs_proposal_proof(new, kind, rec, policy):
            continue
        by = proposer_of(rec)
        why = "no proof"
        for p in proofs.get((rid, by), []):
            items = [index[str(x)] for x in p["records"] if str(x) in index]
            if len(items) != len(p["records"]):
                why = "the proof names a record that is not in these records"
                continue
            try:
                verify(p["token"], statement(new["realm"], items, by, purpose="proposal"), by)
                break
            except guard.InputRejected as e:
                why = str(e)
        else:
            errs.append(f"{rid}: high risk, proposed by {by or 'nobody named'} without their own signature "
                        f"({guard.safe_for_log(why, 120)})")
    return errs


class BrokerProofs:
    """Verifies a proof: an ID token the broker signed (RS256, its published keys), from one of the allowed clients,
    whose nonce is the statement, whose anchor is the approver, and whose sign-in was fresh when it was issued. Keys the
    broker published once are kept in an archive, so a proof still verifies after the broker rotates its keys."""

    def __init__(self, issuers, audiences, max_age: int, jwks_url: str, archive: Path | None = None, fetch=None,
                 acr: str | None = None):
        self.issuers, self.audiences, self.max_age = set(issuers), set(audiences), int(max_age)
        self.acr = acr                                 # the authentication level a proof must carry, if any
        self.resolve = None                            # claims -> internal anchor (decision 0028), set by the signer
        self.jwks_url, self.archive, self._fetch = jwks_url, archive, fetch
        self.keys: dict = {}
        self.fetched_at = 0.0
        if archive and Path(archive).exists():
            try:
                self.keys = {k: v for k, v in json.loads(Path(archive).read_text(encoding="utf-8")).items()
                             if isinstance(v, dict) and v.get("kty") == "RSA"}
            except (ValueError, OSError):
                self.keys = {}

    def _refresh(self) -> None:
        if time.time() - self.fetched_at < 10:
            return
        self.fetched_at = time.time()
        if self._fetch:
            body = self._fetch()
        else:
            guard.broker_url(self.jwks_url.split("/realms/")[0])
            with urllib.request.urlopen(self.jwks_url, timeout=30) as r:
                body = guard.read_response(r)
        new = {k["kid"]: {x: k[x] for x in ("kty", "n", "e", "kid")} for k in body.get("keys", [])
               if k.get("kty") == "RSA" and k.get("use", "sig") == "sig" and k.get("kid")}
        if any(k not in self.keys for k in new):
            self.keys.update(new)
            self.keys = dict(list(self.keys.items())[-MAX_ARCHIVED_KEYS:])
            if self.archive:
                tmp = Path(self.archive).with_suffix(".tmp")
                tmp.write_text(json.dumps(self.keys), encoding="utf-8")
                os.replace(tmp, self.archive)

    def _key(self, kid: str) -> dict:
        if kid not in self.keys:
            self._refresh()
        if kid not in self.keys:
            raise guard.InputRejected("the proof is signed by a key the broker never published")
        return self.keys[kid]

    def __call__(self, token: str, nonce: str, by: str) -> dict:
        claims = rs256(token, self._key)
        if claims.get("iss") not in self.issuers:
            raise guard.InputRejected("the proof is from another issuer")
        aud = claims.get("aud")
        if not set(aud if isinstance(aud, list) else [aud]) & self.audiences:
            raise guard.InputRejected("the proof is for another client")
        if claims.get("nonce") != nonce:
            raise guard.InputRejected("the proof is for another change or another person")
        who = self.resolve(claims) if self.resolve else claims.get("anchor")
        if who != by:                                  # decision 0028: through the store's mapping where there is one
            raise guard.InputRejected("the proof is someone else's")
        at, iat = claims.get("auth_time"), claims.get("iat")
        if not isinstance(at, (int, float)) or not isinstance(iat, (int, float)) or not 0 <= iat - at <= self.max_age:
            raise guard.InputRejected("the proof is not from a fresh sign-in")
        if self.acr and claims.get("acr") != self.acr:
            raise guard.InputRejected(f"the proof is not at the authentication level {self.acr}")
        return claims
