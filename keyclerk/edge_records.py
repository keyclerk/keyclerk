# SPDX-License-Identifier: EUPL-1.2
"""Edges in the records (decision 0014 points 1, 5 and 7): what makes an edge, a person key and a visit lease valid.

Each is a governed change: an edge is enrolled by the root with the security officer's key; a person key is registered
by the person with a second key from the security officer or a named approver; a visit lease takes a second key from
the security officer or a named approver. The edge's officer is never a core administrator.
"""
from __future__ import annotations

import re
from datetime import datetime

from keyclerk import delegation as D

HEX64 = re.compile(r"[0-9a-f]{64}")
SSH_KEY = re.compile(r"(ssh-ed25519|sk-ssh-ed25519@openssh\.com) [A-Za-z0-9+/=]{40,800}( [ -~]{0,80})?")
EDGE_KINDS = (("edges", "edge_id"), ("person_keys", "key_id"), ("edge_visit_leases", "lease_id"))


def _ts(v) -> datetime:
    return D._ts(v)


def _ended(doc: dict, rid: str, at: datetime) -> bool:
    return bool(D._revs(doc, rid, at))


def _second_key(doc: dict, approved_by: list, not_by: list, at: datetime) -> bool:
    """The security officer's key, or a named approver's, from someone who is none of not_by."""
    officer = (doc.get("root") or {}).get("officer")
    for a in approved_by or []:
        if any(D.same(doc, a, x) for x in not_by if x):
            continue
        if D.same(doc, a, officer) or D.named_approver(doc, a, at):
            return True
    return False


def _privileged_member(doc: dict, anchor: str, at: datetime) -> bool:
    for g in doc.get("groups", []):
        if D.effective_risk(doc, g["group_id"]) == "privileged" and any(
                D.same(doc, anchor, m) for m in D.effective_members(doc, g["group_id"], at)):
            return True
    return False


def officer_errors(doc: dict, e: dict, at: datetime) -> list[str]:
    """The edge's officer is independent of the core at `at`: never the root, the security officer or a member of a
    privileged group. Checked at enrolment, at every ceiling and at every bundle cut."""
    o, eid = e["officer"], e["edge_id"]
    officer = (doc.get("root") or {}).get("officer")
    if D.same(doc, o, D.root_at(doc, at)) or D.same(doc, o, officer) or _privileged_member(doc, o, at):
        return [f"{eid}: the edge's officer is never a core administrator (the root, the security officer or a member of a "
                "privileged group): a core administrator must not be able to widen an edge's ceiling"]
    return []


def edge_errors(doc: dict, e: dict) -> list[str]:
    from keyclerk import edge as E
    eid, t0, errs = e["edge_id"], _ts(e["at"]), []
    officer = (doc.get("root") or {}).get("officer")
    root = D.root_at(doc, t0)
    if not D.same(doc, e["by"], root):
        errs.append(f"{eid}: an edge is enrolled by the root trust owner of that time")
    if not _second_key(doc, [x for x in e.get("approved_by", []) if D.same(doc, x, officer)], [e["by"]], t0):
        errs.append(f"{eid}: enrolling an edge needs the security officer's key")
    if not (HEX64.fullmatch(e["enrolment_key"]) and HEX64.fullmatch(e["officer_key"])):
        errs.append(f"{eid}: keys are Ed25519 public keys, 64 hex characters")
    if e["enrolment_key"] == e["officer_key"]:
        errs.append(f"{eid}: the edge's enrolment key and its officer's key are different keys")
    o = e["officer"]
    if D.kind_of(doc, o) != "tenant":
        errs.append(f"{eid}: the edge's officer is a person of the organisation")
    errs += officer_errors(doc, e, t0)
    tpm, terrs = e.get("tpm"), []
    if tpm is not None:
        terrs = tpm_errors(eid, tpm)
        errs += terrs
    errs += unlock_key_errors(eid, e.get("unlock_key"))
    st = E.officer_statement(eid, o, e["officer_key"],
                             [E.node(e["enrolment_key"], e.get("unlock_key"), E.tpm_commitment(tpm) if tpm and not terrs else None)])
    errs += statement_errors(eid, e.get("statement"), st)
    if any(r.get("id") == eid and _ts(r["at"]) < t0 for r in doc.get("admin_revocations", [])):
        errs.append(f"{eid}: that edge id was ended before; an ended edge id is never used again: "
                    "enrol the machine under a new id")
    if sum(1 for x in doc.get("edges", []) if x["enrolment_key"] == e["enrolment_key"]) > 1:
        errs.append(f"{eid}: an enrolment key serves one edge")
    cust = e.get("custodians") or []
    if cust and (len({D.person_rec(doc, c) and D.person_rec(doc, c)["person"] for c in cust}) < 2
                 or any(D.kind_of(doc, c) != "tenant" for c in cust)):
        errs.append(f"{eid}: escrow custodians are at least two different people of the organisation")
    cat = {c["entitlement"] for c in doc.get("catalogue", [])}
    for t in e.get("targets", []):
        if t["entitlement"] not in cat:
            errs.append(f"{eid}: target {t['target']} names an entitlement not in the catalogue ({t['entitlement']})")
    if len({t["target"] for t in e.get("targets", [])}) != len(e.get("targets", [])):
        errs.append(f"{eid}: a target appears twice")
    return errs


def unlock_key_errors(rid: str, key) -> list[str]:
    if key is None:
        return []
    from keyclerk import edge as E
    try:
        E.load_unlock_public(key)
        return []
    except ValueError as x:
        return [f"{rid}: unlock_key: {x}"]


def statement_errors(rid: str, sealed, expected: dict) -> list[str]:
    """The statement the officer and each node of the edge signed over the same bytes (amendment 0014d) says exactly
    what the record holds: who signs what is checked over bytes, never over a document rebuilt here."""
    from keyclerk import edge as E
    if not isinstance(sealed, dict):
        return [f"{rid}: the statement the officer and the edge sign is missing (python -m keyclerk.edge_cli statement, "
                "then cosign by the officer and by the edge)"]
    good = E.multi_signers(sealed)
    errs = []
    if expected["officer_key"] not in good:
        errs.append(f"{rid}: the officer signs the statement with their own key (the root cannot choose it)")
    for n in expected["nodes"]:
        if n["enrolment_key"] not in good:
            errs.append(f"{rid}: the edge signs the statement with its enrolment key ({E.key_id(n['enrolment_key'])})")
    if errs:
        return errs
    try:
        body = E.unseal_multi(sealed, E.statement_signers(expected), E.OFFICER_FORMAT)
    except ValueError as x:
        return [f"{rid}: the statement: {x}"]
    if body != expected:
        diff = sorted(k for k in set(body) | set(expected) if body.get(k) != expected.get(k))
        return [f"{rid}: the signed statement is not this record's ({', '.join(diff)} differ): the officer and the edge "
                "sign what the records hold"]
    return []


def person_key_errors(doc: dict, k: dict) -> list[str]:
    kid, t0, errs = k["key_id"], _ts(k["at"]), []
    if not D.same(doc, k["by"], k["anchor"]):
        errs.append(f"{kid}: a person registers their own key")
    if D.person_rec(doc, k["anchor"]) is None:
        errs.append(f"{kid}: no such person")
    if not _second_key(doc, k.get("approved_by", []), [k["anchor"]], t0):
        errs.append(f"{kid}: registering a person key needs a second key from the security officer or a named approver")
    if k.get("user_verification") is not True:
        errs.append(f"{kid}: the authenticator must verify the user (PIN or biometric)")
    try:
        from keyclerk import relay
        relay.public_key(k["public_key"])
    except ValueError as x:
        errs.append(f"{kid}: public_key: {x}")
    if k.get("ssh_key") and not SSH_KEY.fullmatch(k["ssh_key"]):
        errs.append(f"{kid}: ssh_key is an ssh-ed25519 or sk-ssh-ed25519 public key line")
    return errs


def visit_lease_errors(doc: dict, v: dict, horizon_hours: int) -> list[str]:
    lid, t0, t1, errs = v["lease_id"], _ts(v["from"]), _ts(v["until"]), []
    edges = {e["edge_id"]: e for e in doc.get("edges", [])}
    e = edges.get(v["edge"])
    if e is None:
        errs.append(f"{lid}: no such edge {v['edge']}")
    else:
        names = {t["target"] for t in e.get("targets", [])}
        if not set(v["targets"]) <= names:
            errs.append(f"{lid}: targets not on edge {v['edge']}: {', '.join(sorted(set(v['targets']) - names))}")
        if e.get("profile") != "assured":
            errs.append(f"{lid}: visit leases need an assured edge")
    if t1 <= t0:
        errs.append(f"{lid}: ends before it starts")
    elif (t1 - t0).total_seconds() > horizon_hours * 3600:
        errs.append(f"{lid}: a visit window longer than {horizon_hours} hours (set in edge.rego)")
    keys = [k for k in doc.get("person_keys", []) if D.same(doc, k["anchor"], v["person"]) and k.get("ssh_key")
            and not _ended(doc, k["key_id"], t0)]
    if not any(k["ssh_key"] == v["ssh_key"] for k in keys):
        errs.append(f"{lid}: the SSH key is not a registered key of that person")
    if not _second_key(doc, v.get("approved_by", []), [v["person"], v["by"]], t0):
        errs.append(f"{lid}: a visit lease needs a second key from the security officer or a named approver")
    return errs


def current(doc: dict, e: dict, at: datetime) -> dict:
    """An edge as it stands at `at`: its record with the latest rotation in force applied (decision 0014c)."""
    rots = [r for r in doc.get("edge_rotations", []) if r["edge"] == e["edge_id"] and _ts(r["at"]) <= at]
    if not rots:
        return e
    r = rots[-1]
    return {**e, "enrolment_key": r["enrolment_key"], "officer": r["officer"], "officer_key": r["officer_key"],
            "unlock_key": r.get("unlock_key")}       # the rotation statement states the node whole (0014d)


def _new_keys_errors(doc: dict, rid: str, r: dict) -> list[str]:
    """What an enrolment requires of its keys and officer, for the keys and officer a rotation brings: two different
    keys, a person of the organisation as officer, and an enrolment key no other edge has ever used (decision 0014a)."""
    errs = []
    if not (HEX64.fullmatch(str(r.get("enrolment_key"))) and HEX64.fullmatch(str(r.get("officer_key")))):
        errs.append(f"{rid}: the enrolment and officer keys are Ed25519 public keys in hex")
    if r.get("enrolment_key") == r.get("officer_key"):
        errs.append(f"{rid}: the edge's enrolment key and its officer's key are different keys")
    if D.kind_of(doc, r.get("officer")) != "tenant":
        errs.append(f"{rid}: the edge's officer is a person of the organisation")
    used = {x["enrolment_key"] for x in doc.get("edges", []) if x["edge_id"] != r["edge"]} |            {x["enrolment_key"] for x in doc.get("edge_rotations", []) if x["edge"] != r["edge"]}
    if r.get("enrolment_key") in used:
        errs.append(f"{rid}: an enrolment key serves one edge")
    return errs


def rotation_errors(doc: dict, r: dict) -> list[str]:
    from keyclerk import edge as E
    rid, t0, errs = r["rotation_id"], _ts(r["at"]), []
    e = next((x for x in doc.get("edges", []) if x["edge_id"] == r["edge"]), None)
    if e is None:
        return [f"{rid}: no such edge {r['edge']}"]
    officer = (doc.get("root") or {}).get("officer")
    if not (D.same(doc, r["by"], D.root_at(doc, t0)) or D.same(doc, r["by"], current(doc, e, t0)["officer"])):
        errs.append(f"{rid}: a rotation is proposed by the root or the edge's officer")
    if not _second_key(doc, [x for x in r.get("approved_by", []) if D.same(doc, x, officer)], [r["by"]], t0):
        errs.append(f"{rid}: rotating an edge's keys needs the security officer's key")
    errs += _new_keys_errors(doc, rid, r)                 # the enrolment's own invariants hold for a rotation too
    tpm = e.get("tpm")
    errs += unlock_key_errors(rid, r.get("unlock_key"))
    st = E.officer_statement(r["edge"], r["officer"], r["officer_key"],
                             [E.node(r["enrolment_key"], r.get("unlock_key"),
                                     E.tpm_commitment(tpm) if tpm and not tpm_errors(rid, tpm) else None)], purpose="rotation")
    errs += statement_errors(rid, r.get("statement"), st)
    errs += [x.replace(e["edge_id"] + ":", rid + ":") for x in officer_errors(doc, {**e, "officer": r["officer"]}, t0)]
    return errs


def check(doc: dict) -> list[str]:
    from keyclerk import policy_wasm
    errs = []
    for e in doc.get("edges", []):
        errs += edge_errors(doc, e)
    now_keys = [k for k in doc.get("person_keys", []) if not _ended(doc, k["key_id"], _ts(k["at"]))]
    for k in doc.get("person_keys", []):
        errs += person_key_errors(doc, k)
    seen_pub, active = {}, {}
    for k in now_keys:
        if k["public_key"] in seen_pub and not D.same(doc, seen_pub[k["public_key"]], k["anchor"]):
            errs.append(f"{k['key_id']}: the same public key is registered for another person")
        seen_pub.setdefault(k["public_key"], k["anchor"])
    keys = doc.get("person_keys", [])
    for i, k in enumerate(keys):                          # one active key per person: a newer one needs the old one ended
        others = [o for o in keys[:i] if D.same(doc, o["anchor"], k["anchor"]) and not _ended(doc, o["key_id"], _ts(k["at"]))]
        if others:
            errs.append(f"{k['key_id']}: one key per person: end {others[0]['key_id']} first")
        active[k["anchor"]] = k
    for r in doc.get("edge_rotations", []):
        errs += rotation_errors(doc, r)
    ssh = {}
    for k in now_keys:                                   # an SSH key belongs to one person
        if k.get("ssh_key"):
            body = " ".join(k["ssh_key"].split()[:2])
            if body in ssh and not D.same(doc, ssh[body], k["anchor"]):
                errs.append(f"{k['key_id']}: that SSH key is registered for another person")
            ssh.setdefault(body, k["anchor"])
    if doc.get("edge_visit_leases"):
        hours = int(policy_wasm.edge("settings", {})["visit_max_hours"])
        for v in doc["edge_visit_leases"]:
            errs += visit_lease_errors(doc, v, hours)
    return errs


def tpm_errors(eid: str, tpm: dict) -> list[str]:
    """An edge's TPM record (decision 0016): an RSA EK and its fingerprint, a restricted AK fixed to its TPM, a PCR
    baseline. Whether the EK certificate chains to a manufacturer root is checked at activation, against the roots the
    deployment lists then."""
    import base64
    import binascii
    import re
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from keyclerk import attest as A
    errs = []
    try:
        ek = serialization.load_der_public_key(base64.b64decode(str(tpm.get("ek_public", "")), validate=True))
    except (binascii.Error, ValueError, TypeError):
        return [f"{eid}: tpm.ek_public is the endorsement key's SubjectPublicKeyInfo, base64 DER"]
    if not isinstance(ek, rsa.RSAPublicKey) or ek.key_size < 2048:
        errs.append(f"{eid}: tpm.ek_public is an RSA 2048 endorsement key (the TCG default template)")
    elif A.spki_sha256(ek) != str(tpm.get("ek_sha256", "")).lower():
        errs.append(f"{eid}: tpm.ek_sha256 is not the fingerprint of tpm.ek_public")
    try:
        A.check_ak(A.parse_public(base64.b64decode(str(tpm.get("ak_public", "")), validate=True)))
    except (A.AttestError, binascii.Error, ValueError) as x:
        errs.append(f"{eid}: tpm.ak_public: {x}")
    base = tpm.get("pcr_baseline")
    if not isinstance(base, dict) or not base or not all(
            str(k).isdigit() and 0 <= int(k) <= 23 and re.fullmatch(r"[0-9a-f]{64}", str(v).lower()) for k, v in base.items()):
        errs.append(f"{eid}: tpm.pcr_baseline maps PCR numbers (0 to 23) to 64 hex characters")
    if tpm.get("ek_cert") is not None:
        try:
            base64.b64decode(str(tpm["ek_cert"]), validate=True)
        except (binascii.Error, ValueError):
            errs.append(f"{eid}: tpm.ek_cert is the EK certificate, base64 DER")
    return errs
