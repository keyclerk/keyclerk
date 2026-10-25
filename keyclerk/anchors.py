# SPDX-License-Identifier: EUPL-1.2
"""Internal anchors (decision 0028 point 1): the change log names a person by a random anchor of KeyClerk's own, never
by the identity provider's id.

    kc:<32 hex>    an internal anchor, minted once per account and never reused

The identity provider's id lives only in two erasable side tables of the store, never in a link:
    anchor_map  internal anchor -> {anchor, idp, salt, label}   the mapping, and the person's label
    anchor_idp  sha256(idp id)  -> {anchor}                     the reverse lookup a sign-in needs
The log carries an accounts record per internal anchor, {anchor, commit} with commit sha256(salt || idp id), so the
signer and the reconciler can check every mapping row, whether or not the account has a person record: a desk cannot
quietly re-point an anchor at someone else. Erasing a person deletes both rows and with them the salt; the commitment then points at nobody.

rekey(doc, amap) rewrites every anchor at records.ANCHOR_PATHS through a mapping {old anchor: new anchor} and refuses
an anchor it has no mapping for, so a migration can never leave an identity provider's id behind in the log.
"""
from __future__ import annotations

import copy
import hashlib
import re
import secrets

from keyclerk import records

PREFIX = "kc:"
INTERNAL = re.compile(r"kc:[0-9a-f]{32}")
COMMIT = re.compile(r"sha256:[0-9a-f]{64}")
# Values at an anchor path that name no person, and are never re-keyed: a situation feed (situation.py reads "feed:"
# sources), the reserved uid: prefix for a broker member without an anchor (guard.anchor), and the engine's own actors
# (visits.TIMER, keyclerk:timer, for the steps of its visit schedule).
NOT_PERSONS = ("feed:", "uid:", "keyclerk:")


class Unmapped(ValueError):
    """An anchor rekey() has no mapping for: the record and path name it."""


def new() -> str:
    """A fresh internal anchor (128 random bits)."""
    return PREFIX + secrets.token_hex(16)


def is_internal(anchor) -> bool:
    return isinstance(anchor, str) and INTERNAL.fullmatch(anchor) is not None


def is_person(value) -> bool:
    """Whether a value at an anchor path names a person (and is re-keyed), not a feed or the reserved uid: form."""
    return isinstance(value, str) and not value.lower().startswith(NOT_PERSONS)


def commitment(salt: str, idp_id: str) -> str:
    """What the log carries for an account: sha256 over the salt's bytes and the identity provider's id."""
    return "sha256:" + hashlib.sha256(bytes.fromhex(salt) + idp_id.encode("utf-8")).hexdigest()


def idp_key(idp_id: str) -> str:
    """The reverse table's key for an identity provider's id (kept only in the erasable side table)."""
    return hashlib.sha256(idp_id.encode("utf-8")).hexdigest()


def sub_key(subject: str) -> str:
    """The reverse table's key for a broker subject (the user id a token's sub carries), once the reconciler linked it."""
    return idp_key("sub:" + subject)


def resolve(view, claims: dict) -> str | None:
    """The internal anchor a token's claims name, through a store's mapping (decision 0028), or None.

    Two phases: a row the reconciler has linked to its broker subject accepts only that subject, so an anchor attribute
    moved to another account names nobody; a row not yet linked accepts the legacy anchor claim, as before the change
    log (no regression while the reconciler links everyone)."""
    sub, legacy = claims.get("sub"), claims.get("anchor")
    if isinstance(sub, str) and sub:
        hit = view.side_get("anchor_idp", sub_key(sub))
        if hit is not None:
            return hit["anchor"]
    if not isinstance(legacy, str) or not legacy:
        return None
    hit = view.side_get("anchor_idp", idp_key(legacy))
    if hit is None:
        return None
    row = view.side_get("anchor_map", hit["anchor"]) or {}
    if row.get("sub") is not None and row.get("sub") != sub:
        return None                                   # linked to another subject: the attribute was moved or copied
    return hit["anchor"]


def mapping_row(idp_id: str, label: str | None = None, anchor: str | None = None) -> dict:
    """A mapping row for one account: a new internal anchor (unless given), the id and a fresh salt."""
    row = {"anchor": anchor or new(), "idp": idp_id, "salt": secrets.token_hex(16)}
    if label:
        row["label"] = label
    return row


def accounts(person: dict) -> list[str]:
    """A person record's accounts: its anchors and its personas' (an admin persona is an account of its own); the
    record's commits[] vouch for each of them."""
    return list(person.get("anchors") or []) + [x.get("anchor") for x in person.get("personas") or []
                                                 if isinstance(x, dict) and isinstance(x.get("anchor"), str)]


def inward(view, value: str) -> str | None:
    """The internal anchor for a value naming a person (decision 0028, the boundary): itself when internal, through
    the mapping when it is an account the store maps, None when the store knows no such person."""
    if is_internal(value):
        return value
    hit = view.side_get("anchor_idp", idp_key(value))
    return hit["anchor"] if hit else None


def row_matches(row: dict, commits) -> bool:
    """Whether a mapping row is one the log vouches for: its commitment is among the account's commitments."""
    try:
        return commitment(row["salt"], row["idp"]) in set(commits or ())
    except (KeyError, TypeError, ValueError):
        return False


def _rewrite(node, parts: list[str], fn) -> None:
    if not parts or not isinstance(node, dict):
        return
    head, rest = parts[0], parts[1:]
    many = head.endswith("[]")
    key = head[:-2] if many else head
    if key not in node:
        return
    if many:
        items = node[key]
        if not isinstance(items, list):
            return
        if rest:
            for item in items:
                _rewrite(item, rest, fn)
        else:
            node[key] = [fn(v) if isinstance(v, str) else v for v in items]
    elif rest:
        _rewrite(node[key], rest, fn)
    elif isinstance(node[key], str):
        node[key] = fn(node[key])


def _parts(path: str) -> list[str]:
    return path.replace("[].", "[] ").replace(".", " ").split()


def rekey(doc: dict, amap: dict[str, str]) -> dict:
    """A copy of a records document with every anchor at records.ANCHOR_PATHS replaced through amap. An anchor amap does
    not name, and that is not already internal, raises Unmapped: nothing of the identity provider may stay behind."""
    out = copy.deepcopy(doc)
    for kind, paths in records.ANCHOR_PATHS.items():
        value = out.get(kind)
        recs = [value] if isinstance(value, dict) else value if isinstance(value, list) else []
        for rec in recs:
            for path in paths:
                def fn(a, kind=kind, path=path):
                    if a in amap:
                        return amap[a]
                    if is_internal(a) or not is_person(a):
                        return a
                    raise Unmapped(f"{kind}.{path}: no internal anchor for {a[:40]!r}")
                _rewrite(rec, _parts(path), fn)
    return out


def unmapped(doc: dict, amap: dict[str, str]) -> list[str]:
    """Every anchor in a document that rekey(doc, amap) would refuse, as kind.path=value."""
    out = []
    for kind in records.ANCHOR_PATHS:
        value = doc.get(kind)
        for rec in ([value] if isinstance(value, dict) else value if isinstance(value, list) else []):
            if isinstance(rec, dict):
                out += [f"{kind}.{p}={v}" for p, v in records.anchor_values(kind, rec)
                        if v not in amap and not is_internal(v) and is_person(v)]
    return out
