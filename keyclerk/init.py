# SPDX-License-Identifier: EUPL-1.2
"""keyclerk init: the first run. It writes the few records a fresh realm needs before anyone can act from the desk.

No desk action writes the catalogue, the realm's head or the people in the records, and creating a group needs a parent
group, so a fresh install starts from records written outside the desk. Init writes the minimum, checks it with the
engine's own checks (the same ones the desk, the signer and the reconciler run) and refuses when they fail:
  realm.yaml             the realm, the root trust owner, the security officer, and the first administrators as persons
  catalogue/<id>.yaml    one first entitlement, with its application, risk class and owner
  groups/<id>.yaml       one top group carrying that entitlement
  seed.yaml              the same records as one file: the form the desk seeds from and signs as revision 1
Init only bootstraps the first administrators (the root, the security officer, optionally an edge officer and the
entitlement's owner). Everyone else comes from the source of joiners, never from init.

Init signs nothing and holds no key. The first signed revision is made by the desk when it starts on an empty store
with --seed (with --signer, the checking signer signs it; with --signing-key, the desk's own key).

    python -m keyclerk.init TARGET --config keyclerk.yaml                       (asks for each value)
    python -m keyclerk.init TARGET --config keyclerk.yaml --no-input \\
        --realm example --root idp:root-1 --officer idp:officer-1 \\
        --entitlement admin-console --application keyclerk --risk privileged \\
        --group all [--owner ANCHOR] [--group-risk CLASS] [--edge-officer ANCHOR] [--home NAME]

TARGET must be empty or absent: init never overwrites. No value it asks for is a secret.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

RISKS = ("low", "elevated", "privileged")
SEED = "seed.yaml"
APPOINTED_BY = "keyclerk-init"      # the root holder's appointment is recorded as made by the install


class InitRefused(Exception):
    """Init will not write these records: the message says why, next_steps what completes the intent."""

    def __init__(self, message: str, next_steps: list[str] | None = None):
        super().__init__(message)
        self.next_steps = next_steps or []


# --- the values ----------------------------------------------------------------------------------------------------

FIELDS = [
    # (name, prompt, kind, required)
    ("realm", "realm name (lowercase letters, digits and hyphens)", "realm", True),
    ("home", "the home that masters these grants (empty: the realm name)", "ident", False),
    ("root", "the root trust owner's anchor at the identity provider", "anchor", True),
    ("officer", "the security officer's anchor (another person than the root)", "anchor", True),
    ("entitlement", "the first entitlement's id", "ident", True),
    ("application", "the application that entitlement belongs to", "ident", True),
    ("risk", "its risk class (low, elevated, privileged)", "risk", True),
    ("owner", "its owner's anchor (empty: the root)", "anchor", False),
    ("group", "the top group's id (it carries that entitlement)", "group", True),
    ("group_risk", "the top group's fixed class (empty: the entitlement's class)", "risk", False),
    ("edge_officer", "an edge officer's anchor (empty: none; never the root or the security officer)", "anchor", False),
]


def _value(kind: str, name: str, v: str) -> str:
    """One value through the same guards the records and the desk use; the error names the flag."""
    from keyclerk import guard
    from keyclerk.desk import GROUP_ID
    flag = "--" + name.replace("_", "-")
    try:
        if kind == "anchor":
            return guard.anchor(v, flag)
        if kind == "realm":
            guard.name(v, flag)
            if not all(c.islower() or c.isdigit() or c == "-" for c in v):
                raise guard.InputRejected(f"{flag} is lowercase letters, digits and hyphens")
            return v
        if kind == "group":
            if not GROUP_ID.fullmatch(v):
                raise guard.InputRejected(f"{flag} is 2 to 63 lowercase letters, digits and hyphens, starting with "
                                          "a letter or digit (the desk's rule for group ids)")
            return v
        if kind == "risk":
            if v not in RISKS:
                raise guard.InputRejected(f"{flag} is one of {', '.join(RISKS)}")
            return v
        return guard.ident(v, flag)
    except guard.InputRejected as e:
        raise InitRefused(str(e), [f"give {flag} again in the form it names"]) from None


def collect(a: argparse.Namespace, ask) -> dict:
    """Every value from the flags, asking for the missing ones when ask is given (one retry loop per value)."""
    out = {}
    for name, prompt, kind, required in FIELDS:
        v = getattr(a, name)
        while True:
            if v is None or v == "":
                if ask is None:
                    if required:
                        raise InitRefused(f"--{name.replace('_', '-')} is missing and init may not ask "
                                          "(--no-input, or no terminal)",
                                          [f"pass --{name.replace('_', '-')}, or run init in a terminal without --no-input"])
                    v = None
                    break
                v = ask(prompt).strip()
                if not v and not required:
                    v = None
                    break
                if not v:
                    continue
            try:
                v = _value(kind, name, v)
                distinct({**out, name: v})
                break
            except InitRefused as e:
                if ask is None:
                    raise
                print(f"  {e}", file=sys.stderr)
                v = None
        out[name] = v
    for name in ("root_person", "officer_person", "edge_officer_person", "owner_person"):
        out[name] = getattr(a, name)
    return out


def distinct(v: dict) -> None:
    """The roles init fills are held by different people (checked as each value comes, and again on the whole)."""
    root, officer, edge = v.get("root"), v.get("officer"), v.get("edge_officer")
    if root is not None and root == officer:
        raise InitRefused("the root trust owner and the security officer are one anchor: the officer's key is the "
                          "second key on the root's changes, so they are two people",
                          ["give --officer the anchor of another person than --root"])
    if edge is not None and edge in (root, officer):
        raise InitRefused("the edge officer is the root or the security officer: an edge's officer is never a core "
                          "administrator, or a core administrator could widen an edge's ceiling",
                          ["give --edge-officer the anchor of a third person, or leave it out and enrol the edge's "
                           "officer later from the source of joiners"])


# --- the records ---------------------------------------------------------------------------------------------------

def build(v: dict, now: datetime | None = None) -> dict:
    """The minimal records document from the values, or a refusal for what the engine's checks cannot see as wrong
    on an empty realm (two roles in one person, an edge officer from the core)."""
    from keyclerk import guard
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    distinct(v)
    root, officer, edge = v["root"], v["officer"], v.get("edge_officer")
    owner = v.get("owner") or root
    people = [(v.get("root_person") or "root-holder", root), (v.get("officer_person") or "security-officer", officer)]
    if edge is not None:
        people.append((v.get("edge_officer_person") or "edge-officer", edge))
    if owner not in (a for _, a in people):
        people.append((v.get("owner_person") or "entitlement-owner", owner))
    names = [n for n, _ in people]
    for n in names:
        try:
            guard.name(n, "a person's name")
        except guard.InputRejected as e:
            raise InitRefused(f"{e}: {n!r}", ["give the --*-person flags plain identifiers (letters, digits, hyphens)"]) \
                from None
    if len(set(names)) != len(names):
        raise InitRefused("two of the first administrators have the same person name",
                          ["give --root-person, --officer-person, --edge-officer-person and --owner-person "
                           "different names"])
    doc: dict = {"realm": v["realm"], "home": v.get("home") or v["realm"]}   # the loader reads a missing home as null
    doc["root"] = {"officer": officer,
                   "holders": [{"anchor": root, "appointed_by": APPOINTED_BY,
                                "from": now.isoformat().replace("+00:00", "Z")}]}
    doc["persons"] = [{"person": n, "kind": "tenant", "anchors": [a]} for n, a in people]
    if (v.get("group_risk") or v["risk"]) == "privileged":
        # power over a privileged group, and membership in it, take an admin persona (decision 0011a, enforced by
        # default): each first administrator's anchor states it, or the root could not add anyone to the top group
        for p in doc["persons"]:
            p["personas"] = [{"anchor": p["anchors"][0], "purpose": "admin"}]
    doc["grants"], doc["revocations"] = [], []
    doc["catalogue"] = [{"entitlement": v["entitlement"], "application": v["application"], "risk": v["risk"],
                         "owner": owner}]
    doc["groups"] = [{"group_id": v["group"], "parent": None, "max_risk": v.get("group_risk") or v["risk"],
                      "carries": [{"entitlement": v["entitlement"], "by": owner}]}]
    return doc


def check(doc: dict) -> list[str]:
    """The engine's own checks: schema, identifiers, zoned times, duplicates, grants, the delegation tree (as the desk,
    the checking signer and the reconciler run them)."""
    from keyclerk.reconcile import check_records
    return check_records(doc)


def _dump(doc: dict) -> str:
    from keyclerk.records import _Plain
    return yaml.dump(doc, Dumper=_Plain, sort_keys=False, default_flow_style=False, allow_unicode=False)


def refuse_non_empty(target: Path) -> None:
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        raise InitRefused(f"{target} is not an empty directory: init never overwrites records",
                          ["give an empty or new directory; a realm that already has records is changed through the "
                           "desk, not by init"])


def write(doc: dict, target: Path) -> list[Path]:
    """Check, then write the records one file per record (the engine's layout) and as one seed file, then read both
    back through the loader and check them again; the target gets all of it or nothing. Refuses a target that is not
    empty."""
    from keyclerk import records
    target = Path(target)
    refuse_non_empty(target)
    errs = check(doc)
    if errs:
        raise InitRefused("the engine's checks refuse these records: " + "; ".join(errs[:10]),
                          ["change the values the checks name and run init again"])
    target.parent.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=f".{target.name}.init-", dir=target.parent))   # all or nothing in the target
    try:
        records.split(doc, work)
        (work / SEED).write_text(_dump(doc), encoding="utf-8", newline="\n")
        as_dir = records.canonical(records.load(work))
        as_file = records.canonical(records.loads((work / SEED).read_text(encoding="utf-8")))
        want = records.canonical(doc)
        if any(as_dir.get(k) != v or as_file.get(k) != v for k, v in want.items() if v != []):
            raise InitRefused("the records read back differently from what init wrote",
                              ["report this as a fault in init; nothing was written to the target"])
        errs = check(records.loads((work / SEED).read_text(encoding="utf-8")))
        if errs:
            raise InitRefused("the records as written are refused by the engine's checks: " + "; ".join(errs[:10]),
                              ["report this as a fault in init: they passed before writing; nothing was written to "
                               "the target"])
        refuse_non_empty(target)                              # again: nothing appeared in the meantime
        if target.exists():
            target.rmdir()
        os.replace(work, target)
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    return sorted(p for p in target.rglob("*") if p.is_file())


def next_steps(target: Path, doc: dict) -> list[str]:
    seed = Path(target) / SEED
    root = doc["root"]["holders"][0]["anchor"]
    return [
        f"review the records in {target} (the first revision of realm {doc['realm']})",
        f"start the desk on an empty store with --seed {seed} and --signer (the checking signer, which signs the "
        f"first revision) or --signing-key (the key in the desk's process); the desk writes records.yaml and "
        f"records.yaml.sig as revision 1, the form the reconciler verifies with --signing-key",
        f"sign in at the desk as the root trust owner ({root}) and create the groups under {doc['groups'][0]['group_id']}",
        "connect the source of joiners: every other person comes from there, not from init",
    ]


# --- the command ---------------------------------------------------------------------------------------------------

def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="python -m keyclerk.init",
        description="Write and check the minimal records of a fresh realm: the root trust owner, the security officer, "
                    "one entitlement and one top group. Init only bootstraps the first administrators; every other "
                    "person comes from the source of joiners. It signs nothing: the desk signs the first revision "
                    "when it seeds from the file init writes.",
        epilog="Values left out are asked for in a terminal; with --no-input a missing value is refused. "
               "No value is a secret.")
    ap.add_argument("target", help="an empty or new directory for the records")
    ap.add_argument("--config", help="the KeyClerk configuration (or KEYCLERK_CONFIG); the checks read its rules")
    ap.add_argument("--no-input", action="store_true", help="never ask: every required value comes from a flag")
    for name, prompt, _, _ in FIELDS:
        ap.add_argument("--" + name.replace("_", "-"), dest=name, help=prompt)
    ap.add_argument("--root-person", help="the root's person name in the records (default root-holder)")
    ap.add_argument("--officer-person", help="the security officer's person name (default security-officer)")
    ap.add_argument("--edge-officer-person", help="the edge officer's person name (default edge-officer)")
    ap.add_argument("--owner-person", help="the owner's person name, when the owner is none of the above "
                                           "(default entitlement-owner)")
    return ap


def main(argv: list[str] | None = None) -> int:
    a = parser().parse_args(argv)
    from keyclerk import config
    try:
        if a.config:
            config.configure(a.config)
        elif not os.environ.get("KEYCLERK_CONFIG"):
            raise InitRefused("no configuration: the engine's checks read the roles and limits from it",
                              ["pass --config keyclerk.yaml, or set KEYCLERK_CONFIG"])
        target = Path(a.target)
        refuse_non_empty(target)                              # before asking anything
        ask = None if a.no_input or not sys.stdin.isatty() else (lambda p: input(f"{p}: "))
        doc = build(collect(a, ask))
        files = write(doc, target)
    except InitRefused as e:
        print(f"keyclerk init refused: {e}", file=sys.stderr)
        for s in e.next_steps:
            print(f"  next: {s}", file=sys.stderr)
        return 1
    print(f"keyclerk init wrote realm {doc['realm']} in {target}:")
    for f in files:
        print(f"  {f.relative_to(target).as_posix()}")
    print("The engine's checks accept these records. Next:")
    for i, s in enumerate(next_steps(target, doc), 1):
        print(f"  {i}. {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
