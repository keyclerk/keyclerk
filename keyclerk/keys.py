# SPDX-License-Identifier: EUPL-1.2
"""Keys and custody in the access-path graph.

A credential (a mechanical key, a badge, a code, a secret, a token, a key share, a sealed break-glass key) is a thing
in the graph: it is stored in a node (a keybox: an electronic key cabinet, a safe, a sealed envelope; a vault or PAM
check-out in software) or issued to people, and it opens named checkpoints. A checkpoint may need one key, any one of
several (a master key also opens it), or M of N held by different people (dual control, split knowledge). Physical
and digital line up: keybox and vault, master key and root credential, sealed backup and recovery shares, a key
behind its own door and an unseal key kept in the vault it unseals.

check() finds:
- lockout: a key whose every copy is behind the checkpoints it opens;
- custody: a keybox weaker than the most sensitive target its keys lead to (a master key in reception);
- dual control: one person able to gather M keys of an M-of-N checkpoint, or quorum keys in one store;
- break-glass: a sealed key whose store is not two-person, alarmed and tamper-evident, or not replaced after use;
- audit: an unlogged key on the way to something Sensitive or Restricted;
- single copy: a key with no copy and no sealed backup on the way to something Sensitive or Restricted.

Usage: library, run through tools/access_paths.py check.
"""
from __future__ import annotations



from keyclerk import access_paths as A
LABEL_ORDER = ["Internal", "Sensitive", "Restricted"]


def _creds(g: dict) -> dict[str, dict]:
    return {k["credential_id"]: k for k in g.get("credentials", [])}


def opens(g: dict, key: str) -> list[dict]:
    """The checkpoints a key opens; a backup opens what its original opens."""
    k = _creds(g).get(key, {})
    target = k.get("backup_of", key)
    return [c for c in A.checkpoints(g) if target in A.key_spec(c)[1]]


def behind(g: dict, c: dict) -> str | None:
    """The most sensitive label reachable beyond a checkpoint, with everything held (what its key leads to)."""
    allp = {x["requires"] for x in A.checkpoints(g)}
    allk = set(_creds(g))
    allp |= {x["device_requires"] for x in A.checkpoints(g) if x.get("device_requires")}
    seen = A._bfs(g, {c["to"]}, allp, allp, "normal", False, allk, True)
    labels = [n.get("label") for n in g.get("nodes", []) if n["node_id"] in seen and n.get("label")]
    return max(labels, key=LABEL_ORDER.index) if labels else None


def _store_strength(g: dict, node: str) -> int:
    return A.weakest(g, node)["layers"] or 0


def _store_strength(g: dict, node: str, scenario: str = "normal") -> int:
    return A.weakest(g, node, scenario)["layers"] or 0


def _root(creds: dict, kid: str) -> str:
    seen = set()
    while creds.get(kid, {}).get("backup_of") and kid not in seen:
        seen.add(kid)
        kid = creds[kid]["backup_of"]
    return kid


def _family(creds: dict, kid: str) -> list[str]:
    """A key with every backup of it, resolved through backup chains."""
    root = _root(creds, kid)
    return [x for x in creds if _root(creds, x) == root]


def check(g: dict, people: dict[str, set[str]] | None = None) -> list[str]:
    errs = []
    creds = _creds(g)
    nodes = A._nodes(g)
    allp = {x["requires"] for x in A.checkpoints(g)} | {x["device_requires"] for x in A.checkpoints(g) if x.get("device_requires")}
    into = lambda n: [x for x in A.checkpoints(g) if x["to"] == n]  # noqa: E731
    for n in nodes.values():   # every keybox declares its admin and override paths, which are ways in
        if n.get("keybox") and not n.get("no_override") and not any(x["kind"] in ("override", "admin") for x in into(n["node_id"])):
            errs.append(f"{n['node_id']}: a keybox declares its admin and override paths (or no_override)")
    for k in creds.values():
        kid = k["credential_id"]
        if k.get("stored_in") and k["stored_in"] not in nodes:
            errs.append(f"{kid}: stored in unknown node {k['stored_in']}")
            continue
        gated = opens(g, kid)
        if not gated:
            errs.append(f"{kid}: opens no checkpoint (an orphan key is still a key: remove or declare it)")
            continue
        label = max((behind(g, c) for c in gated if behind(g, c)), key=LABEL_ORDER.index, default=None)
        copies = [] if k.get("backup_of") else _family(creds, kid)
        for scenario in A.R["scenarios"]:
            tag = "" if scenario == "normal" else f" ({scenario})"
            if copies and not any(creds[c].get("held_by") for c in copies):
                kept = [x for x in g.get("checkpoints", []) if kid not in A.key_spec(x)[1]
                        and x.get("fails", {}).get(scenario) != "closed"]
                reach = A.reachable({**g, "checkpoints": kept}, set(A.entrances(g)), allp, allp, scenario,
                                    held=set(creds) - set(copies), pair=True)   # can anyone, two together, ever reach it
                if not any(creds[c].get("stored_in") in reach for c in copies):
                    errs.append(f"{kid}: every copy is out of reach{tag} (lockout)")
            if label and k.get("stored_in") and scenario != "break_glass":
                need = A.R["min_independent_layers"][label]
                have = _store_strength(g, k["stored_in"], scenario)
                if have < need:
                    errs.append(f"{kid}: kept in {k['stored_in']} with {have} independent layers{tag}, but it leads to "
                                f"{label} (needs {need})")
        if label in ("Sensitive", "Restricted"):
            if copies and len(copies) == 1 and k.get("copies", 1) < 2:
                errs.append(f"{kid}: leads to {label} with a single copy and no sealed backup")
            if k.get("kind") in ("mechanical_key", "badge") and any(c["requires"] == "possession" for c in gated) \
                    and k.get("copy_resistance") not in ("restricted_keyway", "secure_element"):
                errs.append(f"{kid}: a possession key to {label} declares its copy resistance (restricted keyway with a "
                            "key-control register, or a secure-element badge)")
            if k.get("held_by") and k.get("on_leaver") not in ("revoke", "change"):
                errs.append(f"{kid}: an issued key to {label} is revoked or changed at its holder's leaver event")
        if label == "Restricted" and k.get("kind") == "secret" and not (k.get("dynamic") or k.get("on_read") == "rotate"):
            errs.append(f"{kid}: a secret read is a secret held: dynamic, or rotated on read")
        if k.get("logged"):
            recorded = any(x.get("records_passage") for x in into(k["stored_in"])) if k.get("stored_in") \
                else all(c.get("records_passage") for c in gated)
            if not recorded:
                errs.append(f"{kid}: declared logged, but nothing on its way records it")
        elif label in ("Sensitive", "Restricted"):
            errs.append(f"{kid}: leads to {label} but its use is not logged")
        if k.get("sealed"):
            edges_in = into(k.get("stored_in"))
            if not edges_in or not all(x.get("two_person") and x.get("alarm") for x in edges_in) or not k.get("tamper_evident"):
                errs.append(f"{kid}: a sealed key's store is two-person, alarmed and tamper-evident on every way in")
            if k.get("on_use") != "replace":
                errs.append(f"{kid}: a sealed key is replaced (rekeyed) after every use")
    for c in A.checkpoints(g):
        m, ks = A.key_spec(c)
        if m < 2:
            continue
        fams = [_family(creds, x) for x in ks if x in creds]
        stores = [{creds[y].get("stored_in") for y in f if creds[y].get("stored_in")} for f in fams]
        keepers = [{h for y in f for h in creds[y].get("held_by", [])} for f in fams]
        for i in range(len(fams)):
            for j in range(i + 1, len(fams)):
                if stores[i] & stores[j]:
                    errs.append(f"{c['checkpoint_id']}: shares of a {m}-of-{len(ks)} lock, or their backups, share a "
                                f"store {sorted(stores[i] & stores[j])}")
                if keepers[i] & keepers[j]:
                    errs.append(f"{c['checkpoint_id']}: one custodian keeps two shares {sorted(keepers[i] & keepers[j])}")
        for p in sorted({h for s in keepers for h in s}):
            if sum(p in s for s in keepers) >= m:
                errs.append(f"{c['checkpoint_id']}: {p} holds {m} of its keys (dual control)")
        for p, ents in (people or {}).items():
            for scenario in ("normal", "break_glass"):
                got = A.obtainable_keys(g, ents, ents, p, scenario)
                if len([f for f in fams if set(f) & got]) >= m:
                    errs.append(f"{c['checkpoint_id']}: {p} can gather {m} of its keys alone"
                                f"{'' if scenario == 'normal' else ' (break-glass)'} (dual control)")
    return list(dict.fromkeys(errs))
