# SPDX-License-Identifier: EUPL-1.2
"""Access paths: one graph of where a subject can be and what it can act on, physical and digital.

Nodes are spaces and containers (physical), devices, sessions, segments, workloads and data (digital), plus outside
entrances. Every edge is a checkpoint with one enforcement point and a requirement (an entitlement of the catalogue,
or free), for the person, the device or both. Hosting links the two worlds: a workload hosted in a container can be
reached from that container through its console.

Strength is not a count of names: a checkpoint lists what it depends on (its controller, its credential, its admin
path); checkpoints that share a dependency fail together, so a way in counts one layer per group of checkpoints joined
by shared dependencies. A portable container's lock counts as delay only. A free exit is also a way in
through its exit hardware. Every Restricted target needs a two-person checkpoint on every way in.
Scenarios (fire release, power loss, cut off) open the checkpoints that fail open in them, and every analysis runs per
scenario. The search is depth-first with an adjacency index and branch and bound; hitting the length bound is
a finding, never a silent pass.

Usage: python -m keyclerk.access_paths GRAPH.yaml [--records RECORDS.yaml]
"""
from __future__ import annotations

import sys
from collections import defaultdict, deque
from pathlib import Path

import yaml

from keyclerk import config

R = config.Section("access_paths")
REQUIRED = ("checkpoint_id", "from", "to", "kind", "layer", "pep", "requires", "depends_on")


def _nodes(g: dict) -> dict[str, dict]:
    return {n["node_id"]: n for n in g.get("nodes", [])}


def checkpoints(g: dict) -> list[dict]:
    """The declared checkpoints plus derived ones: console edges from a hosting container to what it hosts."""
    out = list(g.get("checkpoints", []))
    for n in g.get("nodes", []):
        h = n.get("hosted_in")
        if h:
            out.append({"checkpoint_id": f"console:{h}>{n['node_id']}", "from": h, "to": n["node_id"],
                        "kind": "console", "layer": "physical", "pep": n.get("console_pep", "console"),
                        "requires": n.get("console_requires", "free"),
                        "depends_on": n.get("console_depends_on", [f"console:{h}"]), "derived": True,
                        **({"keys": n["console_keys"]} if n.get("console_keys") else {})})
    return out


def _open_in(c: dict, scenario: str) -> bool:
    return scenario != "normal" and c.get("fails", {}).get(scenario) == "open"


def edges(g: dict, scenario: str = "normal") -> list[tuple[str, str, dict, bool]]:
    """(from, to, checkpoint, reverse) for every crossing: forward; back when both ways; back for free when it is a
    free exit (leaving)."""
    out = []
    for c in checkpoints(g):
        out.append((c["from"], c["to"], c, False))
        if c.get("direction") == "both" or c.get("exit") == "free":
            out.append((c["to"], c["from"], c, True))
    return out


def _free(c: dict, reverse: bool, scenario: str = "normal") -> bool:
    return c.get("requires") == "free" or (reverse and c.get("exit") == "free") or _open_in(c, scenario)


def key_spec(c: dict) -> tuple[int, list[str]]:
    """(m, keys): the checkpoint opens with m of these credentials; a list means all of them."""
    k = c.get("keys")
    if not k:
        return 0, []
    if isinstance(k, list):
        return len(k), k
    return k["m"], k["of"]


def keys_ok(c: dict, held: set[str]) -> bool:
    m, ks = key_spec(c)
    return len([x for x in ks if x in held]) >= m


def passes(c: dict, reverse: bool, person: set[str], device: set[str], scenario: str = "normal",
           held: set[str] = frozenset(), pair: bool = False) -> bool:
    """Whether a subject crosses c: authorised for its requirement (a PEP that checks who you are) and holding its
    keys (a lock that checks what you hold); possession means the keys alone decide."""
    if _free(c, reverse, scenario):
        return True
    if c.get("two_person") and not pair:
        return False   # one subject alone never crosses a two-person checkpoint
    if not keys_ok(c, held):
        return False
    need, who = c["requires"], c.get("subject", "person")
    if need == "possession":
        return True
    dev_need = c.get("device_requires", need)
    return (who == "device" or need in person) and (who == "person" or dev_need in device)


def reachable(g: dict, starts: set[str], person: set[str], device: set[str] = frozenset(),
              scenario: str = "normal", tailgating: bool = False, held: set[str] = frozenset(),
              anchor: str | None = None, pair: bool = False) -> set[str]:
    """Nodes reachable from starts. tailgating: a checkpoint without tailgate resistance is crossable by anyone next
    to a holder, so presence is widened through it. Keys: the subject holds what was issued to it (anchor) and
    picks up every credential stored in a node it reaches, until nothing new is reached (a fixed point)."""
    held = set(held) | held_keys(g, anchor)
    seen = set(starts)
    while True:
        seen = _bfs(g, seen, person, device, scenario, tailgating, held, pair)
        found = {k["credential_id"] for k in g.get("credentials", []) if k.get("stored_in") in seen
                 and k.get("release_requires") in (None, *person) and _usable(k, scenario)}
        found |= {k["backup_of"] for k in g.get("credentials", []) if k["credential_id"] in found and k.get("backup_of")}
        if found <= held:
            return seen
        held |= found


def _usable(k: dict, scenario: str) -> bool:
    """Sealed keys are taken only in the break-glass scenario, never on a routine route."""
    return not k.get("sealed") or scenario == "break_glass"


def held_keys(g: dict, anchor: str | None) -> set[str]:
    """Keys issued to the subject; a sealed backup in hand counts as the key it backs up."""
    own = {k["credential_id"] for k in g.get("credentials", []) if anchor and anchor in k.get("held_by", [])}
    return own | {k["backup_of"] for k in g.get("credentials", []) if k["credential_id"] in own and k.get("backup_of")}


def obtainable_keys(g: dict, person: set[str], device: set[str] = frozenset(), anchor: str | None = None,
                    scenario: str = "normal") -> set[str]:
    seen = reachable(g, set(entrances(g)), person, device, scenario, anchor=anchor)
    got = held_keys(g, anchor) | {k["credential_id"] for k in g.get("credentials", []) if k.get("stored_in") in seen
                                  and k.get("release_requires") in (None, *person) and _usable(k, scenario)}
    return got | {k["backup_of"] for k in g.get("credentials", []) if k["credential_id"] in got and k.get("backup_of")}


def _bfs(g, starts, person, device, scenario, tailgating, held, pair=False) -> set[str]:
    adj = defaultdict(list)
    for a, b, c, rev in edges(g, scenario):
        adj[a].append((b, c, rev))
    seen, todo = set(starts), deque(starts)
    while todo:
        u = todo.popleft()
        for b, c, rev in adj[u]:
            if b in seen:
                continue
            if passes(c, rev, person, device, scenario, held, pair) or (
                    tailgating and c.get("tailgate_resistance", "none") == "none" and _kind(g, b) in ("space", "outside")):
                seen.add(b)
                todo.append(b)
    return seen


def _kind(g: dict, nid: str) -> str:
    return _nodes(g).get(nid, {}).get("kind", "")


def possible_presence(g: dict, last_checkpoint: str, person: set[str], device: set[str] = frozenset(),
                      scenario: str = "normal", tailgating: bool = True) -> set[str]:
    """Where the subject can be (physical) or reach (digital) after passing last_checkpoint; by default tailgating
    through checkpoints that do not resist it is assumed, because a roll call that ignores it is wrong."""
    c = next((x for x in checkpoints(g) if x["checkpoint_id"] == last_checkpoint), None)
    if c is None:
        raise ValueError(f"unknown checkpoint {last_checkpoint}")
    return reachable(g, {c["to"]}, person, device, scenario, tailgating)


def entrances(g: dict) -> list[str]:
    return [n["node_id"] for n in g.get("nodes", []) if n.get("entrance")]


def _inward(g: dict, scenario: str) -> dict[str, list[tuple[str, dict]]]:
    """The edges a way in may use: every checkpoint forward and both-way ones backwards. An emergency exit is declared
    as its own checkpoint from outside in, requiring exit-hardware, so a propped or forced exit is a way in."""
    adj = defaultdict(list)
    for c in checkpoints(g):
        adj[c["from"]].append((c["to"], c))
        if c.get("direction") == "both":
            adj[c["to"]].append((c["from"], c))
    return adj


def layers(g: dict, path: list[dict], scenario: str = "normal") -> int:
    """Independent layers on a way in: checkpoints that require something (in this scenario) grouped by shared
    dependencies; a portable container's lock is delay only."""
    ns = _nodes(g)
    parent: dict[str, str] = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            x = parent[x]
        return x

    groups = set()
    counted = [c for c in path if not _free(c, False, scenario) and not ns.get(c["to"], {}).get("portable")]
    for c in counted:
        deps = _deps(g, c)
        for d in deps[1:]:
            parent[find(d)] = find(deps[0])
    for c in counted:
        groups.add(find(_deps(g, c)[0]))
    return len(groups)


def _deps(g: dict, c: dict) -> list[str]:
    """What a checkpoint fails with: its declared dependencies and every key that opens it, with that key's backups,
    so one master key across many doors is one layer."""
    ks = key_spec(c)[1]
    backups = [b["credential_id"] for b in g.get("credentials", []) for k in ks if b.get("backup_of") == k]
    return (c.get("depends_on") or [c["checkpoint_id"]]) + [f"key:{k}" for k in ks + backups]


def weakest(g: dict, target: str, scenario: str = "normal") -> dict:
    """The way in with the fewest independent layers, by depth-first search with branch and bound (layers never shrink
    along a way, so a branch at or above the best is cut); truncated is set when the length bound cut a search, which
    is a finding. two_person_everywhere: no way in avoids every two-person checkpoint."""
    adj = _inward(g, scenario)
    best = {"layers": None, "path": [], "truncated": False}

    def walk(u: str, seen: frozenset, trail: list):
        if len(trail) > R["max_path_length"]:
            best["truncated"] = True
            return
        cur = layers(g, trail, scenario)
        if best["layers"] is not None and cur >= best["layers"]:
            return
        if u == target:
            best["layers"], best["path"] = cur, [c["checkpoint_id"] for c in trail]
            return
        for b, c in adj[u]:
            if b not in seen:
                walk(b, seen | {b}, trail + [c])

    for e in entrances(g):
        walk(e, frozenset({e}), [])
    best["any"] = best["layers"] is not None
    seen, todo = set(entrances(g)), deque(entrances(g))
    while todo:   # can the target be reached without crossing any two-person checkpoint?
        u = todo.popleft()
        for b, c in adj[u]:
            if b not in seen and not (c.get("two_person") and not _free(c, False, scenario)):
                seen.add(b)
                todo.append(b)
    best["two_person_everywhere"] = target not in seen
    return best


def route(g: dict, target: str, person: set[str], device: set[str] = frozenset(), requester: str | None = None,
          others: dict[str, set[str]] | None = None, scenario: str = "normal") -> dict:
    """The way in with the fewest gaps. An escort holds the whole rest of the way from the first gap and is not the
    requester; a broker gap (digital) is bridged only by a recording broker service with an approver other than the
    requester, never by sharing someone's entitlement."""
    adj = _inward(g, scenario)
    found: list[list[dict]] = []

    def walk(u, seen, trail):
        if len(trail) > R["max_path_length"]:
            return
        if u == target:
            found.append(trail)
            return
        for b, c in adj[u]:
            if b not in seen:
                walk(b, seen | {b}, trail + [c])

    for e in entrances(g):
        walk(e, {e}, [])
    if not found:
        return {"reachable": False, "path": [], "missing": [], "prerequisites": [], "escorts": [], "broker": [],
                "obligations": []}
    held = obtainable_keys(g, person, device, requester, scenario)
    p, gaps = min(((p, [c for c in p if not passes(c, False, person, device, scenario, held)]) for p in found),
                  key=lambda x: (len(x[1]), len(x[0])))
    rest = p[p.index(gaps[0]):] if gaps else []
    physical_gaps = [c for c in gaps if c["layer"] == "physical"]
    escorts = []
    if physical_gaps and all(c.get("escort") == "allowed" for c in physical_gaps):
        need = {c["requires"] for c in rest if c["layer"] == "physical" and not _free(c, False, scenario)
                and c["requires"] != "possession"}
        keyed = [c for c in rest if c["layer"] == "physical" and key_spec(c)[1]]
        escorts = sorted(a for a, ents in (others or {}).items() if need <= ents and a != requester
                         and all(keys_ok(c, obtainable_keys(g, ents, ents, a, scenario)) for c in keyed))
    broker = [c["checkpoint_id"] for c in gaps if c.get("broker")]
    stores = {k["credential_id"]: k.get("stored_in") or "issued" for k in g.get("credentials", [])}
    second_person = [c["checkpoint_id"] for c in p if c.get("two_person") and not _free(c, False, scenario)]
    missing_keys = {c["checkpoint_id"]: {k: stores.get(k) for k in key_spec(c)[1] if k not in held}
                    for c in gaps if key_spec(c)[1] and not keys_ok(c, held)}
    return {"reachable": not gaps, "path": [c["checkpoint_id"] for c in p], "missing": [c["checkpoint_id"] for c in gaps],
            "prerequisites": sorted({c["requires"] for c in gaps if c["requires"] not in ("possession", *person)}),
            "escorts": escorts,
            "broker": broker, "missing_keys": missing_keys, "second_person": second_person,
            "obligations": obligations(p)[0]}


def obligations(path: list[dict]) -> tuple[list[str], list[str]]:
    """(obligations, problems): they add up; an obligation outside the vocabulary, one the checkpoint's PEP cannot
    enforce, or two that conflict is a problem, and a problem denies."""
    vocab, conflicts = set(R["obligations"]), [set(x) for x in R["obligation_conflicts"]]
    got, problems = set(), []
    for c in path:
        for o in c.get("obligations", []):
            if o not in vocab:
                problems.append(f"{c['checkpoint_id']}: unknown obligation {o}")
            if "enforces" in c and o not in c["enforces"]:
                problems.append(f"{c['checkpoint_id']}: {c['pep']} cannot enforce {o}")
            got.add(o)
    problems += [f"conflicting obligations {sorted(x)}" for x in conflicts if x <= got]
    return sorted(got), problems


def check(g: dict, catalogue: set[str] | None = None, people: dict[str, set[str]] | None = None) -> list[str]:
    errs = []
    ns = _nodes(g)
    if not entrances(g):
        errs.append("no entrance node")
    for c in g.get("checkpoints", []):
        miss = [f for f in REQUIRED if f not in c]
        if miss:
            errs.append(f"{c.get('checkpoint_id', '?')}: missing {miss}")
            continue
        for end in (c["from"], c["to"]):
            if end not in ns:
                errs.append(f"{c['checkpoint_id']}: unknown node {end}")
        if catalogue is not None and c["requires"] not in ("free", "exit-hardware", "possession") and c["requires"] not in catalogue:
            errs.append(f"{c['checkpoint_id']}: requires {c['requires']}, which is not in the catalogue")
        errs += obligations([c])[1]
    if errs:
        return errs
    for n in ns.values():
        if n.get("hosted_in") and n["hosted_in"] not in ns:
            errs.append(f"{n['node_id']}: hosted in unknown node {n['hosted_in']}")
    for scenario in R["scenarios"]:
        tag = "" if scenario == "normal" else f" ({scenario})"
        for n in ns.values():
            if n["kind"] == "space" and scenario == "normal" and not reachable_free_exit(g, n["node_id"]):
                errs.append(f"{n['node_id']}: no free way out to an entrance (life safety)")
            label = n.get("label")
            if not label:
                continue
            w = weakest(g, n["node_id"], scenario)
            if w["truncated"]:
                errs.append(f"{n['node_id']}: the search hit the path length bound{tag}; the weakest way in is unknown")
            if not w["any"]:
                continue
            need = R["min_independent_layers"][label]
            if w["layers"] < need:
                errs.append(f"{n['node_id']}: {label} needs {need} independent layers, the weakest way in has "
                            f"{w['layers']}{tag}: {' > '.join(w['path'])}")
            if label in R["two_person_for"] and not w["two_person_everywhere"]:
                errs.append(f"{n['node_id']}: a way in without a two-person checkpoint{tag}")
    from keyclerk import keys
    from keyclerk import pools
    errs += keys.check(g, people)
    errs += pools.check(g, people)
    return list(dict.fromkeys(errs))


def reachable_free_exit(g: dict, start: str) -> bool:
    seen, todo = {start}, deque([start])
    ents = set(entrances(g))
    adj = edges(g)
    while todo:
        u = todo.popleft()
        if u in ents:
            return True
        for a, b, c, rev in adj:
            if a == u and b not in seen and _free(c, rev):
                seen.add(b)
                todo.append(b)
    return False


def roster(grants_file: Path) -> dict[str, set[str]]:
    """Every person of the realm with the entitlements they hold now through groups, so the dual-control and pool
    checks run for real people."""
    from datetime import datetime, timezone
    from keyclerk import delegation
    from keyclerk import records
    doc = records.load(grants_file)
    now = datetime.now(timezone.utc)
    return {a: set(delegation.effective_entitlements(doc, a, now)) for p in doc.get("persons", []) for a in p["anchors"]}


def main(argv: list[str]) -> int:
    """python -m keyclerk.access_paths GRAPH.yaml [--records RECORDS.yaml]: check a graph; with records, against their
    catalogue and with every person's entitlements (the dual-control and pool checks)."""
    args = list(argv)
    records_file = None
    if "--records" in args:
        i = args.index("--records")
        records_file = Path(args[i + 1])
        del args[i:i + 2]
    bad = 0
    for f in [Path(a) for a in args]:
        cat, people = None, None
        if records_file:
            doc = yaml.safe_load(records_file.read_text(encoding="utf-8")) or {}
            cat = {e["entitlement"] for e in doc.get("catalogue", [])}
            people = roster(records_file)
        for e in check(yaml.safe_load(f.read_text(encoding="utf-8")), cat, people):
            print(f"{f}: {e}", file=sys.stderr)
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
