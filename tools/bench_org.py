"""A real organisation's working day through the checking signer (decision 0022): what a change costs, how long changes
wait at the busiest hour, and how much headroom is left. The method, the assumptions and their sources:
docs/testing/realistic-load.md.

The organisation (defaults: 20,000 employees, 5,000 groups, 1,000 agents, 5,000 workloads, 1,000 contractors):
departments are groups under the fixture's office group, each with a manager holding a delegation over it, teams are
groups under the departments; birthright access comes from attribute rules (one rule record per department), so only
the exceptions are named memberships (--named per employee). Visits, devices and gate events are not here: visits are
files outside the signed log, devices and gate passages never become records.

The day: per kind of change a daily count (JOINERS and the rest below, overridable), spread over the working hours by
HOURS. The run measures what each kind costs by proposing --sample changes drawn from the day's mix, then replays the
whole day's arrivals against those costs on one queue (the signer applies one change at a time), so the wait at the
busiest hour comes from measured service times, not an assumption.

    python tools/bench_org.py [--employees 20000] [--groups 5000] [--agents 1000] [--workloads 5000]
                              [--named 2] [--history-days 0] [--sample 200] [--scale 1.0] [--agent-tasks 0]
                              [--rate KIND=N ...] [--full-check] [--json FILE]

--history-days N adds N working days of past changes as ended records (an organisation after N days in production,
nothing pruned). --scale multiplies every daily count (a busy day, or a reorganisation week). --agent-tasks K gives
every agent K task grants a day (agents that ask for access per task).
"""
from __future__ import annotations

import argparse
import copy
import json
import random
import shutil
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from bench_checks import FIXTURES, bench_config  # noqa: E402
from bench_scale import peak_mb  # noqa: E402
from keyclerk import config  # noqa: E402

AT = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
FIRST = datetime(2026, 10, 1, tzinfo=timezone.utc)       # the fixture's delegations start here
LAST = datetime(2027, 3, 29, tzinfo=timezone.utc)        # and end the day after this
PART = 500
WORKING_DAYS = 230

# Changes per working day for 20,000 employees (scaled by headcount); each line's source is in the document.
DAILY = {
    "joiner": 10,       # 12 % turnover a year: 2,400 joiners over 230 working days
    "leaver": 10,       # the same 2,400 leaving
    "mover": 17,        # up to 20 % change role or department a year in a large organisation (31 a day May to July)
    "request": 175,     # 2 access requests per employee a year that rules do not cover
    "removal": 40,      # access given back or taken away early
    "renewal": 11,      # recertification: every named membership renewed twice a year, by its manager, 40 at a time
    "jit": 200,         # privileged access for a few hours: 500 administrators, most days one or two
    "lease": 15,        # contractors: 1,000 at a time, three months each, plus extensions
    "workload": 10,     # services deployed or retired (credential rotation is not a record)
    "group": 5,         # a team created or restructured
}
RENEWAL_BATCH = 40
# Share of the day's changes in each working hour, 08:00 to 18:00 (a morning peak, a lunch dip, an afternoon peak).
HOURS = {8: 0.10, 9: 0.15, 10: 0.14, 11: 0.11, 12: 0.06, 13: 0.09, 14: 0.12, 15: 0.11, 16: 0.08, 17: 0.04}


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Org:
    """The generated organisation's shape, so changes can be made against it without reading the store."""

    def __init__(self, a, rnd: random.Random):
        self.a, self.rnd = a, rnd
        self.depts = max(1, a.groups // 20)                    # 20 groups to a department: 1 department, 19 teams
        self.teams = max(1, a.groups - self.depts)
        self.units = ["office", "site-crews", "herent-desk"]
        self.next = Counter()
        self.members: dict[str, list[tuple[str, str, int]]] = defaultdict(list)   # anchor -> (membership id, team, dept)
        self.keys = Keys()

    def emp(self, i: int) -> str:
        return f"idp:{i:06x}-emp"

    def manager(self, d: int) -> str:
        return self.emp(d)                                     # the first employees manage the departments

    def dept_of(self, i: int) -> int:
        return (i + 1) % self.depts if i < self.depts else i % self.depts   # a manager is added by another

    def team(self, d: int) -> int:
        return d + self.depts * self.rnd.randrange(max(1, self.teams // self.depts))

    def nid(self, prefix: str) -> str:
        self.next[prefix] += 1
        return f"{prefix}-org-{self.next[prefix]:06d}"

    def membership(self, anchor: str, d: int, start: datetime, end: datetime | None = None) -> dict:
        t = self.team(d)
        mid = self.nid("M")
        rec = {"membership_id": mid, "group": f"team-{t}", "member": {"anchor": anchor}, "under": f"D-dept-{d:04d}",
               "by": self.manager(d), "start": iso(start), "end": iso(min(end or start + timedelta(days=170), LAST))}
        self.members[anchor].append((mid, f"team-{t}", d))
        return rec


def put(kind: str, key: str, rec: dict) -> dict:
    return {"op": "put", "kind": kind, "key": key, "record": rec}


class Keys:
    """The organisation is generated with readable identity provider names; the log names people only by internal
    anchors (decision 0028). Every op is re-keyed here, by a deterministic anchor per name, and the first change that
    names an account carries its accounts record (and, proposed, its mapping row), as a desk's change would."""

    def __init__(self):
        self.seen: set[str] = set()

    @staticmethod
    def anchor(name: str) -> str:
        import hashlib
        return "kc:" + hashlib.sha256(("anchor:" + name).encode()).hexdigest()[:32]

    @staticmethod
    def row(name: str) -> dict:
        import hashlib
        return {"anchor": Keys.anchor(name), "idp": name, "salt": hashlib.sha256(("salt:" + name).encode()).hexdigest()[:32]}

    def rekeyed(self, ops: list[dict]) -> tuple[list[dict], list[dict]]:
        """(the ops re-keyed with the accounts records of names seen for the first time, their mapping rows)."""
        from keyclerk import anchors as A
        from keyclerk import records as R
        names: set[str] = set()
        for op in ops:
            if op["op"] != "put":
                continue
            kind, recs = (op["key"], op["record"]["value"]) if op["kind"] == "head" else (op["kind"], op["record"])
            for rec in recs if isinstance(recs, list) else [recs]:
                if isinstance(rec, dict):
                    names |= {v for _, v in R.anchor_values(kind, rec) if A.is_person(v) and not A.is_internal(v)}
        amap = {n: self.anchor(n) for n in names}
        out = []
        for op in ops:
            if op["op"] == "put" and op["kind"] == "head":
                out.append({**op, "record": {"value": A.rekey({op["key"]: op["record"]["value"]}, amap)[op["key"]]}})
            elif op["op"] == "put":
                out.append({**op, "record": A.rekey({op["kind"]: [op["record"]]}, amap)[op["kind"]][0]})
            else:
                out.append(op)
        rows = [self.row(n) for n in sorted(names - self.seen)]
        self.seen |= names
        out += [put("accounts", r["anchor"], {"anchor": r["anchor"], "commit": A.commitment(r["salt"], r["idp"])})
                for r in rows]
        return sorted(out, key=lambda o: (o["kind"], o["key"])), rows


def stream(org: Org, history_days: int):
    """The fixture's records, then the organisation part by part (ops lists), so it is never held whole."""
    from keyclerk.store import migrate as M
    a = org.a
    doc = yaml.safe_load((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
    head, ops, _ = M.split(doc)
    yield head + ops
    template_lease = doc["leases"][0]
    part: list[dict] = []

    def flush():
        nonlocal part
        if len(part) >= PART:
            out, part = part, []
            return out
        return None

    for d in range(org.depts):
        part.append(put("groups", f"dept-{d}", {"group_id": f"dept-{d}", "parent": "office", "max_risk": "low",
                                                "carries": []}))
        part.append(put("delegations", f"D-dept-{d:04d}", M._json({
            "delegation_id": f"D-dept-{d:04d}", "delegate": org.manager(d), "group": f"dept-{d}", "powers": ["members", "rules"],
            "max_risk": "low", "max_membership_days": 180, "depth_left": 0, "start": FIRST, "end": LAST + timedelta(days=1),
            "by": "idp:7c1f-ann", "parent": "D-example-0001", "approved_by": ["idp:31ee-ingrid"]})))
        part.append(put("memberships", f"M-rule-{d:04d}", {
            "membership_id": f"M-rule-{d:04d}", "group": f"team-{d}", "under": f"D-dept-{d:04d}", "by": org.manager(d),
            "member": {"rule": {"attribute": "unit", "values": [f"dept-{d}"], "source": "HR source",
                                "max_age_hours": 24}}, "start": iso(FIRST), "end": iso(FIRST + timedelta(days=170))}))
        if (out := flush()):
            yield out
    for t in range(org.teams):
        d = t % org.depts
        part.append(put("groups", f"team-{t}", {"group_id": f"team-{t}", "parent": f"dept-{d}", "max_risk": "low",
                                                "carries": [{"entitlement": "share-read", "by": "idp:2b9e-owner"}]}))
        if (out := flush()):
            yield out
    span = (AT - FIRST).days

    def person(kind: str, i: int, anchor: str, d: int, n: int):
        rec = {"person": anchor.split(":")[1], "kind": kind, "anchors": [anchor]}
        if kind == "tenant":
            rec["unit"] = org.units[i % 3]
        else:
            rec["owner"] = org.manager(d)                      # who answers for it
            if kind == "agent":
                rec["director"] = org.manager(d)
        part.append(put("persons", rec["person"], rec))
        for _ in range(n):
            start = FIRST + timedelta(days=org.rnd.randrange(max(1, span)), minutes=org.rnd.randrange(600))
            m = org.membership(anchor, d, start)
            part.append(put("memberships", m["membership_id"], m))

    for i in range(a.employees):
        person("tenant", i, org.emp(i), org.dept_of(i), a.named)
        if (out := flush()):
            yield out
    for i in range(a.agents):
        person("agent", i, f"agent:{i:06x}-bot", i % org.depts, 1)
        if (out := flush()):
            yield out
    for i in range(a.workloads):
        person("workload", i, f"spiffe:{i:06x}-svc", i % org.depts, 1)
        if (out := flush()):
            yield out
    for i in range(a.contractors):
        rec = M._json({**copy.deepcopy(template_lease), "lease_id": f"L-org-{i:06d}", "anchor": f"ext:{i:06x}-ctr",
                       "identity_hash": f"hmac-sha256:{i:016x}"})
        part.append(put("leases", rec["lease_id"], rec))
        if (out := flush()):
            yield out
    # History: what N past working days left behind as ended records (requests, removals, renewals, movers).
    per_day = int(DAILY["request"] + DAILY["removal"] + DAILY["renewal"] * RENEWAL_BATCH + DAILY["mover"] * 2)
    per_day = int(per_day * a.employees / 20000)
    for _ in range(history_days):
        for _ in range(per_day):
            i = org.rnd.randrange(org.depts, a.employees)
            start = FIRST + timedelta(days=org.rnd.randrange(max(1, span - 1)), minutes=org.rnd.randrange(600))
            m = org.membership(org.emp(i), org.dept_of(i), start, start + timedelta(days=1))
            org.members[org.emp(i)].pop()                      # ended: not a membership a change can touch
            part.append(put("memberships", m["membership_id"], m))
            if (out := flush()):
                yield out
    if part:
        yield part


def build(org: Org, state: Path, key, history_days: int):
    from keyclerk.signer import Signer
    from keyclerk.store import link as L
    from keyclerk.store import migrate as M
    from keyclerk.store.sqlite import SqliteStore
    s = Signer(key, state)
    store = SqliteStore(state / "replica.db", s.public_key(), "example")
    h = None
    for ops in stream(org, history_days):
        ops, rows = org.keys.rekeyed(ops)
        M.put_rows(store, rows)
        sealed = L.seal_link(key, "example", store.size(), h.hex() if h else L.ZERO, 1, iso(AT), ops, {"action": "bench"})
        h = store.append(sealed)
    store.add_checkpoint(L.seal_checkpoint(key, "example", store.size(), store.root(), h, 1, iso(AT)))
    s._hold()
    s.replica = store
    s._write_mark()
    s.config_pending = False
    return s


def change(kind: str, org: Org, s, i: int) -> list[dict]:
    """One change of this kind, as the desk would propose it."""
    from keyclerk.store import migrate as M
    a, rnd, r = org.a, org.rnd, s.replica
    now = AT + timedelta(minutes=i)
    pick = lambda: rnd.randrange(org.depts, a.employees)        # noqa: E731 - an employee who is not a manager
    if kind in ("joiner", "workload"):
        n = org.next["J"] = org.next["J"] + 1
        anchor = f"idp:{n:06x}-new" if kind == "joiner" else f"spiffe:{n:06x}-new"
        d = rnd.randrange(org.depts)
        p = {"person": anchor.split(":")[1], "kind": "tenant" if kind == "joiner" else "workload", "anchors": [anchor]}
        if kind == "joiner":
            p["unit"] = rnd.choice(org.units)
        else:
            p["owner"] = org.manager(d)
        ms = [org.membership(anchor, d, now) for _ in range(a.named if kind == "joiner" else 1)]
        return [put("persons", p["person"], p)] + [put("memberships", m["membership_id"], m) for m in ms]
    if kind == "leaver":
        who = org.emp(pick())
        ops = [put("suspensions", f"S-org-{i:06d}", {"suspension_id": f"S-org-{i:06d}", "anchor": who, "at": iso(now),
                                                 "by": "idp:2b9e-owner", "reason": "left the organisation"})]
        for mid, _, _ in org.members.pop(who, []):
            m = r.get("memberships", mid)
            if m:
                ops.append(put("memberships", mid, {**m, "end": iso(max(now, datetime.fromisoformat(
                    m["start"].replace("Z", "+00:00")) + timedelta(minutes=1)))}))
        return ops
    if kind in ("removal", "mover"):
        i_emp = pick()
        who = org.emp(i_emp)
        ops = []
        if org.members.get(who):
            mid, _, _ = org.members[who].pop(rnd.randrange(len(org.members[who])))
            m = r.get("memberships", mid)
            if m:
                start = datetime.fromisoformat(m["start"].replace("Z", "+00:00"))
                ops.append(put("memberships", mid, {**m, "end": iso(max(now, start + timedelta(minutes=1)))}))
        if kind == "mover":
            p = r.get("persons", who.split(":")[1])
            ops.append(put("persons", p["person"], {**p, "unit": rnd.choice(org.units)}))
            m = org.membership(who, rnd.randrange(org.depts), now)
            ops.append(put("memberships", m["membership_id"], m))
        return ops or change("request", org, s, i)
    if kind == "request":
        i_emp = pick()
        m = org.membership(org.emp(i_emp), org.dept_of(i_emp), now)
        return [put("memberships", m["membership_id"], m)]
    if kind == "renewal":
        d = rnd.randrange(org.depts)
        ops = []
        for _ in range(RENEWAL_BATCH):
            i_emp = d + org.depts * rnd.randrange(1, max(2, (a.employees - d) // org.depts))
            m = org.membership(org.emp(i_emp), d, now)
            ops.append(put("memberships", m["membership_id"], m))
        return ops
    if kind == "jit":
        g = r.get("grants", "G-example-0001")
        rec = M._json({**g, "grant_id": org.nid("G"), "start": iso(now), "end": iso(now + timedelta(hours=4))})
        return [put("grants", rec["grant_id"], rec)]
    if kind == "lease":
        base = r.get("leases", "L-example-0001")
        n = org.next["C"] = org.next["C"] + 1
        rec = {**base, "lease_id": org.nid("L"), "anchor": f"ext:{n:06x}-new", "identity_hash": f"hmac-sha256:{n:016x}ff"}
        return [put("leases", rec["lease_id"], rec)]
    if kind == "group":
        d = rnd.randrange(org.depts)
        gid = org.nid("team")
        return [put("groups", gid, {"group_id": gid, "parent": f"dept-{d}", "max_risk": "low",
                                    "carries": [{"entitlement": "share-read", "by": "idp:2b9e-owner"}]})]
    raise ValueError(kind)


def desk_costs(org: Org, s, tmp: Path, n: int) -> dict:
    """What a desk proposal costs on the change log (S5 T9): a manager adds an employee to a team of their department,
    end to end through the desk (build, judge, propose, follow), judged on the reach, then in full for comparison."""
    from keyclerk.desk import Desk
    from keyclerk.store.log_desk import LogStore
    t = time.perf_counter()
    store = LogStore(tmp / "desk", s)
    desk = Desk(store, clock=lambda: AT)
    opened = round(time.perf_counter() - t, 1)
    out: dict = {"open_seconds": opened}
    try:
        for mode, count in (("scoped", n), ("full", 2)):
            store.scoped_judging = mode == "scoped"
            times, outcomes = [], Counter()
            for _ in range(count):
                i = org.rnd.randrange(org.depts, org.a.employees)
                d = org.dept_of(i)
                body = {"action": "add_member", "group": f"team-{org.team(d)}", "anchor": org.emp(i), "days": 30}
                t = time.perf_counter()
                try:
                    outcomes[desk.propose({"anchor": org.manager(d), "roles": []}, body)["outcome"]] += 1
                except Exception as e:   # noqa: BLE001 - a refusal is an outcome, measured like the rest
                    outcomes[f"refused: {str(e)[:80]}"] += 1
                times.append(time.perf_counter() - t)
            out[mode] = {"median_s": round(statistics.median(times), 2), "max_s": round(max(times), 2),
                         "outcomes": dict(outcomes)}
    finally:
        store.close()
    out["peak_mb"] = round(peak_mb())
    return out


def daily(a) -> dict[str, float]:
    f = a.scale * a.employees / 20000
    out = {k: v * f for k, v in DAILY.items()}
    out["jit"] = DAILY["jit"] * a.scale                        # administrators do not grow with headcount here
    out["workload"] = DAILY["workload"] * a.scale * a.workloads / 5000
    if a.agent_tasks:
        out["agent_task"] = a.agent_tasks * a.agents * a.scale
    for r in a.rate:                                           # a deployment's own numbers, per day, as given
        kind, _, n = r.partition("=")
        if kind not in DAILY:
            raise SystemExit(f"--rate {r}: the kinds are {', '.join(DAILY)}")
        out[kind] = float(n) * a.scale
    return out


def replay(day: dict[str, float], cost: dict[str, list[float]], rnd: random.Random) -> dict:
    """The day's arrivals (Poisson within each hour) on one queue, each served in a time drawn from that kind's
    measured costs: utilisation per hour, waits, and what is left at the end of the day."""
    arrivals = []
    for kind, n in day.items():
        for h, share in HOURS.items():
            k = n * share
            count = int(k) + (rnd.random() < k - int(k))
            arrivals += [(h * 3600 + rnd.random() * 3600, kind) for _ in range(count)]
    arrivals.sort()
    free, waits, busy = 0.0, defaultdict(list), Counter()
    for t, kind in arrivals:
        pool = cost.get(kind) or cost.get("jit" if kind == "agent_task" else "request")
        serve = rnd.choice(pool)
        start = max(t, free)
        waits[int(t // 3600)].append(start - t)
        free = start + serve
        busy[int(start // 3600)] += serve
    every = [w for ws in waits.values() for w in ws]
    peak = max(HOURS, key=lambda h: busy[h])
    pct = lambda xs, q: sorted(xs)[min(len(xs) - 1, int(len(xs) * q))] if xs else 0.0   # noqa: E731
    return {"changes": len(arrivals), "busiest_hour": f"{peak:02d}:00",
            "busiest_hour_utilisation": round(busy[peak] / 3600, 3),
            "busiest_hour_changes": len(waits[peak]),
            "wait_p50_s": round(pct(every, 0.5), 2), "wait_p95_s": round(pct(every, 0.95), 2),
            "wait_max_s": round(max(every) if every else 0, 2),
            "busiest_hour_wait_p95_s": round(pct(waits[peak], 0.95), 2),
            "queue_empties_at": f"{int(free // 3600):02d}:{int(free % 3600 // 60):02d}"}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--employees", type=int, default=20000)
    ap.add_argument("--groups", type=int, default=5000)
    ap.add_argument("--agents", type=int, default=1000)
    ap.add_argument("--workloads", type=int, default=5000)
    ap.add_argument("--contractors", type=int, default=1000)
    ap.add_argument("--named", type=int, default=2, help="named memberships per employee beyond the rules")
    ap.add_argument("--history-days", type=int, default=0)
    ap.add_argument("--sample", type=int, default=200, help="changes actually proposed to measure their cost")
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--agent-tasks", type=float, default=0)
    ap.add_argument("--full-check", action="store_true")
    ap.add_argument("--validate", action="store_true", help="check the generated organisation adds no errors (slow)")
    ap.add_argument("--rate", action="append", default=[], metavar="KIND=N",
                    help="changes of this kind per day, replacing the default (repeatable)")
    ap.add_argument("--desk", type=int, default=0, metavar="N",
                    help="also time N desk proposals on the change log (a manager adding a member), judged on the "
                         "reach, and two judged in full (decision 0022 S5 T9); then stop")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--json")
    a = ap.parse_args(argv)
    config.configure(bench_config())
    from keyclerk.signer import SignerRefused
    rnd = random.Random(a.seed)
    org = Org(a, rnd)
    key = Ed25519PrivateKey.generate()
    tmp = Path(tempfile.mkdtemp(prefix="bench-org-"))
    result: dict = {"organisation": {k: getattr(a, k) for k in ("employees", "groups", "agents", "workloads",
                                                                  "contractors", "named", "history_days")}}
    try:
        t = time.perf_counter()
        s = build(org, tmp / "state", key, a.history_days)
        counts = {k: s.replica.count(k) for k in ("persons", "groups", "memberships", "leases", "delegations")} \
            if hasattr(s.replica, "count") else {}
        result["build"] = {"seconds": round(time.perf_counter() - t, 1), "links": s.replica.size(),
                           "replica_mb": round((tmp / "state" / "replica.db").stat().st_size / 1e6, 1),
                           "records": counts, "peak_mb": round(peak_mb())}
        print(json.dumps(result["build"]), flush=True)
        if a.validate:                                         # the generated organisation must add no errors
            from keyclerk.fullcheck import _errors
            from keyclerk.store import replay as RP
            base = yaml.safe_load((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
            known = set(_errors(base, AT))
            new = [e for e in _errors(RP.records(s.replica), AT) if e not in known]
            result["new_errors"] = {"count": len(new), "first": new[:5]}
            print(json.dumps(result["new_errors"]), flush=True)
        if a.desk:
            result["desk"] = desk_costs(org, s, tmp, a.desk)
            print(json.dumps(result["desk"]), flush=True)
            return 0
        day = daily(a)
        result["day"] = {k: round(v, 1) for k, v in day.items()}
        total = sum(day.values())
        kinds = list(day)
        weights = [day[k] / total for k in kinds]
        # Every kind measured at least a few times, the rest in proportion to the day.
        plan = [k for k in kinds for _ in range(3)] + rnd.choices(kinds, weights, k=max(0, a.sample - 3 * len(kinds)))
        rnd.shuffle(plan)
        cost: dict[str, list[float]] = defaultdict(list)
        refused: Counter = Counter()
        reasons: dict[str, str] = {}
        fallback: dict[str, Counter] = defaultdict(Counter)    # kind -> why the change was judged on the whole records
        from keyclerk import metrics, scope
        from keyclerk.store import working
        real, wide = working.working_doc, Counter()

        def counted(ix, reach, rev):                           # why a working set was declined, as bench_scale does
            try:
                return real(ix, reach, rev)
            except scope.Wide as e:
                wide[str(e)[:80]] += 1
                raise
        working.working_doc = counted

        def falls() -> Counter:
            return Counter({k[1][0][1]: v for k, v in metrics._counters.items() if k[0] == "keyclerk_check_fallback_total"})
        for i, kind in enumerate(plan):
            ops, rows = org.keys.rekeyed(change("jit" if kind == "agent_task" else kind, org, s, i))
            before, wide_before = falls(), Counter(wide)
            t = time.perf_counter()
            try:
                s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, {"ops": ops, "entry": {}}, [],
                          rows or None)
            except SignerRefused as e:
                refused[kind] += 1
                reasons.setdefault(kind, str(e)[:300])
            cost[kind].append(time.perf_counter() - t)
            why = dict(falls() - before)
            fallback[kind].update(why)
            print(f"{i + 1:4d}/{len(plan)} {kind:9s} {cost[kind][-1]:7.2f} s"
                  + (f"  full check: {why} {dict(Counter(wide) - wide_before) or ''}" if why else ""), flush=True)
        working.working_doc = real
        result["fallback"] = {k: dict(v) for k, v in fallback.items() if v}
        result["working_set_declined"] = dict(wide)
        result["cost_s"] = {k: {"n": len(v), "median": round(statistics.median(v), 3),
                                "p90": round(sorted(v)[max(0, int(len(v) * 0.9) - 1)], 3)} for k, v in cost.items()}
        result["refused"] = dict(refused)
        result["refused_why"] = reasons
        result["replay"] = replay(day, cost, random.Random(a.seed))
        result["peak_mb"] = round(peak_mb())
        print(json.dumps({k: result[k] for k in ("cost_s", "refused", "fallback", "working_set_declined", "replay")},
                         indent=1), flush=True)
        if reasons:
            print(json.dumps(reasons, indent=1), flush=True)
        if a.full_check:
            t = time.perf_counter()
            ok = s.background_check().ok
            result["full_check"] = {"seconds": round(time.perf_counter() - t, 1), "ok": ok, "peak_mb": round(peak_mb())}
            print(json.dumps(result["full_check"]), flush=True)
        s.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if a.json:
        Path(a.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
