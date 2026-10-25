"""What a change costs through the checking signer at scale (decision 0022 S4 (c)): N generated people written to a
signer's replica as plain links (no YAML: a YAML store holds at most about 4,000 people), then random changes
proposed and timed.

The organisation is bench_checks' (the fixture plus N people, each with the fixture's person-anchored memberships),
generated as a stream, so it is never held whole in memory. Changes, at random: a new membership for a generated
person, a membership ended sooner, a person's unit changed, a suspension. For each size it prints the per-change
median and 90th percentile, the working set loaded (persons, memberships, grants, leases), the share of changes that
fell back to the full check and why, and, unless --no-full-check, the background full check's duration and the
process's peak memory.

Two profiles: concentrated (the default: every generated membership keeps the fixture's approvers, as a real
organisation's security officer and few managers approve most records) and spread (each generated membership is
approved by another generated person).

    python tools/bench_scale.py [N ...] [--changes 30] [--profile concentrated|spread] [--no-full-check]
"""
from __future__ import annotations

import argparse
import copy
import ctypes
import json
import os
import random
import shutil
import statistics
import sys
import tempfile
import time
from collections import Counter
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from bench_checks import FIXTURES, bench_config  # noqa: E402
from keyclerk import config  # noqa: E402
from keyclerk import delegation as D  # noqa: E402

AT = "2026-10-24T12:00:00Z"
PART = 500


def peak_mb() -> float:
    """The process's peak working set (Windows), or its maximum resident size elsewhere, in MB."""
    if os.name == "nt":
        class PMC(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong), ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t), ("a", ctypes.c_size_t), ("b", ctypes.c_size_t),
                        ("c", ctypes.c_size_t), ("d", ctypes.c_size_t), ("e", ctypes.c_size_t), ("f", ctypes.c_size_t)]
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        k32 = ctypes.windll.kernel32
        k32.GetCurrentProcess.restype = ctypes.c_void_p
        k32.K32GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(PMC), ctypes.c_ulong]
        k32.K32GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(pmc), pmc.cb)
        return pmc.PeakWorkingSetSize / 2 ** 20
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def stream(n: int, profile: str = "concentrated"):
    """(the fixture's records as put ops, then the generated people's ops, part by part)."""
    from keyclerk.store import migrate as M
    doc = yaml.safe_load((FIXTURES / "records.yaml").read_text(encoding="utf-8"))
    head, ops, _ = M.split(doc)
    yield head + ops
    templates = [m for m in doc.get("memberships", []) if "anchor" in m.get("member", {})]
    deleg = {d["delegation_id"]: d for d in doc.get("delegations", [])}

    def room(m) -> int:
        end = D._ts(m["end"])
        if m["under"] in deleg and deleg[m["under"]].get("end"):
            end = min(end, D._ts(deleg[m["under"]]["end"]))
        for r in doc.get("admin_revocations", []):
            if r["id"] == m["under"]:
                end = min(end, D._ts(r["at"]))
        return max(1, min(20, (end - D._ts(m["start"])).days - 1))
    part = []
    for i in range(n):
        anchor = f"idp:{i:06x}-gen"
        part.append({"op": "put", "kind": "persons", "key": f"gen-{i}",
                     "record": {"person": f"gen-{i}", "kind": "tenant", "anchors": [anchor]}})
        for j, m in enumerate(templates):
            start = D._ts(m["start"]) + timedelta(days=i % room(m), minutes=1 + (i % 720))
            rec = M._json({**copy.deepcopy(m), "membership_id": f"M-gen-{i}-{j}", "member": {"anchor": anchor},
                           "start": start})
            if profile == "spread" and rec.get("approved_by") and n > 1:
                rec["approved_by"] = [f"idp:{(i * 7 + j + 1) % n:06x}-gen"]
            part.append({"op": "put", "kind": "memberships", "key": rec["membership_id"], "record": rec})
        if len(part) >= PART:
            yield part
            part = []
    if part:
        yield part


def build(n: int, state: Path, key, profile: str = "concentrated"):
    """A signer whose replica holds the organisation, written as plain links (a bench's shortcut: no migration)."""
    from keyclerk.signer import Signer
    from keyclerk.store import link as L
    from keyclerk.store.sqlite import SqliteStore
    s = Signer(key, state)
    store = SqliteStore(state / "replica.db", s.public_key(), "example")
    h = None
    for ops in stream(n, profile):
        sealed = L.seal_link(key, "example", store.size(), h.hex() if h else L.ZERO, 1, AT, ops, {"action": "bench"})
        h = store.append(sealed)
    store.add_checkpoint(L.seal_checkpoint(key, "example", store.size(), store.root(), h, 1, AT))
    s._hold()
    s.replica = store
    s._write_mark()
    s.config_pending = False
    return s


def change(s, rnd: random.Random, n: int, i: int) -> list[dict]:
    from keyclerk.store import migrate as M
    r = s.replica
    who = rnd.randrange(n)
    kind = rnd.choice(["member", "member", "end", "unit", "suspend"])
    m = r.get("memberships", f"M-gen-{who}-{rnd.randrange(17)}")
    if kind == "member" and m:
        rec = {**m, "membership_id": f"M-bench-{i}", "start": m["start"]}
        return [{"op": "put", "kind": "memberships", "key": rec["membership_id"], "record": rec}]
    if kind == "end" and m:
        rec = {**m, "end": m["start"]}
        return [{"op": "put", "kind": "memberships", "key": rec["membership_id"], "record": rec}]
    if kind == "unit":
        p = r.get("persons", f"gen-{who}")
        rec = {**p, "unit": rnd.choice(["sales", "ops", "plant"])}
        return [{"op": "put", "kind": "persons", "key": rec["person"], "record": rec}]
    rec = M._json({"suspension_id": f"S-bench-{i}", "anchor": f"idp:{who:06x}-gen", "at": AT, "by": "idp:2b9e-owner"})
    return [{"op": "put", "kind": "suspensions", "key": rec["suspension_id"], "record": rec}]


def run(n: int, changes: int, full_check: bool, key, profile: str = "concentrated") -> None:
    from keyclerk import metrics
    from keyclerk.signer import SignerRefused
    from keyclerk.store import working
    d = Path(tempfile.mkdtemp(dir=ROOT))
    try:
        t = time.perf_counter()
        s = build(n, d / "state", key, profile)
        print(f"{n:7d} people ({profile}): replica written in {time.perf_counter() - t:7.1f} s, "
              f"{(d / 'state' / 'replica.db').stat().st_size / 1e6:7.1f} MB, peak {peak_mb():7.0f} MB", flush=True)
        sizes: list[dict] = []
        real = working.working_doc

        wide: Counter = Counter()

        def counted(ix, reach, rev):
            from keyclerk import scope
            try:
                doc = real(ix, reach, rev)
            except scope.Wide as e:
                wide[str(e)] += 1
                raise
            sizes.append({k: len(doc.get(k) or []) for k in ("persons", "memberships", "grants", "leases")})
            return doc
        working.working_doc = counted
        before = Counter({k[1][0][1]: v for k, v in metrics._counters.items() if k[0] == "keyclerk_check_fallback_total"})
        rnd, times, refused = random.Random(n), [], 0
        for i in range(changes):
            ops = change(s, rnd, n, i)
            t = time.perf_counter()
            try:
                s.propose({"size": s.replica.size(), "head": s.replica.head().hex()}, {"ops": ops, "entry": {}}, [])
            except SignerRefused:
                refused += 1
            times.append(time.perf_counter() - t)
        working.working_doc = real
        after = Counter({k[1][0][1]: v for k, v in metrics._counters.items() if k[0] == "keyclerk_check_fallback_total"})
        falls = after - before
        times.sort()
        ws = {k: int(statistics.median(x[k] for x in sizes)) if sizes else 0 for k in ("persons", "memberships", "grants",
                                                                                      "leases")}
        print(f"{n:7d} people: {changes} changes ({refused} refused): median {statistics.median(times):6.2f} s, "
              f"p90 {times[int(len(times) * 0.9) - 1]:6.2f} s; working set (median per side) {json.dumps(ws)}; "
              f"fell back {sum(falls.values())}/{changes} {dict(falls)} (working set declined: {dict(wide)}); "
              f"peak {peak_mb():7.0f} MB", flush=True)
        if full_check:
            t = time.perf_counter()
            result = s.background_check()
            print(f"{n:7d} people: background full check {time.perf_counter() - t:7.1f} s, ok {result.ok}, "
                  f"peak {peak_mb():7.0f} MB", flush=True)
        s.close()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sizes", nargs="*", type=int, default=[5000])
    ap.add_argument("--changes", type=int, default=30)
    ap.add_argument("--no-full-check", action="store_true")
    ap.add_argument("--profile", choices=("concentrated", "spread"), default="concentrated")
    a = ap.parse_args(argv)
    config.configure(bench_config())
    key = Ed25519PrivateKey.generate()
    for n in a.sizes:
        run(n, a.changes, not a.no_full_check, key, a.profile)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
