"""The background full check (decision 0022 S4): the scoped checks verified, on a snapshot (a long read of the live
database would starve its write-ahead log; a failed check must not halt signing).

It runs on a snapshot of the signer's replica (the online backup API, never the live database), at one moment T:
  1. the full check equals the scoped judgement run over every subject at T (the working-set path is exact);
  2. reach: against the previous run's snapshot S0, every error the full check finds now and did not find on S0 (both
     at T) belongs to a subject inside the union of the reaches of the changes in between; one outside is a reach bug;
     one inside was accepted at its change's time and is wrong at T, so time-born;
  3. the records rebuilt from the links equal the replica's (the replica is a replay of its log).
A difference that reproduces on a second run is a verified integrity violation: signing freezes, a signed line in the
signer's audit log and state/frozen.json, until an operator resumes with the signer's resume command (a signed line
too, saying who, why, and whether the current state becomes the baseline); deleting the file resumes nothing.
The baseline (the previous run's snapshot) moves only after a run that completed and found nothing to freeze or
doubt. An incomplete or transient check (a crash, a timeout, a difference
that does not reproduce) retries and alarms; so does a time-born error. A frozen signer never revokes edges: they run on
their horizon. The run's duration is keyclerk_check_seconds.

It needs free space beside the replica for two snapshots (this run's and the previous one, each the replica's size:
about 13 KB per person, 6.6 GB each at 500,000 people) and refuses to start, saying why and what to free, without it.
"""
from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from keyclerk import clock, metrics, scope
from keyclerk.store import replay as RP
from keyclerk.store.link import StoreRefused


class NoSpace(StoreRefused):
    """Not enough free space for the background full check's snapshots."""


@dataclass
class Result:
    ok: bool
    frozen: str | None = None
    alarms: list[str] = field(default_factory=list)
    seconds: float = 0.0
    size: int = 0


def needed_space(replica_path: Path) -> int:
    return 2 * replica_path.stat().st_size


def check_space(replica_path: Path) -> None:
    need, free = needed_space(replica_path), shutil.disk_usage(replica_path.parent).free
    if free < need:
        raise NoSpace(f"the background full check needs {need // 2**20} MiB free beside {replica_path.parent} (two "
                      f"snapshots of the replica's size), and {free // 2**20} MiB is free: free that much space there, "
                      "or move the signer's state to a larger volume")


def _errors(doc: dict, t) -> list[str]:
    from keyclerk.reconcile import check_records
    with clock.at(t):
        return check_records(doc, log_backed=True)


def _everything(doc: dict) -> set[str]:
    from keyclerk import records as R
    ids = {str(r.get(f)) for k, f in R.KINDS.items() for r in doc.get(k, []) if isinstance(r, dict) and r.get(f)}
    ids |= {p["person"] for p in doc.get("persons", [])} | {g["group_id"] for g in doc.get("groups", [])}
    ids |= {str(r.get(f)) for k, f in R.KIND_IDS.items() for r in doc.get(k, []) if isinstance(r, dict) and r.get(f)}
    return ids | {"rate:*", "subtree:*", "adminrev:*", "sod:*", "tree", "places"}


def _by_subject(errs: list[str], doc: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for e in errs:
        out.setdefault(scope.subject_of(e, doc), set()).add(e.removesuffix(" (now)"))
    return out


def _findings(snap, previous, t, schema_changed: bool = False) -> tuple[list[str], list[str]]:
    """(integrity violations, alarms) of one run. Records that fail the records schema: under a schema the engine
    changed since the last passing run, a "needs migration" alarm (an upgrade, never a freeze); under the schema they
    were checked against, a violation."""
    from keyclerk import records as R
    violations, alarms = [], []
    doc = RP.records(snap)
    schema_errors = R.validate(doc, log_backed=True)
    if schema_errors:
        if schema_changed:
            return [], [f"needs migration: the replica's records do not meet this engine's records schema "
                        f"({schema_errors[0][:160]}). Run the records migration for this engine version, or roll the "
                        "engine back; until then every change is judged in full"]
        return [f"the replica's records fail the records schema they were checked against: {schema_errors[0][:160]}"], []
    full = _errors(doc, t)
    with clock.at(t):
        everything = scope.scoped_errors(doc, _everything(doc))
    if sorted(full) != sorted(everything):
        diff = sorted(set(full) ^ set(everything))[:3]
        violations.append(f"the scoped judgement over every subject differs from the full check: {diff}")
    violations += _working_set_sample(snap, doc, full, t)
    rebuilt = RP.records(RP.replay(snap.links(), snap.pinned, snap.realm, RP.side_of(snap)))
    if rebuilt != doc:
        violations.append("the records rebuilt from the links differ from the replica's")
    if previous is not None:
        old = RP.records(previous)
        before, after = _by_subject(_errors(old, t), old), _by_subject(full, doc)
        new_subjects = {s for s, es in after.items() if not es <= before.get(s, set())}
        if new_subjects:
            reach = _reaches(previous, snap, old)
            for s in sorted(new_subjects):
                if reach is not None and not scope.covered(s, reach):
                    violations.append(f"a new error outside every change's reach: {sorted(after[s])[:2]}")
                else:
                    alarms.append(f"time-born: {sorted(after[s])[:2]}")
    return violations, alarms


def _reaches(previous, snap, old: dict) -> set[str] | None:
    """The union of the reaches of the links after previous's head, each applied to the records before it (from the
    baseline's records, never replayed from the genesis); None when a change reached everyone. A change's reach is
    the rules' answer, whichever path judged it: an error outside it is a reach bug either way."""
    from keyclerk import edge as E
    out: set[str] = set()
    doc = old
    for sealed in snap.links(previous.size()):
        body = E._parse(E._raw(sealed["bytes"]))
        new = RP.apply_ops(doc, body, snap)
        r = scope.reach(doc, new, body["change"]["ops"])
        if isinstance(r, scope.Full):
            return None
        out |= r
        doc = new
    return out


BASELINE = "fullcheck-previous.sqlite"


def run(replica, state: Path, t=None, schema_changed: bool = False) -> Result:
    """One background full check of a replica. Its snapshot becomes the baseline the next run compares against only
    when the run completed and found nothing to freeze or doubt: an incomplete run keeps the old baseline (the next run
    spans the whole interval), and so does a violation (the frozen state never becomes the baseline; a resume that
    accepts it says so, signed). The caller freezes on result.frozen."""
    check_space(Path(replica.path))
    t = t or clock.now()
    started = time.perf_counter()
    prev_path = state / BASELINE
    snap = replica.snapshot()
    previous, settled = None, False
    try:
        if prev_path.exists():
            from keyclerk.store.sqlite import SqliteStore
            try:
                previous = SqliteStore(prev_path, replica.pinned, replica.realm, _readonly=True)
            except StoreRefused:
                previous = None
        result = Result(ok=True, size=snap.size())
        try:
            violations, alarms = _findings(snap, previous, t, schema_changed)
            if violations:                        # verified only when it reproduces
                again, _ = _findings(snap, previous, t, schema_changed)
                alarms += [f"did not reproduce: {v}" for v in violations if v not in again]
                violations = [v for v in violations if v in again]
            settled = not violations and not any(a.startswith(("did not reproduce", "needs migration")) for a in alarms)
        except Exception as e:   # noqa: BLE001 - incomplete: retried at the next run, never a freeze (a transient
            # failure must not halt signing)
            violations, alarms = [], [f"incomplete: {type(e).__name__}: {str(e)[:200]}"]
        result.alarms = alarms
        if violations:
            result.ok, result.frozen = False, "; ".join(violations)[:2000]
        for a in alarms:
            metrics.inc("keyclerk_check_alarms_total", kind="incomplete" if a.startswith("incomplete") else
                        "time_born" if a.startswith("time-born") else
                        "needs_migration" if a.startswith("needs migration") else "other")
    finally:
        if previous is not None:
            previous.close()
        keep = snap._tmp
        snap._tmp = None
        snap.close()
        if settled:
            os.replace(keep, prev_path)           # this run's snapshot is the next run's baseline
        else:
            for suffix in ("", "-wal", "-shm", "-journal"):
                Path(keep + suffix).unlink(missing_ok=True)
    result.seconds = time.perf_counter() - started
    metrics.observe("keyclerk_check_seconds", result.seconds)
    return result


def accept_baseline(replica, state: Path) -> None:
    """The replica as it stands becomes the baseline (a resume that accepts the current state, signed by the caller)."""
    snap = replica.snapshot()
    keep = snap._tmp
    snap._tmp = None
    snap.close()
    os.replace(keep, state / BASELINE)


def freeze(state: Path, why: str) -> None:
    tmp = state / "frozen.json.tmp"
    tmp.write_text(json.dumps({"at": clock.now().isoformat(), "why": why}), encoding="utf-8", newline="\n")
    os.replace(tmp, state / "frozen.json")


RESUME = ("python -m keyclerk.signer resume --key KEY --state DIR --config FILE --by NAME --reason TEXT "
          "[--accept-baseline], at the signer's terminal with the signer stopped")


def frozen_message(at: str, why: str) -> str:
    return (f"signing is frozen since {at}: the background full check found an integrity violation ({why}). "
            f"Investigate, then resume with {RESUME} (decision 0022 S4); removing frozen.json does not resume")


SAMPLE = 40               # subjects per run whose working set is judged against the full check


def _working_set_sample(snap, doc: dict, full: list[str], t) -> list[str]:
    """The working-set path against the full check, for a sample of subjects (memberships, delegations, persons and
    their separation of duty), the same sample on a rerun (seeded by the head). A gap in what the working set loads
    shows here as a difference: a violation."""
    import random

    from keyclerk.store import replay as RP
    from keyclerk.store.working import StoreIx, working_doc
    rnd = random.Random(snap.head().hex() if snap.head() else "empty")
    pool = sorted(m["membership_id"] for m in doc.get("memberships", []))
    pool += sorted(d["delegation_id"] for d in doc.get("delegations", []))
    pool += sorted(p["person"] for p in doc.get("persons", []))
    pool += sorted(f"sod:{m['member']['anchor']}" for m in doc.get("memberships", []) if "anchor" in m["member"])
    out = []
    for s in sorted(set(rnd.sample(pool, min(SAMPLE, len(pool))))) if pool else []:
        reach = {s}
        try:
            ws = working_doc(StoreIx(snap), reach, RP.revision(snap))
        except scope.Wide:
            continue
        with clock.at(t):
            got = sorted(scope.scoped_errors(ws, reach))
        want = sorted(e for e in full if scope.covered(scope.subject_of(e, doc), reach))
        if got != want:
            out.append(f"the working set judges {s} differently from the full check: {sorted(set(got) ^ set(want))[:2]}")
    return out
