# SPDX-License-Identifier: EUPL-1.2
"""Metrics (decision 0018 H2, H3): a short fixed list in Prometheus text format, standard library only, served on the
management listener (keyclerk.health). Each metric names the alert or budget it serves; nothing outside this list is
ever exported. Labels are fixed, low-cardinality classes: no person, group or edge id is a label (H3 settled at build
time: the per-person drill-down stays in the audit trail, so a metrics store cannot be joined with it).

A counter is incremented where the event happens; a gauge is read at scrape time from a function the process
registers (gauge_fn), so a scrape never writes and never runs a records check."""
from __future__ import annotations

import bisect
import threading
import time
from typing import Callable

CHECK_BUCKETS = (0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120)          # seconds; decision 0017's CI budget is 30 s at 1,000
SIGNER_BUCKETS = (0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 30)

# name -> (type, help: what it is for, allowed label names, allowed values per label or None for "known values only")
SPEC: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "keyclerk_build_info": ("gauge", "The engine version; 1.", ("version",)),
    "keyclerk_changes_total": ("counter", "Changes logged by outcome. Alert: refused rising against applied.",
                               ("outcome",)),
    "keyclerk_refusals_total": ("counter", "Refusal reasons by the kind of person who can resolve them "
                                "(approvers, managers, root, other). Alert: a class that suddenly dominates.",
                                ("reason_class",)),
    "keyclerk_pending_changes": ("gauge", "Changes waiting for approval. Alert: above the deployment's bound.", ()),
    "keyclerk_check_seconds": ("histogram", "Duration of one records check (decision 0017 budget).", ()),
    "keyclerk_check_fallback_total": ("counter", "Changes judged by the full check instead of the scoped one, by "
                                      "reason: by the signer, and by the desk on the change log (decision 0022 S4).", ("reason",)),
    "keyclerk_check_alarms_total": ("counter", "Background full check alarms: incomplete runs, time-born errors "
                                    "(decision 0022 S4). Alert: incomplete, repeatedly.", ("kind",)),
    "keyclerk_signer_seconds": ("histogram", "Round trip to the checking signer.", ("op",)),
    "keyclerk_signer_errors_total": ("counter", "Signer calls that failed or were refused. Alert: any.", ("op",)),
    "keyclerk_reconcile_age_seconds": ("gauge", "Seconds since the reconciler's last run started. Alert: above the "
                                       "readiness bound.", ()),
    "keyclerk_reconcile_drift": ("gauge", "Findings in the reconciler's last run (drift from the records).", ()),
    "keyclerk_reconcile_failed": ("gauge", "1 when the reconciler's last run errored or refused. Alert: 1.", ()),
    "keyclerk_edge_pulls_total": ("counter", "Bundle pulls by edges by result (served, refused).", ("result",)),
    "keyclerk_edge_incidents_total": ("counter", "Edge incidents by kind. Alert: attestation_failed, any.",
                                      ("kind",)),
    "keyclerk_edges_silent": ("gauge", "Edges that stopped pulling past pull_max_hours. Alert: any.", ()),
    "keyclerk_log_breaks": ("gauge", "Breaks in the change log's hash chain or signatures, and times the desk could not "
                            "follow the checking signer. Alert: any.", ()),
    "keyclerk_signing_frozen": ("gauge", "1 while the checking signer has frozen signing: the desk is read-only. "
                                "Alert: 1.", ()),
    "keyclerk_timer_refused_total": ("counter", "Visit timer steps (a reminder, a suspension) the engine refused: the "
                                     "step did not happen. Alert: any.", ()),
    "keyclerk_ready": ("gauge", "1 when /readyz answers ready.", ()),
}
# label values that may appear; anything else is counted as "other" (a fixed list keeps cardinality bounded)
VALUES: dict[str, tuple[str, ...]] = {
    "outcome": ("applied", "pending", "refused", "recovered", "withdrawn", "expired", "other"),
    "reason_class": ("approvers", "managers", "root", "other"),
    "reason": ("head", "places", "situations", "sod", "catalogue", "group_tree", "schema", "root", "bound", "unknown",
               "forced", "config", "other"),
    "op": ("public_key", "sign_line", "commit", "ping", "migrate", "head", "propose", "links", "tokens", "checkpoint",
           "anchors", "start", "link_subject", "other"),
    "result": ("served", "refused"),
    "kind": ("attestation_failed", "edge_silent", "drift", "report", "incomplete", "time_born", "needs_migration",
             "other"),
}

_lock = threading.Lock()
_counters: dict[tuple, float] = {}
_hists: dict[tuple, list] = {}               # key -> [bucket counts..., +Inf count, sum]
_gauges: dict[str, Callable[[], list[tuple[dict, float]]]] = {}


def _labels(name: str, labels: dict) -> tuple:
    allowed = SPEC[name][2]
    if set(labels) != set(allowed):
        raise ValueError(f"{name} takes labels {allowed}")
    out = []
    for k in allowed:
        v = str(labels[k])
        known = VALUES.get(k)
        out.append((k, v if known is None or v in known else "other"))
    return tuple(out)


def inc(name: str, amount: float = 1, **labels) -> None:
    if SPEC[name][0] != "counter":
        raise ValueError(f"{name} is not a counter")
    key = (name, _labels(name, labels))
    with _lock:
        _counters[key] = _counters.get(key, 0) + amount


def observe(name: str, seconds: float, **labels) -> None:
    if SPEC[name][0] != "histogram":
        raise ValueError(f"{name} is not a histogram")
    buckets = CHECK_BUCKETS if name == "keyclerk_check_seconds" else SIGNER_BUCKETS
    key = (name, _labels(name, labels))
    with _lock:
        h = _hists.setdefault(key, [0] * (len(buckets) + 1) + [0.0])
        h[bisect.bisect_left(buckets, seconds)] += 1
        h[-1] += seconds


class timed:
    """with metrics.timed("keyclerk_check_seconds"): ..."""

    def __init__(self, name: str, **labels):
        self.name, self.labels = name, labels

    def __enter__(self):
        self.t = time.perf_counter()
        return self

    def __exit__(self, *exc):
        observe(self.name, time.perf_counter() - self.t, **self.labels)
        return False


def gauge_fn(name: str, fn: Callable[[], float | list[tuple[dict, float]]]) -> None:
    """Register how a gauge is read at scrape time: a number, or [(labels, value), ...]."""
    if SPEC[name][0] != "gauge":
        raise ValueError(f"{name} is not a gauge")

    def read():
        v = fn()
        return v if isinstance(v, list) else [({}, float(v))]
    _gauges[name] = read


def reset() -> None:
    """Tests only: forget every counter, histogram and gauge."""
    with _lock:
        _counters.clear()
        _hists.clear()
    _gauges.clear()


def _fmt_labels(pairs) -> str:
    if not pairs:
        return ""
    esc = lambda v: str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')   # noqa: E731
    return "{" + ",".join(f'{k}="{esc(v)}"' for k, v in pairs) + "}"


def _num(v: float) -> str:
    return str(int(v)) if float(v).is_integer() else repr(float(v))


def render() -> str:
    """The Prometheus text exposition (version 0.0.4). A gauge whose reader fails is left out, never guessed."""
    lines: list[str] = []
    with _lock:
        counters = dict(_counters)
        hists = {k: list(v) for k, v in _hists.items()}
    for name, (kind, help_, _) in SPEC.items():
        lines.append(f"# HELP {name} {help_}")
        lines.append(f"# TYPE {name} {kind}")
        if kind == "counter":
            for (n, pairs), v in sorted(counters.items()):
                if n == name:
                    lines.append(f"{name}{_fmt_labels(pairs)} {_num(v)}")
        elif kind == "histogram":
            buckets = CHECK_BUCKETS if name == "keyclerk_check_seconds" else SIGNER_BUCKETS
            for (n, pairs), h in sorted(hists.items()):
                if n != name:
                    continue
                cum = 0
                for le, c in zip([*map(str, buckets), "+Inf"], h[:-1], strict=False):   # the counts end with the sum
                    cum += c
                    lines.append(f"{name}_bucket{_fmt_labels([*pairs, ('le', le)])} {cum}")
                lines.append(f"{name}_sum{_fmt_labels(pairs)} {_num(h[-1])}")
                lines.append(f"{name}_count{_fmt_labels(pairs)} {cum}")
        else:
            read = _gauges.get(name)
            if read is None:
                continue
            try:
                rows = read()
            except Exception:   # noqa: BLE001 - a gauge that cannot be read is absent, which an alert can see
                continue
            for labels, v in rows:
                lines.append(f"{name}{_fmt_labels(_labels(name, labels) if labels else ())} {_num(v)}")
    return "\n".join(lines) + "\n"
