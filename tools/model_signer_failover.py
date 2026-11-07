"""Explore docs/specs/SignerFailover.tla exhaustively (decision 0031 point 8, decision 0033 point 9): the same
transition system, every reachable state, the state invariants on each, CommitOnlyGrows on each step but a reset, the
custodian's two step properties on each signature, and a takeover check that can fail: from every reachable state with
the head below its bound, an alive signer can get the committed links (from the commit witness, which keeps their
bodies, or from someone alive who holds them) and append. Breadth-first, so a counterexample is a shortest one.
Standard library only; TLC checks the .tla where Java and the TLA+ tools are set up.

Each node's records key is held by its key custodian (decision 0033), the authority on positions: it signs only the
next position and never while behind its persisted witness floor, reads the witness at start and raises its floor to
the witness's size (behind it, it signs nothing until it has followed; it stops only on a witness below its floor or
another tree at its own size), follows the committed log only onto the witness's tree and never below its own size
(review 2026-11-07, D2), and two people may bring the committed log to a stuck one (the recovery ceremony).

The design, and eight broken assumptions that must each yield a counterexample:
    --act-on-uncommitted    consumers act on a signer's own log, not only on what the commit witness took
    --witness-rollback      the commit witness is restored from an older backup
    --split-cas             the witness checks a submission and writes it in two separate steps
    --no-bodies             the commit witness keeps checkpoints only, not the committed links' bodies
    --unfenced-break-glass  the break-glass switch to unwitnessed signing while the commit witness still takes appends
    --reset-empty           the commit witness's owner resets it to an empty log instead of seeding it
    --no-start-check        a custodian starts without raising its floor to the witness's (a restored one signs again)
    --follow-below-own      a custodian follows a committed log shorter than what it holds
    python tools/model_signer_failover.py --all   each case, exit 0 only when each behaves as stated
"""
from __future__ import annotations

import argparse
import sys
from collections import deque

SIGNERS = ("a", "b")
FIELDS = ("logs", "ctr", "alive", "wit", "backup", "msgs", "checked", "acted", "answered", "mode", "bg",
          "floor", "stopped", "hw", "known")


def is_prefix(x: tuple, y: tuple) -> bool:
    return len(x) <= len(y) and y[:len(x)] == x


def at(t: tuple, i: int, v) -> tuple:
    return t[:i] + (v,) + t[i + 1:]


class Model:
    """State: (logs, ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg, floor, stopped, hw, known)
    logs: what each node's custodian holds; wit: the committed log; acted: heads consumers acted on; answered: heads a
    proposer was told committed; mode: "witnessed" or "glass" (after break-glass); bg: (signer, base) of the
    break-glass statement; floor: each custodian's persisted witness floor; stopped: a custodian that found the witness
    below its floor or another tree at its own size; hw (ghost): the most links each custodian held since its last restore or ceremony;
    known (ghost): the largest committed size each custodian was ever shown."""

    def __init__(self, max_signs=2, max_len=3, max_msgs=2, act_on_uncommitted=False, witness_rollback=False,
                 split_cas=False, no_bodies=False, unfenced_break_glass=False, reset_empty=False, no_start_check=False,
                 follow_below_own=False, break_glass=True, reset=True):
        self.max_signs, self.max_len, self.max_msgs = max_signs, max_len, max_msgs
        self.act_on_uncommitted, self.witness_rollback, self.split_cas = act_on_uncommitted, witness_rollback, split_cas
        self.no_bodies, self.unfenced_break_glass, self.reset_empty = no_bodies, unfenced_break_glass, reset_empty
        self.no_start_check, self.follow_below_own = no_start_check, follow_below_own
        self.break_glass, self.reset = break_glass, reset
        self.step_property = True

    def init(self):
        zero = (0,) * len(SIGNERS)
        return (((), ()), zero, frozenset(SIGNERS), (), (), frozenset(), frozenset(), frozenset(), frozenset(),
                "witnessed", None, zero, (False,) * len(SIGNERS), zero, zero)

    def accepts(self, wit, m):
        return len(wit) == m[0] and is_prefix(wit, m[1])

    @staticmethod
    def newest(heads) -> tuple:
        return max(heads, key=len, default=())

    def can_fetch(self, st, s_index) -> bool:
        """Whether a signer can get the committed links: from the witness's bodies, or from an alive signer or a
        consumer holding them (consumers hold what they acted on)."""
        logs, alive, wit, acted = st[0], st[2], st[3], st[7]
        if not self.no_bodies:
            return True
        return any(SIGNERS[j] in alive and is_prefix(wit, logs[j]) for j in range(len(SIGNERS))) or \
            any(is_prefix(wit, x) for x in acted)

    def started(self, st, i: int, held: tuple, f: int) -> dict:
        """The custodian of node i starts holding held with floor f: it reads the witness and raises its floor to the
        witness's size (behind it, it signs nothing until it has followed); it stops only on a witness below its floor
        (rolled back) or another tree at its own size, which the ceremony settles (point 5)."""
        wit, floor, stopped, known = st[3], st[11], st[12], st[14]
        if self.no_start_check:
            return {"floor": at(floor, i, f), "stopped": at(stopped, i, False)}
        bad = len(wit) < f or (len(wit) == len(held) and wit != held)
        return {"floor": at(floor, i, f if bad else max(f, len(wit))), "stopped": at(stopped, i, bad),
                "known": at(known, i, max(known[i], len(wit)))}

    def successors(self, st):
        logs, ctr, alive, wit, backup, msgs, checked, acted, answered, mode, bg, floor, stopped, hw, known = st

        def put(**kw):
            d = dict(zip(FIELDS, st, strict=True))
            d.update(kw)
            return tuple(d.values())
        witness_on = mode == "witnessed" or self.unfenced_break_glass
        for i, s in enumerate(SIGNERS):
            if s in alive and not stopped[i] and ctr[i] < self.max_signs and len(logs[i]) < self.max_len \
                    and len(logs[i]) >= floor[i]:                    # the next position, never behind its floor
                yield "sign " + s, put(logs=at(logs, i, logs[i] + ((s, ctr[i] + 1),)), ctr=at(ctr, i, ctr[i] + 1),
                                       hw=at(hw, i, max(hw[i], len(logs[i]) + 1)))
            if s in alive and logs[i] and len(msgs) < self.max_msgs:
                for o in range(len(logs[i]) + 1):
                    yield f"submit {s} old={o}", put(msgs=msgs | {(o, logs[i])})
            glass_signer = mode == "glass" and bg[0] == s                        # it follows no witness then
            if s in alive and not stopped[i] and logs[i] != wit and self.can_fetch(st, i) and not glass_signer \
                    and len(wit) >= floor[i] and (self.follow_below_own or len(wit) >= len(logs[i])):   # D2
                yield "follow " + s, put(logs=at(logs, i, wit), floor=at(floor, i, len(wit)),
                                         hw=at(hw, i, max(hw[i], len(wit))), known=at(known, i, max(known[i], len(wit))))
            if s in alive:
                yield "crash " + s, put(alive=alive - {s})
            else:
                yield "recover " + s, put(alive=alive | {s}, **self.started(st, i, logs[i], floor[i]))
            low = len(self.newest(acted)) if glass_signer else 0                 # 0019: resume at the newest head
            for k in range(low, len(logs[i])):                                  # consumers acted on
                kw = {"logs": at(logs, i, logs[i][:k]), "hw": at(hw, i, k)}
                if s in alive:                                                   # an older copy, its floor no higher
                    kw.update(self.started(st, i, logs[i][:k], min(floor[i], k)))
                else:
                    kw["floor"] = at(floor, i, min(floor[i], k))
                yield f"restore {s} to {k}", put(**kw)
            stuck = stopped[i] or (len(logs[i]) > len(wit) and not is_prefix(wit, logs[i]))   # refused, or a fork (D2)
            if mode == "witnessed" and s in alive and self.can_fetch(st, i) and stuck:
                yield f"ceremony brings {s} to {len(wit)}", put(          # two people, only when stuck (recover, Q6)
                    logs=at(logs, i, wit), floor=at(floor, i, len(wit)), stopped=at(stopped, i, False),
                    hw=at(hw, i, len(wit)), known=at(known, i, max(known[i], len(wit))))
            if self.break_glass and mode == "witnessed" and s in alive:          # two people: s signs unwitnessed
                base = self.newest(acted | answered)                             # the newest head the desk saw
                if is_prefix(base, logs[i]):
                    yield f"break-glass to {s} at {len(base)}", put(mode="glass", bg=(s, base))
        for m in msgs:
            if witness_on and self.accepts(wit, m):
                if not self.split_cas:
                    yield f"witness takes {m}", put(wit=m[1], answered=answered | {m[1]})
                else:
                    yield f"witness checks {m}", put(checked=checked | {m})
            yield f"drop {m}", put(msgs=msgs - {m})
        for m in checked:
            yield f"witness writes {m}", put(wit=m[1], checked=checked - {m}, answered=answered | {m[1]})
        if mode == "witnessed" or self.unfenced_break_glass:
            if wit not in acted:
                yield "act on the committed head", put(acted=acted | {wit})
        if mode == "glass":                                                      # consumers follow the glass signer
            s, base = bg
            i = SIGNERS.index(s)
            if is_prefix(base, logs[i]) and logs[i] not in acted:
                yield "act on the break-glass signer", put(acted=acted | {logs[i]}, answered=answered | {logs[i]})
        if self.act_on_uncommitted:
            for i, s in enumerate(SIGNERS):
                if logs[i] not in acted:
                    yield f"act on {s}'s own log", put(acted=acted | {logs[i]})
        if self.witness_rollback and backup != wit:
            yield "back up the witness", put(backup=wit)
            yield "restore the witness", put(wit=backup)
        if self.reset and mode == "witnessed":                                   # the owner re-seeds the witness
            seed = () if self.reset_empty else self.newest(acted | answered)
            if seed != wit:
                yield f"reset the witness to {len(seed)}", put(wit=seed, msgs=frozenset(), checked=frozenset())

    @staticmethod
    def invariants(st) -> str | None:
        wit, acted, answered, mode = st[3], st[7], st[8], st[9]
        for x in acted:
            for y in acted:
                if not (is_prefix(x, y) or is_prefix(y, x)):
                    return f"OneHistory: {x} and {y} were both acted on"
        if mode == "witnessed":
            for x in acted | answered:
                if not is_prefix(x, wit):
                    return f"ActedCommitted: {x} was acted on or answered but is not committed ({wit})"
        return None

    @staticmethod
    def signed(st, nxt, label) -> str | None:
        """CustodianOneBody and NoSignBelowCommitted on a step: a signature at or below what the custodian held since
        its last restore or ceremony is a second body there; one at or below a size it was shown committed signs into
        the committed log."""
        for i, s in enumerate(SIGNERS):
            if nxt[1][i] > st[1][i]:
                p = len(nxt[0][i])
                if p <= st[13][i]:
                    return f"CustodianOneBody: {label} signs position {p}, and {s}'s custodian held {st[13][i]} links"
                if p <= st[14][i]:
                    return f"NoSignBelowCommitted: {label} signs position {p}, and {s}'s custodian was shown " \
                        f"{st[14][i]} committed"
        return None

    def takeover(self, st) -> str | None:
        """A signer that is up can always get the committed links and append, while the head has room."""
        ctr, alive, wit, mode = st[1], st[2], st[3], st[9]
        if mode != "witnessed" or len(wit) >= self.max_len:
            return None
        for i, s in enumerate(SIGNERS):
            if s in alive and ctr[i] < self.max_signs:
                if self.can_fetch(st, i):
                    return None
                return f"takeover: {s} is up but cannot get the committed links {wit} (no one alive holds them)"
        return None

    def run(self, limit: int = 8_000_000) -> tuple[str | None, list[str], int]:
        start = self.init()
        parent: dict = {start: None}
        queue = deque([start])
        while queue:
            st = queue.popleft()
            bad = self.invariants(st) or self.takeover(st)
            if bad:
                return bad, self._trace(parent, st), len(parent)
            for label, nxt in self.successors(st):
                if self.step_property:
                    bad = self.signed(st, nxt, label)
                    if not bad and st[9] == nxt[9] == "witnessed" and not label.startswith("reset") \
                            and not is_prefix(st[3], nxt[3]):
                        bad = f"CommitOnlyGrows: {label} took the head from {st[3]} to {nxt[3]}"
                    if bad:
                        return bad, self._trace(parent, st) + [label], len(parent)
                if nxt not in parent:
                    parent[nxt] = (st, label)
                    queue.append(nxt)
                    if len(parent) > limit:
                        return f"state limit {limit} reached: not exhaustive", [], len(parent)
        return None, [], len(parent)

    @staticmethod
    def _trace(parent, st) -> list[str]:
        out = []
        while parent.get(st):
            st, label = parent[st]
            out.append(label)
        return list(reversed(out))


CASES = {"design": ({}, False), "act-on-uncommitted": ({"act_on_uncommitted": True}, True),
         "witness-rollback": ({"witness_rollback": True}, True), "split-cas": ({"split_cas": True}, True),
         "no-bodies": ({"no_bodies": True}, True), "unfenced-break-glass": ({"unfenced_break_glass": True}, True),
         "reset-empty": ({"reset_empty": True}, True), "no-start-check": ({"no_start_check": True}, True),
         "follow-below-own": ({"follow_below_own": True}, True)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in CASES:
        if name != "design":
            ap.add_argument(f"--{name}", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--state-only", action="store_true", help="the state invariants only, so a broken variant shows "
                    "where it leads rather than its first bad step")
    ap.add_argument("--max-len", type=int, default=3)
    ap.add_argument("--max-signs", type=int, default=2)
    ap.add_argument("--max-msgs", type=int, default=2)
    a = ap.parse_args(argv)
    chosen = [n for n in CASES if n != "design" and getattr(a, n.replace("-", "_"))]
    run = list(CASES) if a.all else (chosen or ["design"])
    ok = True
    for name in run:
        flags, must_fail = CASES[name]
        model = Model(a.max_signs, a.max_len, a.max_msgs, **flags)
        model.step_property = not a.state_only
        bad, trace, n = model.run()
        as_stated = bool(bad) == must_fail and not (bad or "").startswith("state limit")
        ok &= as_stated
        print(f"{name}: {n} states, {'violated: ' + bad if bad else 'all properties hold'} "
              f"({'as expected' if as_stated else 'NOT AS EXPECTED'})", flush=True)
        for step in trace:
            print(f"    {step}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
