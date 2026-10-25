# 0017. An access timeline per revision, and checks scoped to what a change reaches

- Status: accepted in part (2026-10-24, choice H0): points 1, 2, 4 and 5; the full check always runs.
  Point 3 (scoped checks) is deferred: built only if the benchmark at 5,000 people misses its budget.
- Context: a review of the release footprint (2026-10-24) measured what the engine's checks cost as an organisation
  grows; its figures follow.

## Problem
Every change runs every engine check over the whole records, in the desk and twice in the checking signer (old and new
revision). The check grows superlinearly with people and memberships: about 6 s at 200 extra people and over a minute
at 400 on a synthetic probe. A profile at 200 people (19.9 s under the profiler) puts 92% in the separation-of-duties
check, which runs at each of 808 distinct membership start times and each time flattens every person's entitlements
again (168,064 entitlement flattenings, 2.18 million group-member expansions), and 17% in 7,758 separate identity-policy
calls into Wasm. Every feature decided on 2026-10-24 (reviews, dormancy, impact diffs, holder bounds, outliers,
converged reviews, leaver proof) asks the same question, who holds what from when to when, so building them on this
would multiply the cost and need rework later.

## Baseline (tools/bench_checks.py, valid generated organisations, 2026-10-24)
| Extra people | Memberships | check_records |
|---|---|---|
| 10 | 189 | 4.2 s |
| 25 | 444 | 34 s |
| 50 | 869 | 136 s |

Each generated person holds the fixture's 17 person-anchored memberships; none adds a check error.

## Progress (2026-10-24, exact: every step proven by equivalence tests in tests/test_sod_scaling.py)
1. SoD is flattened only for groups carrying an entitlement an SoD rule names, and checked only at the start times
   of memberships that can bring such an entitlement (plus now).
2. Indexes built once per check inside the memo scope: anchor to person, records by who made them (reciprocity),
   include edges.
3. Policy answers cached per exact input (a policy's data is fixed at load, so an answer depends on its input only).

| Extra people | Before | After steps 1 to 3 |
|---|---|---|
| 50 | 136 s | 0.3 s |
| 100 | | 0.8 s |
| 200 | | 2.4 s |
| 400 | | 9.3 s |
| 1,000 | | 77 s |

4. The timeline (point 2): at each start time that can bring an SoD entitlement, only the people it reaches (the new
   member, an included group's members, a rule's matches) are judged, each by a direct membership test (member_of)
   that answers exactly as expanding the group (tested for every person, group and moment, both persona modes, with a
   suspension and an agent); at now, everyone.
5. person_rec and kind_of through the same once-per-check index.

| Extra people | After steps 1 to 3 | After steps 4 and 5 |
|---|---|---|
| 1,000 | 77 s | 4.3 s |
| 2,000 | | 9.6 s |
| 5,000 | | 27 s |

Near linear now. The budget in CI: 1,000 people under 30 s (tests/test_sod_scaling.py).

One deliberate difference from checking everyone at every start: a conflict that arises without a membership start
(a situation level turns a standby membership on) was only ever found by chance, at some later unrelated start; now it
is found by the check at "now", which judges everyone.

## Prior art
- NIST RBAC (proposed standard, sections 2.3 and 4): static separation of duty is enforced in AssignUser, for the
  user being assigned.
- SailPoint IdentityIQ: policies are evaluated per identity, at aggregation, refresh or request time.
- midPoint: role exclusions are evaluated when an assignment is made; time is handled by the focus validity scan,
  which recomputes only objects whose validFrom or validTo boundary fell within the scanned interval; a role change
  recomputes its members.
- Zanzibar (USENIX ATC 2019, section 3.2.4): recursive pointer chasing through nested groups was too slow; the Leopard
  index keeps nested sets flattened and updates them incrementally. SpiceDB caches resolved answers per revision.
- DBSP (VLDB 2023) and differential dataflow: general incremental view maintenance; not needed at this scale.

What KeyClerk guarantees is stricter than all of them (every revision valid at every moment, past and future), and it
stays. How it is checked changes: by induction, as the signer's "no new errors" rule already half does, instead of
proving the whole organisation over all time on every change.

## Decision (proposed)
1. **Flattened membership per revision.** Group membership (nesting, includes, rules) is flattened once per revision
   into per-person sets with their validity intervals, cached by the revision's hash, never recomputed per call or per
   moment.
2. **A timeline per person from boundaries.** A person's effective entitlements change only where one of their
   memberships, delegations, leases, situations or the records' rules start or end; the timeline is the list of those
   intervals with what holds in each. SoD and the other time-dependent checks test intervals, not every start time of
   everyone.
3. **Checks scoped to what a change reaches.** A revision is checked for the people its added or changed records reach
   (through the flattened groups) and from the earliest moment it affects. A change that reaches everyone (an SoD rule,
   a catalogue risk class, the group tree near its root, the policy) is checked in full. When the reach cannot be
   computed, the check is full.
4. **Batched policy calls.** The identity policy decides all memberships of a check in one Wasm call.
5. **Read-only records snapshots** shared between readers, copied only by code that edits them.

## Guards
- A benchmark with generated valid organisations (100, 1,000 and 5,000 people) and a time budget in CI.
- A property test: on random revisions, the scoped check and the full check find the same new errors.
- The full check runs nightly and on every signer start; a disagreement with the scoped results is an incident.
- First version: the whole timeline is rebuilt once per revision (no incremental maintenance); incremental
  maintenance only if the benchmark misses its budget.

## Consequences
The governance features (decision 0020) become queries on the timeline. The signer keeps the previous revision's
result. The engine's checks become a contract a deployment can hold a time budget against.
