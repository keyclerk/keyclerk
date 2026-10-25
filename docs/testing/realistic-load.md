# Realistic load: a working day of a 20,000-person organisation

How the signed change log and the checking signer (decision 0022) hold up in an ordinary production rhythm, and how
that is measured. The stress benchmarks (`tools/bench_scale.py`) answer "where does it break"; this one answers "what
does a normal day cost, and how much headroom is left". Both are needed: a stress number on its own says nothing about
whether a real organisation ever gets near it.

## The organisation

| What | Default | How it appears in the records |
|---|---|---|
| Employees | 20,000 | one person record each (`tenant`, with a unit) |
| Groups | 5,000 | 250 departments under the office group, 4,750 teams under the departments |
| Delegates | 250 | each department's manager holds a delegation over it (members and rules) |
| Access from rules | one rule per department | the unit attribute from the HR source; nobody covered by a rule needs a named membership |
| Named memberships | 2 per employee | the exceptions rules do not cover (projects, shared mailboxes, a second team) |
| Agents | 1,000 | one person record each (`agent`, with an owner and a director) and one membership |
| Workloads | 5,000 | one person record each (`workload`, with an owner) and one membership |
| Contractors | 1,000 at a time | one lease each |
| Devices | 10,000 | not records: a device certificate is the edge's to check against KeyClerk's policy |
| Visitors | 1,000 a day | not in the signed log: a visit is its own file, vouched for by the desk's log by id only and erased 30 days after it closes (`tests/test_visit_store.py`); gate passages are visit events in that file |

Records at day zero: 26,012 persons, 5,013 groups, 46,269 memberships, 1,002 leases, 253 delegations. The generated
part adds no error to the engine's full check (`--validate` proves it on every run that passes it).

The weight is in the memberships, not the people. The stress benchmark gives every generated person the fixture's 17
memberships, so its 5,000 people carry 85,000 memberships and its 50,000 people 850,000: an organisation that names
every access by hand. With rules doing the birthright work, 20,000 employees carry about 46,000.

## The rhythm of change

Changes per working day for 20,000 employees (230 working days a year), scaled with headcount by `--employees` and as a
whole by `--scale`:

| Change | Per day | Basis |
|---|---|---|
| Joiner (person record and 2 named memberships, one change) | 10 | turnover of about 12 % a year: 2,400 joiners. Measured: Acerta reports 7.9 % of permanent employees in Belgium left their employer in the first half of 2025, a record ([Acerta, 16 September 2025](https://www.acerta.be/nl/in-de-pers/recordaantal-werknemers-vertrok-dit-jaar-al-bij-zijn-werkgever)), about 15 % a year at that pace; 12 % is a mid value |
| Leaver (suspension and the named memberships ended, one change) | 10 | the same turnover |
| Mover (unit changed, one membership ended, one new) | 17 | up to 20 % of a large organisation's staff change role or department in a year (4,000), not evenly: they peak between May and July (from experience in large organisations; the split assumed here is half of them in those months). That is about 31 a day in those 65 working days and 12 a day the rest of the year; 17 is the yearly average, `--rate mover=31` the season |
| Access request (one named membership) | 175 | assumption: 2 requests per employee a year that the rules do not cover |
| Access removed early | 40 | assumption |
| Recertification (a manager renews 40 named memberships in one change) | 11 | every named membership renewed twice a year (`max_membership_days` 180) |
| Privileged access for a few hours (a grant) | 200 | assumption: about 500 administrators, most days one or two; does not grow with headcount |
| Contractor lease | 15 | 1,000 contractors at a time, three months each, plus extensions |
| Workload deployed or retired | 10 | assumption; scales with `--workloads`. Credential rotation is not a record |
| Team created or restructured | 5 | assumption |
| Agent task grants | 0 | off by default; `--agent-tasks K` gives each agent K grants a day, for agents that ask for access per task |

About 493 changes a day (the season adds 14 more movers). The day runs from 08:00 to 18:00 with a morning peak (15 % of the day's changes between 09:00
and 10:00), a lunch dip and a smaller afternoon peak (`HOURS` in the tool).

What is not a change: a membership or lease that ends at its end time (time does that, no record is written), a rule
picking up a new HR attribute (the rule is evaluated, not rewritten), a visitor arriving, a badge read at a gate, a
device checking in.

## How it is measured

`tools/bench_org.py` does three things:

1. **Builds the organisation** as signed links in a signer's replica (SQLite), streamed in parts so it is never held
   whole in memory. `--history-days N` adds N working days of past changes as ended records, so the state looks like
   an organisation after N days in production with nothing pruned.
2. **Measures what each kind of change costs**: it proposes `--sample` changes (default 200), each kind at least three
   times and the rest in proportion to the day's mix, through `Signer.propose`, exactly the path the desk uses: the
   change is applied in one transaction, judged by the scoped check against the replica's state, signed and kept.
   Every refused change is counted with its reason; a run with refusals is not a valid measurement.
3. **Replays the whole day on one queue.** The signer applies one change at a time, so the day is a single queue: the
   day's arrivals are drawn per hour (Poisson within the hour), and each is served in a time drawn from the measured
   costs of its kind. That gives the busiest hour's utilisation, the waits (median, 95th percentile, maximum) and the
   time the queue empties. The waits come from measured service times, not from an assumed one.

With `--full-check` it also times the background full check once, the job that runs daily and checks every record.

```
python tools/bench_org.py --sample 200 --full-check --json day0.json
python tools/bench_org.py --history-days 230 --sample 200 --full-check --json year1.json
python tools/bench_org.py --scale 3 --sample 200 --json busy.json          # a reorganisation week
python tools/bench_org.py --agent-tasks 2 --sample 200 --json agents.json  # agents asking per task
```

Small runs check the generator: `python tools/bench_org.py --employees 400 --groups 100 --agents 20 --workloads 100
--contractors 20 --sample 60 --history-days 5 --validate` must report `"count": 0` new errors and no refusals.

## Results

### Day zero, 2026-10-25 (the operator's Windows workstation, Python 3.14, while other work ran)

Built in 35 s: 26,012 persons, 5,013 groups, 46,269 memberships, 1,002 leases, 253 delegations; replica 81 MB.
200 changes proposed, none refused, peak memory 365 MB.

| Change | n | Median | p90 | Judged |
|---|---|---|---|---|
| Privileged grant (JIT) | 69 | 0.41 s | 0.55 s | scoped |
| Contractor lease | 10 | 0.60 s | 0.71 s | scoped |
| Access request | 73 | 1.22 s | 1.69 s | scoped |
| Joiner | 4 | 1.27 s | 1.29 s | scoped |
| Recertification (40 memberships) | 7 | 1.27 s | 1.32 s | scoped |
| Workload | 3 | 1.31 s | 1.31 s | scoped |
| Access removed | 13 | 1.43 s | 1.48 s | scoped |
| Mover | 9 | 1.70 s | 2.19 s | scoped |
| Leaver | 7 | 1.84 s | 1.98 s | scoped |
| Team created | 5 | 64 s | 65 s | in full (`group_tree`, by design) |

Background full check: 64 s, no finding.

The day replayed on those costs, one queue, per scenario (`--rate`):

| Scenario | Changes a day | Busiest hour | Its utilisation | Wait p95 | Longest wait | Signer busy a day |
|---|---|---|---|---|---|---|
| Normal (12 to 15 % turnover, movers 17 a day) | 491 | 73 | 3.7 % | 0 s | 45 s | 13 min |
| High churn (33 %: 30 joiners and 30 leavers, 200 contractor leases) | 714 | 80 | 3.6 % | 0 s | 2 s | 16 min |
| 50 joiners and 50 leavers a day, 200 contractor leases | 753 | 83 | 3.7 % | 0 s | 2 s | 17 min |
| The same in May to July (31 movers a day) | 763 | 114 | 4.9 % | 0 s | 56 s | 17 min |
| May to July, every agent asking 2 task grants a day | 2,763 | 414 | 8.4 % | 0 s | 61 s | 31 min |

The longest waits are the changes queued behind a team being created (about a minute, judged in full). Everything
else waits for nothing: at the busiest hour of the hardest scenario the signer is idle more than 90 % of the time.

### What the first runs found (fixed on the 0.25.0 branch the same day)

- **Every membership change was judged in full.** A membership's reach named its subtree's rate bucket for every day
  (`subtree:<top>:*`), so in an organisation where all departments hang under one top delegation, each change pulled in
  every membership of the organisation and went over the working-set bound. The bucket a membership counts in is its
  start day's, and the reach already names the start day of the old and the new record, so the all-days bucket was
  dropped (test: `test_a_membership_judged_scoped_meets_the_subtree_cap_of_its_own_day`, at the cap on the same day and
  on another day).
- **The full check rebuilt the group map for every membership** (`delegation._groups`, 91 % of the time: 46,000
  memberships times 5,000 groups). It is now built once per check inside the existing memo. Together: a change from 9 to
  13 s down to 0.4 to 1.8 s, a team creation and the background full check from more than ten minutes down to about one.

### The desk on the change log, 2026-10-25 (the same workstation)
`python tools/bench_org.py --desk 10` opens a desk on the generated log and times ten desk proposals end to end (a
manager adds an employee to a team of their department: build, judge, propose through the signer, follow), then two
judged in full for comparison. The organisation is the day-zero one above, its people under internal anchors with an
accounts record each (decision 0028).

| | 5,000 employees | 20,000 employees |
|---|---|---|
| a desk change, judged on its reach (median) | 1.5 s | 3.4 s (max 4.4 s) |
| the same, judged in full | | 47 s (max 59 s) |
| opening the desk on the log (catching up, the mapping) | 8 s | 52 s |
| peak memory | | 530 MB |

How it got there (decision 0022 S5 step T9): the desk judges a change the signer's way, on its own replica with the
change tried and rolled back (one shared function, `store/working.py`), commits the ops it judged instead of a diff of
two whole documents, moves its records forward by each new link instead of replaying them, and syncs the mapping in
one transaction. The first version, which judged on whole documents, took 11.9 s at 20,000 and opened in 169 s.
What is left in a change is the desk's own copy of the records it hands out (a deep copy, as on the YAML store) and the
signer's judgement in the same process; a streaming working set for the desk's views is an 0.26.x item.

## Limits of this model

- The rates marked as assumptions are defaults to be replaced by a deployment's own numbers: the tool takes them as
  parameters for that reason.
- Privileged grants are clones of one fixture grant, so their check cost is that of one administrator's grants, not of
  500 administrators' separation-of-duty sets.
- The day is replayed on the measured costs of a sample taken at day zero (or at the history given); the cost of a
  change grows with the state, which is what `--history-days` measures.
- Visits are outside the signed log by design; their own cost (the desk's visit files, the 30-day erasure) is measured
  by the visit tests, not here.
