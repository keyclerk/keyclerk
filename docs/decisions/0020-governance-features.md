# 0020. Governance features: reviews, dormancy, impact, exceptions, holders, outliers, orphans, agents, witness, leavers

- Status: accepted (2026-10-24, choices G1 to G11), not built. Each feature is a query on the 0017
  timeline or one small record kind; each carries a guard against growing into a suite.
- Context: decision 0004 makes certification core, and no review code exists; a scan of niche IGA features
  (Saviynt, Omada, ConductorOne, Opal, Lumos, midPoint, SailPoint) found what fits KeyClerk's records and signatures.

| | Decision | Guard |
|---|---|---|
| G1 | Event-driven micro-reviews, each decision signed; an "unreviewed for N months" trigger covers review at regular intervals | triggers in Rego; a weekly cap per reviewer folds the rest into one review; a campaign-style report rendered from records, never scheduled |
| G2 | Unused standing access goes dormant after N days, then a review, then it ends | only known signals act (broker sign-ins, edge session evidence); unknown usage gives a review only; "rare use" entitlements exempt; usage facts recorded as inputs |
| G3 | Every approval shows who gains and loses what, and signs the diff's hash | effective access from records only, never target-system effects; re-sign only when the same people's diff changes |
| G4 | An SoD conflict may be accepted for a time: a control, an owner, an end date, signed by someone other than the holder | off by default, a short maximum in Rego, the control is free text (no controls library); the end opens a review |
| G5 | Minimum and maximum holders per entitlement; ownership passes on when an owner leaves | the maximum is soft (a second key exceeds it); the minimum blocks a removal but a leaver always wins and raises an incident; succession only along existing records |
| G6 | Peer outliers, deterministic, feed reviews | peers are the recorded org unit and place; a minimum group size; nothing learned is stored |
| G7 | Orphan and shadow accounts are findings with a review for the system's owner, never removed silently | exact matching on recorded identifiers; the first run is one batch; automatic disabling only opt-in per system later |
| G8 | An agent acting for a person holds a subset of that person's access, never longer | on-behalf-of and own-workload agents are distinct; the person signs the scope; per-call enforcement stays with broker and target |
| G9 | Physical and logical access at a place in one review | each owner signs their part; a badge-versus-logical mismatch is a trigger; zone-level data only |
| G10 | A witness the deployment runs countersigns each revision head that continues the last; edges echo the head they saw | another machine and owner; an unwitnessed head raises an incident after N minutes (policy may make it block); a linear chain, no Merkle proofs yet |
| G11 | A per-leaver report: every system and edge, when it confirmed removal, against the bound | derived on demand from signed acknowledgements; the evidence type labelled per system; manual systems listed with their owner, never ticketed |

## Order
G1 with G5 and G4 first (reviews need owners), then G3, G2, G7, G6, G9, G8, G10 (before or with 0019), G11.
