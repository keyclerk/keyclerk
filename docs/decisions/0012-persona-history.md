# 0012: A persona's history, and the history of the identity providers behind it

- Status: accepted (2026-10-23, choices D1 to D6). The need: opening a persona shows its history, as known to this
  instance or as announced by a federated KeyClerk that shares it (the federated case is where FTEF, the Federated
  Trust Evidence Framework, an open specification, applies), on a slider with a timeline that marks significant
  changes; the same for the identity providers that identified the persona over time, with their state at the same
  moments; and all of it protected by role- and attribute-based rules, because a person's history is among the most
  sensitive views KeyClerk can draw.
- Date: 2026-10-23

## What exists to build on
- The desk keeps every revision of the records, signed (one file per revision), and an append-only change log; the
  persona graph already answers "as at" any moment and steps to the previous and next change (0009).
- Visits, badges, codes and timers are events; last seen is planned in two tiers (0009, D6).
- Identity sources are configuration; the broker's identity providers and their state are observed by the reconciler.

## Proposal
1. **The persona's own history**, folded from the record revisions: accounts added and removed, the purpose of each
   account (daily, admin), the kind (staff, external, workload, agent), the unit, an agent's director or a workload's
   owner, and around it the memberships, delegations, leases, approvals, visits and badges with their windows.
2. **Significant changes** are marked by rule (Rego decides which events are significant for which viewer): an account
   added or removed, a first privileged right, an admin persona used, a suspension, a revocation for cause, a change of
   identity provider, a director changed.
3. **The identity providers behind the persona over time**: for each account, which source identified it (by the
   configured identity sources), and that source's state at each moment: enabled or not, its federation link's state
   and band per kind of claim, an incident or suspension on it.
4. **Federated history.** Another KeyClerk that federates with this one may announce events about its own people (a
   person of partner B joined or left B, B's identity provider was suspended). Announcements are signed by the partner,
   carried under the federation link as their own kind of claim, kept with their source, as of when, and never
   merged into this instance's records as truth. FTEF's person-binding proposal (binding people to partner records) is
   where this meets the spec; the announcement format is an FTEF candidate.
5. **Who sees what (RBAC and ABAC, in Rego).** The view policy decides per kind of fact: a viewer and the root see all
   of this instance's history; a person sees their own; a manager sees what touches groups, chains and places they
   look after; sign-in and presence detail stays with the security officer (0009 D6); federated announcements are shown
   only to roles the link names. Every look is logged, as for the graph.
6. **The view.** A slider over time with marks for significant changes, a lane per account and per identity provider
   (swimlanes), and at the slider's position the state of everything in the lanes. The graph and the history share the
   moment, so moving one moves the other.

## Decided (2026-10-23)
| # | Decision | Outcome |
|---|---|---|
| D1 | Source | fold the signed record revisions and the event log; nothing new stored; a cache derived from them later for speed, never authority |
| D3 | Significant changes | every change a small tick; a default set marked big (accounts added or removed, a first privileged right, an admin persona used, a suspension or revocation for cause, an identity provider change, a director change); Rego decides per viewer; configurable |
| D4 | Identity-provider state | the configured sources, the broker's provider state as the reconciler observed it (an event per change), and the federation link's band per kind of claim once links exist |
| D6 | The view | a slider with ticks and marks, a lane per account and per identity provider, the state at the slider, a table with the same content, the moment shared with the persona graph; amended: a UX specialist designs and reviews it before it is built |
| D2 | How far back | a viewer and the root the full life; the person their own full history; managers 13 months of what touches their part; sign-in and presence detail 30 days, the security officer only; settings, decided in Rego |
| D5 | Federated history | pushed by the partner and pulled on reconnect, signed, kept 13 months, shown only to roles the link names, never merged as truth; built with the federation link; the format proposed to FTEF through its own review process |
