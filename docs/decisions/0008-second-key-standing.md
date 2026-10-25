# 0008: A second key needs standing, decided by one policy compiled into the engine

- Status: accepted
- Date: 2026-10-22
- Decider: maintainer

## Context
A change to an elevated or privileged group waits for a second key. Until now a second key was anyone independent of
the actor: a person of the organisation, not the actor or the member, outside the actor's chain of delegations, not
compromised. That lets any colleague approve, and lets two deputies approve each other's changes in turn. Prior art
counts only approvers with standing: GitHub counts reviews from people with write access, Entra PIM has designated
approvers per role, midPoint has approver relations, banks use authorised checkers.

The rule also existed twice, in Python (the engine) and in Rego (the policy an OPA server runs), and the two drifted
within a day: the Rego copy never learned that externals and agents are not second keys.

## Decision
1. **Who counts.** Under enforce, a second key must be independent of the actor (as before) and have standing:
   - the tenant's security officer;
   - a named approver: appointed by the root trust owner with the security officer's key, for a limited time
     (delegation.max_approver_days, default 365), a person of the organisation, never the root;
   - someone who manages the group, or a group above it, through another chain of delegations, and who is not in the
     actor's organisational unit where both units are recorded (persons[].unit).
2. **The root never counts** as a second key, not even when it is also the officer. With no named approver, the way
   out is to appoint one; the desk's next steps say so.
3. **No favours returned.** An approver whose own change carried the actor's key within delegation.reciprocity_days
   (default 30) does not count for the actor. 0 makes reciprocity a signal only.
4. **Standing as things stand.** Like every rule in the engine, standing is judged now, not frozen at approval:
   appointing someone makes their earlier keys count, and ending the appointment makes approvals that rested on it
   stop counting (the membership falls, as when any rule stops holding). The as-made pass checks independence only.
   Reciprocity is measured at the moment of the change.
5. **Rollout by a setting**, delegation.second_key_standing:
   - off: today's rule (independence);
   - warn (default): the same, and `python -m keyclerk.delegation --standing-impact FILE` lists what enforce would
     refuse, with the reason per approver;
   - enforce: standing is required.
   A tenant moves to enforce once the impact list is empty, normally after appointing its named approvers.
6. **One rule, in Rego, run in process.** keyclerk/policy/second_key.rego is the only definition. The engine
   compiles it to WebAssembly at build time (tools/build_policy.py, which records the source digest; a test refuses
   a stale build) and evaluates it in process with wasmtime. Python only gathers the facts per approver. The
   OPA policy keyclerk/policy/delegation.rego, for deployments that run OPA, builds the same facts from its policy data
   and calls the same function, and a test checks the two agree. KeyClerk needs no policy server or any outside service to decide: it runs on its own.
7. **Appointments are records** (approvers), ended through the administrative revocations like delegations, never
   deleted or changed once ended (the history guard covers them), and the officer's key on them carries a broker
   proof like every other approval (decision 0006).

## Consequences
- A dependency: wasmtime (hash-locked; the image installs only locked wheels). The policy needs no host builtins; a
  build that did would fail when loaded, never at a decision.
- An evaluation takes about 0.2 ms for five approvers.
- Moving a tenant to enforce can make memberships fall when an appointment ends; the warn list and the desk's next
  steps make that visible before it happens.
- Not decided here: whether a plain member may approve anything at all once standing applies (only second keys are
  covered).
