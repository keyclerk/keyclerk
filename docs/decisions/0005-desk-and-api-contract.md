# 0005: The desk: one API contract for every front end; changes become signed record revisions

- Status: accepted
- Date: 2026-10-22
- Decider: maintainer

## Context
Decision 0004 makes requests and approvals KeyClerk's core. Deputies need to act (add and remove members, nest groups,
create subgroups, delegate, end delegations) and see why things are as they are, in a front end, and others must be
able to build their own front ends without reimplementing any rule.

## Decision
1. **The desk core** (`keyclerk/desk.py`) turns an action into the records it would add and runs the candidate records
   through every engine check, the same the reconciler runs. The answer is applied (a new revision), pending (only a
   key someone else must add is missing: a second key from outside the chain, the security officer) or refused, with
   the engine's reasons. The desk decides nothing the engine does not: it finds the delegation the actor acts under and
   builds records.
2. **The API is the contract** (`schema/api.openapi.json`, `/api/v1`): every view and every action. The bundled front
   end (`keyclerk/ui`) is a static page that uses only this API; tests hold the server's routes, the front end's calls
   and every response to the contract. Breaking the contract needs a new version path.
3. **Two ways in**: a browser session from the desk's own sign-in (PKCE; HttpOnly SameSite cookie; a CSRF token in a
   header on every write), or a bearer token from a broker client the deployment names (front ends built by others).
4. **The desk is the records author.** It writes each revision with a detached Ed25519 signature, keeps every revision
   and a hash-chained change log. The reconciler verifies the signature with the public key the deployment pins and
   still applies its own guards (history, removal cap). The desk's signing key is a deployment secret given to the
   desk only.
5. **Who may read**: people of the realm see the tree, the delegations, the changes and their own access; a viewer
   (the deployment's viewer role) and the root see anyone's access.

## Consequences
- A deployment that keeps records in git can mirror the desk's revisions into it, or keep merge requests as its way
  in; both produce the same signed file.
- Every revision the desk signs carries its serial (records `revision`); the reconciler refuses one older than the
  newest it applied, which it keeps in the broker as well as in its state, so a lost state folder cannot let an older signed revision
  replay (0.4.3).
- Writes are limited per person and the change log costs the same at any length, so a long log or a flood of refused
  attempts cannot stop the desk for everyone (0.4.3); a change that needs keys from several people collects them one
  approval at a time, instead of refusing an approval that is one key of two.
- One desk process owns a store, so two processes cannot overwrite each other's revisions or reuse a serial; commits
  are written ahead with signed log lines and the desk repairs a crash or a stray write only towards a revision its own
  signed log vouches for (0.4.4).
- Reads are need-to-know in the desk itself, so a plain member cannot read every group, delegation and change, and
  every front end gets the same scoping (0.4.5); the contract explains itself and the bundled API page is built from
  it, with a preview call that never writes.
- Approvals as the approver's own signature: decision 0006 (0.5.0), so the desk's one signing key no longer vouches
  for every approval.
- Every refusal and every change that waits says why, what would complete the intent and who can do it (next, keyclerk.remedies,
  0.6.1): the people are asked of the engine, never guessed; a reason without a rule sends the person to the root.
