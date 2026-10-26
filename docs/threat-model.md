# Threat model

What KeyClerk protects, from whom, and how. Each defence names the code that implements it and the tests that hold it.
This page describes defences that are built and tested; it is updated with each release.

## What is protected
- **Who may access what, and until when:** the records of grants, memberships, delegations, leases and approvals.
- **That access ends:** an access that should have ended must not survive in the identity provider or at an edge.
- **That every change is accountable:** who proposed it, who approved it, and that nobody rewrote history afterwards.
- **People's personal data** in those records.

## Who it defends against
- An outsider with network access to the desk, the edges or the identity provider.
- An insider who wants more access than they should have, or wants to keep access after leaving.
- A compromised component: the desk's web process, an edge, or the identity provider's administration.

## Trust boundaries
- **The desk** (the web front end and API) proposes changes. It does not decide alone: approvals are the approvers' own
  signatures, made by the identity provider after a fresh sign-in.
- **The signer** holds the records key, checks every change in full before signing, and keeps its own copy of the
  records built only from what it signed.
- **The reconciler** applies only signed, checked records to the identity provider.
- **Edges** at sites admit people to systems on the strength of signed bundles, with keys pinned on site by people,
  never taken from the desk.
- **The identity provider** (Keycloak) authenticates people; KeyClerk decides their access.

## Defences
- **Approvals are signatures the desk cannot make.** Every approval carries a proof the identity provider signs after a
  fresh sign-in, over a statement naming the exact records; a proof fits only its records, its person and its time.
  The proposer of a high-risk change signs it too. (`keyclerk/approvals.py`; `tests/test_approvals.py`,
  `tests/test_proposer_proofs.py`)
- **A separate signer checks everything it signs.** Whoever takes over the desk still cannot get a change signed that
  breaks the rules or lacks its approvals. (`keyclerk/signer.py`; `tests/test_signer.py`)
- **Only the reconciler links a person to their sign-in account**, on the signer's own listener with its own
  credential, and only for one account it read with that person's anchor; the signer bounds what a link and a new
  account's row may carry. (`keyclerk/signer.py`, `keyclerk/store/log_reconcile.py`; `tests/test_signer_roles.py`,
  `tests/test_reconcile_links.py`)
- **Only signed, checked, non-rewriting records are applied**, and revocations can never be dropped from history.
  (`keyclerk/reconcile.py`, `keyclerk/records.py`; `tests/test_reconcile.py`)
- **Edges trust only what was pinned on site:** bundles, ceilings and notices are checked against keys a person pinned,
  with serial and time floors so old bundles cannot be replayed; the security officer's ceiling bounds what any bundle
  can grant, for leases and visits alike; an edge can prove its hardware and boot state.
  (`keyclerk/edge.py`, `keyclerk/attest.py`; `tests/test_edge_primitives.py`, `tests/test_edges.py`,
  `tests/test_attest.py`, and the conformance set in `tests/conformance/edge.json`)
- **Hostile input is bounded:** oversized, deeply nested or alias-expanding documents, injection-shaped identifiers,
  times without a zone, plain HTTP to another host and unbounded responses are refused. (`keyclerk/guard.py`;
  `tests/test_guard.py`)
- **KeyClerk touches only what it manages in the identity provider:** groups it did not create, members without an
  anchor and role mappings on managed groups are refused. (`keyclerk/connectors/keycloak.py`; `tests/test_connectors.py`)
- **The web front end is locked down:** authenticated requests only, known hosts only, no framing, a strict content
  security policy, and sender-constrained tokens (DPoP). (`keyclerk/console.py`, `keyclerk/oidc.py`, `keyclerk/dpop.py`;
  `tests/test_console.py`, `tests/test_broker_features.py`)
- **The supply chain is pinned:** every runtime dependency is locked with its hash, and vendored browser code is checked
  against its record. (`tests/test_supply_chain.py`)

## Out of scope
- The security of the identity provider itself, the operating system and the network around a deployment.
- What people do inside a session once access is granted (recording and review are the edge's and the deployment's).
