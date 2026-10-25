# 0007: Use what the broker already offers: back-channel logout, events, step-up, DPoP, phone approvals

- Status: accepted
- Date: 2026-10-22
- Decider: maintainer

## Context
Keycloak 26.8 enables, by default, fine-grained admin permissions (v2), OpenID Connect back-channel logout, admin and
user events, step-up authentication with levels of authentication, passkeys, client policies, DPoP, CIBA and
Workflows. KeyClerk used little of it, which left gaps: a writer that could edit any user, desk sessions that outlived
the broker's, manual changes nobody could attribute, approvals at password strength, and stolen bearer tokens that
worked from anywhere.

## Decision
1. **A writer that manages membership, not people.** The engine needs, from the broker, only: create and mark its
   groups, add and remove members, read users and groups. With fine-grained permissions that is all a deployment
   gives it. Logging a person out on removal needs the right to manage users (which includes changing their
   attributes, such as the anchor), so it becomes a setting (reconcile.logout_on_removal); without it, short access
   tokens bound how long a removed membership is still claimed.
2. **Back-channel logout** for the desk and the console: the broker posts a signed logout token; sessions for that
   person or broker session, issued before it, end. Replays, other clients' tokens and nonces are refused.
3. **Attribution from admin events:** when the reconciler removes a membership the records never required, it looks
   up who added it in the broker and puts that in the finding (best effort, bounded, never part of a decision).
4. **The approval level:** a deployment can require every approval proof to carry an authentication level (acr),
   such as a level its broker binds to a passkey; the desk asks for it, the reconciler checks it.
5. **DPoP for front ends built by others:** a client named with --dpop-client must send DPoP-bound tokens; the desk
   checks the proof of possession (key thumbprint, method, URL, time, token hash, single use).
6. **Approving on another device:** the desk gives an approver a short-lived link (and its QR image), signed by the
   desk and naming that approver; opening it starts the same signed approval (decision 0006) without a desk session.
   The link only says who may try; the broker's fresh sign-in is the approval. CIBA as Keycloak ships it carries no
   nonce and lets the authentication channel declare consent, so it is not used for approvals while that channel would
   be the desk.
7. **Workflows** belong to the deployment's broker configuration; the engine's rule is that they never manage
   KeyClerk's groups (the reconciler would remove such memberships as intrusions).

## Consequences
- A leaked writer secret no longer changes credentials, roles or anchors.
- The QR image needs a QR encoder: segno (pure Python, no dependencies), hash-locked like every dependency.
