# 0024. External people sign in at their own provider only through a governed binding

- Status: accepted (2026-10-24), not built. Target 0.30.0, with the session constraints in the lease.
- Context: a contractor's or vendor's engineer often signs in at their own organisation's OpenID provider, brokered
  by the deployment's Keycloak. Linking such a brokered identity to a person in KeyClerk's records is today an
  administrator's action in Keycloak, outside KeyClerk: nothing records who linked whom, a link outlives the person
  it was made for, and linking by e-mail lets anyone who controls an address at the other provider take an account
  over. Who may sign in as whom is identity data, and it belongs in the records like everything else KeyClerk governs.

## Decision
1. **A binding on an external person.** A person of kind external may carry bindings, each
   `{provider, subject}`:
   - `provider` is the alias of an identity provider brokered for one of the realm's connected organisations;
   - `subject` is that provider's subject identifier for the person.

   It is never an e-mail address, a username or any other claim the provider's users can change.
2. **Kept with the person's attributes, outside the signed log.** A binding is personal data, so it lives where the
   person's names and attributes live, keyed by the person's anchor, and is erased with them. What the signed log
   carries is the change that created, changed or ended it, with the person's anchor and the provider alias, never the
   subject in clear: a salted hash of it, enough to prove which binding a change made.
3. **Every change to a binding is governed.** Creating, changing or ending a binding is a change with the security
   officer's key, because rebinding a person to someone else's subject is an account takeover. The proposer is never
   the person bound. Ending a binding needs no second key: taking access away never does.
4. **The reconciler applies it.** The reconciler makes Keycloak's federated-identity link for each binding, and
   removes it when the binding ends, when the person ends, or when the external organisation is no longer connected.
   A link KeyClerk did not make, found on a person KeyClerk governs, is drift: reported, and removed when the
   deployment's drift policy says so.
5. **Unbound means no sign-in.** A brokered sign-in whose subject is bound to no person is refused. The deployment's
   own second factor (for example a passkey) is still required after the provider's sign-in; a binding never replaces
   it.
6. **A manual link stays a break-glass.** Linking by hand in Keycloak remains possible for an emergency. It is an
   incident, appears as drift, and is either replaced by a governed binding or removed.

## Consider the opposite
- Keeping links in Keycloak alone is simpler and needs no new record kind. But it leaves the most sensitive identity
  fact of an external person, which account at which organisation is them, outside the approvals, the history, the
  leaver process and erasure that govern everything else. A link that survives its person is exactly the orphaned
  access KeyClerk exists to prevent.
- Requiring the security officer's key slows onboarding of external staff. Bindings change rarely, a takeover through
  one is severe, and ending a binding is never slowed.

## Consequences
- A new attribute on external persons and a new change kind, with its second-key rule in the engine's policy.
- The reconciler gains the federated-identity link through Keycloak's admin interface, beside its SCIM writes, with
  read-back and idempotent replay as for users and groups.
- The desk shows an external person's bindings (provider and a shortened subject) to those who may see the person,
  and the security officer's approval queue shows binding changes.
- Erasure of an external person removes the binding and, through the reconciler, the link.
