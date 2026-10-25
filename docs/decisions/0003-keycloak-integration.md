# 0003: Keycloak through SCIM, as measured on 26.8.1

- Status: accepted
- Date: 2026-10-22
- Decider: maintainer
- Evidence: an end-to-end run of the reconciler against Keycloak 26.8.1 (writes, read-back, removals with logout,
  idempotent replay)

## Facts measured
- The SCIM_API feature is on, but each realm must switch SCIM on (`scimApiEnabled`).
- SCIM accepts tokens only from confidential clients, and only with the realm's SCIM base URL as an audience.
- `externalId` is kept only when a user-profile attribute is annotated `kc.scim.schema.attribute: externalId`.
- Neither groups nor users report memberships through SCIM.

## Decision
- People are found by `externalId`, kept in an admin-only user-profile attribute `anchor`, so usernames stay human.
- Memberships are written through SCIM and read back through the admin API.
- The reconciler's service account holds `manage-users`, `view-users`, `query-users` and `query-groups` only, with
  full scope off, and logs a person out when a membership is removed.
