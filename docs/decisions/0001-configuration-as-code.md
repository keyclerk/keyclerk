# 0001: The engine holds no rules and names no deployment

- Status: accepted
- Date: 2026-10-22
- Decider: maintainer

## Decision
- Every rule the engine applies comes from one configuration document validated against
  `keyclerk/schema/config.schema.json`. A deployment keeps it as code in its own repository.
- Deployment facts are configuration, never code: the operator's subject kind, subject kinds, scope levels, the roles
  allowed to cross planes, broker realms, connector tags.
- The repository names no deployment. A test fails if any file does.
- Deployments pin the engine by version tag; the Rego and schemas ship inside the package.

## Consequences
Engine changes are released by tag; a deployment adopts them by moving its pin and running its own scenario tests.
