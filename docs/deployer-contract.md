# What a deployer must supply

Generated from `keyclerk/contract.py` (`python -m keyclerk.contract render`); a test keeps it current.
Check a planned deployment before starting it: `python -m keyclerk.init check --config FILE --for signer,desk,reconciler,witness [--SERVICE-args "..."]` names everything missing at once.

## signer

Starts as `python -m keyclerk.signer`.

- Required flags: `--state`, `--config`
- Files that must exist when given: `--key`, `--config`, `--token`, `--reconciler-token`, `--approval-jwks`, `--identity-key`, `--custodian-token`
- Directories: `--state`
- Configuration keys: `approvals.acr`
- the records key's holder: --custodian (production) or --key (development), one of them
- --custodian-token for a custodian over TCP
- --listen (unix:/path or tcp:127.0.0.1:port), unless --adopt
- --token for a TCP listener
- HA: --ha-node and --commit-witness together
- --ha-hold of at least 5 seconds
- approvals.proofs required: --approval-issuer, --approval-audience and --approval-jwks
- the reconciler's listener has its own --reconciler-token
- --identity-key, the reconciler's public key, where a reconciler is wired (0.29.0: leases name bastion accounts only from its sealed identity map; python -m keyclerk.init identity-key)

## desk

Starts as `python -m keyclerk.api`.

- Required flags: `--config`, `--store`, `--oidc-public-issuer`, `--oidc-redirect`
- Files that must exist when given: `--config`, `--signer-token`, `--signing-key`, `--mgmt-token-file`
- Directories: `--store`
- Configuration keys: `approvals.acr`
- --signer (a checking signer) or --signing-key (development)
- --signer-token for a TCP signer
- --mgmt-port needs --mgmt-token-file

## reconciler

Starts as `python -m keyclerk.reconcile`.

- Required flags: `--config`, `--keycloak`, `--realm`, `--secret-file`, `--state`
- Files that must exist when given: `--config`, `--secret-file`, `--reader-secret-file`, `--mark-key`, `--signer-token`, `--records`
- Directories: `--state`
- Configuration keys: `approvals.acr`
- --records (the YAML store) or --log-replica with --signer and --records-key
- --mark-key: the broker keeps a high-water mark the reconciler signs (0.27.0)
- approvals.proofs required: --approval-issuer and --approval-audience

## witness

Starts as `python -m keyclerk.witness serve`.

- Required flags: `--key`, `--name`, `--state`, `--log`
- Files that must exist when given: `--key`
- Directories: `--state`
