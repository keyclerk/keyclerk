# Security

KeyClerk decides who may access what, signs those decisions and applies them. A weakness in it can grant access or
keep access alive that should have ended, so reports are welcome and handled with priority.

## Reporting a vulnerability
Report privately through this repository's "Report a vulnerability" button (GitHub private vulnerability reporting:
<https://github.com/keyclerk/keyclerk/security/advisories/new>),
never in a public issue or pull request. Please include what you found, the version or commit, and how to reproduce it.

- You get an answer within five working days.
- Fixes are prepared in private and released with an advisory; you are credited unless you ask otherwise.
- Please give us a reasonable time to fix before publishing (90 days is the usual default; we will agree a date with
  you).

## Supported versions
The latest release receives security fixes. Formats exchanged with edges change only under a new name, so an edge on
an older format keeps working until it moves; such a format is supported until a newer one has been available for six
months.

## Verifying a release
- Commits and tags are signed; GitHub shows them as verified.
- Each release carries SHA-256 sums and a build provenance attestation:
  `gh attestation verify FILE --repo keyclerk/keyclerk`.
- Dependencies are pinned with hashes (`requirements.lock`, `constraints.txt`); `tests/test_supply_chain.py` holds
  every runtime dependency to its pinned version and hash.

## What the design defends
See [the threat model](docs/threat-model.md) for the assets, the trust boundaries and the defences, each with the code
and tests that hold it.
