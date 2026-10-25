## What and why

<!-- What this changes and why. Link the issue it closes. -->

## Decisions

- Decision records touched or added (`docs/decisions/`):
- A change of intent needs a decision record first; a change that only builds what one says, a link to it.

## Checks

- [ ] `opa test keyclerk/policy/` and `python tools/build_policy.py --check` pass
- [ ] `python -m pytest` passes, with a test for what changed (CONTRIBUTING.md: the test policy)
- [ ] `reuse lint` and `python tools/leak_gate.py .` pass
- [ ] CHANGELOG.md has a line for anything a deployer or an edge implementer would notice

## AI use

Tick the level of AI involvement in this change.

* [ ] Fully AI-generated, not reviewed line by line
* [ ] AI-designed, AI-coded, checked by a human
* [ ] Human-designed, AI-coded
* [ ] Human-designed, human-coded (AI autocompletion and boilerplate only)

*This does not block AI contributions; it tells the reviewer where to look harder. Commits say the same in an
`Assisted-by:` trailer. Adapted from Warpgate's pull request template (Apache-2.0).*
