# Changelog fragments

A pull request with a change worth a line in the release notes adds one file here instead of editing `CHANGELOG.md`:
`<issue>.<section>.md`, where section is one of `security`, `changed`, `added`, `deprecated`, `removed`, `fixed`.
Without an issue, a short slug takes the number's place (`desk-timeouts.fixed.md`).

The file holds Markdown bullets in the style of `CHANGELOG.md`: each entry starts with `- `, continuation lines are
indented two spaces, lines stay within 120 columns, punctuation is plain ASCII. Example, `27.fixed.md`:

    - A restored desk resumes above the highest revision any edge reported, so it never signs a number twice.

`python tools/changelog.py check` checks them (the tests run it); `python tools/changelog.py release X.Y.Z` folds them
into `## X.Y.Z (date)` in the release pull request.
