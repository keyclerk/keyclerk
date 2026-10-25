# The desk: UI and UX upgrade

- Status: built in 0.16.2 to 0.16.4 (slices 1 to 6); operator, 2026-10-23: "I really want that best practice UI and UX upgrade"
- Date: 2026-10-23
- By: the UX specialist agent, from the code of 0.16.0 (`keyclerk/ui/index.html`, `app.js`, `app.css`), the API contract,
  decisions 0005, 0006 and 0012, and `docs/ux/persona-history.md`, whose rules this note keeps. Live check: the sign-in
  page only (light, dark, 1280 px, 360 px; no style attributes, no horizontal scroll); contrast measured for every
  colour token.

Constraints: no inline styles or scripts (the CSP); nothing external (fonts, CDNs); no framework (native `<dialog>`
gives the focus trap and Esc; a combobox is about 120 lines of `h()`); WCAG 2.2 AA; 360 px; light and dark; a calm,
exact console. Visits are frozen: polish only.

## Who uses it, for what
- Everyone: see what I hold and why; approve what waits for my key; check nothing was added behind my back.
- A deputy or manager: add or end a membership, nest a group, delegate; see who is in my group and whether the sign-in
  service has it; renew before it ends.
- The root: delegate from the top; end a delegation for cause; take what nobody else can unblock.
- A viewer or the security officer: investigate a person or a change at a moment; read the log; check the reconciler.
- The front office or a guest (visits, frozen): the gate answer on a phone; record an entry.

## Findings on the 0.16.0 desk
Critical
- C1 A count of what you may not see: `viewGraph` prints "N more items are outside what you may see" (`g.hidden`);
  `pendingList` says "Nobody you can see can add this key now". Remove the count and `hidden` from the response; say
  "Ask the root: they can find who adds this key."
- C2 Approving without seeing what you sign: Approve redirects to the broker at once; the broker does not show the
  change (decision 0006), and the card shows only a summary. A review view comes first (below).

High
- H1 End membership, end delegation, withdraw and the visit buttons skip the preview and the confirm; revoking (which
  voids what was done since) has an optional reason and no impact preview.
- H2 `viewGroup` reloads the whole page every 10 seconds: a half-filled form, its preview and the focus are lost.
- H3 Focus: after an action it falls to `body`; refusals are announced politely only; route changes do not move focus;
  no skip link; the sticky header can cover a focused control (WCAG 2.4.11).
- H4 Contrast: light `.pill.ok` 4.42, `.pill.warn` 3.96, `.pill.key` 2.66, `.warn` text 4.43 at 12-13 px; focus ring
  2.74; input borders 1.51; `input:focus{outline:none}` hides focus on fields. Dark `.scan`: white on ok 2.14, on bad 2.55.
- H5 Status words clash: "pending" means waits for a key, starts later, and a dashed line; `dead` is "ended" and "broken
  above"; risk classes reuse the outcome colours, so "low" looks like "applied".
- H6 The log renders up to 10,000 rows at once, without filters, with relative times only.

Medium
- M1 Navigation: seven or eight equal tabs; Broker and API beside daily tasks; tabs scroll off a phone; counts explained
  only in a tooltip.
- M2 `actionPanel` claims tabs without tab panels or arrow keys.
- M3 Forms: hints not tied to fields; no inline errors; silent failure when a form is incomplete; a select of every
  person; days without the resulting end date; the preview neither focused nor announced.
- M4 Refusals: reasons joined in small muted text, rule ids thrown away, names not links, the why before the do.
- M5 The graph: no keyboard path, `via` only in the tap panel, a random layout on every load.
- M6 Tables: no header semantics; card layout on a phone loses them; anchors and times only in tooltips.
- M7 Home: rights as bare codes; nothing about ends soon or my proposals waiting; four equal stat cards.
- M8 Contract drift: the UI reads log fields (`summary`, `actor`, `actor_name`, `reasons`, `approved_by`,
  `approver_name`, `revision`, `action`) that `LogEntry` does not document.
- M9 Loading dims the old page (stale data looks live), no `aria-busy`, a blank graph while the library loads.

Low: the sign-in title alignment; jargon (records revision, reconciler, anchor, engine, rules); the chain as a
monospace string; switching theme does not redraw the graph.

## Prior art
| Product | Taken | Left |
|---|---|---|
| Microsoft Entra My Access approvals | approvals as their own queue (pending, history); a details pane before Approve | email as the main way in |
| Okta Access Requests | named approvers in order; who is next | chat-app approval |
| Teleport Access Requests | keys given of keys needed; suggested reviewers; time-bound by default | the CLI |
| GitHub sudo mode | say before the prompt that this needs a fresh sign-in, and why | the sudo window |
| GOV.UK error summary and check answers | focus an error summary that links to each field; "Error:" in the title; check your answers with Change links | their typography |
| Primer confirmation dialog, degraded experiences | confirm only high-impact actions, title as a question, the button names the verb; when a part fails, keep the rest useful | dialogs for routine actions |
| W3C APG combobox | the person picker: list autocomplete, arrow keys, `aria-activedescendant` | a widget library |

Sources: learn.microsoft.com entitlement-management-request-approve; help.okta.com access-requests overview;
goteleport.com access-requests docs; docs.github.com sudo-mode; design-system.service.gov.uk error-summary and
check-answers; primer.style confirmation-dialog and degraded-experiences; w3.org WAI-ARIA APG combobox.

## Design system
Tokens (keep the plum and orange identity):
- Light: `--focus:#b4530f` (4.6:1 on paper), `--field-line:#857b93` (4.0:1 on card), `--ok-ink:#256a4c`,
  `--warn-ink:#8a5a0c`, `--key-ink:#9a4a12` (each above 5:1 on its soft fill). Pills and status text use the ink tokens.
- Dark: `--field-line:#7d6f92`, `--on-status:#120a1f` for text on solid ok and bad fills, `--focus-on-dark:#f0954f`
  in the header.
- Type 12 / 13 / 15 body / 18 h2 / 22 h1 on a phone / 26 h1; line height 1.5; tabular numbers; nothing below 12 px.
- Space 4, 8, 12, 16, 24, 32; radius 7 (controls), 10 (cards), 999 (pills); elevation flat, card, dialog.
- Focus: a 2 px outline with a 2 px offset on everything, fields included; `scroll-padding-top` the header height.

Components (built with `h()`, styled by classes): buttons (primary, secondary, ghost, danger; at least 32 px; a verb
and an object; "Checking..." while busy); a field with label, hint and error wired by `aria-describedby`, an error
summary that takes focus; a status pill (glyph and word, always both); a class tag apart from status colours (outlined,
1 to 3 bars, Privileged filled plum); tables with caption, header and scope, absolute times with the relative time as
secondary text; cards with one job; one outcome panel; a native `<dialog>` (title as a question, consequences, Cancel
focused for destructive actions); empty states that say what the area is for and who to ask, never a count of what is
hidden; skeletons with `aria-busy`; a short toast for applied only.

Status vocabulary (one map replacing `STATUS`, `TREE_PILLS` and `WHEN`):
| Domain | Key | Shown | Tone |
|---|---|---|---|
| Change | applied | Done | ok |
| Change | pending | Waiting for a key | warn |
| Change | refused | Refused | bad |
| Change | withdrawn / expired | Withdrawn / Expired unsigned | neutral |
| Grant | active | In force | ok |
| Grant | not started | Starts {date} | neutral |
| Grant | grace | Ending, grace until {date} | warn |
| Grant | ended / dead | Ended / Ended: a link above ended | neutral |
| Grant | revoked / void | Revoked for cause / Void | bad |
| Grant | lapsed | Lapsed | warn |
| Sign-in service | true / false / null | In the sign-in service / Arriving, within a minute / Not known | ok / warn / neutral |
The word "pending" never appears on screen.

## Views
Shell: Home, Approvals (count), Groups, People (when allowed), Delegations, Visits (count), More (Sign-in service, API);
counts in the accessible name ("Approvals, 2 waiting for your key"); a skip link first; on a phone a Menu button opens a
dialog with the full list.

Home: lead with what needs me (waiting for my key, my proposals waiting, ends within 14 days), then what I hold (rights
with how I get them, groups I manage, delegations I hold). "Nothing needs you now." when empty. Ends-soon needs a `/me`
field.

A group: the class tag, what it carries, where it is nested, what I may do; verb buttons (Add a person, Nest a group,
New subgroup, Delegate), each opening a three-step dialog: choose (person combobox, days with the end date shown live),
check (the outcome panel, focused), confirm (the button names the change; when it will wait: "Propose: ask for Dee's
key"). Ending a membership or a delegation uses the same dialog; revoking needs a reason and lists its impact. Only the
"Arriving" cells poll, and not while a form has focus.

Approvals (`#/changes`, named Approvals; tabs Waiting for your key, Your proposals, History) and a review page
`#/change/{id}`: what it changes (person, group with class and what it carries, from and until), who proposed it under
which chain, why it waits, keys given and who may give the next; then Approve with the sentence "Approving is your own
signature. You sign in again with your passkey; the sign-in page will not show this change, so check it here.", the
statement digest with Show in full, and Approve on my phone. On return focus goes to the outcome. No Deny: the contract
has none; pending changes expire. A refusal by the approver would be an engine decision first.

Refusal with next steps: one outcome panel for previews, results and error pages, in this order: what happened, what
you can do (numbered), who can do it (links where the viewer may see them), why (the engine's words), and the rule ids
in a details block for the security officer. Focus moves to its heading; `role=alert` for refused; the page title starts
with "Error:".

Persona graph: keep the persona-history moment bar and tabs; a deterministic layout; table rows select nodes (the
keyboard path); a via column; a side panel on desktop, below on a phone with the table first; a legend in shapes and
words; a skeleton while drawing, and "The graph could not be drawn; the table below shows the same." when it fails.

Delegation tree: a nested list with `role=tree`, `aria-level` and arrow keys first, the diagram on request; rows with
the delegate's name as a link, group, class tag, powers, "may pass on N more levels", end date, status word, and how
many memberships rely on it.

Visits (frozen): fix the dark `.scan` contrast, tie hints to fields, "Add at least one guest", stack forms on a phone,
absolute times as visible text.

## Build plan (each slice ships alone)
1. Foundations and accessibility: tokens and focus, skip link, focus the heading on a route change, scroll padding,
   skeletons with `aria-busy`, table semantics, sign-in title, dark `.scan`; remove the hidden count (C1); a Playwright
   harness on the fixture desk with axe-core (dev only, pinned). Checks: axe 0 serious or critical on home, group,
   changes, graph, tree, visits and scan in light and dark at 1280 and 360; no `[style]`; no horizontal scroll at 360;
   a contrast test over the token pairs; no text "outside what you may see"; the first Tab stop is the skip link.
2. Outcome panel and status vocabulary. Checks: every pill has a word, none says pending; a refused preview focuses the
   panel with `role=alert`; next steps before reasons; rule ids only in details; class tags never use outcome classes.
3. Approvals and the review page; the statement call; a confirm for Withdraw; `LogEntry` documents what the UI reads.
   Checks: Approve only from the review, which shows person, group, class, dates, chain and digest first; at most 10 Tab
   presses from Approvals to Approve; the return focuses the outcome; the contract test validates log entries.
4. Propose, check, confirm in a dialog; error summary; person combobox; live end date; previews for ending and revoking;
   polling scoped. Checks: Esc returns focus to the opener; an empty submit focuses the error summary and the title
   starts with "Error:"; a typed value survives 30 s of polling; combobox keys; the dialog fits 360 px.
5. Shell, home and log: navigation regrouped, More and the phone menu; Needs you; log filters (Mine, Refused, Waiting),
   50 rows then "Show 50 more", absolute times. Checks: accessible nav counts; `aria-current=page`; at most 50 log rows
   first; every nav item reachable at 360 px.
6. Graph and tree: deterministic layout, rows select nodes, via column, the tree as `role=tree`, the visits polish.
   Checks: the same positions on two loads; Enter on a row selects its node; tree arrow keys and `aria-level`; switching
   theme redraws the canvas.
