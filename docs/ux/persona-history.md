# Persona history: UX design (decision 0012, D6)

- Status: design, before build. Date: 2026-10-23. Designs decision 0012 D1 to D6; nothing here reopens them.
- Inputs: decisions 0009, 0011, 0012; `keyclerk/ui/app.js`, `keyclerk/graph.py`; the local desk (kai's graph as root).

## 1. Roles and tasks

| Role | Comes to | Range they get (D2) |
|---|---|---|
| Root or viewer investigating one person | find when a right, account or provider changed; see the state at an incident moment; compare two moments; jump to the graph at that moment | full life |
| The person themselves | see what they held and when; check nothing was added behind their back | own full history |
| A manager | see joins, leaves and rights in the groups, chains and places they look after; prepare a review | 13 months, their part only |
| Security officer | everything the root sees, plus sign-in and presence events for an investigation | sign-in detail 30 days |

Personas: **kai** (daily and admin account: two account lanes, one person), **hana** (brokered Entra directory: the
provider lane matters), an **agent** (director over time; a change is a big mark), a **workload** (owner over time; no
sign-in lane).

## 2. Prior art

| Product | What it does | Take | Leave |
|---|---|---|---|
| SailPoint Access History ([ISC](https://documentation.sailpoint.com/saas/help/identities/access_history.html), [IIQ](https://documentation.sailpoint.com/identityiq/help/access_history/using_the_access_history_ui.html)) | month or day timeline, nodes outlined when something changed; event panel; Compare Access between two dates; report-admin only | changed vs unchanged marks; state at a capture date beside the event list; compare two moments | paging by month or day with arrows; one all-or-nothing permission |
| Microsoft Entra ID Governance ([reports](https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-reports)) | reports show current state; history needs an export to Azure Data Explorer | history as a first-class view | the export |
| Okta System Log ([docs](https://help.okta.com/en-us/Content/Topics/Reports/Reports_SysLog.htm)) | event counts over time; drag across bars to narrow the range | brush to zoom the track | the raw log as the main view |
| Teleport ([audit](https://goteleport.com/docs/reference/deployment/monitoring/audit/)) | audit events; sessions replayed with a scrubber | the scrubber; detail behind a role | session replay |
| GitHub audit log ([docs](https://docs.github.com/en/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization)) | filters by actor and action; 180 days stated plainly | filter chips; retention in one line | query syntax only |
| Grafana state timeline ([docs](https://grafana.com/docs/grafana/latest/visualizations/panels-visualizations/visualizations/state-timeline/)) | a row per entity, state regions with the value written in them | lane = state timeline, state word in the band | colour-only states |
| Datadog Change Overlays ([docs](https://docs.datadoghq.com/dashboards/change_overlays/)) | deployments drawn as vertical markers over graphs | big marks as a thin rule across all lanes | nothing |
| BloodHound Posture ([docs](https://bloodhound.specterops.io/analyze-data/findings/posture)) | trend over time, compare runs by date, filter by zone (Tier Zero) | "privileged only" filter; compare | a graph as history |
| Elimity ([site](https://elimity.com/)) | identity data across sources, shared with business units | per-source lens; managers see their part | no public history view to copy |

None draws the identity provider's state beside the accounts over time: that lane is KeyClerk's own.

## 3. Wireframes

Desktop, root on kai (1240px main column). The person page gets two tabs, Graph and History, sharing the moment.

```
People / kai / history
kai  [root]                                       [ Graph ] [*History*]
Everything that changed for kai, and the state at the moment you pick. Opening this history is logged.

+-- moment ------------------------------------------------------------------------------------+
| 12 Mar 2026, 14:02    7 months ago        [< Previous] [Now] [Next >]  [date input] [Show]  |
| Range: (30 days) (13 months) (*Full life*) (Custom)     Compare with: [ none v ]            |
|                                                                                              |
|  2024        |  2025                         |  2026                  ^ thumb             now  |
|  |..|.|...<>.|....|..|<>|.....|.....<>..|...|...|.|<>...|..|....[  |  ]..|.|...<>..|....|   |
|              admin account added  <>                   suspension <>     IdP change <>       |
+----------------------------------------------------------------------------------------------+
 Filter: [All changes] [Big only] [Privileged only] [Accounts] [Providers] [Access] [Places]

 LANE                           2024 .............. 2025 .................. 2026 ...... | at thumb
 Person      kind, unit       [staff, IT ops ======================================]   | staff, IT ops
 Accounts    Staff sign-in    [daily: idp:bb11-kai ====================================] | active
  (daily)    last used        . .. ... .. . .... ... .. .. ... ... . .. ...            | used that day
             adm (admin)               <>[admin: adm:bb11-kai ====/// suspended ///==] | suspended
             last used                    .   .    .        .                          | not used that day
 Providers   Staff sign-in    [enabled =========================== ! ================] | enabled
             adm  (no source configured: kind unknown) [not observed ..................] | not observed
 Around it   server-admins    [   member ======]    [==== member (4 h, 2nd key) ]     | not a member
             delegations      none
             visits, badges   .  .     .                                               | none open
             :                        |  thumb rule crosses every lane                 |
 Sign-in detail (officer, last 30 days only)  (lane absent for everyone else)

 +-- At 12 Mar 2026, 14:02 ----------------+  +-- What changed here --------------------------+
 | Accounts: daily active; admin suspended |  | 12 Mar 13:55  admin account suspended  <> big |
 | Staff sign-in: enabled                  |  |   by ingrid (security officer), reason: lost  |
 | Groups: none privileged                 |  |   hardware key. [Open in graph at this moment]|
 | Owns: ticket-router, backup-service     |  +-----------------------------------------------+
 +-----------------------------------------+
 As a table:  [Changes] [State at this moment]      (real <table> elements, same content)
```

Band legend (never colour alone): `===` active (solid, state word in the band), `///` suspended (hatched),
`...` not observed (dotted outline, "not observed"), `<>` big mark, `|` small tick, `!` observed problem (triangle
with a word: "incident"), a band end cap with "ended" or "revoked for cause".

Hana: the provider lane is the story.

```
 Providers   Partner directory (Entra, brokered)
             state      [enabled ======= ! sign-in errors (observed) ====== enabled =====]
             federation [  band per claim kind appears here once federation links exist  ]   (lane absent today)
             announced by partner B (their word, not our record)  [ joined B <> ...... ]    (named roles only)
```

Agent (triage-agent) and workload (backup-service): the Person lane carries the relation.

```
 Person   directed by   [ ticket-router ============ ]<>[ ann ======== ]   director changed <>
          owner         [ kai ======================================== ]
          reach         follows its director: [Open ticket-router's history at this moment]
 (workload) owner       [ kai =========== ]<>[ eva ======= ]               no sign-in lanes: never signs in
```

Manager (13 months, their part). Lanes they may not see are absent; the track starts at their horizon.

```
 kai  history                          You see the last 13 months of what touches groups you look after.
 Sep 2025 |....<>....|.....|..<>...|....|  now
 Around it   server-admins [ member ====== ]      [ member (4 h) ]
 (no account, provider or sign-in lanes: none were sent)
```

Phone (390px, 16px gutter, no horizontal scroll). The lanes fold into the state card and a vertical change list.

```
+--------------------------------------+
| kai              [Graph][*History*]  |
| 12 Mar 2026, 14:02                   |
| |..<>..|..<>..|..[ O ]..<>..|  now   |  <- thumb target 44 px
| [< Prev] [Now] [Next >]  [date]      |
| (13 mo) (*Full*) (Big only v)        |
|--------------------------------------|
| At this moment                       |
|  Daily account     active            |
|  Admin account     suspended ///     |
|  Staff sign-in     enabled           |
|  Groups            none privileged   |
|--------------------------------------|
| Changes (newest first)               |
| <> 12 Mar  Admin account suspended   |
|  | 02 Mar  Added to server-admins 4h |
| <> 10 Jan  Admin account added       |
|   [Show older]                       |
+--------------------------------------+
```

## 4. Interaction

- **One moment, two views.** The moment lives in the hash: `#/history/<anchor>?at=` and `#/graph/<anchor>?at=`.
  Tabs keep `at`. While dragging, the state column and card update from the loaded events; on release the hash
  changes (replaceState) and the graph refetches. Previous and Next keep timeBar's meaning: any tick.
- **Range.** Presets and a brush (as Okta), never before the viewer's horizon; presets past it are not offered.
- **Marks.** Every change a tick; Rego's big set a diamond and a rule across all lanes (as Datadog). Big marks
  closer than 12px cluster; the number counts only events sent. Hover or focus names the change.
- **Compare.** A second moment turns the state card into two columns, added and removed (as SailPoint).
- **Lanes.** Person, Accounts, Providers, Around it, Sign-in detail; groups collapse; selecting a band opens its record.
- **Agents and workloads.** A director or owner name is a link that opens that persona's history at the same moment.

## 5. Copy

- Page lead: "Everything that changed for {name}, and the state at the moment you pick. Opening this history is logged."
- Manager line: "You see the last 13 months of what touches groups, chains and places you look after."
- Officer lane title: "Sign-in detail (last 30 days, security officer only)".
- Provider not observed: "Not observed: the reconciler had no reading of this provider then."
- Unknown source: "No identity source is configured for this account's prefix. Add it in the configuration."
- Federated lane: "Announced by {partner}: their word, signed by them, not a record of ours."
- Refusal (same text for unknown and not yours, as the graph): "You may see the history of people in groups you
  manage, in your chain of delegations or at places you look after. A viewer or the root sees everyone. Ask the root
  if you need more."
- Before the first record: "{name} was not in the records yet on {date}. Their history starts {first}." (only when
  the first record is inside the viewer's range).
- Empty range: "Nothing changed for {name} between {from} and {to}." with [Show full range] when the viewer has more.
- Loading: lanes drawn as empty skeletons, "Folding the history..." and `aria-busy`.
- Error: "The history could not be loaded: {reason}. Reload, or open the graph."

## 6. Need to know

- The server sends only what the viewer may see; the page never draws a hidden fact greyed, locked or counted.
- A lane the viewer may not see is absent, with no placeholder. The officer lane never appears for others.
- The track starts at the viewer's horizon, so its length reveals nothing.
- Finding on the existing graph (fix in slice 1): `desk.py` returns `hidden` and `viewGraph` prints "N more items
  are outside what you may see"; that counts hidden facts. Remove both.
- Found on the live desk: the `adm:` prefix has no configured identity source (kind "unknown"); the provider lane
  for kai's admin account will say so until the configuration names it.

## 7. Accessibility (WCAG 2.2 AA)

- The slider is a native `input type=range` laid over the SVG track: arrow keys step to the previous or next change,
  Shift+arrow to the previous or next big mark, PageUp/PageDown by a month, Home to the start of range, End to now.
  `aria-valuetext` reads "12 March 2026, 14:02: admin account suspended".
- A polite live region announces each step (debounced while dragging).
- The SVG is `role=img` with a summary label; the two tables carry the same content (changes; state at this
  moment), with lane, state word and significance as text columns.
- No meaning by colour: state words in bands, hatching and dotted outlines, diamond shape for big marks. Non-text
  contrast at least 3:1 in light and dark; colours only from the `app.css` tokens, SVG styled by classes (CSP).
- Focus order follows the page; targets at least 24px (thumb 44px); `prefers-reduced-motion` respected.

## 8. Acceptance checks

1. `#/graph/X?at=T` to History tab keeps `at=T`; and back.
2. A manager response contains no event older than 13 months and no fact outside their part; the DOM has no text
   matching "more items", "hidden" or "outside what you may see".
3. A non-officer response and DOM have no sign-in detail lane; the officer gets none older than 30 days.
4. Unknown person and not-yours give the same status and body.
5. kai renders two account lanes labelled daily and admin under one Person lane.
6. An agent with a director change shows a big mark "Director changed"; a workload shows no sign-in lane.
7. Every big mark in the SVG has a row in the Changes table with significance "big".
8. Keyboard: ArrowRight from T lands on the next tick; Shift+ArrowRight on the next big mark; `aria-valuetext` names it.
9. At 390px, `document.documentElement.scrollWidth <= 390`, light and dark.
10. axe-core shows no violations in light and dark; no `style` attributes in the DOM.
11. Every history load writes one view-log entry (viewer, subject, range, moment).

## 9. Build plan (slices)

1. API `GET /persons/{anchor}/history?from&to&at` folding revisions and the event log (D1), a `history.rego`
   deciding per fact, per range and significance (D2, D3); the page as two tables only; view log; remove the graph's
   hidden count.
2. The moment control (range slider, marks, keyboard, live region) and the shared `at` with the graph tabs.
3. Lanes in SVG: Person, Accounts, Around it; compare two moments.
4. Provider lanes from the configured sources and the reconciler's observations (D4), "not observed" gaps.
5. Last seen: day tier dots (13 months) and the officer's 30-day sign-in lane (0009 D6).
6. Phone layout and the full accessibility pass; screenshot review against this note.
7. With the federation link: band per claim kind and the partner's announcement lane (D5).

## Addendum (operator, 2026-10-23): the diff at a major change
When the moment steps to the next or previous big mark, the graph shows the difference against the previous major
state: access gained drawn as normal lines with a "new" emphasis, access lost drawn as faint, semi-transparent ghost
lines (dashed, about 25 percent opacity, labelled "until {date}" on focus). The table below the graph gets a "Changed
since {previous mark}" section with the same rows (gained, lost). Only facts the viewer may see are compared: a ghost is
never drawn for something the viewer could not see at either moment. Slice: after the moment control (slice 2).
