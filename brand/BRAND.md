# KeyClerk brand

Status: second-key chosen (operator, 2026-10-24); mark, wordmark, icons and social card built. The name is not cleared yet (trade mark check in TMview pending; risk:
CLERK, an authentication product, and the resemblance to Keycloak), so no wordmark is drawn before that check.

## Brief
- **What it is:** an open-source access-governance engine for Keycloak: people get access for a time, through signed
  approvals, and it ends by itself; every change is a signed record anyone can check.
- **Audience:** security officers, IAM engineers and auditors at European organisations and public bodies; the
  maintainers of the platforms that embed it.
- **Three attributes:** accountable (every grant has a who, why and until when), precise (small, exact, checkable),
  calm (governance without drama; no alarm, no fortress).
- **Must not look like:**
  1. a padlock, a shield or a fortress (the category's default, and the opposite of "access that ends by itself");
  2. Keycloak's or Clerk's marks, or the purple identity cluster (authentik, Teleport, ZITADEL);
  3. a generic SaaS gradient blob or a key icon that could be any password manager's.

## Narrative
Every organisation has a key cabinet, and someone has to keep it. They hand a key only to the right person, for a
reason and for a while. For the keys that matter, they ask a second person first. They write every key down, and
they make sure each one comes back.

That someone is the clerk. KeyClerk is that clerk for digital access: people get access through signed approvals, for
a time, and it ends by itself; anything that matters needs a second key; every change is a signed record that anyone
can check, and that nobody can quietly rewrite.

The mark is two keys on one ring: nobody holds the important ones alone. The orange key is the second one.

## Motto
**Every key signed. Every key returned.**

Alternatives kept for context: "Two keys. One record." (the mark's idea, shorter, colder); "Access that ends by
itself." (the product's promise, but no image).

## Category map (category_scan.py, 2026-10-24)
| Product | Signals |
|---|---|
| Keycloak | grey and blue, a stylised keyhole-like mark |
| midPoint (Evolveum) | blue, a midpoint glyph |
| SailPoint, Saviynt, Okta | corporate blue or black, abstract marks |
| Ory | dark, monochrome |
| authentik | deep purple #2f064b |
| ZITADEL | near-black with pink and violet #7e22ce, #db2777 |
| Teleport | violet #512fc9, #651fff |
| Clerk | near-black #131316 with cyan #64e5ff |
| OpenFGA | green #79ed83, cyan |
| Omada | navy #32445b with a coral orange #da5e3c |

Dominant: blue, purple and violet, dark modes, padlocks and abstract shapes. Free: a warm paper ground with one warm
accent, and a metaphor of time and records rather than walls.

## Starting palette (from the desk, keyclerk/ui/app.css)
ink #1d1530, paper #f8f5f0, key (accent) #e8762c, plum #5b2a6e (secondary, not the brand colour), ok #2e7d5b,
warn #a86a12, bad #b23a48. Dark theme: paper #140e1d, ink #ece6f5, key #f0954f. Checked in phase 4.

## Concepts (phase 1) and ratings (phase 3)
Four metaphors (concepts/sheet.png, sheet-dark.png): lease-arc (a key whose bow is an expiry ring), second-key (one
shaft, two interlocked bows: the two-person rule), ledger-key (a key whose bit is record lines), cut-card (a record
card with a key-cut edge). Two independent reviews, design (pixels) and technical (SVG source):

| Concept | Design S/E/B/D | Technical S/E/B/D | Verdict |
|---|---|---|---|
| second-key | 7/8/8/8 | 8/8/7/8 | strongest: its meaning survives at 24 px, not a category cliche |
| lease-arc | 8/6/7/6 | 6/6/7/7 | reads as a loading spinner small; keep as a UI motif (lease expiry ring) |
| ledger-key | 6/5/6/5 | 8/8/5/5 | collapses to a list icon |
| cut-card | 7/5/5/6 | 7/8/3/4 | collapses to a document icon |

Convergent work-list for second-key: make the interlock real (it otherwise reads as two circles, Mastercard or the
Olympic rings, and merges in monochrome), one tooth, one themed file. Done in concepts/second-key-v4.svg: each ring is
an arc with a gap where the other passes over (no masks, no background-coloured fakes), one tooth, colours by class
with a prefers-color-scheme dark theme, role="img" with its title. Sheet: concepts/sheet-v4.png.

## Palette (operator's choice 2026-10-24: option B, cool paper; previews/palette-options.png)
Four options were mocked up (A current warm cream and terracotta, B cool paper with the same orange, C brass with
navy ink, D ledger green). A sat on a common generated-design pattern (warm cream with a terracotta accent); B drops
the cream and keeps the orange, the mark and the icons.

| Role | Light | Dark |
|---|---|---|
| paper (ground) | #f2f4f7 | #0f1420 |
| ink | #17142b | #ffffff |
| accent (the second key) | #c85d16 | #f0954f |
| orange text | #9a4a12 | #f0954f |

Checked with palette_check.py: ink on paper 16.27:1; accent on paper 3.79:1 (graphics; not small text, so a chip on
the accent takes ink text or the darker orange); accent against ink 4.3:1; dark: white on #0f1420 18.4:1, accent
7.99:1. Colour-blind: the orange sits close to an amber warning (Delta E under 10 protan and deutan), so status never
by colour alone. The desk's interface (keyclerk/ui/app.css) still uses the warm palette: repainting it is a follow-up
with a UX review (surfaces, lines and status colours, both themes), not a find-and-replace.

## The mark (master geometry: python brand/build_mark.py, writes mark/geometry.json)
Two keys on one ring, the second in orange. Interlace construction, from prior art: knotwork bands keep a constant
width and the under band is cut along the over band's edges (Reed's knotwork tutorial, basic interlacing); the Olympic
rings' gapped version (1986 to 2010) expands strokes to shapes and cuts the under ring with a keyline that follows the
over ring; icon practice crosses expanded shapes by boolean operations, never by stopping a stroke. So each ring is a
filled annulus (radius 11, band 6, centres 14 apart so the bands cross twice and leave an open eye); at each crossing
the under band loses the over band grown by a 1.5 gutter, only within 7.5 of that crossing, so the cut ends run
parallel to the over band; convex corners softened by 0.6. Orange passes over ink at the top, ink and shaft over
orange at the bottom. Plain filled paths: no masks, no background-coloured fakes. Files:
- mark/keyclerk-mark.svg: themed (ink #17142b and #c85d16; white and #f0954f under prefers-color-scheme: dark).
- mark/keyclerk-mark-light.svg, keyclerk-mark-dark.svg (white ink, for dark grounds), keyclerk-mark-mono.svg
  (currentColor).

## Wordmark and lockup
IBM Plex Sans SemiBold (SIL Open Font Licence 1.1; glyphs checked for nl and fr: e-acute, e-grave, e-circumflex,
e-diaeresis, i-diaeresis, c-cedilla, a-grave, u-grave, o-circumflex, oe, euro). The lockups are outlined to paths, so
no font ships: wordmark/keyclerk-lockup-light.svg and -dark.svg; the live-text sources (*.src.svg) are kept for
re-typesetting (re-outline after any change with brand-cycle's outline_text.py). Motto and subline: IBM Plex Sans
Regular. Not cleared: the wordmark is redrawn if the trade mark check forces a new name.

## Icons (python brand/build_icons.py, all derived from the master geometry)
favicon.svg and favicon.ico (16, 32, 48; mark at 0.86 so it reads at 16 px), keyclerk-badge.svg, icon-192.png and
icon-512.png (rounded plate with a faint light rim so it separates from very dark grounds), apple-touch-icon.png (180)
and ios-1024.png (full bleed, opaque), android/ adaptive foreground, background and monochrome (432 px = 108 dp, mark
at 95 % of the 66 dp safe zone).

## Social card
social/keyclerk-social.png (1280 x 640, from keyclerk-social.svg). GitHub has no API for the social preview: upload it
by hand in Settings, General, Social preview once the repository is public.

## Changelog
- 2026-10-24: brief, category map, starting palette; four concepts, two reviews, palette check; second-key v4.
- 2026-10-24: second-key chosen by the operator; white ink on dark, narrative and motto, wordmark (IBM Plex Sans), icons, social card.
- 2026-10-24: interlace rebuilt as filled geometry after prior art (operator: the ring closures need finesse); everything regenerated.
- 2026-10-24: palette B (cool paper, same orange) chosen by the operator from four mockups; brand assets recoloured.
