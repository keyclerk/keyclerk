# SPDX-License-Identifier: EUPL-1.2
"""Draw docs/estate/estate-light.svg and estate-dark.svg: the KeyClerk estate for the README, built on the mark.

The mark is two keys on one ring, interlaced; the orange one is the second key (brand/BRAND.md). The estate is drawn
the same way: an orange ring for the guest's side (guests and their own sign-in), an ink ring for inside the
organisation (a home: desk nodes, signer, custodian, signed records; and the edges at its sites), and the public edge
where the two rings cross (the lobby and the broker). Orange passes over ink at the top crossing and ink over orange at
the bottom, as in the mark. Every arrow points from the side that opens the connection: nothing outside connects in.
Deterministic: run again after a change and commit both files.

    python tools/render_estate.py
"""
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "estate"
W, H = 1000, 580
THEMES = {   # brand palette B
    "light": {"paper": "#f2f4f7", "ink": "#17142b", "muted": "#555a67", "accent": "#c85d16", "accent_text": "#9a4a12",
              "band_a": "#f3d2bd", "band_i": "#d6d8e0", "chip": "#ffffff"},
    "dark": {"paper": "#0f1420", "ink": "#ffffff", "muted": "#b4bccb", "accent": "#f0954f", "accent_text": "#f0954f",
             "band_a": "#4a2c1c", "band_i": "#252d42", "chip": "#182033"},
}
FONT = "'IBM Plex Sans', system-ui, -apple-system, 'Segoe UI', Roboto, 'Noto Sans', Arial, sans-serif"
A = (300, 336)          # the orange ring: the guest's side
B = (596, 336)          # the ink ring: inside the organisation
R = 186                 # ring radius
BAND = 26               # band width, like the mark's
GAP = 9                 # degrees cut out of the under band at a crossing


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def pt(c, deg, r=R):
    a = math.radians(deg)
    return c[0] + r * math.cos(a), c[1] + r * math.sin(a)


def arc(c, a0, a1):
    """An arc of a ring from angle a0 to a1 (degrees, clockwise on screen)."""
    x0, y0 = pt(c, a0)
    x1, y1 = pt(c, a1)
    large = 1 if (a1 - a0) % 360 > 180 else 0
    return f"M{x0:.1f},{y0:.1f} A{R},{R} 0 {large} 1 {x1:.1f},{y1:.1f}"


def crossing_angles():
    d = B[0] - A[0]
    h = math.sqrt(R * R - (d / 2) ** 2)
    top, bottom = (A[0] + d / 2, A[1] - h), (A[0] + d / 2, A[1] + h)
    ang = lambda c, p: math.degrees(math.atan2(p[1] - c[1], p[0] - c[0])) % 360   # noqa: E731
    return {"a_top": ang(A, top), "a_bot": ang(A, bottom), "b_top": ang(B, top), "b_bot": ang(B, bottom)}


class Svg:
    """Shapes of the estate are laid out guest side left, then mirrored as a group so inside sits left and outside
    right, as the mark's ink key sits left of the orange one; text is placed at the mirrored position, unmirrored."""

    def __init__(self, t):
        self.t, self.parts, self.texts, self.plain = t, [], [], []
        self.mirror = True

    def add(self, s):
        (self.parts if self.mirror else self.plain).append(s)

    def text(self, x, y, s, size=13, weight=400, color="ink", anchor="start"):
        if self.mirror:
            x, anchor = W - x, {"start": "end", "end": "start"}.get(anchor, anchor)
        el = (f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" font-weight="{weight}" fill="{self.t[color]}" '
              f'text-anchor="{anchor}">{esc(s)}</text>')
        (self.texts if self.mirror else self.plain).append(el)

    def charm(self, x, y, accent=False, hollow=False):
        c = self.t["accent" if accent else "ink"]
        fill = self.t["paper"] if hollow else c
        self.add(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="7" fill="{fill}" stroke="{c}" stroke-width="2.5"/>')

    def chip(self, x, y, w, label, sub=None, accent=False):
        c = self.t["accent" if accent else "ink"]
        h = 44 if sub else 26
        self.add(f'<rect x="{x:.1f}" y="{y:.1f}" width="{w}" height="{h}" rx="13" fill="{self.t["chip"]}" stroke="{c}" '
                 f'stroke-width="1.6"/>')
        self.text(x + w / 2, y + 18, label, 13, 600, "ink", "middle")
        if sub:
            self.text(x + w / 2, y + 34, sub, 11, 500, "accent_text" if accent else "muted", "middle")

    def line(self, d, accent=False, dashed=False, head=True):
        c = self.t["accent" if accent else "ink"]
        dash = ' stroke-dasharray="6 5"' if dashed else ""
        m = ' marker-end="url(#ha)"' if accent and head else (' marker-end="url(#hi)"' if head else "")
        self.add(f'<path d="{d}" fill="none" stroke="{c}" stroke-width="1.8" stroke-linecap="round"{dash}{m}/>')


def mark(t) -> str:
    src = (ROOT / "brand" / "mark" / "keyclerk-mark.svg").read_text(encoding="utf-8")
    paths = dict(re.findall(r'<path class="(i|a)" fill-rule="evenodd" d="([^"]+)"', src))
    return (f'<g transform="translate(28,22) scale(0.9)"><path fill-rule="evenodd" fill="{t["ink"]}" d="{paths["i"]}"/>'
            f'<path fill-rule="evenodd" fill="{t["accent"]}" d="{paths["a"]}"/></g>')


def draw(theme: str) -> str:
    t = THEMES[theme]
    s = Svg(t)
    x = crossing_angles()

    # the two bands, interlaced: orange over ink at the top crossing, ink over orange at the bottom
    def band(c, d):
        s.add(f'<path d="{d}" fill="none" stroke="{t[c]}" stroke-width="{BAND}" stroke-linecap="butt"/>')
    band("band_i", arc(B, x["b_top"] + GAP, x["b_top"] - GAP + 360))           # ink ring, cut under orange at the top
    band("band_a", arc(A, x["a_bot"] + GAP, x["a_bot"] - GAP + 360))           # orange ring, cut under ink at the bottom

    # ring names, above each ring; the public edge above the crossing
    top = A[1] - R - 22
    s.mirror = False                                   # headings read left to right, placed where they end up
    ink_x, orange_x = W - B[0], W - A[0]
    s.text(ink_x - 150, top, "Inside", 14, 600)
    s.text(ink_x - 98, top, "each organisation", 12, 400, "muted")
    s.text(orange_x + 30, top, "Outside", 14, 600, "accent_text")
    s.text(orange_x + 92, top, "the guest's side", 12, 400, "muted")
    s.mirror = True
    cx = (A[0] + B[0]) / 2
    s.text(cx, A[1] - 108, "Public edge", 13, 600, "ink", "middle")
    s.text(cx, A[1] - 92, "where the rings cross", 11, 400, "muted", "middle")

    # outside: guests and their own sign-in, as charms on the orange ring
    gx, gy = pt(A, 180)
    s.charm(gx, gy, accent=True)
    s.text(gx + 18, gy - 4, "External guests", 14, 600)
    s.text(gx + 18, gy + 13, "visitors, contractors,", 12, 400, "muted")
    s.text(gx + 18, gy + 28, "partner staff", 12, 400, "muted")
    px, py = pt(A, 128)
    s.charm(px, py, accent=True, hollow=True)
    s.text(px - 16, py + 28, "Partner sign-in", 14, 600, "ink", "end")
    s.text(px - 16, py + 44, "their own identity provider", 12, 400, "muted", "end")

    # the public edge, where the rings cross
    s.chip(cx - 60, A[1] - 74, 120, "Lobby", "in development", accent=True)
    s.chip(cx - 60, A[1] + 30, 120, "Broker", "Keycloak sign-in")

    # inside: a home (a stack: many homes), its desk nodes, signer, custodian, records
    hx, hy = B[0] - 22, B[1] - 64
    for i in (2, 1):
        s.add(f'<rect x="{hx + 5 * i}" y="{hy - 5 * i}" width="140" height="128" rx="12" fill="{t["chip"]}" '
              f'stroke="{t["ink"]}" stroke-width="1" opacity="{0.35 if i == 2 else 0.6}"/>')
    s.add(f'<rect x="{hx}" y="{hy}" width="140" height="128" rx="12" fill="{t["chip"]}" stroke="{t["ink"]}" '
          f'stroke-width="1.6"/>')
    L = hx + 126                                       # the card's left margin after the mirror
    s.text(L, hy + 24, "Home", 14, 600, "ink", "end")
    s.text(L, hy + 40, "one deployment", 11, 400, "muted", "end")
    for i in range(3):
        s.add(f'<circle cx="{hx + 22 + 16 * i}" cy="{hy + 60}" r="5" fill="none" stroke="{t["ink"]}" stroke-width="1.6"/>')
    s.text(L, hy + 64, "desk nodes", 11, 400, "muted", "end")
    s.text(L, hy + 86, "signer, custodian", 12, 500, "ink", "end")
    s.text(L, hy + 103, "signed records", 12, 500, "ink", "end")

    # the sites: an edge on the ink ring, the bastion and the systems behind it
    ex, ey = pt(B, 0)
    s.charm(ex, ey)
    s.text(ex + 4, ey + 34, "Edge", 14, 600, "ink", "middle")
    s.text(ex + 4, ey + 50, "works offline", 11, 400, "muted", "middle")
    bx = 896
    s.charm(bx, ey, hollow=True)
    s.text(bx, ey - 36, "Bastion", 14, 600, "ink", "middle")
    s.text(bx, ey - 20, "enforces the lease", 11, 400, "muted", "middle")
    s.charm(bx, ey + 110, hollow=True)
    s.text(bx, ey + 140, "Legacy systems", 14, 600, "ink", "middle")
    s.text(bx, ey + 156, "SSH, RDP, web apps", 11, 400, "muted", "middle")

    # who opens which connection
    s.line(f"M{gx + 10},{gy - 20} C{gx + 60},{gy - 100} {cx - 140},{A[1] - 56} {cx - 66},{A[1] - 52}", accent=True)
    s.text(gx + 120, A[1] - 74, "asks", 12, 500, "accent_text")
    s.line(f"M{gx + 10},{gy + 40} C{gx + 60},{gy + 70} {cx - 140},{A[1] + 52} {cx - 66},{A[1] + 50}", accent=True)
    s.text(gx + 128, A[1] + 76, "signs in", 12, 500, "accent_text")
    s.line(f"M{cx - 20},{A[1] + 76} C{cx - 40},{A[1] + 140} {px + 70},{py - 6} {px + 12},{py - 3}")
    s.text(cx - 52, A[1] + 136, "federates", 11, 400, "muted", "end")
    s.line(f"M{hx - 2},{hy + 16} C{hx - 24},{hy + 8} {cx + 90},{A[1] - 52} {cx + 64},{A[1] - 52}", dashed=True)
    s.text(cx + 66, A[1] - 84, "pulls", 11, 400, "muted")
    s.text(cx + 66, A[1] - 70, "requests", 11, 400, "muted")
    s.line(f"M{hx - 2},{hy + 112} C{hx - 24},{hy + 118} {cx + 90},{A[1] + 52} {cx + 64},{A[1] + 52}")
    s.text(cx + 68, A[1] + 82, "trusts", 11, 400, "muted")
    s.text(cx + 68, A[1] + 96, "tokens", 11, 400, "muted")
    s.line(f"M{ex - 10},{ey - 8} C{ex - 40},{ey - 44} {hx + 176},{hy + 30} {hx + 146},{hy + 40}", dashed=True)
    s.text(ex + 2, ey - 62, "pulls signed", 11, 400, "muted", "middle")
    s.text(ex + 2, ey - 48, "bundles", 11, 400, "muted", "middle")
    s.line(f"M{ex + 12},{ey} L{bx - 14},{ey}")
    s.line(f"M{bx},{ey + 14} L{bx},{ey + 96}")

    # header: the mark, the name, the motto (not mirrored)
    s.mirror = False
    s.add(mark(t))
    s.text(92, 52, "The KeyClerk estate", 22, 600)
    s.text(92, 74, "Every key signed. Every key returned.", 13, 400, "muted")

    # key
    y = H - 28
    s.line(f"M32,{y} L64,{y}", accent=True)
    s.text(74, y + 4, "what a guest does", 12, 400, "muted")
    s.line(f"M228,{y} L260,{y}", dashed=True)
    s.text(270, y + 4, "pulled from inside: nothing outside connects in", 12, 400, "muted")
    s.text(W - 32, y + 4, "KeyClerk 0.29", 12, 600, "muted", "end")

    defs = (f'<defs><marker id="hi" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" '
            f'orient="auto"><path d="M0,1 L9,5 L0,9 z" fill="{t["ink"]}"/></marker>'
            f'<marker id="ha" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
            f'<path d="M0,1 L9,5 L0,9 z" fill="{t["accent"]}"/></marker></defs>')
    title = "The KeyClerk estate"
    desc = ("Drawn as the KeyClerk mark: two interlaced rings. On the orange ring, the guest's side: external guests and "
            "their own organisation's sign-in. Where the rings cross, the public edge: the lobby (in development), "
            "where guests ask, and the broker, where they sign in, federated with their own sign-in. On the ink ring, "
            "inside each organisation: homes, each a KeyClerk deployment with desk nodes, signer, custodian and signed "
            "records, which pull sealed requests from the lobby and trust the broker's tokens; and edges at the sites, "
            "which pull signed bundles from their home and work offline, with a bastion enforcing each lease in front "
            "of legacy systems. Every connection is opened from the inside.")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" '
            f'aria-labelledby="t d" font-family="{FONT}">\n<title id="t">{esc(title)}</title>\n<desc id="d">{esc(desc)}'
            f'</desc>\n{defs}\n<rect width="{W}" height="{H}" rx="16" fill="{t["paper"]}"/>\n'
            f'<g transform="translate({W},0) scale(-1,1)">\n' + "\n".join(s.parts) + "\n</g>\n"
            + "\n".join(s.texts + s.plain) + "\n</svg>\n")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for theme in THEMES:
        (OUT / f"estate-{theme}.svg").write_text(draw(theme), encoding="utf-8", newline="\n")
        print(f"wrote docs/estate/estate-{theme}.svg")


if __name__ == "__main__":
    main()
