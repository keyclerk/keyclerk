# SPDX-License-Identifier: EUPL-1.2
"""Build KeyClerk's mark as filled geometry: two interlocked rings and one shaft (brand/BRAND.md, "The mark").

    uv run --with shapely python brand/build_mark.py

Interlace construction (prior art: knotwork bands of constant width, the Olympic rings' gapped version; strokes are
expanded to shapes and crossed by boolean operations, never by stopping a stroke): each ring is a filled annulus; at
each crossing the under band loses the over band's shape grown by a constant gutter, only around that crossing, so the
cut ends run parallel to the over band. Small convex corners are softened. Output is plain filled paths, so it renders
the same everywhere, on any background and in one colour.

Writes brand/mark/geometry.json ({"ink": d, "accent": d}) and the mark files; build_icons.py reads the geometry.
"""
from __future__ import annotations

import json
from pathlib import Path

from shapely.geometry import LineString, Point
from shapely.ops import unary_union

HERE = Path(__file__).resolve().parent
R, W = 11.0, 6.0                       # ring radius (centre of band) and band width, on the 64 grid
GUTTER = 1.5                           # the gap on each side of the over band: a quarter of the band width
SOFT = 0.6                             # radius that softens the cut corners
INK_C, ACC_C = (25.0, 22.0), (39.0, 22.0)    # 14 apart: the bands cross twice and leave an open eye
RES = 64                               # segments per quarter circle


def annulus(c):
    return Point(c).buffer(R + W / 2, RES).difference(Point(c).buffer(R - W / 2, RES))


def crossings():
    """The two points where the ring centre lines cross: (top, bottom)."""
    d = ACC_C[0] - INK_C[0]
    h = (R * R - (d / 2) ** 2) ** 0.5
    x = INK_C[0] + d / 2
    return (x, INK_C[1] - h), (x, INK_C[1] + h)


def soften(g):
    return g.buffer(-SOFT, RES).buffer(SOFT, RES)


def build():
    top, bottom = crossings()
    ink_ring, acc_ring = annulus(INK_C), annulus(ACC_C)
    shaft = unary_union([LineString([(32, bottom[1]), (32, 57)]).buffer(W / 2, RES),
                         LineString([(32, 49), (40, 49)]).buffer(W / 2, RES)])
    ink_over = unary_union([ink_ring, shaft])
    local = 7.5                        # covers one crossing (rings meet at about 79 degrees), short of the eye
    # top crossing: the orange ring passes over the ink ring
    ink = ink_over.difference(acc_ring.buffer(GUTTER, RES).intersection(Point(top).buffer(local, RES)))
    # bottom crossing: the ink ring (and the shaft that leaves from there) passes over the orange ring
    acc = acc_ring.difference(ink_over.buffer(GUTTER, RES).intersection(Point(bottom).buffer(local, RES)))
    return soften(ink), soften(acc)


def path(geom) -> str:
    geom = geom.simplify(0.01, preserve_topology=True)
    polys = getattr(geom, "geoms", [geom])
    out = []
    for p in polys:
        for ring in [p.exterior, *p.interiors]:
            pts = list(ring.coords)[:-1]
            out.append("M" + "L".join(f"{x:.2f} {y:.2f}" for x, y in pts) + "Z")
    return "".join(out).replace(".00", "")


def write(name: str, ink: str, acc: str, style: str, d: dict) -> None:
    """With a theme `style`, colours by class and a <style>; without, plain fill attributes (no <style> at all, so the
    file renders the same under a strict content security policy, as the desk serves it)."""
    if style:
        head = f'<style>.i{{fill:{ink}}}.a{{fill:{acc}}}{style}</style>'
        paths = (f'<path class="i" fill-rule="evenodd" d="{d["ink"]}"/>'
                 f'<path class="a" fill-rule="evenodd" d="{d["accent"]}"/>')
    else:
        head = ""
        paths = (f'<path fill="{ink}" fill-rule="evenodd" d="{d["ink"]}"/>'
                 f'<path fill="{acc}" fill-rule="evenodd" d="{d["accent"]}"/>')
    (HERE / "mark" / name).write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-labelledby="t">'
        f'<title id="t">KeyClerk</title>{head}{paths}</svg>\n', encoding="utf-8")


def main() -> None:
    ink, acc = build()
    d = {"ink": path(ink), "accent": path(acc)}
    (HERE / "mark").mkdir(exist_ok=True)
    (HERE / "mark" / "geometry.json").write_text(json.dumps(d, indent=1) + "\n", encoding="utf-8")
    write("keyclerk-mark.svg", "#17142b", "#c85d16", "@media (prefers-color-scheme:dark){.i{fill:#fff}.a{fill:#f0954f}}", d)
    write("keyclerk-mark-light.svg", "#17142b", "#c85d16", "", d)
    write("keyclerk-mark-dark.svg", "#fff", "#f0954f", "", d)
    write("keyclerk-mark-mono.svg", "currentColor", "currentColor", "", d)
    print({k: len(v) for k, v in d.items()}, "bytes of path data")


if __name__ == "__main__":
    main()
