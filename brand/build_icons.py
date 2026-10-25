# SPDX-License-Identifier: EUPL-1.2
"""Build KeyClerk's icons from the master mark geometry (brand/mark/keyclerk-mark.svg).

    uv run --with cairosvg,pillow python brand/build_icons.py

Writes brand/icons/: favicon.svg, favicon.ico (16, 32, 48), apple-touch-icon.png (180), icon-192.png, icon-512.png,
ios-1024.png (full bleed, opaque; iOS applies its own mask), android/ (adaptive foreground, background, monochrome,
each 432 px = 108 dp at 4x, the mark inside the central 66 dp safe zone). Every file is derived from GEOM below, so
ratios and centres match everywhere; change the mark there and rebuild.
"""
from __future__ import annotations

import io
import json
from pathlib import Path

import cairosvg
from PIL import Image

OUT = Path(__file__).resolve().parent / "icons"
INK, PLATE, WHITE, ORANGE_DARK = "#17142b", "#17142b", "#ffffff", "#f0954f"
# the master geometry (brand/build_mark.py) on a 64 grid, filled paths; its bounding box centre is about (32, 34)
_G = json.loads((Path(__file__).resolve().parent / "mark" / "geometry.json").read_text(encoding="utf-8"))
GEOM = (f'<path fill="{{i}}" fill-rule="evenodd" d="{_G["ink"]}"/>'
        f'<path fill="{{a}}" fill-rule="evenodd" d="{_G["accent"]}"/>')


def mark(scale: float, ink: str, accent: str) -> str:
    """The mark centred on (32, 32) of a 64 viewBox at `scale` of its master size."""
    return (f'<g transform="translate(32 32) scale({scale}) translate(-32 -34)">'
            + GEOM.format(i=ink, a=accent) + "</g>")


def svg(body: str, plate: str | None = None, rx: float = 0, edge: bool = False) -> str:
    """edge: a faint light rim inside a rounded plate, so it separates from very dark grounds (GitHub dark, tabs)."""
    bg = f'<rect width="64" height="64" rx="{rx}" fill="{plate}"/>' if plate else ""
    if plate and edge:
        bg += (f'<rect x=".5" y=".5" width="63" height="63" rx="{max(rx - .5, 0)}" fill="none" '
               'stroke="#fff" stroke-opacity=".2" stroke-width="1"/>')
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" role="img" aria-labelledby="t">'
            f'<title id="t">KeyClerk</title>{bg}{body}</svg>')


def png(src: str, size: int) -> Image.Image:
    return Image.open(io.BytesIO(cairosvg.svg2png(bytestring=src.encode(), output_width=size, output_height=size)))


def lockups_and_card() -> None:
    """The live-text sources of the lockups and the social card, with the current mark; outline them afterwards."""
    root = Path(__file__).resolve().parent
    for name, ink, acc in (("light", "#17142b", "#c85d16"), ("dark", "#ffffff", "#f0954f")):
        (root / "wordmark" / f"lockup-{name}.src.svg").write_text(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 234 64" role="img" aria-labelledby="t">'
            '<title id="t">KeyClerk</title>'
            f'<g transform="translate(0 2) scale(.94)">{GEOM.format(i=ink, a=acc)}</g>'
            f'<text x="62" y="44" font-family="IBM Plex Sans" font-size="34" letter-spacing="-0.4" fill="{ink}">KeyClerk</text>'
            "</svg>" + chr(10), encoding="utf-8")
    (root / "social" / "social.src.svg").write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 640" role="img" aria-labelledby="t">'
        '<title id="t">KeyClerk: every key signed, every key returned</title>'
        '<defs><radialGradient id="g" cx="50%" cy="45%" r="75%"><stop offset="0" stop-color="#1d2338"/>'
        '<stop offset="1" stop-color="#0b0e17"/></radialGradient></defs><rect width="1280" height="640" fill="url(#g)"/>'
        f'<g transform="translate(170 170) scale(3.4)">{GEOM.format(i=WHITE, a=ORANGE_DARK)}</g>'
        '<text x="400" y="304" font-family="IBM Plex Sans SemiBold" font-size="118" letter-spacing="-1.4" fill="#ffffff">KeyClerk</text>'
        '<text x="406" y="386" font-family="IBM Plex Sans" font-size="40" fill="#cfd4e0">Every key signed. Every key returned.</text>'
        '<text x="406" y="444" font-family="IBM Plex Sans" font-size="26" fill="#9aa3b5">Access governance for Keycloak, open source</text>'
        "</svg>" + chr(10), encoding="utf-8")


def main() -> None:
    lockups_and_card()
    (OUT / "android").mkdir(parents=True, exist_ok=True)
    badge = svg(mark(0.76, WHITE, ORANGE_DARK), PLATE, rx=14, edge=True)    # rounded plate: any background
    fav = svg(mark(0.86, WHITE, ORANGE_DARK), PLATE, rx=12, edge=True)      # larger mark: reads at 16 px
    full = svg(mark(0.62, WHITE, ORANGE_DARK), PLATE)                       # full bleed for iOS and touch icons
    (OUT / "favicon.svg").write_text(fav, encoding="utf-8")
    (OUT / "keyclerk-badge.svg").write_text(badge, encoding="utf-8")
    png(fav, 48).save(OUT / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
    png(full, 180).convert("RGB").save(OUT / "apple-touch-icon.png")
    png(full, 1024).convert("RGB").save(OUT / "ios-1024.png")
    png(badge, 192).save(OUT / "icon-192.png")
    png(badge, 512).save(OUT / "icon-512.png")
    # Android adaptive: 108 dp canvas, safe zone the central 66 dp. The mark is 52 of 64 units high, so this scale
    # makes it 95 % of the safe zone's height: 52 * scale / 64 = 0.95 * 66 / 108.
    safe = 0.95 * (66 / 108) * (64 / 52)
    png(svg(mark(safe, WHITE, ORANGE_DARK)), 432).save(OUT / "android" / "ic_launcher_foreground.png")
    png(svg("", PLATE), 432).convert("RGB").save(OUT / "android" / "ic_launcher_background.png")
    png(svg(mark(safe, WHITE, WHITE)), 432).save(OUT / "android" / "ic_launcher_monochrome.png")
    for f in sorted(OUT.rglob("*")):
        if f.is_file():
            print(f"{f.relative_to(OUT.parent)}  {f.stat().st_size} B")


if __name__ == "__main__":
    main()
