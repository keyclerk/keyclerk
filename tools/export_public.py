# SPDX-License-Identifier: EUPL-1.2
"""Export a public release from this repository: only what tools/public_manifest.yaml lists, transformed where it
says, then checked by the leak gate. A release that does not pass is deleted, never left half-made.

    python tools/export_public.py PROFILE OUT [--names FILE]

OUT must not exist. --names is a file of personal names kept outside every repository (tools/leak_gate.py). The
export writes RELEASE.txt (profile, KeyClerk version, files with sha256), so a published release can be traced to
what was exported. Making the public git repository from OUT (one fresh commit per release, under the publishing
identity) and pushing it are the maintainer's steps.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import leak_gate  # noqa: E402

_PREFIX = re.compile(r"^[A-Za-z][\w ]{0,30}: ")        # a contributor's label in front of a case name
_IDS = re.compile(r"^(?:[A-Z]{1,3}-\d+[a-z]? )+| \((?:[A-Z]{1,3}-\d+[a-z]?(?:, )?)+\)")   # "XY-1 ..." and "... (XY-1)"


def neutral_case_names(raw: bytes) -> bytes:
    """Conformance case names without the label of who contributed the case; the cases themselves unchanged."""
    doc = json.loads(raw)

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "name" and isinstance(v, str):
                    x[k] = _IDS.sub("", _PREFIX.sub("", v))
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
            seen: dict[str, int] = {}                  # names stay unique within a family after stripping
            for v in x:
                if isinstance(v, dict) and isinstance(v.get("name"), str):
                    seen[v["name"]] = seen.get(v["name"], 0) + 1
                    if seen[v["name"]] > 1:
                        v["name"] = f"{v['name']} ({seen[v['name']]})"
    walk(doc)
    return (json.dumps(doc, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


TRANSFORMS = {"neutral_case_names": neutral_case_names}


def _selection(prof: dict) -> dict:
    """Published path -> source spec. `tracked` names files git tracks by pattern (include, then exclude; a file keeps
    its own path); `files` names files one by one and wins over `tracked`. Only tracked files can leave: nothing
    untracked or ignored is ever exported."""
    out: dict = {}
    sel = prof.get("tracked")
    if sel:
        listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
        for path in sorted(p for p in listed.decode("utf-8").split("\0") if p):
            if any(fnmatch.fnmatch(path, g) for g in sel.get("include", ["*"])) and \
                    not any(fnmatch.fnmatch(path, g) for g in sel.get("exclude", [])):
                out[path] = path
    out.update(prof.get("files") or {})
    return out


def export(profile: str, out: Path, names: Path | None = None) -> list[str]:
    manifest = yaml.safe_load((ROOT / "tools" / "public_manifest.yaml").read_text(encoding="utf-8"))
    if profile not in manifest:
        raise SystemExit(f"no profile {profile!r}: the profiles are {', '.join(manifest)}")
    if out.exists():
        raise SystemExit(f"{out} exists: an export writes a new folder, never into an existing one")
    version = re.search(r'^__version__ = "([^"]+)"', (ROOT / "keyclerk" / "__init__.py").read_text(encoding="utf-8"),
                        re.M).group(1)                 # this checkout's version, never an installed package's
    lines = [f"profile: {profile}", f"KeyClerk: {version}", "files:"]
    try:
        for dest, spec in sorted(_selection(manifest[profile]).items()):
            src, transform = (spec, None) if isinstance(spec, str) else (spec["from"], spec.get("transform"))
            raw = (ROOT / src).read_bytes()
            if transform:
                raw = TRANSFORMS[transform](raw)
            if b"\0" not in raw:                         # text: LF line ends, the bytes git stores and publishes
                raw = raw.replace(b"\r\n", b"\n")
            target = out / dest
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            lines.append(f"  {dest}  sha256 {hashlib.sha256(raw).hexdigest()}")
        (out / "RELEASE.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        hits = leak_gate.scan(out, names)
    except BaseException:
        shutil.rmtree(out, ignore_errors=True)
        raise
    if hits:
        shutil.rmtree(out, ignore_errors=True)
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="export_public", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("profile")
    ap.add_argument("out")
    ap.add_argument("--names")
    a = ap.parse_args(argv)
    hits = export(a.profile, Path(a.out), Path(a.names) if a.names else None)
    for h in hits:
        print(h)
    if hits:
        print(f"export refused: {len(hits)} leak gate hits; nothing was kept. Reword the sources and export again.")
        return 1
    print(f"exported {a.profile} to {a.out}: the leak gate is clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
