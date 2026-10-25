# SPDX-License-Identifier: EUPL-1.2
"""The README says what runs, what is a library nothing runs yet, and what is designed only (a review finding, 2026-10-23).
These tests keep the first two honest: every module it names exists, and a library it lists as not run is not imported
by any entry point, so wiring one in fails here until the README moves it up."""
import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
ENTRY_POINTS = ("reconcile", "api", "console", "desk")


def _section(title: str) -> str:
    return README.split(f"## {title}", 1)[1].split("\n## ", 1)[0]


def _imports(module: str, seen: set[str]) -> set[str]:
    """Every keyclerk module reachable by import from one module."""
    if module in seen:
        return seen
    seen.add(module)
    path = ROOT / "keyclerk" / (module.replace(".", "/") + ".py")
    if not path.exists():
        path = ROOT / "keyclerk" / module.replace(".", "/") / "__init__.py"
    if not path.exists():
        return seen
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("keyclerk"):
            base = node.module[len("keyclerk"):].lstrip(".")
            for alias in node.names:
                _imports(f"{base}.{alias.name}" if base else alias.name, seen)
            if base:
                _imports(base, seen)
        elif isinstance(node, ast.ImportFrom) and node.level and node.module:
            _imports(node.module, seen)
        elif isinstance(node, ast.ImportFrom) and node.level:
            for alias in node.names:
                _imports(alias.name, seen)
    return seen


def test_every_module_the_readme_names_exists():
    named = set(re.findall(r"`(keyclerk/[\w/]+(?:\.py|\.rego|/))`", README))
    assert named
    missing = [n for n in sorted(named) if not (ROOT / n).exists()]
    assert missing == [], f"the README names modules that do not exist: {missing}"


def test_a_library_the_readme_says_nothing_runs_is_not_imported_by_an_entry_point():
    listed = re.findall(r"`keyclerk/([\w/]+?)(?:\.py|/)`", _section("Tested libraries that nothing runs yet"))
    assert "apply_engine" in listed and "piam" in listed
    reached: set[str] = set()
    for entry in ENTRY_POINTS:
        _imports(entry, reached)
    wired = [m for m in listed if m.replace("/", ".") in reached]
    assert wired == [], f"now run by an entry point; move them to 'What runs today' in the README: {wired}"
