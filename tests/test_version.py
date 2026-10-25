# SPDX-License-Identifier: EUPL-1.2
"""The package's version is declared twice (pyproject.toml for the installer, keyclerk.__version__ for the engine and
its reports); a release that bumps one and not the other installs under the wrong version."""
import tomllib
from pathlib import Path

import keyclerk

ROOT = Path(__file__).resolve().parents[1]


def test_pyproject_and_the_package_name_the_same_version():
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    assert declared == keyclerk.__version__


def test_the_changelog_names_the_current_version():
    assert f"## {keyclerk.__version__} (" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
