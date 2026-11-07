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
    """A candidate's section is headed as its tag says (0.29.0-rc.1, which the release workflow reads), the package as
    PEP 440 writes it (0.29.0rc1): the same version."""
    import re

    from packaging.version import Version
    heads = re.findall(r"^## (\S+) \(", (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"), re.M)
    assert any(Version(h) == Version(keyclerk.__version__) for h in heads)
