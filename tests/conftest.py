# SPDX-License-Identifier: EUPL-1.2
"""Every engine test runs with the neutral test configuration; a deployment keeps its own configuration elsewhere.
Configured when pytest loads this file, before any test module is imported, because some tests build data at import."""
from pathlib import Path

from keyclerk import config

FIXTURES = Path(__file__).resolve().parent / "fixtures"
config.configure(FIXTURES / "config.yaml")
