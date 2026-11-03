# SPDX-License-Identifier: EUPL-1.2
"""Every engine test runs with the neutral test configuration; a deployment keeps its own configuration elsewhere.
Configured when pytest loads this file, before any test module is imported, because some tests build data at import."""
import os
from pathlib import Path

from keyclerk import config

# The pre-push hook runs this suite inside git, which exports the variables that locate a repository. A test that
# makes a scratch repository would otherwise commit into the one being pushed (2026-11-03). Tests that read this
# repository find it from their working directory instead.
for _var in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES",
             "GIT_COMMON_DIR", "GIT_PREFIX", "GIT_NAMESPACE"):
    os.environ.pop(_var, None)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
config.configure(FIXTURES / "config.yaml")
