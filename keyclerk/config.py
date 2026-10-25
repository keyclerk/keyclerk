# SPDX-License-Identifier: EUPL-1.2
"""KeyClerk's configuration: every rule the engine applies comes from here, never from the code.

A configuration is one YAML or JSON document (schema/config.schema.json) with a section per part of the engine:
roles, grant_limits, external_access, delegation, attributes, situation, risk_port, places, access_paths and
availability. A deployment keeps it as code in its own repository; the engine only reads it.

    from keyclerk import config
    config.configure("path/to/keyclerk.yaml")      # or a dict, or KEYCLERK_CONFIG in the environment

Modules read their section through Section, which looks the value up when it is used, so importing a module never
needs a configuration and a test can switch configurations between cases.
"""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from importlib import resources
from pathlib import Path
from typing import Any, Iterator

import jsonschema

_current: dict | None = None


def schema(name: str) -> dict:
    """A JSON schema shipped with the engine (config, records, trust-input)."""
    return json.loads(resources.files("keyclerk.schema").joinpath(f"{name}.schema.json").read_text(encoding="utf-8"))


def policy_files(include_tests: bool = False) -> dict[str, str]:
    """The engine's Rego (package keyclerk.*), file name -> text, for a deployment's policy bundle."""
    pkg = resources.files("keyclerk.policy")
    return {f.name: f.read_text(encoding="utf-8") for f in sorted(pkg.iterdir(), key=lambda x: x.name)
            if f.name.endswith(".rego") and (include_tests or not f.name.endswith("_test.rego"))}


def validate(doc: dict) -> list[str]:
    return [f"config: {e.message} at {'/'.join(map(str, e.path))}"
            for e in jsonschema.Draft202012Validator(schema("config")).iter_errors(doc)]


def configure(src: str | Path | dict) -> dict:
    """Load and validate a configuration; it becomes the current one."""
    global _current
    from keyclerk import guard
    doc = src if isinstance(src, dict) else guard.load_yaml(Path(src))
    if not isinstance(doc, dict):
        raise ValueError("invalid KeyClerk configuration: not a mapping")
    errs = validate(doc)
    if errs:
        raise ValueError("invalid KeyClerk configuration:\n" + "\n".join(errs))
    _current = doc
    return doc


def current() -> dict:
    if _current is None:
        path = os.environ.get("KEYCLERK_CONFIG")
        if not path:
            raise RuntimeError("no KeyClerk configuration: call keyclerk.config.configure() or set KEYCLERK_CONFIG")
        configure(path)
    return _current


class Section(Mapping):
    """A section of the current configuration, looked up on use."""

    def __init__(self, *path: str):
        self.path = path

    def _get(self) -> dict:
        node: Any = current()
        for p in self.path:
            node = node[p]
        return node

    def __getitem__(self, key: str) -> Any:
        return self._get()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._get())

    def __len__(self) -> int:
        return len(self._get())

    def get(self, key: str, default: Any = None) -> Any:
        return self._get().get(key, default)
