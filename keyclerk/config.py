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
    errs = [f"config: {e.message} at {'/'.join(map(str, e.path))}"
            for e in jsonschema.Draft202012Validator(schema("config")).iter_errors(doc)]
    return errs or _across(doc)


def _across(doc: dict) -> list[str]:
    """What one section's schema cannot see: rules between sections and fields (decision 0029 points 3 and 7, the
    witness)."""
    import ipaddress
    errs = []
    keep = (doc.get("store") or {}).get("view_log_keep_days", 400)
    backup = (doc.get("backup") or {}).get("retention_days")
    if backup is not None and backup > keep:
        errs.append(f"config: backup.retention_days ({backup}) is longer than store.view_log_keep_days ({keep}): a "
                    "backup would keep a look after the desk has deleted it. Lower backup.retention_days, or raise "
                    "store.view_log_keep_days if the longer record of looks is intended")
    for n in (doc.get("api") or {}).get("trusted_proxies", []):
        try:
            ipaddress.ip_network(n)
        except ValueError as e:
            errs.append(f"config: api.trusted_proxies: {e}; write a network such as 10.0.0.0/24 or one address")
    if not isinstance((doc.get("approvals") or {}).get("acr"), str) or not doc["approvals"]["acr"].strip():
        errs.append("config: approvals.acr is missing: name the sign-in level every approval proof must carry (the "
                    "broker's acr, such as a level bound to a passkey). python -m keyclerk.init acr --keycloak URL "
                    "--realm REALM proposes one from the realm; or write acr: none, which is a finding at every start "
                    "(decision 0030 point 5)")
    w = doc.get("witness")
    if w:
        from keyclerk.store import note
        if w["origin"].startswith("kc-"):
            errs.append("config: witness.origin starts with kc-, the prefix of KeyClerk's own signed formats: name the "
                        "log as a schema-less URL, such as keyclerk.example.org/realm")
        names = []
        for c in w["cosigners"]:
            try:
                n, kind, _ = note.parse_vkey(c["vkey"])
                names.append(n)
                if kind != note.COSIGNATURE:
                    errs.append(f"config: witness.cosigners: {n} is given by a log key; give the witness's cosigner "
                                "key (python -m keyclerk.witness vkey --type cosigner)")
            except note.NoteRefused as e:
                errs.append(f"config: witness.cosigners: {e}")
        if len(set(names)) != len(names):
            errs.append("config: witness.cosigners: two witnesses with one name; each witness has its own")
        if w.get("quorum", 1) > len(w["cosigners"]):
            errs.append(f"config: witness.quorum ({w['quorum']}) is above the {len(w['cosigners'])} witnesses given")
    return errs


def approval_acr(doc: dict | None = None) -> str | None:
    """The sign-in level an approval proof must carry, or None for acr: none (no level is checked)."""
    v = ((doc if doc is not None else current()).get("approvals") or {}).get("acr")
    return None if v in (None, "none") else v


def acr_finding(doc: dict | None = None) -> str | None:
    """Said at every start while approvals.acr is none (decision 0030 point 5)."""
    v = ((doc if doc is not None else current()).get("approvals") or {}).get("acr")
    return ("approvals.acr is none: an approval proof carries no required sign-in level, so a password-only sign-in "
            "approves as well as a passkey; set the level (python -m keyclerk.init acr)") if v == "none" else None


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
