# SPDX-License-Identifier: EUPL-1.2
"""What a deployer must supply to each long-running service: the deployer contract (the edge implementation's ask, 2026-11-05).

One record per service: the flags it requires, the files and directories those flags name, the rules that tie flags
to each other and to the configuration, and the configuration keys it needs. It is data, so three things read it:
  - the preflight (`python -m keyclerk.init check`), which names everything missing at once, before a service starts;
  - docs/deployer-contract.md, generated from it (`python -m keyclerk.contract render`), which installers test against;
  - a test that compares it with each service's own parser, so the contract cannot drift from the code.
A release whose contract changed carries an "Upgrading" line (tools/changelog.py refuses it otherwise).
"""
from __future__ import annotations

import argparse
import importlib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    """A requirement no parser states: when `when` holds for the parsed flags and configuration, `need` must too."""
    says: str                                    # the requirement, as the deployer reads it
    when: object                                 # (args, cfg) -> bool
    need: object                                 # (args, cfg) -> bool


@dataclass(frozen=True)
class Service:
    name: str
    module: str                                  # its parser is module.parser() (or module.parse's parser)
    command: tuple[str, ...]                     # how it starts: python -m ... [subcommand]
    required: tuple[str, ...]                    # flags the parser itself requires
    files: tuple[str, ...] = ()                  # flags naming a file that must exist and be readable
    dirs: tuple[str, ...] = ()                   # flags naming a directory (created when absent, must be writable)
    config: tuple[str, ...] = ()                 # configuration keys it needs (dotted), beyond the schema's own
    rules: tuple[Rule, ...] = field(default=())


def _get(cfg: dict, dotted: str):
    v = cfg
    for k in dotted.split("."):
        if not isinstance(v, dict) or k not in v:
            return None
        v = v[k]
    return v


def _proofs(cfg) -> bool:
    return (_get(cfg, "approvals.proofs") or "off") == "required"


SERVICES = (
    Service("signer", "keyclerk.signer", ("python", "-m", "keyclerk.signer"), ("--state", "--config"),
            files=("--key", "--config", "--token", "--reconciler-token", "--approval-jwks", "--identity-key",
                   "--custodian-token"),
            dirs=("--state",),
            config=("approvals.acr",),
            rules=(Rule("the records key's holder: --custodian (production) or --key (development), one of them",
                        lambda a, c: True, lambda a, c: bool(a.key) != bool(a.custodian)),
                   Rule("--custodian-token for a custodian over TCP", lambda a, c: str(a.custodian or "").startswith("tcp:"),
                        lambda a, c: bool(a.custodian_token)),
                   Rule("--listen (unix:/path or tcp:127.0.0.1:port), unless --adopt",
                        lambda a, c: not a.adopt, lambda a, c: bool(a.listen)),
                   Rule("--token for a TCP listener", lambda a, c: str(a.listen or "").startswith("tcp:"),
                        lambda a, c: bool(a.token)),
                   Rule("HA: --ha-node and --commit-witness together", lambda a, c: bool(a.ha_node or a.commit_witness),
                        lambda a, c: bool(a.ha_node and a.commit_witness)),
                   Rule("--ha-hold of at least 5 seconds", lambda a, c: bool(a.ha_node), lambda a, c: a.ha_hold >= 5),
                   Rule("approvals.proofs required: --approval-issuer, --approval-audience and --approval-jwks",
                        lambda a, c: _proofs(c),
                        lambda a, c: bool(a.approval_issuer and a.approval_audience and a.approval_jwks)),
                   Rule("the reconciler's listener has its own --reconciler-token", lambda a, c: bool(a.reconciler_listen),
                        lambda a, c: bool(a.reconciler_token) and a.reconciler_token != a.token),
                   Rule("--identity-key, the reconciler's public key, where a reconciler is wired (0.29.0: leases name "
                        "bastion accounts only from its sealed identity map; python -m keyclerk.init identity-key)",
                        lambda a, c: bool(a.reconciler_listen), lambda a, c: bool(a.identity_key)))),
    Service("desk", "keyclerk.api", ("python", "-m", "keyclerk.api"),
            ("--config", "--store", "--oidc-public-issuer", "--oidc-redirect"),
            files=("--config", "--signer-token", "--signing-key", "--mgmt-token-file"), dirs=("--store",),
            config=("approvals.acr",),
            rules=(Rule("--signer (a checking signer) or --signing-key (development)", lambda a, c: True,
                        lambda a, c: bool(a.signer or a.signing_key)),
                   Rule("--signer-token for a TCP signer", lambda a, c: str(a.signer or "").startswith("tcp:"),
                        lambda a, c: bool(a.signer_token)),
                   Rule("--mgmt-port needs --mgmt-token-file", lambda a, c: bool(a.mgmt_port),
                        lambda a, c: bool(a.mgmt_token_file)))),
    Service("reconciler", "keyclerk.reconcile", ("python", "-m", "keyclerk.reconcile"),
            ("--config", "--keycloak", "--realm", "--secret-file", "--state"),
            files=("--config", "--secret-file", "--reader-secret-file", "--mark-key", "--signer-token", "--records"),
            dirs=("--state",), config=("approvals.acr",),
            rules=(Rule("--records (the YAML store) or --log-replica with --signer and --records-key",
                        lambda a, c: True,
                        lambda a, c: bool(a.records) or bool(a.log_replica and a.signer and a.records_key)),
                   Rule("--mark-key: the broker keeps a high-water mark the reconciler signs (0.27.0)",
                        lambda a, c: True, lambda a, c: bool(a.mark_key)),
                   Rule("approvals.proofs required: --approval-issuer and --approval-audience", lambda a, c: _proofs(c),
                        lambda a, c: bool(a.approval_issuer and a.approval_audience)))),
    Service("witness", "keyclerk.witness", ("python", "-m", "keyclerk.witness", "serve"),
            ("--key", "--name", "--state", "--log"), files=("--key",), dirs=("--state",)),
)

BY_NAME = {s.name: s for s in SERVICES}


def parser_of(s: Service) -> argparse.ArgumentParser:
    """The service's own command line parser (for the witness, its serve subcommand)."""
    m = importlib.import_module(s.module)
    ap = m.parser() if hasattr(m, "parser") else None
    if ap is None:                                       # the reconciler builds its parser in parse()
        captured = {}
        real = argparse.ArgumentParser.parse_args

        def grab(self, *args, **kw):
            captured["ap"] = self
            raise SystemExit(0)
        argparse.ArgumentParser.parse_args = grab
        try:
            m.parse([])
        except SystemExit:
            pass
        finally:
            argparse.ArgumentParser.parse_args = real
        ap = captured["ap"]
    if len(s.command) > 3:                               # a subcommand
        sub = next(a for a in ap._actions if isinstance(a, argparse._SubParsersAction))
        ap = sub.choices[s.command[3]]
    return ap


def required_flags(ap: argparse.ArgumentParser) -> set[str]:
    return {a.option_strings[0] for a in ap._actions if a.required and a.option_strings}


def check(service: str, argv: list[str] | None, cfg: dict | None) -> list[str]:
    """Everything missing for one service, at once: unparsable flags, missing files, rules, configuration keys."""
    s, out = BY_NAME[service], []
    for key in s.config:
        if cfg is not None and _get(cfg, key) is None:
            out.append(f"{service}: the configuration needs {key}")
    if argv is None:
        return out
    ap = parser_of(s)
    missing = [f for f in s.required if f not in argv and not any(x.startswith(f + "=") for x in argv)]
    out += [f"{service}: {f} is required" for f in missing]
    try:
        ns, unknown = ap.parse_known_args(argv + [x for f in missing for x in (f, "_")])
    except SystemExit:
        return out + [f"{service}: the command line does not parse: {' '.join(argv)[:200]}"]
    out += [f"{service}: unknown flag {u}" for u in unknown if u.startswith("--")]
    for flag in s.files:
        v = getattr(ns, flag.lstrip("-").replace("-", "_"), None)
        for path in (v if isinstance(v, list) else [v]):
            if path and path != "_" and not Path(path).is_file():
                out.append(f"{service}: {flag} {path}: no such file")
    for flag in s.dirs:
        v = getattr(ns, flag.lstrip("-").replace("-", "_"), None)
        if v and v != "_" and Path(v).exists() and not Path(v).is_dir():
            out.append(f"{service}: {flag} {v}: not a directory")
    for r in s.rules:
        try:
            if r.when(ns, cfg or {}) and not r.need(ns, cfg or {}):
                out.append(f"{service}: {r.says}")
        except AttributeError:
            continue
    return out


def render() -> str:
    """docs/deployer-contract.md."""
    lines = ["# What a deployer must supply", "",
             "Generated from `keyclerk/contract.py` (`python -m keyclerk.contract render`); a test keeps it current.",
             "Check a planned deployment before starting it: `python -m keyclerk.init check --config FILE "
             "--for signer,desk,reconciler,witness [--SERVICE-args \"...\"]` names everything missing at once.", ""]
    for s in SERVICES:
        lines += [f"## {s.name}", "", f"Starts as `{' '.join(s.command)}`.", "",
                  "- Required flags: " + ", ".join(f"`{f}`" for f in s.required)]
        if s.files:
            lines.append("- Files that must exist when given: " + ", ".join(f"`{f}`" for f in s.files))
        if s.dirs:
            lines.append("- Directories: " + ", ".join(f"`{f}`" for f in s.dirs))
        if s.config:
            lines.append("- Configuration keys: " + ", ".join(f"`{k}`" for k in s.config))
        lines += [f"- {r.says}" for r in s.rules] + [""]
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    import sys
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["render"]:
        sys.stdout.write(render())
        return 0
    print("python -m keyclerk.contract render", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
