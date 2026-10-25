# SPDX-License-Identifier: EUPL-1.2
"""Guarded input and output at every seam.

Nothing enters the engine unchecked: files (records, configuration, trust input, graphs), broker responses, command
lines, environment, console requests. Python does not overflow buffers, so the guards here aim at what can still hurt:
oversized or deeply nested input, parser bombs (YAML aliases), injection into filters, URLs, HTML or logs, malformed
identifiers and timestamps without a zone, and unbounded reads from the network. Every limit is a named constant so a
deployment sees what it gets; a violation raises InputRejected with a reason that is safe to log.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from datetime import datetime
from pathlib import Path

import yaml

MAX_FILE_BYTES = 16 * 1024 * 1024        # a records file, a configuration, a graph
MAX_RESPONSE_BYTES = 8 * 1024 * 1024     # one broker response
MAX_DEPTH = 32                           # nesting of mappings and lists
MAX_NODES = 2_000_000                    # scalars, mappings and lists in one document
MAX_STRING = 4096                        # one scalar
MAX_ID = 256                             # one identifier or anchor

ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,255}$")
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f  ‪-‮⁦-⁩]")


# zero-width characters, LRM/RLM/ALM, word joiner, invisible operators, BOM: text that looks other than it is
INVISIBLE = re.compile("[­؜᠎​-‏⁠-⁤⁪-⁯﻿]")


class InputRejected(ValueError):
    """Input refused at a seam; the message is safe to log."""


# --- documents ----------------------------------------------------------------------------------------------------

class _NoAliasLoader(yaml.SafeLoader):
    """A SafeLoader that refuses anchors and aliases (no alias expansion bombs) and counts what it builds."""

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            raise InputRejected("YAML aliases are not accepted")
        event = self.peek_event()
        if getattr(event, "anchor", None):
            raise InputRejected("YAML anchors are not accepted")
        return super().compose_node(parent, index)


def _shape(node, depth: int = 0, count: list | None = None) -> None:
    count = count if count is not None else [0]
    count[0] += 1
    if count[0] > MAX_NODES:
        raise InputRejected(f"document has more than {MAX_NODES} nodes")
    if depth > MAX_DEPTH:
        raise InputRejected(f"document nested deeper than {MAX_DEPTH}")
    if isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, (str, int, float, bool)) and k is not None:
                raise InputRejected("mapping keys must be scalars")
            _shape(k, depth + 1, count)
            _shape(v, depth + 1, count)
    elif isinstance(node, list):
        for v in node:
            _shape(v, depth + 1, count)
    elif isinstance(node, str):
        if len(node) > MAX_STRING:
            raise InputRejected(f"a string longer than {MAX_STRING} characters")
        if "\x00" in node:
            raise InputRejected("a string contains a NUL character")


def read_bounded(path: Path, max_bytes: int = MAX_FILE_BYTES) -> str:
    path = Path(path)
    size = path.stat().st_size
    if size > max_bytes:
        raise InputRejected(f"{path.name} is {size} bytes, above {max_bytes}")
    raw = path.read_bytes()
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise InputRejected(f"{path.name} is not UTF-8") from e


def load_yaml_text(text: str, name: str = "document"):
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise InputRejected(f"{name} is above {MAX_FILE_BYTES} bytes")
    try:
        doc = yaml.load(text, Loader=_NoAliasLoader)   # noqa: S506 - a SafeLoader subclass
    except InputRejected:
        raise
    except yaml.YAMLError as e:
        raise InputRejected(f"{name} is not valid YAML") from e
    _shape(doc)
    return doc


def load_yaml(path: Path):
    return load_yaml_text(read_bounded(path), Path(path).name)


def load_json_bytes(raw: bytes, name: str = "response", max_bytes: int = MAX_RESPONSE_BYTES):
    if len(raw) > max_bytes:
        raise InputRejected(f"{name} is above {max_bytes} bytes")
    try:
        doc = json.loads(raw.decode("utf-8"), parse_constant=lambda c: (_ for _ in ()).throw(InputRejected(f"{c} not accepted")))
    except InputRejected:
        raise
    except (ValueError, UnicodeDecodeError) as e:
        raise InputRejected(f"{name} is not valid JSON") from e
    _shape(doc)
    return doc


# --- values -------------------------------------------------------------------------------------------------------

def ident(value, what: str = "identifier") -> str:
    """An identifier or anchor: printable ASCII from a narrow set, bounded, no spaces, quotes or control characters,
    so it is safe in a SCIM filter, a URL path segment (quoted), a file name stem and an HTML attribute after escaping.
    fullmatch: a trailing newline is refused too."""
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise InputRejected(f"{what} is not a valid identifier")
    return value


def anchor(value, what: str = "anchor") -> str:
    """A person's anchor: an identifier outside the reserved uid: prefix, which stands for a broker member without an
    anchor and must never be matched by a record."""
    ident(value, what)
    if value.lower().startswith("uid:"):
        raise InputRejected(f"{what} uses the reserved uid: prefix")
    return value


def name(value, what: str = "name") -> str:
    """A realm, client or group name: an identifier without a slash, so it is one URL path segment."""
    ident(value, what)
    if "/" in value or ".." in value:
        raise InputRejected(f"{what} may not contain a slash or ..")
    return value


def uuid(value, what: str = "broker id") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F][0-9a-fA-F-]{7,63}", value):
        raise InputRejected(f"{what} is not a broker id")
    return value


def timestamp(value, what: str = "timestamp") -> datetime:
    """A time with an explicit zone; a naive time is refused, never guessed."""
    if isinstance(value, datetime):
        d = value
    elif isinstance(value, str) and len(value) <= 40:
        try:
            d = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as e:
            raise InputRejected(f"{what} is not an ISO 8601 time") from e
    else:
        raise InputRejected(f"{what} is not a time")
    if d.tzinfo is None:
        raise InputRejected(f"{what} has no time zone")
    return d


def text(value, what: str = "text", max_len: int = MAX_STRING, multiline: bool = False) -> str:
    """Free text: bounded and free of control, invisible and direction characters; one line unless multiline."""
    if not isinstance(value, str) or len(value) > max_len or CONTROL.search(value) or INVISIBLE.search(value):
        raise InputRejected(f"{what} is not acceptable text")
    if not multiline and ("\n" in value or "\r" in value or "\t" in value):
        raise InputRejected(f"{what} must be one line")
    return value


def safe_for_log(value, max_len: int = 300) -> str:
    """Anything as one log-safe line: control characters replaced, length bounded."""
    s = INVISIBLE.sub("?", CONTROL.sub("?", str(value))).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return s if len(s) <= max_len else s[:max_len] + "..."


# --- network ------------------------------------------------------------------------------------------------------

def broker_url(url: str) -> str:
    """https, or plain http only to this machine; no credentials, query or fragment in the base."""
    p = urllib.parse.urlsplit(url)
    if p.scheme not in ("https", "http") or not p.hostname:
        raise InputRejected("broker URL must be http(s) with a host")
    if p.scheme == "http" and p.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise InputRejected("plain http only to localhost")
    if p.username or p.password or p.query or p.fragment:
        raise InputRejected("broker URL carries credentials, a query or a fragment")
    return url.rstrip("/")


def read_response(resp, max_bytes: int = MAX_RESPONSE_BYTES, json_only: bool = True):
    """Read a bounded HTTP response; parse JSON when it says so; refuse anything else when json_only."""
    ctype = resp.headers.get("Content-Type", "")
    raw = resp.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise InputRejected(f"response above {max_bytes} bytes")
    if not raw:
        return None
    if "json" not in ctype:
        if json_only:
            raise InputRejected(f"response is {safe_for_log(ctype, 60) or 'untyped'}, not JSON")
        return raw.decode("utf-8", "replace")
    return load_json_bytes(raw)
