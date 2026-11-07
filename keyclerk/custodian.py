# SPDX-License-Identifier: EUPL-1.2
"""The records key behind the custodian (decision 0033): an object the checking signer signs with as it did with the
key itself (sign, public_key), each signature asked of keyclerk-custodian over its local socket. The custodian refuses,
on its own state alone, anything that would break the log's structure; a refusal comes back here as CustodianRefused,
which the signer answers as any refusal: nothing signed.

    signer --custodian unix:/run/keyclerk/custodian.sock
    signer --custodian tcp:127.0.0.1:PORT --custodian-token FILE     (over TCP every request carries the token)
"""
from __future__ import annotations

import base64
import json
import socket
import threading

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_ANSWER = 1 << 20
CHUNK_BYTES = 2 << 20                        # one follow request's links, well inside the custodian's 4 MiB line


class CustodianRefused(Exception):
    """The custodian refused to sign, with why (a structural rule, its state, or its absence)."""


class CustodianKey:
    """Duck-typed Ed25519PrivateKey for the signer: sign(data) -> 64 bytes, public_key()."""

    def __init__(self, address: str, token: str | None = None, timeout: float = 10.0):
        if not (address.startswith("unix:") or address.startswith("tcp:127.0.0.1:") or address.startswith("tcp:[::1]:")):
            raise ValueError("the custodian is local only: unix:PATH, or tcp:127.0.0.1:PORT")
        if address.startswith("tcp:") and not token:
            raise ValueError("over TCP any local user reaches the custodian: give its token (--custodian-token)")
        self.address, self.token, self.timeout = address, token, timeout
        self._lock = threading.Lock()
        self._pub: Ed25519PublicKey | None = None

    def _connect(self) -> socket.socket:
        if self.address.startswith("unix:"):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.address[5:])
            return s
        host, port = self.address[4:].rsplit(":", 1)
        return socket.create_connection((host.strip("[]"), int(port)), timeout=self.timeout)

    def _exchange(self, s: socket.socket, req: dict) -> dict:
        if self.token:
            req = {**req, "token": self.token}
        s.sendall(json.dumps(req).encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            part = s.recv(65536)
            if not part:
                break
            buf += part
            if len(buf) > MAX_ANSWER:
                raise CustodianRefused("the custodian's answer is too large")
        try:
            out = json.loads(buf)
        except ValueError:
            raise CustodianRefused("the custodian's answer does not read") from None
        if "refused" in out:
            raise CustodianRefused(f"the custodian refused: {out['refused']}")
        return out

    def _call(self, req: dict) -> dict:
        with self._lock:
            try:
                with self._connect() as s:
                    return self._exchange(s, req)
            except OSError as e:
                raise CustodianRefused(f"the custodian does not answer at {self.address}: {e}") from None

    def sign(self, data: bytes) -> bytes:
        sig = bytes.fromhex(self._call({"op": "sign", "data": base64.b64encode(data).decode()})["signature"])
        self.public_key().verify(sig, data)       # a custodian that signs with another key is caught here
        return sig

    def public_key(self) -> Ed25519PublicKey:
        if self._pub is None:
            self._pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self._call({"op": "public_key"})["key"]))
        return self._pub

    def state(self) -> dict:
        return self._call({"op": "state"})

    def follow(self, mode: str, links: list[dict], note: str) -> int:
        """HA (decision 0033 Q4): the links the active node committed, on the commit witness's countersigned note, in one
        staged follow on one connection: extend from this custodian's size, or rebuild from link 0 once the committed
        log has passed this custodian's own. Accepted only as exactly the witness's tree; returns the custodian's size."""
        with self._lock:
            try:
                with self._connect() as s:
                    self._exchange(s, {"op": "follow_begin", "mode": mode, "note": note})
                    chunk, size = [], 0
                    for link in links:
                        n = len(link["bytes"]) + len(link["signature"]) + 32
                        if chunk and size + n > CHUNK_BYTES:
                            self._exchange(s, {"op": "follow_links", "links": chunk})
                            chunk, size = [], 0
                        chunk.append(link)
                        size += n
                    if chunk:
                        self._exchange(s, {"op": "follow_links", "links": chunk})
                    return self._exchange(s, {"op": "follow_end"})["size"]
            except OSError as e:
                raise CustodianRefused(f"the custodian does not answer at {self.address}: {e}") from None
