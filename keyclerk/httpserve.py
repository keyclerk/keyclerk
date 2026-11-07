# SPDX-License-Identifier: EUPL-1.2
"""The HTTP server under the desk and the console: a thread per connection, but a bounded number of them.

A connection that sends nothing is dropped after SOCKET_SECONDS (set as the handler's timeout), and past
MAX_CONNECTIONS a new connection is closed at once, so idle or half-sent connections cannot use up the process.
"""
from __future__ import annotations

import socket
import threading
from http.server import ThreadingHTTPServer

MAX_CONNECTIONS = 256                 # connections open at once, idle ones included
SOCKET_SECONDS = 15                   # a connection silent this long is closed
BUSY_WAIT_SECONDS = 3                 # how long a request waits for a free worker before it is told the server is busy


def listen_host(host: str) -> str:
    """A listen address as written: an IPv6 one may come in brackets ([::1])."""
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


class DualStack:
    """A server that listens on IPv6 when its host is an IPv6 address (it contains ':'), and also takes IPv4 on '::'
    where the system allows dual-stack sockets, so one setting serves IPv4, IPv6 and dual-stack hosts. A host without
    ':' listens on IPv4 as before. (ThreadingHTTPServer alone is IPv4 only: '::' fails at bind, and 0.0.0.0 cannot be
    reached on an IPv6-only pod; keyclerk/keyclerk#37.)"""

    def __init__(self, server_address, *a, **k):
        host, port = server_address[0], server_address[1]
        host = listen_host(str(host))
        if ":" in host:
            self.address_family = socket.AF_INET6
        super().__init__((host, port), *a, **k)

    def server_bind(self):
        if self.address_family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass                                  # a system without dual-stack sockets: IPv6 only
        super().server_bind()


class DualStackHTTPServer(DualStack, ThreadingHTTPServer):
    """ThreadingHTTPServer with DualStack: for the management listener and the witness."""


class Server(DualStack, ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *a, max_connections: int = MAX_CONNECTIONS, **k):
        self.slots = threading.BoundedSemaphore(max_connections)
        super().__init__(*a, **k)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()
