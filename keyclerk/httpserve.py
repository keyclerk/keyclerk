# SPDX-License-Identifier: EUPL-1.2
"""The HTTP server under the desk and the console: a thread per connection, but a bounded number of them.

A connection that sends nothing is dropped after SOCKET_SECONDS (set as the handler's timeout), and past
MAX_CONNECTIONS a new connection is closed at once, so idle or half-sent connections cannot use up the process.
"""
from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer

MAX_CONNECTIONS = 256                 # connections open at once, idle ones included
SOCKET_SECONDS = 15                   # a connection silent this long is closed
BUSY_WAIT_SECONDS = 3                 # how long a request waits for a free worker before it is told the server is busy


class Server(ThreadingHTTPServer):
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
