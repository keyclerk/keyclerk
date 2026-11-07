# SPDX-License-Identifier: EUPL-1.2
"""The desk, the console, the management listener and the witness listen on IPv6 (keyclerk/keyclerk#37): an IPv6 host
binds IPv6, '::' takes IPv4 too where the system allows dual-stack sockets, and an IPv4 host is unchanged. On an
IPv6-only pod 0.0.0.0 could not be reached and '::' failed at bind, so the probes killed the desk."""
import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler

import pytest

from keyclerk import health
from keyclerk.httpserve import DualStackHTTPServer, Server, listen_host


def _has_ipv6() -> bool:
    if not socket.has_ipv6:
        return False
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


needs_ipv6 = pytest.mark.skipif(not _has_ipv6(), reason="this host has no IPv6 loopback")


class Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *a):
        pass


def _serve(srv):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def _get(host: str, port: int) -> bytes:
    with urllib.request.urlopen(f"http://{host}:{port}/", timeout=5) as r:
        return r.read()


def test_an_ipv4_host_listens_as_before():
    srv = Server(("127.0.0.1", 0), Hello)
    try:
        assert srv.address_family == socket.AF_INET and _get("127.0.0.1", _serve(srv)) == b"hello"
    finally:
        srv.shutdown()


@needs_ipv6
@pytest.mark.parametrize("make", [lambda a: Server(a, Hello), lambda a: DualStackHTTPServer(a, Hello)])
def test_the_ipv6_any_address_takes_ipv6_and_ipv4(make):
    srv = make(("::", 0))
    try:
        port = _serve(srv)
        assert srv.address_family == socket.AF_INET6
        assert _get("[::1]", port) == b"hello"
        assert _get("127.0.0.1", port) == b"hello"          # dual stack: one setting for every kind of host
    finally:
        srv.shutdown()


@needs_ipv6
def test_a_bracketed_host_and_the_management_listener_bind_ipv6():
    assert listen_host("[::1]") == "::1" and listen_host("::") == "::" and listen_host("0.0.0.0") == "0.0.0.0"
    readiness = type("R", (), {"detail": lambda self: {"ready": True, "checks": {}}, "ready": lambda self: True})()
    srv = health.management_server(("[::1]", 0), readiness, "t" * 32)
    try:
        assert srv.address_family == socket.AF_INET6
        _serve(srv)
    finally:
        srv.shutdown()
