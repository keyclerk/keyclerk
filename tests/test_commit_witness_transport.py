# SPDX-License-Identifier: EUPL-1.2
"""Decision 0031 over HTTP: a page of the commit witness's links is read whole, however large, up to MAX_COMMIT; a
witness's answer over the cap is refused, never cut and parsed. Found by the soak on a slower box: the commit client
used the C2SP witness transport, which reads one note (about 68 KB), so a page of a larger realm's links was cut
mid-string and every grant failed with a JSON error at the same offset."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from keyclerk import commit_witness as C
from keyclerk import witness as W

PAGE = {"links": [{"body": "x" * 4000, "n": i} for i in range(60)], "size": 60}      # about 245 KB


@pytest.fixture
def server():
    raw = json.dumps(PAGE).encode()

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", len(raw)
    srv.shutdown()
    srv.server_close()


def test_a_large_page_of_committed_links_is_read_whole(server):
    url, size = server
    assert size > W.MAX_BODY                           # larger than one witness note: the old cap cut it
    assert C.CommitClient(url).links("keyclerk.example/realm", 0) == PAGE["links"]


def test_an_answer_over_the_cap_is_refused_not_cut(server):
    url, _ = server
    with pytest.raises(OSError, match="over 69632 bytes"):
        W.http("GET", url + "/x", None, 5)
