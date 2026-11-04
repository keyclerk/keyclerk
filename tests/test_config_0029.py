# SPDX-License-Identifier: EUPL-1.2
"""Decision 0029 points 3 and 7: a backup keeps no look past the desk's retention, and behind a listed proxy the
public scan budget is kept per client."""
import email.message
from urllib.parse import urlparse

import ipaddress
import pytest

from keyclerk import api, config


def _doc(**sections):
    return {**config.current(), **sections}


def test_a_backup_kept_longer_than_the_view_logs_is_refused():
    errs = config.validate(_doc(backup={"retention_days": 401}))
    assert errs and "view_log_keep_days (400)" in errs[0], errs            # the default retention
    errs = config.validate(_doc(backup={"retention_days": 90}, store={"view_log_keep_days": 60}))
    assert errs and "Lower backup.retention_days" in errs[0], errs


def test_a_backup_within_the_view_log_retention_passes():
    assert config.validate(_doc(backup={"retention_days": 400})) == []
    assert config.validate(_doc(backup={"retention_days": 500}, store={"view_log_keep_days": 500})) == []


def test_a_proxy_that_is_not_a_network_is_refused():
    errs = config.validate(_doc(api={"trusted_proxies": ["10.0.0.1/8"]}))       # host bits set: a typo
    assert errs and "api.trusted_proxies" in errs[0], errs
    assert config.validate(_doc(api={"trusted_proxies": ["10.0.0.0/8", "2001:db8::1"]})) == []


def _h(**headers):
    m = email.message.Message()
    for k, v in headers.items():
        for line in v if isinstance(v, list) else [v]:
            m[k.replace("_", "-")] = line
    return m


NETS = (ipaddress.ip_network("10.0.0.0/24"), ipaddress.ip_network("2001:db8:f::/48"))


def test_without_listed_proxies_the_header_is_ignored():
    assert api.client_ip("10.0.0.5", _h(X_Forwarded_For="192.0.2.9")) == "10.0.0.5"


def test_a_peer_that_is_not_a_listed_proxy_cannot_set_the_address():
    assert api.client_ip("198.51.100.4", _h(X_Forwarded_For="192.0.2.9"), NETS) == "198.51.100.4"


def test_behind_a_proxy_the_rightmost_untrusted_address_counts():
    # the client wrote 203.0.113.1 itself; the proxy appended the address it saw
    h = _h(X_Forwarded_For="203.0.113.1, 192.0.2.9")
    assert api.client_ip("10.0.0.5", h, NETS) == "192.0.2.9"


def test_a_chain_of_listed_proxies_is_walked():
    h = _h(X_Forwarded_For=["203.0.113.1, 192.0.2.9", "10.0.0.7"])          # two copies of the header
    assert api.client_ip("10.0.0.5", h, NETS) == "192.0.2.9"


def test_an_unreadable_entry_stops_at_the_last_proxy():
    assert api.client_ip("10.0.0.5", _h(X_Forwarded_For="192.0.2.9, junk"), NETS) == "10.0.0.5"


def test_forwarded_is_read_only_when_chosen():
    h = _h(Forwarded='for=203.0.113.1, for="[2001:db8::9]:4711";proto=https', X_Forwarded_For="192.0.2.66")
    assert api.client_ip("10.0.0.5", h, NETS, "forwarded") == "2001:db8::9"
    assert api.client_ip("10.0.0.5", h, NETS) == "192.0.2.66"


def test_a_mapped_v4_proxy_address_is_recognised():
    assert api.client_ip("::ffff:10.0.0.5", _h(X_Forwarded_For="192.0.2.9:5000"), NETS) == "192.0.2.9"


def test_the_scan_budget_is_per_client_behind_the_proxy(monkeypatch, tmp_path):
    from tests.test_api_scan_budget import Auth, start
    s, _, desk = start(tmp_path)
    s.shutdown()
    monkeypatch.setattr(desk, "scan", lambda token: {"unescorted": False})
    monkeypatch.setattr(api.time, "monotonic", lambda: 1000.0)
    H = api.handler(desk, Auth(), {"desk.test"}, ("other-front-end",), False, proxies=NETS)
    h = H.__new__(H)
    h._json = lambda status, obj: status
    h.client_address = ("10.0.0.5", 0)
    u = urlparse("/api/v1/scan/not-a-code")
    h.headers = _h(X_Forwarded_For="192.0.2.9")
    with pytest.raises(api.ApiError):
        for _ in range(100):                                                 # one phone spends its budget
            h._public_visit(u)
    h.headers = _h(X_Forwarded_For="192.0.2.10")
    assert h._public_visit(u) == 200                                         # FAILS on the proxy's own address
