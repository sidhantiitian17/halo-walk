"""M1 observer (halo/controller.py: CT_RE + Ctl.poll_conntrack): conntrack accounting -> per-flow bins.

Only L3/L4 header fields and byte/packet counters are parsed; `conntrack -L` is mocked.
"""
import threading, types

import pytest

from halo import controller
from halo.controller import CT_RE, Ctl

TCP = ("ipv4     2 tcp      6 431999 ESTABLISHED src=10.0.0.2 dst=198.51.100.1 sport=50000 dport=443 "
       "packets=%d bytes=%d src=198.51.100.1 dst=10.0.0.2 sport=443 dport=50000 packets=%d bytes=%d [ASSURED] mark=2 use=1")
UDP6 = ("ipv6     10 udp      17 29 src=fd00::2 dst=2001:db8::5 sport=40000 dport=3478 packets=5 bytes=1000 "
        "src=2001:db8::5 dst=fd00::2 sport=3478 dport=40000 packets=6 bytes=1200 mark=4 use=1")


def test_ct_regex_ipv4_tcp():
    m = CT_RE.match(TCP % (10, 1000, 20, 30000))
    assert m.groups() == ("ipv4", "tcp", "10.0.0.2", "198.51.100.1", "50000", "443", "10", "1000", "20", "30000")


def test_ct_regex_ipv6_udp():
    m = CT_RE.match(UDP6)
    assert m.group(2) == "udp" and m.group(3) == "fd00::2" and m.group(6) == "3478"


def test_ct_regex_ignores_other_protocols():
    assert CT_RE.match("ipv4     2 icmp     1 29 src=10.0.0.2 dst=1.1.1.1 type=8 code=0 id=1 packets=1 bytes=84") is None


def test_poll_conntrack_builds_bins(monkeypatch):
    c = object.__new__(Ctl)
    key = ("tcp", "10.0.0.2", 50000, "198.51.100.1", 443)
    c.flows = {key: {"key": key, "ct": None, "bins": [], "tot": (0, 0), "seen": 0.0}}
    c.flock = threading.Lock()
    outputs = iter([TCP % (10, 1000, 20, 30000), TCP % (20, 2000, 145, 1_280_000)])
    monkeypatch.setattr(controller, "subprocess", types.SimpleNamespace(
        run=lambda *a, **k: types.SimpleNamespace(stdout=next(outputs))))
    times = iter([100.0, 101.0])
    monkeypatch.setattr(controller.time, "time", lambda: next(times))
    c.poll_conntrack(0)
    f = c.flows[key]
    assert f["bins"] == [] and f["tot"] == (1000, 30000)
    c.poll_conntrack(0)
    assert f["bins"] == [(1.0, 1000, 1_250_000, 10, 125)]
    assert f["rate"][1] == pytest.approx(10.0)                 # 1.25 MB/s down = 10 Mbit/s
    assert c.host_rate == {"10.0.0.2": pytest.approx(10.0)}
    assert f["seen"] == 101.0
