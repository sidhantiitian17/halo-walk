"""DATAGEN collection path: conntrack parsing (CT_RE / ct_entry / canon_ip / poll_conntrack) and the generator side
(halo/gen.py: label() appends, rt_server source address). Regression tests for the gaps quantified by
analysis/check_collection.py: every labelled UDP-over-IPv6 call/gaming flow was missing from raw_flows.jsonl.

Host-only: conntrack output is mocked; sockets use IPv4 loopback only (127.0.0.2 stands in for a 2nd WAN address).
"""
import ipaddress, json, os, socket, subprocess, sys, threading, types

import pytest

from halo import controller, gen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from halo.controller import CT_RE, Ctl, canon_ip, ct_entry

# real `conntrack -L -o extended` line shapes (6.8 kernel, conntrack-tools 1.4.x)
UDP6_UNREPLIED = ("ipv6     10 udp      17 29 src=fd00::10 dst=fd00:9::2 sport=20000 dport=3478 packets=120 bytes=130560 "
                  "[UNREPLIED] src=fd00:9::2 dst=fd00::10 sport=3478 dport=20000 packets=0 bytes=0 mark=0 zone=0 use=1")
UDP6_ASSURED = ("ipv6     10 udp      17 119 src=fd00::10 dst=fd00:9::2 sport=20000 dport=3478 packets=120 bytes=130560 "
                "src=fd00:9::2 dst=fd00::10 sport=3478 dport=20000 packets=170 bytes=193800 [ASSURED] mark=4 use=1")
UDP4_UNREPLIED = ("ipv4     2 udp      17 28 src=10.0.0.13 dst=10.9.0.2 sport=20003 dport=3479 packets=61 bytes=64000 "
                  "[UNREPLIED] src=10.9.0.2 dst=10.0.0.13 sport=3479 dport=20003 packets=0 bytes=0 mark=0 use=1")
TCP6_SYN = ("ipv6     10 tcp      6 118 SYN_SENT src=fd00::15 dst=fd00:9::2 sport=57502 dport=443 packets=1 bytes=80 "
            "[UNREPLIED] src=fd00:9::2 dst=fd00::15 sport=443 dport=57502 packets=0 bytes=0 mark=0 use=1")
# what the old rig produced: the WAN server answered from fd00:9::6 -> a second, WAN-initiated one-way entry
UDP6_WAN_INIT = ("ipv6     10 udp      17 29 src=fd00:9::6 dst=fd00::10 sport=3478 dport=20000 packets=170 bytes=193800 "
                 "[UNREPLIED] src=fd00::10 dst=fd00:9::6 sport=20000 dport=3478 packets=0 bytes=0 mark=0 use=1")


@pytest.mark.parametrize("line,key,ctr", [
    (UDP6_UNREPLIED, ("udp", "fd00::10", 20000, "fd00:9::2", 3478), (130560, 0, 120, 0)),
    (UDP6_ASSURED, ("udp", "fd00::10", 20000, "fd00:9::2", 3478), (130560, 193800, 120, 170)),
    (UDP4_UNREPLIED, ("udp", "10.0.0.13", 20003, "10.9.0.2", 3479), (64000, 0, 61, 0)),
    (TCP6_SYN, ("tcp", "fd00::15", 57502, "fd00:9::2", 443), (80, 0, 1, 0)),
    (UDP6_WAN_INIT, ("udp", "fd00::10", 20000, "fd00:9::6", 3478), (0, 193800, 0, 170)),
])
def test_ct_re_real_lines(line, key, ctr):
    """[UNREPLIED] sits BETWEEN the two tuples; the old CT_RE required 'bytes=N src=' and silently skipped such lines"""
    m = CT_RE.match(line)
    assert m is not None
    assert ct_entry(m) == (key, ctr)


def test_canon_ip_matches_sniffer_and_label_spelling():
    for spelled, sniffer_bytes in (("fd00:0:0:0:0:0:0:10", "fd00::10"), ("FD00:0009::0002", "fd00:9::2"),
                                   ("fd00::10", "fd00::10"), ("10.0.0.10", "10.0.0.10")):
        fam = socket.AF_INET6 if ":" in sniffer_bytes else socket.AF_INET
        sniffer = socket.inet_ntop(fam, socket.inet_pton(fam, sniffer_bytes))     # what the sniffer keys on
        assert canon_ip(spelled) == sniffer == str(ipaddress.ip_address(spelled))  # == train_classifier.norm_ip


def _ctl(key):
    c = object.__new__(Ctl)
    c.flows = {key: {"key": key, "ct": None, "bins": [], "tot": (0, 0), "seen": 0.0}}
    c.flock = threading.Lock()
    return c


def test_poll_conntrack_accounts_one_way_ipv6_udp(monkeypatch):
    """a one-way IPv6 UDP flow (non-canonical spelling on purpose) must still reach the sniffer's key and get bins,
    otherwise the dump rule (>= 2 bins) never fires and the flow is missing from raw_flows.jsonl"""
    key = ("udp", "fd00::10", 20000, "fd00:9::2", 3478)
    c = _ctl(key)
    line = UDP6_UNREPLIED.replace("dst=fd00:9::2 sport=20000", "dst=fd00:0009:0:0::2 sport=20000")
    outs = iter([line.replace("packets=120 bytes=130560", "packets=%d bytes=%d" % (p, p * 1088)) for p in (10, 130, 250)])
    monkeypatch.setattr(controller, "subprocess", types.SimpleNamespace(run=lambda *a, **k: types.SimpleNamespace(stdout=next(outs))))
    times = iter([100.0, 101.0, 102.0])
    monkeypatch.setattr(controller.time, "time", lambda: next(times))
    for _ in range(3):
        c.poll_conntrack(0)
    assert c.flows[key]["bins"] == [(1.0, 120 * 1088, 0, 120, 0), (1.0, 120 * 1088, 0, 120, 0)]


# ----------------------------------------------------------------------------- generator side
WRITER = """
import socket, sys
from halo import gen
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("127.0.0.1", 9))
for i in range(150):
    gen.label("udp", s, "10.9.0.2", 3478, "call", {"sid": "w" + sys.argv[1], "i": i, "pad": "x" * 600})
"""


def test_label_appends_are_atomic_across_processes(tmp_path):
    """8 concurrent generator processes append to one labels file (as in a DATAGEN batch)"""
    path = str(tmp_path / "labels.jsonl")
    env = dict(os.environ, HALO_LABELS=path, PYTHONPATH=ROOT)
    ps = [subprocess.Popen([sys.executable, "-c", WRITER, str(w)], env=env) for w in range(8)]
    assert [p.wait(60) for p in ps] == [0] * 8
    rows = [json.loads(l) for l in open(path)]                   # every line parses: no interleaving
    assert len(rows) == 8 * 150
    assert {(r["sid"], r["i"]) for r in rows} == {("w%d" % w, i) for w in range(8) for i in range(150)}


def _server_and_client():
    srv = gen.pktinfo_on(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
    srv.bind(("0.0.0.0", 0))                                     # wildcard, like rt_server
    cl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cl.connect(("127.0.0.2", srv.getsockname()[1]))              # client addresses the NON-primary address
    cl.settimeout(0.5)
    srv.settimeout(1.0)
    cl.send(b"hello")
    return srv, cl


def test_wildcard_reply_without_pktinfo_is_dropped_by_connected_client():
    """documents the bug class: kernel-chosen source (127.0.0.1) != addressed 127.0.0.2 -> connected client drops it"""
    srv, cl = _server_and_client()
    d, peer = srv.recvfrom(64)
    srv.sendto(b"reply", peer)
    with pytest.raises(socket.timeout):
        cl.recv(64)


def test_rt_server_replies_from_the_addressed_ip():
    srv, cl = _server_and_client()
    d, peer, t, dst = gen.recv_ts_dst(srv)
    assert d == b"hello" and socket.inet_ntoa(dst) == "127.0.0.2"
    srv.sendmsg([b"reply"], gen.src_cmsg(srv.family, dst), 0, peer)
    assert cl.recv(64) == b"reply"


def test_src_cmsg_ipv6_layout():
    a = socket.inet_pton(socket.AF_INET6, "fd00:9::2")
    [(lvl, typ, data)] = gen.src_cmsg(socket.AF_INET6, a)
    assert (lvl, typ) == (socket.IPPROTO_IPV6, socket.IPV6_PKTINFO) and data[:16] == a and len(data) == 20
    assert gen.src_cmsg(socket.AF_INET6, None) == []
