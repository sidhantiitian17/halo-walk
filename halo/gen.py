#!/usr/bin/env python3
"""HALO-Walk synthetic traffic generators and measurement sinks (M8 harness).

Everything here is SYNTHETIC: random bytes, no third-party media, no human subjects.
All namespaces of the rig share one kernel clock, so one-way delay (OWD) is exact.

  reflector           UDP echo with receive timestamp (capacity-estimator probes)
  rt_server/rt_client bidirectional real-time UDP flow (voice / video call / gaming)
  chunk_server        TCP "GET <n>" byte server (streaming segments, web objects, bulk)
  tv_client           DASH-like segment fetcher with a throughput-based ABR ladder
  web_client          short random object fetches ("other/web")
  bulk_client         long TCP download or upload (ISO / update / backup)
"""
import argparse, json, os, random, select, socket, struct, sys, threading, time

HDR = struct.Struct("!IId")           # magic, seq, send_ts
MAGIC, HELLO = 0x48414C4F, 0x48454C4F
LABELS = os.environ.get("HALO_LABELS", "/tmp/halo_labels.jsonl")


def now():
    return time.time()


def sleep_until(t):
    d = t - now()
    if d > 0:
        time.sleep(d)


def ts_on(s):
    s.setsockopt(socket.SOL_SOCKET, 35, 1)            # SO_TIMESTAMPNS: kernel receive timestamps
    return s


def recv_ts(s, n=2048):
    """(data, peer, kernel_rx_time) - measurement must not include user-space scheduling latency"""
    d, anc, _, peer = s.recvmsg(n, 64)
    t = now()
    for lvl, typ, cd in anc:
        if lvl == socket.SOL_SOCKET and typ == 35:
            sec, ns = struct.unpack("ll", cd[:16])
            t = sec + ns * 1e-9
    return d, peer, t


def fam(addr):
    return socket.AF_INET6 if ":" in addr else socket.AF_INET


# A server socket bound to the wildcard address replies with a KERNEL-CHOSEN source address. The rig's WAN host
# carries fd00:9::2..::6 on one /64, and IPv6 source selection picks fd00:9::6 (the reflector alias), not the
# fd00:9::2 the client addressed: the client's connect()ed socket then drops every downstream packet and conntrack
# sees two one-way [UNREPLIED] flows instead of one call. IPv4 happened to work only because 10.9.0.2 is the
# primary address. Fix: learn the destination address of each request (IP[V6]_PKTINFO) and send from it.
def pktinfo_on(s):
    if s.family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVPKTINFO, 1)
    else:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_PKTINFO, 1)
    return s


def recv_ts_dst(s, n=2048):
    """recv_ts + the local address the datagram was sent to (packed bytes, None if unknown)"""
    d, anc, _, peer = s.recvmsg(n, 256)
    t, dst = now(), None
    for lvl, typ, cd in anc:
        if lvl == socket.SOL_SOCKET and typ == 35:
            sec, ns = struct.unpack("ll", cd[:16])
            t = sec + ns * 1e-9
        elif lvl == socket.IPPROTO_IPV6 and typ == socket.IPV6_PKTINFO:
            dst = cd[:16]                                  # struct in6_pktinfo {in6_addr addr; int ifindex}
        elif lvl == socket.IPPROTO_IP and typ == socket.IP_PKTINFO:
            dst = cd[8:12]                                 # struct in_pktinfo {ifindex; spec_dst; addr}: addr
    return d, peer, t, dst


def src_cmsg(family, dst):
    """ancillary data that makes sendmsg() use `dst` (from recv_ts_dst) as the source address"""
    if dst is None:
        return []
    if family == socket.AF_INET6:
        return [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, dst + struct.pack("i", 0))]
    return [(socket.IPPROTO_IP, socket.IP_PKTINFO, struct.pack("i", 0) + dst + b"\0\0\0\0")]


def label(proto, sock, dst, dport, cls, extra=None):
    """ground-truth flow label (never visible to the classifier)"""
    ip, port = sock.getsockname()[:2]
    rec = {"t": now(), "proto": proto, "lan_ip": ip, "lan_port": port, "wan_ip": dst,
           "wan_port": dport, "cls": cls, "batch": os.environ.get("HALO_BATCH", "")}
    rec.update(extra or {})
    # ~20 generator processes append to one file concurrently: one O_APPEND write() per record is atomic on a
    # local filesystem, so lines can never interleave or overwrite (a buffered text stream gives no such guarantee).
    fd = os.open(LABELS, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
    try:
        os.write(fd, (json.dumps(rec) + "\n").encode())
    finally:
        os.close(fd)


def rfc3550_jitter(transits):
    j = 0.0
    for a, b in zip(transits, transits[1:]):
        j += (abs(b - a) - j) / 16.0
    return j


def pct(v, q):
    if not v:
        return float("nan")
    s = sorted(v)
    k = (len(s) - 1) * q / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


# ----------------------------------------------------------------------------- reflector
def reflector(a):
    """one socket per reflector address so replies carry the probed address as source"""
    socks = []
    for addr in a.addrs:
        s = ts_on(socket.socket(fam(addr), socket.SOCK_DGRAM))
        s.bind((addr, a.port))
        socks.append(s)
    while True:
        for s in select.select(socks, [], [])[0]:
            d, peer, t = recv_ts(s, 256)
            s.sendto(d[:16] + struct.pack("!d", t), peer)


# ----------------------------------------------------------------------------- real-time UDP
def rt_server(a):
    """one socket per port (v4+v6). HELLO starts a paced downstream stream back to the client;
    upstream packets are logged with their one-way delay."""
    os.makedirs(a.out, exist_ok=True)
    socks = []
    for p in a.ports:
        for f, host in ((socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")):
            s = pktinfo_on(ts_on(socket.socket(f, socket.SOCK_DGRAM)))
            if f == socket.AF_INET6:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s.bind((host, p))
            socks.append(s)
    sessions = {}

    def downstream(s, peer, pps, size, dur, seed, anc):
        # anc = src_cmsg(...): reply from the address the client sent to (see pktinfo_on)
        rnd = random.Random(seed)
        t0, n = now(), 0
        while now() - t0 < dur:
            sz = max(HDR.size, int(size * rnd.uniform(0.85, 1.15)))
            try:
                s.sendmsg([HDR.pack(MAGIC, n, now()) + b"\0" * (sz - HDR.size)], anc, 0, peer)
            except OSError:
                pass
            n += 1
            sleep_until(t0 + n / pps)
        # trailer tells the client how many packets were sent
        for _ in range(3):
            try:
                s.sendmsg([HDR.pack(HELLO, n, now())], anc, 0, peer)
            except OSError:
                pass
            time.sleep(0.02)

    while True:
        for s in select.select(socks, [], [], 1.0)[0]:
            d, peer, t, dst = recv_ts_dst(s)
            if len(d) < HDR.size:
                continue
            magic, seq, ts = HDR.unpack(d[:HDR.size])
            if magic == HELLO:
                info = json.loads(d[HDR.size:].decode())
                if peer not in sessions:
                    sessions[peer] = open(os.path.join(a.out, info["sid"] + "_up.csv"), "w")
                    if info["pps_down"] > 0:
                        threading.Thread(target=downstream, daemon=True, args=(
                            s, peer, info["pps_down"], info["size_down"], info["dur"], info["seed"],
                            src_cmsg(s.family, dst))).start()
            elif magic == MAGIC and peer in sessions:
                f = sessions[peer]
                f.write("%.6f,%d,%.3f\n" % (t, seq, (t - ts) * 1e3))
                f.flush()


def rt_client(a):
    s = ts_on(socket.socket(fam(a.dst), socket.SOCK_DGRAM))
    if a.sport:
        s.bind(("", a.sport))
    s.connect((a.dst, a.dport))
    label("udp", s, a.dst, a.dport, a.cls, {"sid": a.sid})
    hello = {"sid": a.sid, "pps_down": a.pps_down, "size_down": a.size_down, "dur": a.dur, "seed": a.seed}
    s.send(HDR.pack(HELLO, 0, now()) + json.dumps(hello).encode())
    rows, sent_down, stop = [], [None], [False]

    def rx():
        s.settimeout(0.5)
        while not stop[0]:
            try:
                d, _, t = recv_ts(s)
            except socket.timeout:
                continue
            except OSError:
                continue
            magic, seq, ts = HDR.unpack(d[:HDR.size])
            if magic == MAGIC:
                rows.append((t, seq, (t - ts) * 1e3))
            elif magic == HELLO:
                sent_down[0] = seq

    th = threading.Thread(target=rx, daemon=True)
    th.start()
    rnd = random.Random(a.seed)
    t0, n = now(), 0
    while now() - t0 < a.dur:
        if a.pps_up > 0:
            sz = max(HDR.size, int(a.size_up * rnd.uniform(0.85, 1.15)))
            try:
                s.send(HDR.pack(MAGIC, n, now()) + b"\0" * (sz - HDR.size))
            except OSError:
                pass
            n += 1
            sleep_until(t0 + n / a.pps_up)
        else:
            time.sleep(0.05)
    time.sleep(0.6)
    stop[0] = True
    th.join()
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as f:
        f.write("t,seq,owd_ms\n")
        for r in rows:
            f.write("%.6f,%d,%.3f\n" % r)
    json.dump({"sid": a.sid, "cls": a.cls, "t0": t0, "sent_up": n, "sent_down": sent_down[0],
               "recv_down": len(rows)}, open(a.out + ".json", "w"))


# ----------------------------------------------------------------------------- TCP byte server
def chunk_server(a):
    blob = os.urandom(1 << 16)

    def serve(c):
        try:
            c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            f = c.makefile("rb")
            while True:
                line = f.readline()
                if not line:
                    break
                p = line.split()
                if p[0] == b"GET":
                    n = int(p[1])
                    while n > 0:
                        k = min(n, len(blob))
                        c.sendall(blob[:k])
                        n -= k
                elif p[0] == b"PUT":           # upload sink: read n bytes
                    n = int(p[1])
                    while n > 0:
                        d = f.read(min(n, 1 << 16))
                        if not d:
                            break
                        n -= len(d)
                    c.sendall(b"OK\n")
        except OSError:
            pass
        finally:
            c.close()

    socks = []
    for p in a.ports:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        s.bind(("::", p))
        s.listen(64)
        socks.append(s)
    while True:
        for s in select.select(socks, [], [])[0]:
            c, _ = s.accept()
            threading.Thread(target=serve, args=(c,), daemon=True).start()


def tcp_connect(dst, dport, sport=0):
    s = socket.socket(fam(dst), socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if sport:
        s.bind(("", sport))
    s.connect((dst, dport))
    return s


def fetch(s, n):
    s.sendall(b"GET %d\n" % n)
    got = 0
    while got < n:
        d = s.recv(min(1 << 16, n - got))
        if not d:
            raise OSError("closed")
        got += len(d)


def tv_client(a):
    """DASH-like: one segment of `seg` seconds every `seg` seconds, rung chosen from last throughput."""
    s = tcp_connect(a.dst, a.dport, a.sport)
    label("tcp", s, a.dst, a.dport, "streaming", {"sid": a.sid})
    ladder = sorted(a.ladder)
    rung, rows, t0, k = ladder[0], [], now(), 0
    while now() - t0 < a.dur:
        nbytes = int(rung * 1e6 / 8 * a.seg)
        ts = now()
        try:
            fetch(s, nbytes)
        except OSError:
            break
        dt = now() - ts
        tput = nbytes * 8 / dt / 1e6
        rows.append((ts, rung, nbytes, dt, int(dt > a.seg)))
        ok = [r for r in ladder if r <= 0.8 * tput]
        rung = ok[-1] if ok else ladder[0]
        k += 1
        sleep_until(t0 + k * a.seg)
    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    with open(a.out, "w") as f:
        f.write("t,rung_mbps,bytes,dl_s,stall\n")
        for r in rows:
            f.write("%.3f,%.1f,%d,%.3f,%d\n" % r)


def web_client(a):
    rnd = random.Random(a.seed)
    t0 = now()
    while now() - t0 < a.dur:
        try:
            s = tcp_connect(a.dst, a.dport, 0)
            label("tcp", s, a.dst, a.dport, "other", {"sid": a.sid})
            for _ in range(rnd.randint(1, 4)):
                fetch(s, int(rnd.lognormvariate(11.0, 1.0)))     # ~60 kB median objects
                time.sleep(rnd.uniform(0.05, 0.4))
            s.close()
        except OSError:
            pass
        time.sleep(rnd.uniform(0.3, 2.0))


def bulk_client(a):
    """long transfer; logs goodput every 100 ms"""
    s = tcp_connect(a.dst, a.dport, a.sport)
    label("tcp", s, a.dst, a.dport, "bulk", {"sid": a.sid})
    rows, t0, got, last, lastb = [], now(), 0, now(), 0
    if a.upload:
        s.sendall(b"PUT %d\n" % (1 << 40))
        blob = os.urandom(1 << 15)
    else:
        s.sendall(b"GET %d\n" % (1 << 40))
    s.settimeout(1.0)
    while now() - t0 < a.dur:
        try:
            if a.upload:
                got += s.send(blob)
            else:
                d = s.recv(1 << 16)
                if not d:
                    break
                got += len(d)
        except socket.timeout:
            pass
        except OSError:
            break
        t = now()
        if t - last >= 0.1:
            rows.append((t, (got - lastb) * 8 / (t - last) / 1e6))
            last, lastb = t, got
    if a.out:
        os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
        with open(a.out, "w") as f:
            f.write("t,mbps\n")
            for r in rows:
                f.write("%.3f,%.3f\n" % r)
    s.close()


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    q = sub.add_parser("reflector"); q.add_argument("--port", type=int, default=7000); q.add_argument("--addrs", nargs="+", default=["10.9.0.3", "10.9.0.4", "10.9.0.5", "fd00:9::6"])
    q = sub.add_parser("rt_server"); q.add_argument("--ports", type=int, nargs="+", required=True); q.add_argument("--out", default="/tmp/halo_rt")
    q = sub.add_parser("rt_client")
    for k, t, d in (("dst", str, None), ("dport", int, None), ("sport", int, 0), ("pps_up", float, 50), ("size_up", int, 200),
                    ("pps_down", float, 50), ("size_down", int, 200), ("dur", float, 20), ("cls", str, "call"),
                    ("sid", str, "rt"), ("seed", int, 1), ("out", str, "/tmp/rt.csv")):
        q.add_argument("--" + k, type=t, default=d)
    q = sub.add_parser("chunk_server"); q.add_argument("--ports", type=int, nargs="+", required=True)
    q = sub.add_parser("tv_client")
    for k, t, d in (("dst", str, None), ("dport", int, 443), ("sport", int, 0), ("seg", float, 2.0), ("dur", float, 20),
                    ("sid", str, "tv"), ("out", str, "/tmp/tv.csv")):
        q.add_argument("--" + k, type=t, default=d)
    q.add_argument("--ladder", type=float, nargs="+", default=[1.5, 3.0, 5.0])
    q = sub.add_parser("web_client")
    for k, t, d in (("dst", str, None), ("dport", int, 443), ("dur", float, 20), ("sid", str, "web"), ("seed", int, 1)):
        q.add_argument("--" + k, type=t, default=d)
    q = sub.add_parser("bulk_client")
    for k, t, d in (("dst", str, None), ("dport", int, 443), ("sport", int, 0), ("dur", float, 20), ("sid", str, "bulk"), ("out", str, "")):
        q.add_argument("--" + k, type=t, default=d)
    q.add_argument("--upload", action="store_true")
    a = p.parse_args()
    globals()[a.cmd](a)


if __name__ == "__main__":
    main()
