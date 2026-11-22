#!/usr/bin/env python3
"""HALO-Walk controller daemon (runs inside the gateway).

  OBSERVE -> CLASSIFY -> ESTIMATE -> DECIDE -> SHIELD -> ENFORCE -> VERIFY -> COMMIT | ROLLBACK

threads: prober (OWD probes, 20 Hz aggregate), sniffer (kernel-sampled first packets of each flow),
main loop (100 ms tick: rates, estimators, transactions; 1 s: conntrack accounting + classification).
"""
import argparse, itertools, json, os, re, select, signal, socket, struct, subprocess, sys, threading, time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from halo import policy, verifier
from halo.classifier import BULK_PORTS, HORIZONS, N1, Model, heuristic
from halo import enforcer as _enf_mod
from halo.enforcer import LAN, MON, STATE_DIR, WAN, Enforcer, safe_state, sh
from halo.estimator import DirEstimator, EstParams
from halo import sentinel as _sentinel
from halo.probe_gov import CONFIRM_N, CONFIRM_WIN, ProbeGovernor, collapsed, decay_peak, ewma_alpha

LAN4, LAN6 = "10.0.0.", "fd00::"
# `conntrack -L -o extended`: original tuple, then "[UNREPLIED]" while the reply direction has seen no packet,
# then the reply tuple (then [ASSURED], mark=, zone=, use=). The flag between the tuples must be allowed, or every
# one-way / not-yet-answered flow (e.g. an upload-only UDP stream) never gets accounting bins.
CT_RE = re.compile(r"^(ipv4|ipv6)\s+\d+\s+(tcp|udp)\s+\d+\s+.*?src=(\S+) dst=(\S+) sport=(\d+) dport=(\d+) packets=(\d+) bytes=(\d+)\s+"
                   r"(?:\[\w+\]\s+)*src=\S+ dst=\S+ sport=\d+ dport=\d+ packets=(\d+) bytes=(\d+)")


def canon_ip(s):
    """one spelling per address, identical to the sniffer's inet_ntop() (e.g. fd00:0:0::10 -> fd00::10)"""
    return socket.inet_ntop(socket.AF_INET6, socket.inet_pton(socket.AF_INET6, s)) if ":" in s else s


def is_lan(ip):
    return ip.startswith(LAN4) or ip.startswith(LAN6)


def ct_entry(m):
    """CT_RE match -> (LAN-first key, (up_bytes, dn_bytes, up_pkts, dn_pkts)), oriented like the sniffer's key:
    a WAN-initiated entry (original src = WAN host) is flipped so it can still meet the sniffer's flow."""
    _, pn, src, dst, sp, dp, p_o, b_o, p_r, b_r = m.groups()
    src, dst = canon_ip(src), canon_ip(dst)
    if not is_lan(src) and is_lan(dst):
        return (pn, dst, int(dp), src, int(sp)), (int(b_r), int(b_o), int(p_r), int(p_o))
    return (pn, src, int(sp), dst, int(dp)), (int(b_o), int(b_r), int(p_o), int(p_r))


# ---- conntrack accounting over ctnetlink (no `conntrack` exec: a fork+exec+text parse per dump is the largest cost of
# the slow loop on the 2-vCPU emulated gateway; the kernel-side walk is the same) ----------------------------------
NETLINK_NETFILTER, CT_GET_DUMP = 12, (1 << 8) | 1          # NFNL_SUBSYS_CTNETLINK << 8 | IPCTNL_MSG_CT_GET
CTA_TUPLE_ORIG, CTA_COUNTERS_ORIG, CTA_COUNTERS_REPLY = 1, 9, 10
_REAL_SUBPROCESS = subprocess


def ct_request(seq=1):
    return struct.pack("IHHII", 20, CT_GET_DUMP, 0x301, seq, 0) + struct.pack("BBH", 0, 0, 0)   # REQUEST|DUMP, AF_UNSPEC


_HDR, _NLA, _U16, _Q = struct.Struct("IH"), struct.Struct("HH"), struct.Struct("!H"), struct.Struct("!Q")
_inet_ntoa, _inet_ntop, _AF6 = socket.inet_ntoa, socket.inet_ntop, socket.AF_INET6


def parse_ct_dump(buf):
    """ctnetlink CT_NEW messages -> (proto, src, sport, dst, dport, pkts_orig, bytes_orig, pkts_reply, bytes_reply)
    for tcp/udp entries (same fields the `conntrack -L -o extended` regex extracts). Flat loop on purpose: this runs
    inside the controller process, so its CPU counts; non-tcp/udp entries are skipped after their tuple."""
    off, n = 0, len(buf)
    nla = _NLA.unpack_from
    while off + 20 <= n:
        ln, typ = _HDR.unpack_from(buf, off)
        if ln < 16:
            return
        end = off + ln
        if typ == 256 and ln >= 20:                          # IPCTNL_MSG_CT_NEW
            src = dst = sp = dp = pn = None
            co = cr = (0, 0)
            a = off + 20
            while a + 4 <= end:
                al, t = nla(buf, a)
                if al < 4:
                    break
                t &= 0x3FFF
                if t == CTA_TUPLE_ORIG:
                    b, e2 = a + 4, a + al
                    while b + 4 <= e2:
                        bl, t2 = nla(buf, b)
                        t2 &= 0x3FFF
                        c, e3 = b + 4, b + bl
                        if t2 == 1:                          # CTA_TUPLE_IP
                            while c + 4 <= e3:
                                cl, t3 = nla(buf, c)
                                t3 &= 0x3FFF
                                if t3 == 1:
                                    src = _inet_ntoa(buf[c + 4:c + 8])
                                elif t3 == 2:
                                    dst = _inet_ntoa(buf[c + 4:c + 8])
                                elif t3 == 3:
                                    src = _inet_ntop(_AF6, buf[c + 4:c + 20])
                                elif t3 == 4:
                                    dst = _inet_ntop(_AF6, buf[c + 4:c + 20])
                                c += (cl + 3) & ~3
                        elif t2 == 2:                        # CTA_TUPLE_PROTO
                            while c + 4 <= e3:
                                cl, t3 = nla(buf, c)
                                t3 &= 0x3FFF
                                if t3 == 1:
                                    pn = buf[c + 4]
                                elif t3 == 2:
                                    sp = _U16.unpack_from(buf, c + 4)[0]
                                elif t3 == 3:
                                    dp = _U16.unpack_from(buf, c + 4)[0]
                                c += (cl + 3) & ~3
                        if bl < 4:
                            break
                        b += (bl + 3) & ~3
                    if pn != 6 and pn != 17:
                        break                                # icmp & co: no counters wanted
                elif t == CTA_COUNTERS_ORIG or t == CTA_COUNTERS_REPLY:
                    pk = by = 0
                    b, e2 = a + 4, a + al
                    while b + 4 <= e2:
                        bl, t2 = nla(buf, b)
                        t2 &= 0x3FFF
                        if t2 == 1:
                            pk = _Q.unpack_from(buf, b + 4)[0]
                        elif t2 == 2:
                            by = _Q.unpack_from(buf, b + 4)[0]
                        b += (bl + 3) & ~3
                    if t == CTA_COUNTERS_ORIG:
                        co = (pk, by)
                    else:
                        cr = (pk, by)
                        break                                # CTA_COUNTERS_REPLY is the last attribute we need
                a += (al + 3) & ~3
            if (pn == 6 or pn == 17) and src and dst and sp is not None and dp is not None:
                yield ("tcp" if pn == 6 else "udp", src, sp, dst, dp, co[0], co[1], cr[0], cr[1])
        off += (ln + 3) & ~3


def ct_entry_t(pn, src, sp, dst, dp, p_o, b_o, p_r, b_r):
    """parsed tuple -> (LAN-first key, counters): the orientation rule of ct_entry() for ctnetlink entries"""
    if not is_lan(src) and is_lan(dst):
        return (pn, dst, dp, src, sp), (b_r, b_o, p_r, p_o)
    return (pn, src, sp, dst, dp), (b_o, b_r, p_o, p_r)


def ct_dump_netlink():
    """{key: (up_b, dn_b, up_p, dn_p)} of every tcp/udp conntrack entry, read in-process"""
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
    out = {}
    try:
        s.settimeout(2.0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
        s.send(ct_request())
        while True:
            buf = s.recv(1 << 17)
            for ent in parse_ct_dump(buf):
                k, c = ct_entry_t(*ent)
                out[k] = c
            # the dump ends with NLMSG_DONE (3) (or an error message (2))
            o, last = 0, None
            while o + 16 <= len(buf):
                ln, last = struct.unpack_from("IH", buf, o)
                if ln < 16:
                    break
                o += (ln + 3) & ~3
            if last in (2, 3) or not buf:
                return out
    finally:
        s.close()


# many concurrent bulk flows: lower the shaped-rate ceiling (see Ctl.many_flows_cap and policy.many_flows_margin)
MANY_FLOWS_N = int(os.environ.get("HALO_MANY_FLOWS_N", policy.MANY_FLOWS_N))
MANY_FLOWS_MARGIN = float(os.environ.get("HALO_MANY_FLOWS_MARGIN", policy.MANY_FLOWS_MARGIN))
HEUR_SIZE_ACTS = os.environ.get("HALO_HEUR_SIZE_ACTS") == "1"     # diagnostics: act on the elephant (size) verdict
NEED_BINS = max(HORIZONS) + 1      # baseline poll + bins for the largest classification horizon
# At saturation the native sentinel probes on every calm tick, and immediately starts fast probing when it sees
# a capacity-loss signal. Keep full-rate saturation monitoring on the Python fallback, which lacks this native path.
SAT_FRAC = float(os.environ.get("HALO_SAT_FRAC", "0.9"))
GUARD_POLL_S = 5.0                 # otherwise dump only for the demote-on-behaviour / per-host rate guard


def background_thread():
    """classification/observation threads are best-effort work: SCHED_IDLE never delays packet forwarding (ksoftirqd)
    or the 10 Hz rate loop; child processes (conntrack) inherit it."""
    try:
        os.sched_setscheduler(0, os.SCHED_IDLE, os.sched_param(0))
    except (AttributeError, OSError, PermissionError):
        pass


RATE_LOOP_NICE = -5


def name_thread(name):
    """kernel thread name (/proc/<pid>/task/<tid>/comm), so per-thread CPU is attributable; best effort"""
    try:
        import ctypes
        ctypes.CDLL(None).prctl(15, name.encode()[:15], 0, 0, 0)
    except Exception:
        pass


def rate_loop_thread():
    """the 10 Hz rate loop and the 20 Hz OWD prober are the control path of the shaper: a few ms of CPU per second, but
    when the emulated gateway is CPU-saturated (iperf + softirq) a nice-10 loop was seen to stall for 1-3 s between
    ticks (S2 telemetry: p99 tick gap 1.3 s, max 3.5 s), delaying the capacity-drop reaction by seconds. Only these
    two threads are raised (nice is per thread on Linux); classification and conntrack stay SCHED_IDLE."""
    try:
        os.setpriority(os.PRIO_PROCESS, 0, RATE_LOOP_NICE)
    except (AttributeError, OSError, PermissionError):
        pass


def boost_priority(nice=-10):
    """raise the CALLING THREAD (and the children it forks) above the data-plane load; used on the rollback path.
    Returns the previous nice value, or None if not permitted."""
    try:
        old = os.getpriority(os.PRIO_PROCESS, 0)
        os.setpriority(os.PRIO_PROCESS, 0, nice)
        return old
    except (AttributeError, OSError, PermissionError):
        return None


def restore_priority(old):
    if old is not None:
        try:
            os.setpriority(os.PRIO_PROCESS, 0, old)
        except (AttributeError, OSError, PermissionError):
            pass


class Ctl:
    def __init__(self, a):
        self.a = a
        os.makedirs(STATE_DIR, exist_ok=True)
        os.makedirs(a.out, exist_ok=True)
        self.ev = open(os.path.join(a.out, "events.jsonl"), "a", buffering=1)
        self.tel = open(os.path.join(a.out, "telemetry.csv"), "w", buffering=1 << 16)
        self.tel.write("t,r_dl,r_ul,c_dl,c_ul,st_dl,st_ul,ach_dl,ach_ul,d_dl,d_ul,bloat_dl,bloat_ul,fsm\n")
        self.lim = policy.Limits(r_min_dl=a.rmin_dl, r_max_dl=a.plan_dl, r_min_ul=a.rmin_ul, r_max_ul=a.plan_ul)
        self.enf = Enforcer()
        r_dl, r_ul = 0.95 * a.plan_dl, 0.95 * a.plan_ul
        self.enf.install(r_dl, r_ul, marks=True)
        self.est = {
            "dl": DirEstimator(EstParams(r_min=a.rmin_dl, r_max=r_dl), rate=r_dl, behind=True),       # never above 95 % of plan
            "ul": DirEstimator(EstParams(r_min=a.rmin_ul, r_max=r_ul), rate=r_ul, behind=False)}
        self.dev = {"dl": LAN, "ul": WAN}
        self.autorate = a.autorate
        self.promote_p = a.promote_p
        self.fsm = "STEADY"
        self.probes = deque(maxlen=4000)          # (t, d_ul, d_dl, lost)
        self.pending = {}
        self.flows, self.flock = {}, threading.Lock()
        self.model = Model(a.model) if a.classifier == "ml" else None
        self.raw = open(os.path.join(a.out, "raw_flows.jsonl"), "a", buffering=1) if a.collect else None
        self.last_action = {"dl": 0.0, "ul": 0.0}
        self.rollbacks = deque(maxlen=16)
        self.txn = None
        self.stop = False
        self.gov = ProbeGovernor(a.probe_hz, getattr(a, "quiet_probe_hz", a.probe_hz), a.tick,
                                 getattr(a, "quiet_tick", a.tick), t0=time.time())
        self.kick = threading.Event()              # prober -> rate loop: act now (delay evidence), do not wait out the quiet tick
        self._pwake = socket.socketpair()          # rate loop -> prober: the full rate starts now
        self._pwake[0].setblocking(False)
        self._pwake[1].setblocking(False)
        self._burst = False
        self.sent = None                           # in-process C calm-mode sentinel (halo/sentinel.py), None = pure-Python calm path
        self._mwake = socket.socketpair()          # SIGUSR1 -> main loop: leave the sentinel wait (new transaction request / override)
        self._mwake[0].setblocking(False)
        self._mwake[1].setblocking(False)
        self.n_sent_alerts = {}
        self.cpu_poll = 0.0                        # ... of which the conntrack poll (slow loop)
        self.cpu_slow = 0.0                        # thread CPU seconds of the slow loop (diagnostic, in the gov event)
        self.n_slow = self.n_slow_poll = 0
        self.n_probe = self.n_tick_fast = self.n_tick = 0
        self._seq = itertools.count()
        self._rr = 0
        self.socks = []
        self._calm_sent = 0.0
        self.wake = threading.Event()              # set by SIGUSR1 (API override) -> the slow loop classifies at once
        self._ovr_cache = (None, {})
        self._flows_json = (0.0, None)
        self.host_rate = {}
        self.event("start", mode=vars(a))
        self.event("commit", lkg=self.enf.commit(self.params()), why="initial")

    def params(self):
        return {"autorate": self.autorate, "promote_p": self.promote_p, "tin_mode": "diffserv4"}

    def event(self, kind, **kw):
        kw.update(t=round(time.time(), 4), kind=kind)
        self.ev.write(json.dumps(kw) + "\n")

    # ---------------------------------------------------------------- prober (M3 input)
    def send_probe(self, i):
        """one OWD probe to reflector i; callable from the prober thread (full rate / bursts) and from the rate loop (the
        calm-mode probe rides on its tick, so a calm second costs one wakeup less)"""
        ts, seq = time.time(), next(self._seq)
        try:
            self.socks[i].send(struct.pack("!IId", 0x48414C4F, seq, ts))
            self.pending[seq] = (ts, i)
            self.n_probe += 1
        except (OSError, IndexError):
            pass

    def prober(self):
        """OWD prober. Full rate (--probe-hz, one probe per reflector in turn) whenever the governor says the link is not
        calm; in calm mode the rate loop sends the (--quiet-probe-hz) probes and this thread only receives. One selector
        over all reflector sockets + a wake pipe; no per-probe polling."""
        rate_loop_thread()
        name_thread("halo-prober")
        a, gov = self.a, self.gov
        socks = []
        for r in a.reflectors:
            s = socket.socket(socket.AF_INET6 if ":" in r else socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((r, 7000)); s.setblocking(False)
            s.setsockopt(socket.SOL_SOCKET, 35, 1)        # kernel RX timestamps (SO_TIMESTAMPNS)
            socks.append(s)
        self.socks = socks
        idx = {s: i for i, s in enumerate(socks)}
        wake_r = self._pwake[0]
        watch = socks + [wake_r]
        nxt = time.time()
        thresh = self.est["dl"].p.thresh_ms
        while not self.stop:
            t = time.time()
            burst = self._burst
            quiet = not gov.is_fast(t)
            if burst or (not quiet and t >= nxt):
                self._burst = False
                for i in (range(len(socks)) if burst else (self._rr % len(socks),)):
                    self.send_probe(i)
                if not burst:
                    self._rr += 1
                t = time.time()
                per = gov.probe_period(t)
                nxt = nxt + per if (not burst and t - nxt < per) else t + per
            # sleep until the next send (full rate) or the next pending probe turns late (0.4 s) / lost (1 s); in calm mode
            # there is no send to wait for (the rate loop sends), only a wake-up for the next governor change
            wake_at = nxt if not quiet else t + 5.0
            for v in tuple(self.pending.values()):
                wake_at = min(wake_at, v[0] + (1.0 if len(v) == 3 else 0.4) + 0.001)
            to = wake_at - time.time()
            ready = select.select(watch, [], [], to)[0] if to > 0 else []
            for s in ready:
                if s is wake_r:
                    try:
                        wake_r.recv(64)
                    except OSError:
                        pass
                    nxt = min(nxt, time.time())
                    continue
                try:
                    d, anc, _, _ = s.recvmsg(64, 64)
                except OSError:
                    continue
                tr = time.time()
                for lvl, typ, cd in anc:
                    if lvl == socket.SOL_SOCKET and typ == 35:
                        sec, nsec = struct.unpack("ll", cd[:16]); tr = sec + nsec * 1e-9
                _, sq, ts, tref = struct.unpack("!IIdd", d[:24])
                if self.pending.pop(sq, None) is None:   # unknown or already expired
                    continue
                ri = idx[s]
                up, dn = (tref - ts) * 1e3, (tr - tref) * 1e3
                self.est["ul"].on_probe(ri, up, tr)
                self.est["dl"].on_probe(ri, dn, tr)
                self.probes.append((tr, self.est["ul"].last_delta, self.est["dl"].last_delta, 0))
                act = gov.sample(time.time(), max(self.est["ul"].last_delta, self.est["dl"].last_delta) > thresh)
                if act == "burst":
                    self._burst = True
                    nxt = time.time()
                elif act == "fast":
                    nxt = min(nxt, time.time())
                    self.kick.set()
            t = time.time()
            for sq, v in tuple(self.pending.items()):
                age = t - v[0]
                if age > 1.0:
                    self.pending.pop(sq, None)
                    self.probes.append((t, float("nan"), float("nan"), 1))
                    gov.late(t)
                elif age > 0.4 and len(v) == 2:
                    # late reply: attribute the extra delay to the direction that currently shows the larger queue
                    d = "dl" if self.est["dl"].last_delta >= self.est["ul"].last_delta else "ul"
                    self.est[d].on_late(t, age * 1e3)
                    self.pending[sq] = v + (True,)
                    if not gov.is_fast(t):
                        nxt = min(nxt, t)
                        self.kick.set()
                    gov.late(t)

    def _on_usr1(self, *_):
        self.wake.set()                                      # slow loop: classify now
        try:
            self._mwake[1].send(b"x")                        # main loop: leave the sentinel wait (maybe a txn request)
        except OSError:
            pass

    def nudge_prober(self):
        """tell the prober the governor changed (full rate now): its sleep may be up to 1/quiet_hz long"""
        if self.sent is not None:
            return                                  # the C thread owns the probing
        self._burst = True                          # and one probe to every reflector, for a quick delay vote
        try:
            self._pwake[1].send(b"x")
        except OSError:
            pass

    # ---------------------------------------------------------------- sniffer (M1)
    def sniffer(self):
        """headers only: the kernel mirrors just the first packets of each flow to mon0;
        at most 96 bytes are read and only L2-L4 header fields are parsed."""
        background_thread()
        name_thread("halo-sniffer")
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        s.bind((MON, 0))
        s.setsockopt(socket.SOL_SOCKET, 35, 1)            # SO_TIMESTAMPNS
        while not self.stop:
            try:
                d, anc, _, _ = s.recvmsg(96, 64)
            except OSError:
                continue
            t = time.time()
            for lvl, typ, cd in anc:
                if lvl == socket.SOL_SOCKET and typ == 35:
                    sec, ns = struct.unpack("ll", cd[:16]); t = sec + ns * 1e-9
            et = d[12:14]
            if et == b"\x08\x00":
                ihl = (d[14] & 15) * 4
                proto, ttl, size = d[23], d[22], struct.unpack("!H", d[16:18])[0]
                src, dst = socket.inet_ntoa(d[26:30]), socket.inet_ntoa(d[30:34])
                l4 = 14 + ihl
            elif et == b"\x86\xdd":
                proto, ttl, size = d[20], d[21], struct.unpack("!H", d[18:20])[0] + 40
                src, dst = socket.inet_ntop(socket.AF_INET6, d[22:38]), socket.inet_ntop(socket.AF_INET6, d[38:54])
                l4 = 54
            else:
                continue
            if proto not in (6, 17) or len(d) < l4 + 4:
                continue
            sp, dp = struct.unpack("!HH", d[l4:l4 + 4])
            pn = "tcp" if proto == 6 else "udp"
            up = src.startswith(LAN4) or src.startswith(LAN6)
            key = (pn, src, sp, dst, dp) if up else (pn, dst, dp, src, sp)
            with self.flock:
                f = self.flows.get(key)
                if f is None:
                    self.wake.set()                           # classify the new flow at once (the slow loop may be idling)
                    f = self.flows[key] = {"key": key, "proto": pn, "pkts": [], "t0": t, "bins": [], "ct": None,
                                           "tot": (0, 0), "cls": "other", "p": 0.0, "abstain": True, "stage": 0,
                                           "tin": 2, "done_h": 0, "seen": t, "ovr": None, "t_tin": t}
                if len(f["pkts"]) < 2 * N1:
                    f["pkts"].append((t, size if up else -size, ttl))

    # ---------------------------------------------------------------- conntrack accounting (M1)
    def poll_conntrack(self, now):
        # direct exec (no shell): one process per dump. A dump walks the whole conntrack table under the kernel's
        # bucket locks, which competes with packet forwarding (A/B in S3: game p99 22-38 ms with 1 s dumps vs 9-12 ms
        # without), so the slow loop only dumps every second while some flow still needs classification bins.
        seen = None
        sent = getattr(self, "sent", None)
        if sent is not None and subprocess is _REAL_SUBPROCESS and _enf_mod._fast_ok() and not getattr(self, "_ct_c_broken", False):
            try:                                             # dump + parse + match in C (the Python parser walks every entry)
                with self.flock:
                    keys = list(self.flows)
                seen = sent.ct_dump(keys)
            except OSError as e:
                self._ct_c_broken = True
                self.event("sentinel", msg="C conntrack dump unavailable (%s): Python parser" % e)
        if seen is None and subprocess is _REAL_SUBPROCESS and _enf_mod._fast_ok() and not getattr(self, "_ct_nl_broken", False):
            try:
                seen = ct_dump_netlink()
            except (OSError, struct.error):
                self._ct_nl_broken = True                    # no ctnetlink here: use the exec path from now on
        if seen is None:
            out = subprocess.run(["conntrack", "-L", "-o", "extended"], capture_output=True, text=True).stdout
            seen = {}
            for line in out.splitlines():
                m = CT_RE.match(line)
                if m:
                    k, c = ct_entry(m)
                    seen[k] = c
        now = time.time()
        host = {}
        with self.flock:
            for key, f in self.flows.items():
                c = seen.get(key)
                if c is None:
                    continue
                if f["ct"] is not None:
                    pt, pc = f["ct"]
                    d = (now - pt, c[0] - pc[0], c[1] - pc[1], c[2] - pc[2], c[3] - pc[3])
                    if len(f["bins"]) < 8:
                        f["bins"].append(d)
                    f["rate"] = (d[1] * 8 / d[0] / 1e6, d[2] * 8 / d[0] / 1e6)
                    if d[1] or d[2]:
                        f["seen"] = now
                    host[key[1]] = host.get(key[1], 0.0) + f["rate"][1]
                f["ct"], f["tot"] = (now, c), (c[0], c[1])
        self.host_rate = host

    # ---------------------------------------------------------------- classification + marks (M2 -> M5 -> M6)
    def classify(self, now):
        a, lines, dump = self.a, [], []
        ovr = {}
        try:
            fn = os.path.join(STATE_DIR, "overrides.json")
            st = os.stat(fn)
            sig = (st.st_mtime_ns, st.st_size)
            if self._ovr_cache[0] != sig:                    # re-parse only when the API rewrote it
                self._ovr_cache = (sig, json.load(open(fn)))
            ovr = self._ovr_cache[1]
        except Exception:
            self._ovr_cache = (None, {})
        with self.flock:
            items = list(self.flows.items())
        voice = []
        for key, f in items:
            age = now - f["t0"]
            if now - f["seen"] > 30:
                with self.flock:
                    self.flows.pop(key, None)
                continue
            old = (f["cls"], f["tin"])
            o = ovr.get("|".join(map(str, key))) or ovr.get(key[1])
            if o and o["until"] > now:
                f.update(cls=o["cls"], p=1.0, abstain=False, stage=9, ovr=o["cls"])
            elif a.classifier == "heur":
                c, p, ab = heuristic(f)
                if c == "bulk" and f["key"][4] not in BULK_PORTS and not HEUR_SIZE_ACTS:
                    # a cumulative-size verdict alone is advisory: paced streaming (DASH/TV) crosses any byte threshold
                    # and, demoted into CAKE's Bulk tin (rate/16 -> multi-10 ms standing queue), it raised the
                    # co-located game flow's p99 by ~20 ms (S3 C3 4/4 reps; r41 without the demotion: 17.7 ms).
                    # The size verdict is ignored here; HALO_HEUR_SIZE_ACTS=1 restores the old act. (Merged scheme: the
                    # Bulk tin is entered only by an explicit operator override - policy.tin_for AUTO_BULK_TIN=False -
                    # so even a port-rule bulk verdict is reported but stays in Best Effort.)
                    c, p, ab = "other", 0.5, True
                f.update(cls=c, p=p, abstain=ab, stage=1)
            elif a.classifier == "ml":
                try:
                    if f["stage"] == 0 and (len(f["pkts"]) >= N1 or age > 1.0) and len(f["pkts"]) >= 2:
                        c, p, _ = self.model.predict1(f)
                        f.update(cls=c, p=p, abstain=p < self.promote_p, stage=1)
                    for h in HORIZONS:
                        if f["done_h"] < h and len(f["bins"]) >= h:
                            c, p, _ = self.model.predict2(f, h)
                            if p >= self.promote_p or h == HORIZONS[-1]:
                                f.update(cls=c, p=p, abstain=p < self.promote_p, stage=2)
                            f["done_h"] = h
                except Exception as e:                       # model failure -> stay Best Effort
                    self.event("classifier_error", err=str(e))
            if self.raw is not None and f.get("dumped") is None and (
                    len(f["bins"]) >= HORIZONS[-1] or (len(f["bins"]) >= 2 and now - f["seen"] > 3)):
                f["dumped"] = 1
                self.raw.write(json.dumps({"key": key, "proto": f["proto"], "t0": f["t0"], "pkts": f["pkts"], "bins": f["bins"]}) + "\n")
            tin = policy.tin_for(f["cls"], f["p"], f["abstain"], self.promote_p, explicit=f["ovr"] is not None)
            # demote-on-behaviour guard: an "interactive" flow that behaves like bulk loses its promotion
            if tin == 4 and f["ovr"] is None:
                f["viol"] = f.get("viol", 0) + 1 if f.get("rate", (0, 0))[1] > a.voice_envelope else 0
                if f["viol"] >= 2 and not f.get("demoted"):
                    f["demoted"] = True
                    self.event("demote_on_behaviour", key=key, rate=f["rate"][1])
            if f.get("demoted") and tin == 4:
                tin = 2
            if tin == 4:
                f.setdefault("t_voice", now)
                voice.append((key, f.get("rate", (0, 0))[1], f["t_voice"]))
                if f.get("capdem"):                          # shield voice-cap demotion in force (see below)
                    tin = 2
                elif f.get("vid"):                           # drain in progress: promoted flows ride in Video (voice_to_video)
                    tin = 3
            if tin != f["tin"]:
                f["t_tin"] = now
            f["tin"] = tin
            if a.classifier != "none" and (old != (f["cls"], tin) or now - f.get("t_mark", 0) > 10):
                if tin != 2 or f.get("t_mark"):
                    if f.get("t_mark") and now - f["t_mark"] < 25:
                        lines.append(Enforcer.flow_delete(key))        # map elements are replaced, not updated
                    lines.append(Enforcer.flow_element(key, tin))
                    f["t_mark"] = now
                if old != (f["cls"], tin):
                    self.event("classify", key=key, cls=f["cls"], p=round(f["p"], 3), abstain=f["abstain"], tin=tin,
                               stage=f["stage"], age=round(age, 2))
            dump.append({"key": key, "cls": f["cls"], "p": round(f["p"], 3), "abstain": f["abstain"], "tin": policy.TIN_NAME[tin],
                         "stage": f["stage"], "override": f["ovr"], "rate_dn": round(f.get("rate", (0, 0))[1], 3),
                         "model": getattr(self.model, "version", a.classifier)})
        # shield invariant: promoted (Voice-tin) load <= 25 % of the shaped rate
        # The cap is judged against the shaped rate, which a congestion episode cuts to ~30 % of capacity for about a second
        # (S2: 3.1 Mbit -> cap 0.78 Mbit < a 1.5 Mbit call). A permanent demotion on that transient put the call into Best
        # Effort with the bulk flows (call p95 +470 ms, T_adapt 2.4 s). So: demote only after the budget has been exceeded for
        # VOICE_CAP_GRACE_S continuously, and re-promote as soon as it is met again (hysteresis, not a one-way latch).
        # active TCP flows: seen within one conntrack poll period (GUARD_POLL_S + 1.5 s); a flow older than that must also
        # have moved bytes at the last poll. Young flows count at once (the sniffer sees them), so a 32-flow load is
        # recognised within the first second instead of after the first rate poll.
        # A flow has no rate until its SECOND conntrack poll (a delta needs two samples), i.e. up to 2 x GUARD_POLL_S after it
        # appeared; with the event-driven slow loop (polls every GUARD_POLL_S, not every second) it would drop out of the count
        # between age 5 s and its second poll (S1x32: n 33 -> 0 -> 32, the M3 ceiling released for ~1 s). Until it has been
        # measured it counts as active for 2 polls + margin.
        self.n_bulk = sum(1 for _, f in items if f["proto"] == "tcp" and (
            (now - f["t0"] < 2 * GUARD_POLL_S + 1.5) if "rate" not in f else
            (now - f["seen"] < GUARD_POLL_S + 1.5 and f["rate"][1] > 0.02)))
        self.voice_dl = sum(m for k, m, _ in voice if not (self.flows.get(k) or {}).get("capdem"))   # promoted load, Mbit/s
        keep, demote = policy.admit_voice(voice, self.est["dl"].rate, self.lim)
        for key in keep:
            f = self.flows.get(key)
            if f is not None:
                f["over_since"] = None
                if f.get("capdem"):
                    f["capdem"] = False
                    self.event("voice_cap_restored", key=key)
        for key in demote:
            f = self.flows.get(key)
            if f is None or f.get("capdem"):
                continue
            if f.get("vid"):                                 # transient low rate of a drain: not a sustained overshoot
                f["over_since"] = None
                continue
            if f.get("over_since") is None:
                f["over_since"] = now
            elif now - f["over_since"] >= policy.VOICE_CAP_GRACE_S:
                f["capdem"] = True
                self.event("shield_voice_cap", key=key)
        if lines:
            try:
                self.enf.nft_batch(lines)
            except Exception as e:
                self.event("nft_error", err=str(e)[:200])
        # /v1/flows snapshot: rewritten when a classification changed, otherwise at most every 3 s
        sig = [(d["key"], d["cls"], d["tin"], d["override"]) for d in dump]
        if lines or sig != self._flows_json[1] or now - self._flows_json[0] >= 3.0:
            with open(os.path.join(STATE_DIR, "flows.json.tmp"), "w") as fj:
                fj.write(json.dumps({"t": now, "flows": dump}))      # dumps (C encoder), not dump (pure-Python chunked encoder)
            os.replace(os.path.join(STATE_DIR, "flows.json.tmp"), os.path.join(STATE_DIR, "flows.json"))
            self._flows_json = (now, sig)

    def many_flows_cap(self, now):
        """lower/restore the ceiling of the download rate with the number of concurrent active TCP flows (hysteresis).
        Many flows each hold >= 2 packets in flight: 32 flows offer ~2x a 20 Mbit link within one base RTT, so the sum of
        their windows overshoots the modem (which sits UPSTREAM of the shaper) in bursts and fills its FIFO; every real-time
        packet then waits in that FIFO (S1x32: call p99 +17..43 ms, 6 flows: +9 ms). More headroom between the shaped rate
        and the line rate keeps the burst inside the shaper's queue, where the call has its own tin."""
        e = self.est["dl"]
        base = 0.95 * self.a.plan_dl
        n = getattr(self, "n_bulk", 0)
        on = getattr(self, "many_on", False)
        if not on and n >= MANY_FLOWS_N:
            on = True
        elif on and n < MANY_FLOWS_N * 0.75 and now - getattr(self, "many_t", 0.0) > 4.0:
            on = False
        if on and n >= MANY_FLOWS_N * 0.75:
            self.many_t = now
        if on == getattr(self, "many_on", False) or e.state == "DRAIN":
            return
        self.many_on = on
        newmax = base * (MANY_FLOWS_MARGIN if on else 1.0)
        e.p.r_max = newmax
        self.event("many_flows", on=on, n=n, r_max=round(newmax, 3))
        if e.rate > newmax * 1.001:
            old = e.rate
            v = policy.shield_rate(newmax, old, self.lim.r_min_dl, self.lim.r_max_dl, self.lim, True, 1e9)
            e.rate = v.value
            try:
                self.enf.set_rate(self.dev["dl"], v.value)
            except Exception as ex:
                self.event("tc_error", err=str(ex)[:200])
                self.enter_safe("tc_failed")
                return
            self.last_action["dl"] = now
            self.event("rate", dir="dl", old=round(old, 3), new=v.value, why="many_flows", c_est=round(e.c_est, 3),
                       ach=0.0, shield=v.reasons)

    def voice_to_video(self, now):
        """start of a congestion drain: move the promoted (Voice) flows to the Video tin. The drain cuts the shaper to
        ~0.3 x capacity; Voice's threshold is 25 % of the shaped rate, Video's 50 %, so a call that fits the Video
        threshold keeps its priority there while a Voice-tin call would be rationed (delay +470 ms, S2). Written to the
        kernel at once from the rate loop (in-process nft, ms); classify() keeps the flag until video_to_voice."""
        lines = []
        with self.flock:
            items = [(k, f) for k, f in self.flows.items() if f["tin"] == 4 and not f.get("capdem")]
        for key, f in items:
            f["vid"], f["tin"], f["t_mark"] = True, 3, now
            lines += [Enforcer.flow_destroy(key), Enforcer.flow_element(key, 3)]
        if lines:
            self.vid_on = True
            try:
                self.enf.nft_batch(lines)
            except Exception as e:
                self.event("nft_error", err=str(e)[:200])
            self.event("voice_to_video", n=len(items))

    def video_to_voice(self, now):
        """the drain is over and the shaped rate fits the call in the Voice tin again: restore the Voice marks"""
        lines = []
        with self.flock:
            items = [(k, f) for k, f in self.flows.items() if f.get("vid")]
        for key, f in items:
            f["vid"] = False
            if f["tin"] == 3 and not f.get("capdem"):
                f["tin"], f["t_mark"] = 4, now
                lines += [Enforcer.flow_destroy(key), Enforcer.flow_element(key, 4)]
        self.vid_on = False
        if lines:
            try:
                self.enf.nft_batch(lines)
            except Exception as e:
                self.event("nft_error", err=str(e)[:200])
        self.event("video_to_voice", n=len(items))

    # ---------------------------------------------------------------- verifier window (M7)
    def window(self, t0, t1, d="dl"):
        idx = 2 if d == "dl" else 1
        s = [p for p in tuple(self.probes) if t0 <= p[0] <= t1]   # atomic snapshot (prober thread appends)
        owd = [max(p[1], p[2]) for p in s if not p[3]]
        lost = sum(p[3] for p in s)
        tp = [x[1] for x in tuple(self.ach_hist) if t0 <= x[0] <= t1]
        return {"owd": owd, "loss": lost / len(s) if s else float("nan"), "tput": sum(tp) / len(tp) if tp else None}

    # ---------------------------------------------------------------- two-phase transaction (M6)
    def start_txn(self, req, now):
        v = policy.shield_policy(req, self.lim)
        if not v.ok:
            self.event("txn_rejected", req=req, reasons=v.reasons)
            return
        cand = {LAN: req.get("rate_dl") or self.enf.rate[LAN], WAN: req.get("rate_ul") or self.enf.rate[WAN]}
        self.fsm = "VERIFYING"
        self.txn = {"stage": "SHADOW", "req": req, "cand": cand, "res": None, "t": now}

        def shadow():
            # SHADOW-CHECK (AFRO-style): apply the candidate in a scratch namespace and read it back first
            sc = ("unshare -n sh -c 'ip link add lan0 type dummy && tc qdisc replace dev lan0 root cake bandwidth %dkbit %s "
                  "&& tc -j qdisc show dev lan0 root'" % (int(cand[LAN] * 1000), Enforcer.DL_OPTS))
            r = subprocess.run(sc, shell=True, capture_output=True, text=True)
            self.txn["res"] = (r.returncode == 0 and '"cake"' in r.stdout, r.stderr[-120:])
        threading.Thread(target=shadow, daemon=True).start()

    def apply_txn(self, now):
        x = self.txn
        req, cand = x["req"], x["cand"]
        if not x["res"][0]:
            self.event("txn_rejected", req=req, reasons=["shadow_check_failed", x["res"][1]])
            self.txn, self.fsm = None, "STEADY"
            return
        pre = self.window(now - self.a.health_s, now)
        self.event("txn_prepare", req=req, lkg=self.enf.lkg["hash"], shadow_check="ok",
                   pre={k: (len(v) if k == "owd" else v) for k, v in pre.items()})
        saved = (self.autorate, self.promote_p)
        try:
            for d in (LAN, WAN):
                if abs(cand[d] - self.enf.rate[d]) > 1e-6:
                    self.enf.set_rate(d, cand[d])
            if "autorate" in req:
                self.autorate = bool(req["autorate"])
            if req.get("promote_p") is not None:
                self.promote_p = float(req["promote_p"])
            bad = self.enf.verify_applied(cand)
        except Exception as e:
            bad = [("apply", str(e)[:120])]
        self.est["dl"].rate, self.est["ul"].rate = self.enf.rate[LAN], self.enf.rate[WAN]
        self.event("txn_applied", readback_mismatch=bad)
        x.update(stage="HEALTH", t=time.time(), pre=pre, saved=saved, bad=bad)

    def finish_txn(self, now):
        x = self.txn
        if x["stage"] == "SHADOW":
            if x["res"] is not None:
                self.apply_txn(now)
            return
        if not x["bad"] and now - x["t"] < self.a.health_s:
            # early exit: probe blackout or severe regression is visible long before the window ends
            if now - x["t"] < 1.5:
                return
            post = self.window(x["t"] + 0.3, now)
            v, info = verifier.verdict(x["pre"], post)
            if v != "REGRESSED":
                return
        else:
            post = self.window(x["t"] + 0.3, now)
            v, info = ("REGRESSED", {"reason": "readback"}) if x["bad"] else verifier.verdict(x["pre"], post)
        self.txn = None
        if v == "REGRESSED":
            t0 = time.time()
            self.autorate, self.promote_p = x["saved"]
            prio = boost_priority(-10)                      # the restore path outranks the data-plane load (nice 0)
            with open(os.path.join(STATE_DIR, "heartbeat"), "w") as f:
                f.write("%.3f ROLLBACK" % now)
            try:
                ok, dt, lkg = self.enf.rollback()           # prebuilt LKG: one rtnetlink change per direction + read-back
            finally:
                restore_priority(prio)
            self.est["dl"].rate, self.est["ul"].rate = self.enf.rate[LAN], self.enf.rate[WAN]
            self.rollbacks.append(now)
            self.event("rollback", verdict=v, info=info, ok=ok, rollback_s=round(time.time() - t0, 3), lkg=lkg["hash"],
                       detect_s=round(t0 - x["t"], 3))
            if not ok:
                self.enter_safe("rollback_failed")
            elif sum(1 for r in self.rollbacks if now - r < 600) > 3:
                self.fsm = "DEGRADED"                        # freeze at LKG
                self.autorate = False
                self.event("degraded", why=">3 rollbacks in 10 min")
            else:
                self.fsm = "STEADY"
        else:
            self.event("commit", verdict=v, info=info, lkg=self.enf.commit(self.params()))
            self.fsm = "STEADY"

    def enter_safe(self, why):
        safe_state(self.a.safe_dl, self.a.safe_ul)
        self.fsm, self.autorate = "SAFE", False
        self.event("safe_state", why=why)

    def poll_due(self, t0, last_poll):
        """conntrack accounting cadence: 1 s while a flow still collects the bins its classifier/collector needs
        (ML / --collect); otherwise only every GUARD_POLL_S (cumulative byte counts for the elephant rule, per-host rate
        guard). The heuristic classifier never reads bins, so it no longer forces a 1 Hz dump."""
        if t0 - last_poll >= GUARD_POLL_S:
            return True
        if self.a.classifier == "ml" or self.raw is not None:
            with self.flock:
                return any(len(f["bins"]) < NEED_BINS and t0 - f.get("seen", f["t0"]) < 5.0 for f in self.flows.values())
        return False

    def slow_period(self, t0, last_poll, woken):
        """seconds until the slow loop must run again by itself. 1 s while anything can still change a verdict (a poll just
        landed, a flow is new, a wake-up, ML bins, collection). A settled flow table is event-driven: the only timers left
        are the guard poll (cumulative byte counts for the elephant rule, per-host rate guard: GUARD_POLL_S) and the
        10 s mark refresh; new flows (sniffer) and overrides (SIGUSR1) wake the loop at once."""
        if woken or self.raw is not None:
            return 1.0
        with self.flock:
            if any(t0 - f["t0"] < 3.0 for f in self.flows.values()):
                return 1.0
            if self.a.classifier == "ml" and any(len(f["bins"]) < NEED_BINS and t0 - f.get("seen", f["t0"]) < 5.0
                                                 for f in self.flows.values()):
                return 1.0                                   # bins are 1 s conntrack deltas: a timer by nature
        until = [o.get("until", 0.0) - t0 for o in tuple(self._ovr_cache[1].values()) if isinstance(o, dict)]
        until = [u for u in until if u > 0]                  # an override that is about to expire reverts at once
        return min([GUARD_POLL_S] + [u + 0.05 for u in until])

    def slow_loop(self):
        """observe + classify + mark, off the fast control loop. Runs when a flow is new / an override arrives (wake), every
        second while ML flows still collect bins, otherwise only at the guard poll: a settled table costs no per-second pass"""
        background_thread()
        name_thread("halo-slow")
        no_poll = os.environ.get("HALO_DEBUG_NO_CTPOLL") == "1"     # diagnostics only (A/B of the poll's cost)
        last_poll = 0.0
        while not self.stop:
            t0, c0 = time.time(), time.thread_time()
            woken = self.wake.is_set()
            self.wake.clear()
            try:
                if not no_poll and self.poll_due(t0, last_poll) and not (woken and t0 - last_poll < 0.5):
                    self.poll_conntrack(t0)
                    last_poll = t0
                    self.n_slow_poll += 1
                    self.cpu_poll += time.thread_time() - c0
                self.classify(time.time())
                self.n_slow += 1
            except Exception as e:
                self.event("slow_loop_error", err=repr(e)[:200])
            self.cpu_slow += time.thread_time() - c0
            self.wake.wait(max(0.05, self.slow_period(t0, last_poll, woken) - (time.time() - t0)))

    # ---------------------------------------------------------------- main loop
    def govern(self, now, ach, peak, dt):
        """decide whether the control path must run at the full rate (see halo/probe_gov.py)"""
        gov, hot = self.gov, False
        for d in ("dl", "ul"):
            e = self.est[d]
            peak[d] = decay_peak(peak[d], ach[d], dt)
            if e.state != "STEADY" and not (e.state == "PROBING_UP" and e.rate >= 0.999 * e.p.r_max):
                hot = True                                   # INIT / DEGRADED / DRAIN / still climbing
            elif e.bloat(now) or now - self.last_action[d] < 3.0:
                hot = True
            elif (e.rate < 0.999 * e.p.r_max and ach[d] >= 0.9 * e.p.load_thresh * e.rate
                  and now >= e.t_hold_until - 0.5):
                hot = True                                   # about to probe upwards
            elif collapsed(ach[d], e.rate, peak[d], e.p.collapse):
                hot = True                                   # the arrival rate fell away: possible capacity loss
            elif self.sent is None and SAT_FRAC > 0 and ach[d] >= SAT_FRAC * e.rate:
                hot = True                                   # fallback saturation monitoring
        if self.txn is not None or self.fsm == "VERIFYING":
            hot = True               # (fsm "ADAPTING" is sticky after a rate change and is covered by the estimator states)
        if hot:
            was_quiet = not gov.is_fast(now)
            gov.force(now)
            if was_quiet:
                self.nudge_prober()

    # ---------------------------------------------------------------- in-process C sentinel (calm mode)
    def sent_params(self, now, ach, peak):
        """calm-mode inputs for the C thread: the same thresholds the Python governor / estimators use"""
        g, e1, e2 = self.gov, self.est["dl"], self.est["ul"]
        p = _sentinel.Params()
        p.tick_s, p.probe_s, p.thresh_ms, p.late_s = g.quiet_tick, 1.0 / g.quiet_hz, e1.p.thresh_ms, 0.4
        p.confirm_win, p.confirm_n, p.base_alpha, p.peak_tau = CONFIRM_WIN, CONFIRM_N, e1.p.base_alpha, 2.0
        p.gate_s, p.ewma_alpha_ref, p.ewma_dt_ref = _sentinel.GATE_S, 0.6, 0.1
        p.load_thresh, p.collapse, p.rr = e1.p.load_thresh, e1.p.collapse, self._rr
        p.sat_frac = SAT_FRAC
        for i, (d, e) in enumerate((("dl", e1), ("ul", e2))):
            p.rate[i], p.rmax[i], p.c_est[i], p.hold_until[i] = e.rate, e.p.r_max, e.c_est, e.t_hold_until
            p.ach[i], p.peak[i], p.last_delta[i] = ach[d], peak[d], e.last_delta
            p.st[i].value = e.state.encode()[:15]
        for ri, b in e2.base.items():                       # "ul" estimator = sender->reflector direction
            if 0 <= ri < _sentinel.MAXR:
                p.base_ul[ri], p.has_base_ul[ri] = b, 1
        for ri, b in e1.base.items():
            if 0 <= ri < _sentinel.MAXR:
                p.base_dl[ri], p.has_base_dl[ri] = b, 1
        p.fsm = self.fsm.encode()[:15]
        return p

    def sent_collect(self, now, ach, peak, calm=True):
        """replay what the C thread observed since the last call (probe samples -> estimators, ach samples -> histories,
        telemetry text -> file) and return its alert code (0 = none)"""
        sent, gov = self.sent, self.gov
        alert = sent.ack_alert()
        for kind, t, a, b, ri in sent.drain():
            if kind == _sentinel.EV_PROBE:
                self.est["ul"].on_probe(ri, a, t)
                self.est["dl"].on_probe(ri, b, t)
                self.probes.append((t, self.est["ul"].last_delta, self.est["dl"].last_delta, 0))
            elif kind == _sentinel.EV_LOST:
                self.probes.append((t, float("nan"), float("nan"), 1))
                gov.late(t)
            elif kind == _sentinel.EV_ACH:
                self.est["dl"].ach_hist.append((t, a))
                self.est["ul"].ach_hist.append((t, b))
                self.ach_hist.append((t, a))
            elif kind == _sentinel.EV_LATE:
                d = "dl" if self.est["dl"].last_delta >= self.est["ul"].last_delta else "ul"
                self.est[d].on_late(t, a)
                gov.late(t)
            elif kind == _sentinel.EV_BURST:
                gov.n_burst += 1
            elif kind == _sentinel.EV_FAST:
                gov.n_fast += 1
                gov.force(t)
        if not calm:                                         # FAST mode: Python counts bytes and writes telemetry itself
            return alert, None, None
        st = sent.state()
        ach["dl"], ach["ul"], peak["dl"], peak["ul"] = st.ach[0], st.ach[1], st.peak[0], st.peak[1]
        txt = sent.telemetry()
        if txt:
            self.tel.write(txt)
        if alert:
            nm = _sentinel.ALERTS.get(alert, alert)
            self.n_sent_alerts[nm] = self.n_sent_alerts.get(nm, 0) + 1
            self.event("sent_alert", why=nm, ach_dl=round(ach["dl"], 2), ach_ul=round(ach["ul"], 2))
            if alert in (_sentinel.AL_COLLAPSE, _sentinel.AL_PROBEUP):
                gov.force(now)
        return alert, (st.rx, st.tx), st.t_counters

    def sent_failed(self, why):
        """the C thread reported an error: pure-Python path (full-rate prober thread) from now on"""
        self.event("sentinel", msg="%s: pure-Python calm path from now on" % why)
        try:
            self.sent.stop()
        except Exception:
            pass
        self.sent = None
        threading.Thread(target=self.prober, daemon=True).start()

    def run(self):
        rate_loop_thread()
        name_thread("halo-main")
        a = self.a
        if a.classifier != "none" or a.collect:
            threading.Thread(target=self.sniffer, daemon=True).start()
            threading.Thread(target=self.slow_loop, daemon=True).start()
        # persistent fds + pread: the 10 Hz loop does no open/close (sysfs counters, heartbeat) - on the emulated
        # gateway every syscall and every wakeup shows up in the controller's CPU time
        fds = {p: os.open("/sys/class/net/%s/statistics/%s" % (WAN, p), os.O_RDONLY) for p in ("rx_bytes", "tx_bytes")}
        rd = lambda p: int(os.pread(fds[p], 32, 0))
        last_b, last_t = (rd("rx_bytes"), rd("tx_bytes")), time.time()
        with open(os.path.join(STATE_DIR, "ctl.pid"), "w") as f:
            f.write(str(os.getpid()))
        try:
            signal.signal(signal.SIGUSR1, self._on_usr1)
            signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        except ValueError:
            pass
        hb = os.path.join(STATE_DIR, "heartbeat")
        if getattr(a, "sentinel", 0) and self.gov.enabled:
            self.sent = _sentinel.Sentinel.load(a.reflectors, WAN, hb, path=getattr(a, "sentinel_lib", None) or None,
                                                log=lambda m: self.event("sentinel", msg=m))
            if self.sent is not None:
                self.event("sentinel", msg="C calm-mode thread loaded")
        else:
            self.event("sentinel", msg="disabled (--sentinel 0 or adaptive probing off): pure-Python calm path")
        sent, armed = self.sent, False
        if sent is not None:
            sent.set_fast(1.0 / self.gov.fast_hz, 0.4)      # the C thread probes at the full rate until the governor says calm
        else:
            threading.Thread(target=self.prober, daemon=True).start()
        ach = {"dl": 0.0, "ul": 0.0}
        self.ach_hist = deque(maxlen=600)
        self.host_rate = {}
        hb_fd = None
        req_f = os.path.join(STATE_DIR, "txn_request.json")
        t_flush, n_tick, t_gov = 0.0, 0, time.time()
        t_heavy = 0.0
        gov = self.gov
        peak = {"dl": 0.0, "ul": 0.0}
        while not self.stop:
            # event-driven: the tick length follows the governor (a.tick when active, quiet_tick when calm) and a prober
            # alert (kick) ends the wait at once, but never before 50 ms of byte counters have accumulated
            if armed:
                # calm mode: the C thread probes, counts bytes, writes telemetry + heartbeat and watches for the delay /
                # late / collapse / probe-up signals; this thread sleeps until an alert or its sync tick (liveness bump)
                r = select.select([sent.efd, self._mwake[0]], [], [], _sentinel.SYNC_S)[0]
                sent.bump()                                 # liveness: the heartbeat is gated on this counter
                now = time.time()
                if not r and now - t_heavy < _sentinel.HEAVY_S:
                    continue                                # light wake-up: nothing happened, nothing to replay yet
                t_heavy = now
                if self._mwake[0] in r:
                    try:
                        self._mwake[0].recv(64)
                    except OSError:
                        pass
                alert, last_b, last_t = self.sent_collect(now, ach, peak)
                dt = 0.0
                if alert:
                    armed = False                           # the C thread switched itself to full-rate probing
                    if alert == _sentinel.AL_ERROR:
                        self.sent_failed("C thread reported an error")
                        sent = None
                n_tick += 1
            else:
                self.kick.wait(gov.tick_period(time.time()))
                if self.kick.is_set():
                    self.kick.clear()
                    if time.time() - last_t < 0.05:
                        time.sleep(0.05 - (time.time() - last_t))
                now = time.time()
                b = (rd("rx_bytes"), rd("tx_bytes"))
                dt = now - last_t
                inst = {"dl": (b[0] - last_b[0]) * 8 / dt / 1e6, "ul": (b[1] - last_b[1]) * 8 / dt / 1e6}
                last_b, last_t = b, now
                al = ewma_alpha(dt)
                for d in ("dl", "ul"):
                    ach[d] += al * (inst[d] - ach[d])             # ~200 ms EWMA (alpha follows the tick length)
                self.ach_hist.append((now, ach["dl"]))
                n_tick += 1
                if sent is not None:                        # full-rate probe samples of the C thread -> estimators
                    if self.sent_collect(now, ach, peak, calm=False)[0] == _sentinel.AL_ERROR:
                        self.sent_failed("C thread reported an error")
                        sent = None
            if (armed or n_tick % 3 == 0) and os.path.exists(req_f) and self.txn is None and self.fsm in ("STEADY", "ADAPTING"):   # 0.3 s
                try:
                    req = json.load(open(req_f))
                finally:
                    os.remove(req_f)
                self.start_txn(req, now)
            if self.txn is not None:
                self.finish_txn(now)
            if self.autorate and self.txn is None and self.fsm not in ("SAFE", "DEGRADED"):
                self.many_flows_cap(now)
                for d in ("dl", "ul"):
                    e = self.est[d]
                    old = e.rate
                    new, why = e.tick(now, ach[d])
                    if (d == "dl" and getattr(self, "vid_on", False) and e.state != "DRAIN"
                            and e.rate * self.lim.voice_share >= 1.05 * getattr(self, "voice_dl", 0.0)):
                        self.video_to_voice(now)
                    if why in ("bloat_unconfirmed", "burst_at_capacity"):
                        continue
                    if why == "reflectors_lost_hold_rate":
                        self.event("estimator_degraded", dir=d)
                    if new is None:
                        continue
                    emergency = why in ("bloat_fast_down", "drain_refine", "settle_at_margin")
                    lo, hi = (self.lim.r_min_dl, self.lim.r_max_dl) if d == "dl" else (self.lim.r_min_ul, self.lim.r_max_ul)
                    if d == "dl" and why in ("bloat_fast_down", "drain_refine") and getattr(self, "voice_dl", 0.0) > 0:
                        lo = policy.voice_floor(lo, self.voice_dl, e.c_est, self.lim, self.lim.video_share)
                    v = policy.shield_rate(new, old, lo, hi, self.lim, emergency, now - self.last_action[d],
                                          restore_to=new if why == "settle_at_margin" else None,
                                          probe=(why == "slow_up"))
                    if not v.ok:
                        e.rate = old
                        continue
                    e.rate = v.value
                    if (d == "dl" and why in ("bloat_fast_down", "drain_refine") and not getattr(self, "vid_on", False)
                            and getattr(self, "voice_dl", 0.0) > self.lim.voice_share * v.value):
                        self.voice_to_video(now)
                    try:
                        self.enf.set_rate(self.dev[d], v.value)
                    except Exception as ex:
                        self.event("tc_error", err=str(ex)[:200])
                        self.enter_safe("tc_failed")
                        break
                    self.last_action[d] = now
                    self.fsm = "ADAPTING" if e.state in ("DRAIN", "PROBING_UP") else "STEADY"
                    self.event("rate", dir=d, old=round(old, 3), new=v.value, why=why, c_est=round(e.c_est, 3),
                               ach=round(ach[d], 3), shield=v.reasons)
            e1, e2 = self.est["dl"], self.est["ul"]
            if gov.enabled:
                self.govern(now, ach, peak, dt)
            if armed and (gov.is_fast(now) or self.txn is not None):
                sent.set_fast(1.0 / gov.fast_hz, 0.4, True)  # not calm any more: C probes at the full rate (+ one burst)
                armed = False
                _, last_b, last_t = self.sent_collect(now, ach, peak)   # whatever the C thread saw until it switched
            self.n_tick += 1
            self.n_tick_fast += gov.is_fast(now)
            if armed:
                pass
            elif self.socks and not gov.is_fast(now) and now - self._calm_sent >= 1.0 / gov.quiet_hz - 0.5 * gov.quiet_tick:
                self._calm_sent = now                   # calm mode: this tick carries the (low-rate) probe
                self.send_probe(self._rr % len(self.socks))
                self._rr += 1
            if now - t_gov >= 10.0:
                t_gov = now
                self.event("gov", probes=self.n_probe, ticks=self.n_tick, ticks_full=self.n_tick_fast,
                           bursts=gov.n_burst, to_full=gov.n_fast, sentinel=sent is not None, sent_alerts=self.n_sent_alerts,
                           cpu_main=round(time.thread_time(), 2), cpu_slow=round(self.cpu_slow, 2), cpu_poll=round(self.cpu_poll, 2),
                           slow_runs=self.n_slow, slow_polls=self.n_slow_poll,
                           ct_in_c=sent is not None and not getattr(self, "_ct_c_broken", False))
            if not armed:
                self.tel.write("%.3f,%.3f,%.3f,%.3f,%.3f,%s,%s,%.3f,%.3f,%.2f,%.2f,%d,%d,%s\n" % (
                    now, e1.rate, e2.rate, e1.c_est, e2.c_est, e1.state, e2.state, ach["dl"], ach["ul"],
                    e1.last_delta, e2.last_delta, e1.bloat(now), e2.bloat(now), self.fsm))
                msg = ("%.3f %s" % (now, self.fsm)).encode()
                if hb_fd is None:
                    hb_fd = os.open(hb, os.O_WRONLY | os.O_CREAT, 0o644)
                os.pwrite(hb_fd, msg, 0)                   # mtime = liveness (watchdog); content = last tick
                os.ftruncate(hb_fd, len(msg))
            if now - t_flush >= 1.0:                       # telemetry is block-buffered, flushed once a second
                self.tel.flush()
                t_flush = now
            if (sent is not None and not armed and gov.enabled and not self.stop and self.txn is None
                    and self.fsm != "VERIFYING" and not gov.is_fast(time.time())):
                # calm: hand the probing / byte counting / telemetry / heartbeat to the C thread
                sent.arm(self.sent_params(now, ach, peak))
                sent.bump()
                armed, t_heavy = True, time.time()

    def close(self):
        """clean shutdown (SIGTERM -> KeyboardInterrupt in the main loop): stop the C thread (the heartbeat stops with it),
        flush the telemetry"""
        self.stop = True
        if self.sent is not None:
            try:
                self.sent.stop()
            except Exception:
                pass
            self.sent = None
        try:
            self.tel.flush()
        except Exception:
            pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--plan-dl", type=float, default=100.0, dest="plan_dl")
    p.add_argument("--plan-ul", type=float, default=20.0, dest="plan_ul")
    p.add_argument("--rmin-dl", type=float, default=2.0, dest="rmin_dl")
    p.add_argument("--rmin-ul", type=float, default=0.5, dest="rmin_ul")
    p.add_argument("--safe-dl", type=float, default=8.0, dest="safe_dl")
    p.add_argument("--safe-ul", type=float, default=1.6, dest="safe_ul")
    p.add_argument("--autorate", type=int, default=1)
    p.add_argument("--classifier", choices=["none", "heur", "ml"], default="none")
    p.add_argument("--model", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "model.pkl"))
    p.add_argument("--collect", action="store_true")
    p.add_argument("--promote-p", type=float, default=0.9, dest="promote_p")
    p.add_argument("--voice-envelope", type=float, default=6.0, dest="voice_envelope")
    p.add_argument("--reflectors", nargs="+", default=["10.9.0.3", "10.9.0.4", "10.9.0.5", "fd00:9::6"])
    p.add_argument("--probe-hz", type=float, default=20.0, dest="probe_hz")
    p.add_argument("--tick", type=float, default=0.1)
    p.add_argument("--quiet-probe-hz", type=float, default=2.0, dest="quiet_probe_hz",
                   help="probe rate while the link is calm (no delay signal, estimators STEADY); --probe-hz otherwise. "
                        "Set equal to --probe-hz (and --quiet-tick to --tick) to disable adaptive probing")
    p.add_argument("--quiet-tick", type=float, default=0.25, dest="quiet_tick")
    p.add_argument("--sentinel", type=int, default=1, choices=[0, 1],
                   help="1: calm mode runs in the in-process C thread (halo/libhalo_sentinel.so, build with `make`); falls back to the "
                        "pure-Python calm path if the library cannot be loaded. 0: always pure Python")
    p.add_argument("--sentinel-lib", default="", dest="sentinel_lib", help="path of the sentinel shared library (default halo/libhalo_sentinel.so)")
    p.add_argument("--health-s", type=float, default=5.0, dest="health_s")
    p.add_argument("--out", default="/tmp/halo_ctl")
    p.add_argument("--nice", type=int, default=10,
                   help="control plane runs below the data plane (ksoftirqd = nice 0) so it can never starve forwarding")
    a = p.parse_args()
    if a.nice:
        os.nice(a.nice)
    c = Ctl(a)
    try:
        c.run()
    except KeyboardInterrupt:
        pass
    finally:
        c.close()


if __name__ == "__main__":
    main()
