"""M6 - Enforcer: open, inspectable enforcement with Linux tc (CAKE) + nftables.

  download : CAKE on the gateway LAN egress   (lab "Mode L")  - or IFB + act_ctinfo ("Mode P")
  upload   : CAKE on the gateway WAN egress
  tin      : CAKE `fwmark 0x0f` -> 1 Bulk, 2 Best Effort, 3 Video, 4 Voice  (diffserv4)
  marks    : nftables `inet` table (IPv4 + IPv6): per-flow maps written by the classifier,
             per-device override maps, and intent sets whose elements EXPIRE IN THE KERNEL.
Two-phase transaction: checkpoint(LKG) -> apply -> read-back -> health window -> commit | rollback.
`nft -f` is atomic; `tc` is not, so read-back + rollback covers it.
"""
import ctypes, hashlib, json, os, socket, struct, subprocess, threading, time

LAN, WAN, MON, IFB = "lan0", "wan0", "mon0", "ifb4wan0"
STATE_DIR = os.environ.get("HALO_STATE", "/run/halo")
SAMPLE_PKTS = 16                    # headers of the first N packets of each flow go to the observer
# lease boost budget per leased device, kbytes/s: udp (a call needs ~190 kB/s down / 125 up) and everything else
LEASE_UDP_DL, LEASE_UDP_UL, LEASE_OTHER_DL, LEASE_OTHER_UL, LEASE_BURST_KB = 500, 250, 125, 60, 25
# the kernel timeout is set this much UNDER the granted TTL: a lease may end early but never outlive its TTL
# (nft timeouts are whole seconds from the instant the element is added, which is after the API accepted it)
LEASE_TTL_MARGIN_S = 1

NFT_TABLE = """
table inet halo {
  map flow4 { type inet_proto . ipv4_addr . inet_service . ipv4_addr . inet_service : mark; flags timeout; size 65535; }
  map flow6 { type inet_proto . ipv6_addr . inet_service . ipv6_addr . inet_service : mark; flags timeout; size 65535; }
  map dev4  { type ipv4_addr : mark; flags timeout; size 1024; }
  map dev6  { type ipv6_addr : mark; flags timeout; size 1024; }
  set intent_mac { type ether_addr; flags timeout; size 64; }
  set intent_v4  { type ipv4_addr;  flags timeout; size 256; }
  set intent_v6  { type ipv6_addr;  flags timeout; size 256; }
  chain halo_forward {
    type filter hook forward priority mangle; policy accept;
    meta mark set 0x2
    iifname "%(lan)s" meta mark set meta l4proto . ip  saddr . th sport . ip  daddr . th dport map @flow4
    iifname "%(lan)s" meta mark set meta l4proto . ip6 saddr . th sport . ip6 daddr . th dport map @flow6
    oifname "%(lan)s" meta mark set meta l4proto . ip  daddr . th dport . ip  saddr . th sport map @flow4
    oifname "%(lan)s" meta mark set meta l4proto . ip6 daddr . th dport . ip6 saddr . th sport map @flow6
    iifname "%(lan)s" meta mark set ip  saddr map @dev4
    iifname "%(lan)s" meta mark set ip6 saddr map @dev6
    oifname "%(lan)s" meta mark set ip  daddr map @dev4
    oifname "%(lan)s" meta mark set ip6 daddr map @dev6
    # intent lease = a priority BUDGET, not a blank cheque: per leased device, real-time (udp) traffic is boosted to
    # Voice up to LEASE_UDP_*, anything else (tcp, ...) only up to LEASE_OTHER_*. Packets over budget keep the mark
    # of their flow, so a boosted device cannot starve the other tins by opening bulk flows.
    iifname "%(lan)s" ether saddr @intent_mac meta l4proto udp meter lease_ul_u { ether saddr timeout 120s limit rate %(u_ul)d kbytes/second burst %(burst)d kbytes } meta mark set 0x4
    iifname "%(lan)s" ether saddr @intent_mac meta l4proto != udp meter lease_ul_o { ether saddr timeout 120s limit rate %(o_ul)d kbytes/second burst %(burst)d kbytes } meta mark set 0x4
    oifname "%(lan)s" ip  daddr @intent_v4 meta l4proto udp meter lease_dl4_u { ip daddr timeout 120s limit rate %(u_dl)d kbytes/second burst %(burst)d kbytes } meta mark set 0x4
    oifname "%(lan)s" ip  daddr @intent_v4 meta l4proto != udp meter lease_dl4_o { ip daddr timeout 120s limit rate %(o_dl)d kbytes/second burst %(burst)d kbytes } meta mark set 0x4
    oifname "%(lan)s" ip6 daddr @intent_v6 meta l4proto udp meter lease_dl6_u { ip6 daddr timeout 120s limit rate %(u_dl)d kbytes/second burst %(burst)d kbytes } meta mark set 0x4
    oifname "%(lan)s" ip6 daddr @intent_v6 meta l4proto != udp meter lease_dl6_o { ip6 daddr timeout 120s limit rate %(o_dl)d kbytes/second burst %(burst)d kbytes } meta mark set 0x4
    ct mark set meta mark
    ct packets < %(n)d meta mark set meta mark or 0x100
  }
}
"""


def nft_table():
    """the ruleset text with the interface name, sampling threshold and lease budgets substituted"""
    return NFT_TABLE % {"lan": LAN, "n": SAMPLE_PKTS + 1, "u_dl": LEASE_UDP_DL, "u_ul": LEASE_UDP_UL,
                        "o_dl": LEASE_OTHER_DL, "o_ul": LEASE_OTHER_UL, "burst": LEASE_BURST_KB}


def lease_timeout(ttl):
    """kernel element timeout (whole seconds) for a lease of `ttl` s: strictly under the TTL, at least 1 s"""
    return max(1, int(ttl) - LEASE_TTL_MARGIN_S)


def sh(cmd, check=True, inp=None):
    r = subprocess.run(cmd, shell=isinstance(cmd, str), input=inp, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError("cmd failed: %s\n%s" % (cmd, r.stderr.strip()))
    return r.stdout


_real_sh = sh


def _fast_ok():
    """in-process kernel access (libnftables / rtnetlink) only against the real shell: unit tests replace `sh` with a
    FakeKernel and must see every command, and HALO_NO_FASTPATH=1 forces the exec path (diagnostics)."""
    return sh is _real_sh and os.environ.get("HALO_NO_FASTPATH") != "1"


class NftLib:
    """nftables through libnftables.so (ctypes): no fork/exec, no libnftables load per call.
    On a 2-vCPU emulated gateway one `nft` exec costs 0.3-0.8 s under load; the in-process call a few ms."""

    def __init__(self):
        self.lock, self.ctx, self.lib, self.tried = threading.Lock(), None, None, False

    def available(self):
        if not self.tried:
            self.tried = True
            try:
                lib = ctypes.CDLL("libnftables.so.1")
                lib.nft_ctx_new.restype = ctypes.c_void_p
                lib.nft_ctx_new.argtypes = [ctypes.c_uint32]
                lib.nft_ctx_buffer_error.argtypes = [ctypes.c_void_p]
                lib.nft_run_cmd_from_buffer.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
                lib.nft_ctx_get_error_buffer.restype = ctypes.c_char_p
                lib.nft_ctx_get_error_buffer.argtypes = [ctypes.c_void_p]
                ctx = lib.nft_ctx_new(0)
                if ctx:
                    lib.nft_ctx_buffer_error(ctx)
                    self.lib, self.ctx = lib, ctx
            except (OSError, AttributeError):
                self.lib = self.ctx = None
        return self.ctx is not None

    def run(self, text):
        """one nft transaction (atomic, like `nft -f -`); RuntimeError with the nft error text on failure"""
        with self.lock:
            rc = self.lib.nft_run_cmd_from_buffer(self.ctx, text.encode())
            if rc != 0:
                err = (self.lib.nft_ctx_get_error_buffer(self.ctx) or b"").decode(errors="replace")[-300:]
                raise RuntimeError("nft failed: %s" % err.strip())


NFT = NftLib()


def nft_run(text, check=True):
    """run nft commands (atomic batch): in-process libnftables, else `nft -f -`"""
    if _fast_ok() and NFT.available():
        try:
            NFT.run(text)
        except RuntimeError:
            if check:
                raise
    else:
        sh("nft -f -", inp=text, check=check)


# ---- rtnetlink: CAKE rate change + read-back without fork/exec ---------------------------------------------------
NLM_F_REQUEST, NLM_F_ACK, NLM_F_DUMP = 1, 4, 0x300
RTM_NEWQDISC, RTM_GETQDISC = 36, 38
TCA_KIND, TCA_OPTIONS, TCA_CAKE_BASE_RATE64 = 1, 2, 2
TC_H_ROOT = 0xFFFFFFFF


def _nla(typ, data):
    n = 4 + len(data)
    return struct.pack("HH", n, typ) + data + b"\0" * (-n % 4)


def cake_rate_msg(ifindex, mbit, seq=1):
    """RTM_NEWQDISC (no CREATE/REPLACE flag = `tc qdisc change`) for the root cake qdisc: bandwidth only,
    exactly what `tc qdisc change dev X root cake bandwidth <int(mbit*1000)>kbit` sends (kbit -> bytes/s = *125)."""
    rate = int(mbit * 1000) * 125
    body = struct.pack("BBHiIII", 0, 0, 0, ifindex, 0, TC_H_ROOT, 0) + _nla(TCA_KIND, b"cake\0") + \
        _nla(TCA_OPTIONS, _nla(TCA_CAKE_BASE_RATE64, struct.pack("Q", rate)))
    return struct.pack("IHHII", 16 + len(body), RTM_NEWQDISC, NLM_F_REQUEST | NLM_F_ACK, seq, 0) + body


def parse_cake_rates(buf):
    """RTM_NEWQDISC dump -> {ifindex: bandwidth bytes/s} for root cake qdiscs"""
    out, off = {}, 0
    while off + 16 <= len(buf):
        ln, typ = struct.unpack_from("IH", buf, off)
        if ln < 16:
            break
        if typ == RTM_NEWQDISC and ln >= 36:
            _, _, _, idx, _, parent, _ = struct.unpack_from("BBHiIII", buf, off + 16)
            kind, rate, a, end = None, None, off + 36, off + ln
            while a + 4 <= end:
                al, at = struct.unpack_from("HH", buf, a)
                if al < 4:
                    break
                at &= 0x3FFF
                if at == TCA_KIND:
                    kind = buf[a + 4:a + al].rstrip(b"\0")
                elif at == TCA_OPTIONS:
                    b = a + 4
                    while b + 4 <= a + al:
                        bl, bt = struct.unpack_from("HH", buf, b)
                        if bl < 4:
                            break
                        if bt & 0x3FFF == TCA_CAKE_BASE_RATE64 and bl >= 12:
                            rate = struct.unpack_from("Q", buf, b + 4)[0]
                        b += (bl + 3) & ~3
                a += (al + 3) & ~3
            if kind == b"cake" and parent == TC_H_ROOT and rate is not None:
                out[idx] = rate
        off += (ln + 3) & ~3
    return out


def _nl_talk(msg, want_dump):
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    try:
        s.settimeout(2.0)
        s.bind((0, 0))
        s.send(msg)
        data = b""
        while True:
            chunk = s.recv(65536)
            data += chunk
            typ = struct.unpack_from("H", chunk, 4)[0] if len(chunk) >= 16 else 3
            if typ == 2:                                        # NLMSG_ERROR: errno 0 = ACK
                e = struct.unpack_from("i", chunk, 16)[0]
                if e:
                    raise OSError(-e, os.strerror(-e))
                return data
            if not want_dump or typ == 3 or len(chunk) < 16:    # NLMSG_DONE
                return data
    finally:
        s.close()


def rtnl_cake_rates(devs):
    """{dev: Mbit/s} of the root cake qdisc of each device (kernel read-back, one dump)"""
    req = struct.pack("IHHII", 16 + 20, RTM_GETQDISC, NLM_F_REQUEST | NLM_F_DUMP, 1, 0) + b"\0" * 20
    got = parse_cake_rates(_nl_talk(req, True))
    return {d: got[socket.if_nametoindex(d)] * 8 / 1e6 for d in devs if socket.if_nametoindex(d) in got}


def rtnl_set_rates(rates):
    """{dev: Mbit/s}: change the root cake bandwidth of each device in place (queues kept)"""
    for i, (dev, mbit) in enumerate(rates.items()):
        _nl_talk(cake_rate_msg(socket.if_nametoindex(dev), mbit, i + 1), False)


def cake_cmd(dev, verb, mbit, extra):
    return "tc qdisc %s dev %s root handle 1: cake bandwidth %dkbit %s" % (verb, dev, int(mbit * 1000), extra)


class Enforcer:
    DL_OPTS = "diffserv4 dual-dsthost ingress fwmark 0x0f"
    UL_OPTS = "diffserv4 dual-srchost ack-filter fwmark 0x0f"

    def __init__(self, log=None):
        self.log = log or (lambda *a, **k: None)
        self.rate = {LAN: None, WAN: None}
        self.lkg = None
        os.makedirs(STATE_DIR, exist_ok=True)

    # ---- base data plane ---------------------------------------------------
    def install(self, rate_dl, rate_ul, marks=True):
        sh("sysctl -qw net.netfilter.nf_conntrack_acct=1", check=False)
        if marks:
            sh("nft delete table inet halo", check=False)
            sh("nft -f -", inp=nft_table())
            sh("ip link add %s type dummy" % MON, check=False)
            sh("ip link set %s up" % MON)
            for dev in (LAN, WAN):
                sh("tc qdisc add dev %s clsact" % dev, check=False)
                sh("tc filter del dev %s egress" % dev, check=False)
                sh("tc filter add dev %s egress protocol all prio 1 handle 0x100/0x100 fw "
                   "action mirred egress mirror dev %s" % (dev, MON))
        sh(cake_cmd(LAN, "replace", rate_dl, self.DL_OPTS))
        sh(cake_cmd(WAN, "replace", rate_ul, self.UL_OPTS))
        self.rate = {LAN: rate_dl, WAN: rate_ul}

    def set_rate(self, dev, mbit):
        """rate-only change in place: `tc qdisc change` keeps queued packets (unit test U-7)."""
        if _fast_ok():
            try:
                rtnl_set_rates({dev: mbit})                  # same RTM_NEWQDISC `tc qdisc change` sends, no fork/exec
                self.rate[dev] = mbit
                return
            except (OSError, struct.error):
                pass
        sh("tc qdisc change dev %s root cake bandwidth %dkbit" % (dev, int(mbit * 1000)))
        self.rate[dev] = mbit

    def read_rate(self, dev):
        j = json.loads(sh("tc -j qdisc show dev %s root" % dev))
        for q in j:
            if q.get("kind") == "cake":
                return q["options"]["bandwidth"] * 8 / 1e6          # bytes/s -> Mbit/s
        return None

    def tin_stats(self, dev):
        j = json.loads(sh("tc -s -j qdisc show dev %s root" % dev))
        for q in j:
            if q.get("kind") == "cake":
                return q
        return {}

    # ---- marks ---------------------------------------------------------------
    def nft_batch(self, lines):
        """one atomic nft transaction; if it fails, fall back to line-by-line so one bad element cannot block the rest"""
        if not lines:
            return
        try:
            nft_run("\n".join(lines) + "\n")
        except RuntimeError:
            for l in lines:
                nft_run(l + "\n", check=False)

    @staticmethod
    def flow_element(key, tin, ttl=30):
        proto, lip, lport, wip, wport = key
        m = "flow6" if ":" in lip else "flow4"
        return "add element inet halo %s { %s . %s . %d . %s . %d timeout %ds : 0x%x }" % (
            m, proto, lip, lport, wip, wport, ttl, tin)

    @staticmethod
    def flow_delete(key):
        proto, lip, lport, wip, wport = key
        m = "flow6" if ":" in lip else "flow4"
        return "delete element inet halo %s { %s . %s . %d . %s . %d }" % (m, proto, lip, lport, wip, wport)

    @staticmethod
    def flow_destroy(key):
        """delete-if-present (nft >= 1.0.8, Linux >= 6.3): lets replace-in-place be one atomic transaction"""
        return Enforcer.flow_delete(key).replace("delete element", "destroy element", 1)

    def add_lease(self, mac, ips, ttl):
        ttl = lease_timeout(ttl)
        lines = ["add element inet halo intent_mac { %s timeout %ds }" % (mac, ttl)]
        for ip in ips:
            lines.append("add element inet halo %s { %s timeout %ds }" % ("intent_v6" if ":" in ip else "intent_v4", ip, ttl))
        self.nft_batch(lines)

    def del_lease(self, mac, ips):
        lines = ["delete element inet halo intent_mac { %s }" % mac]
        for ip in ips:
            lines.append("delete element inet halo %s { %s }" % ("intent_v6" if ":" in ip else "intent_v4", ip))
        for l in lines:
            sh("nft " + l, check=False)

    def leases(self):
        j = json.loads(sh("nft -j list set inet halo intent_mac"))
        out = []
        for o in j.get("nftables", []):
            for e in o.get("set", {}).get("elem", []) or []:
                e = e.get("elem", e)
                out.append({"mac": e.get("val"), "expires_s": e.get("expires")})
        return out

    def override_device(self, ip, tin, ttl):
        m = "dev6" if ":" in ip else "dev4"
        # one atomic transaction (destroy = delete-if-present, nft >= 1.0.8 / Linux >= 6.3)
        self.nft_batch(["destroy element inet halo %s { %s }" % (m, ip),
                        "add element inet halo %s { %s timeout %ds : 0x%x }" % (m, ip, ttl, tin)])

    # ---- checkpoint / rollback (Koo-Toueg: permanent = LKG, tentative = candidate) --------
    def snapshot(self, params=None):
        snap = {"t": time.time(), "rate": dict(self.rate), "params": params or {},
                "tc": {d: sh("tc qdisc show dev %s root" % d).strip() for d in (LAN, WAN)},
                "nft": sh("nft list table inet halo", check=False)}
        snap["hash"] = hashlib.sha256(json.dumps([snap["rate"], snap["params"], snap["tc"]], sort_keys=True).encode()).hexdigest()[:16]
        return snap

    def commit(self, params=None):
        self.lkg = self.snapshot(params)
        json.dump(self.lkg, open(os.path.join(STATE_DIR, "lkg.json"), "w"))
        self._prebuild(self.lkg)
        return self.lkg["hash"]

    def _prebuild(self, lkg):
        """render the restore batches now (commit time) so a rollback is syscalls only"""
        pairs = ((LAN, self.DL_OPTS), (WAN, self.UL_OPTS))
        self._pre = {"hash": lkg["hash"],
                     "change": "\n".join(cake_cmd(d, "change", lkg["rate"][d], o)[3:] for d, o in pairs) + "\n",
                     "replace": "\n".join(cake_cmd(d, "replace", lkg["rate"][d], o)[3:] for d, o in pairs) + "\n"}
        return self._pre

    def rates_now(self):
        if _fast_ok():
            try:
                return rtnl_cake_rates((LAN, WAN))
            except (OSError, struct.error):
                pass
        out = {}
        for q in json.loads(sh("tc -j qdisc show")):
            if q.get("kind") == "cake" and q.get("dev") in (LAN, WAN) and "root" in q:
                out[q["dev"]] = q["options"]["bandwidth"] * 8 / 1e6
        return out

    def rollback(self, restore_nft=False):
        """restore the last-known-good bundle (tc [+ nft] + params) and verify by read-back.
        Fast path: the rate is restored with one rtnetlink change per direction and read back with one dump (no fork);
        fallback: one prebuilt `tc -batch` (in-place `change`, then `replace`) and `tc -j qdisc show`."""
        t0 = time.time()
        lkg = self.lkg or json.load(open(os.path.join(STATE_DIR, "lkg.json")))
        pre = getattr(self, "_pre", None)
        if not pre or pre["hash"] != lkg["hash"]:
            pre = self._prebuild(lkg)
        got = None
        if _fast_ok():
            try:
                rtnl_set_rates({d: lkg["rate"][d] for d in (LAN, WAN)})
                got = rtnl_cake_rates((LAN, WAN))
            except (OSError, struct.error):
                got = None
        if got is None:
            try:
                sh("tc -batch -", inp=pre["change"])
            except Exception:
                sh("tc -batch -", inp=pre["replace"])
            got = None
        if restore_nft and lkg.get("nft"):
            nft_run("flush table inet halo\n" + lkg["nft"])     # atomic
        self.rate = dict(lkg["rate"])
        if got is None:
            got = self.rates_now()
        ok = all(abs(got.get(d, 0) - lkg["rate"][d]) < 0.01 * lkg["rate"][d] + 0.01 for d in (LAN, WAN))
        return ok, time.time() - t0, lkg

    def verify_applied(self, want):
        """read-back: kernel state must equal intent"""
        got = self.rates_now()
        return [(d, r, got.get(d)) for d, r in want.items() if d not in got or abs(got[d] - r) > 0.01 * r + 0.01]


def safe_state(rate_dl, rate_ul):
    """KNOWN SAFE STATE: static CAKE diffserv4 at a conservative rate, per-host fairness,
    every lease/override/flow mark flushed. Needs no controller to stay low-latency and fair."""
    # fast path: the two rate changes over rtnetlink (the qdisc options - diffserv4, per-host fairness - are static since
    # install(), only the rate differs), no process spawn; else one tc batch (process spawns are the slow part)
    done = False
    if _fast_ok():
        try:
            rtnl_set_rates({LAN: rate_dl, WAN: rate_ul})
            done = True
        except (OSError, struct.error):
            done = False
    if not done:
        tcb = "\n".join(c.split(" ", 1)[1] for c in (cake_cmd(LAN, "replace", rate_dl, "diffserv4 dual-dsthost ingress"),
                                                     cake_cmd(WAN, "replace", rate_ul, "diffserv4 dual-srchost")))
        try:
            sh(["tc", "-batch", "-"], inp=tcb + "\n")
        except Exception:
            sh(cake_cmd(LAN, "replace", rate_dl, "diffserv4 dual-dsthost ingress"), check=False)
            sh(cake_cmd(WAN, "replace", rate_ul, "diffserv4 dual-srchost"), check=False)
    nf = "".join("flush set inet halo %s\n" % s for s in ("intent_mac", "intent_v4", "intent_v6")) + \
         "".join("flush map inet halo %s\n" % m for m in ("flow4", "flow6", "dev4", "dev6"))
    try:
        if _fast_ok() and NFT.available():
            NFT.run(nf)                                   # in-process: no exec on the watchdog's critical path
        else:
            sh(["nft", "-f", "-"], inp=nf)
    except Exception:
        for line in nf.splitlines():
            sh("nft " + line, check=False)
    os.makedirs(STATE_DIR, exist_ok=True)
    json.dump({"t": time.time(), "rate_dl": rate_dl, "rate_ul": rate_ul}, open(os.path.join(STATE_DIR, "safe.json"), "w"))


if __name__ == "__main__":
    import sys
    if sys.argv[1] == "safe":
        safe_state(float(sys.argv[2]), float(sys.argv[3]))
    elif sys.argv[1] == "static":
        Enforcer().install(float(sys.argv[2]), float(sys.argv[3]), marks=False)
