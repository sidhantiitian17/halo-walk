"""ctypes wrapper of the in-process C calm-mode sentinel (halo/csrc/sentinel.c, built by `make`).

`Sentinel.load(...)` returns None (and logs why) when the shared library is missing, does not match this wrapper or fails to
start: the controller then keeps its pure-Python calm path.  Nothing here runs unless the controller arms it."""
import ctypes, os, socket, sys

MAXR = 8
LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "libhalo_sentinel.so")
EV_PROBE, EV_ACH, EV_LATE, EV_BURST, EV_FAST, EV_LOST, EV_DROP_CONFIRMED = range(1, 8)
AL_NONE, AL_DELAY, AL_LATE, AL_COLLAPSE, AL_PROBEUP, AL_ERROR = range(6)
ALERTS = {0: "none", 1: "delay", 2: "late", 3: "collapse", 4: "probe_up", 5: "error"}
SYNC_S = 1.0                    # the Python main loop wakes at least this often while the sentinel runs (liveness bump)
HEAVY_S = 4.0                  # ... but replays the C thread's samples / runs the estimator tick only this often (or on an alert / SIGUSR1)
GATE_S = 1.3                    # the heartbeat is written only if the Python liveness counter moved within this many seconds


class Params(ctypes.Structure):
    _fields_ = [(n, ctypes.c_double) for n in ("tick_s", "probe_s", "thresh_ms", "late_s", "confirm_win", "base_alpha", "peak_tau",
                                               "gate_s", "ewma_alpha_ref", "ewma_dt_ref")] + [
        ("rate", ctypes.c_double * 2), ("rmax", ctypes.c_double * 2), ("c_est", ctypes.c_double * 2),
        ("hold_until", ctypes.c_double * 2), ("ach", ctypes.c_double * 2), ("peak", ctypes.c_double * 2),
        ("last_delta", ctypes.c_double * 2), ("probe_gate", ctypes.c_double * 2), ("collapse", ctypes.c_double),
        ("sat_frac", ctypes.c_double), ("burst_max", ctypes.c_double),
        ("base_ul", ctypes.c_double * MAXR), ("base_dl", ctypes.c_double * MAXR),
        ("has_base_ul", ctypes.c_int32 * MAXR), ("has_base_dl", ctypes.c_int32 * MAXR),
        ("confirm_n", ctypes.c_int32), ("rr", ctypes.c_int32),
        ("st", (ctypes.c_char * 16) * 2), ("fsm", ctypes.c_char * 16)]


class Event(ctypes.Structure):
    _fields_ = [("t", ctypes.c_double), ("a", ctypes.c_double), ("b", ctypes.c_double), ("kind", ctypes.c_int32), ("ri", ctypes.c_int32)]


class State(ctypes.Structure):
    _fields_ = [("ach", ctypes.c_double * 2), ("peak", ctypes.c_double * 2), ("last_delta", ctypes.c_double * 2),
                ("t_counters", ctypes.c_double), ("dl_collapse_at", ctypes.c_double),
                ("rx", ctypes.c_uint64), ("tx", ctypes.c_uint64),
                ("alert", ctypes.c_int32), ("armed", ctypes.c_int32)]


class CKey(ctypes.Structure):
    _fields_ = [("proto", ctypes.c_uint8), ("v6", ctypes.c_uint8), ("pad0", ctypes.c_uint8), ("pad1", ctypes.c_uint8),
                ("lport", ctypes.c_uint16), ("wport", ctypes.c_uint16), ("lan", ctypes.c_uint8 * 16), ("wan", ctypes.c_uint8 * 16)]


class CVal(ctypes.Structure):
    _fields_ = [("up_b", ctypes.c_uint64), ("dn_b", ctypes.c_uint64), ("up_p", ctypes.c_uint64), ("dn_p", ctypes.c_uint64),
                ("found", ctypes.c_int32), ("pad", ctypes.c_int32)]


_IPB = {}


def _ipbytes(ip):
    b = _IPB.get(ip)
    if b is None:
        b = _IPB[ip] = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip).ljust(16, b"\0")
    return b


def ct_keys(keys):
    """[(proto, lan_ip, lan_port, wan_ip, wan_port)] -> ctypes array for hs_ct_dump (LAN-first, like the sniffer's flow key)"""
    arr = (CKey * max(1, len(keys)))()
    for i, (pn, lan, lp, wan, wp) in enumerate(keys):
        k = arr[i]
        k.proto, k.v6, k.lport, k.wport = (6 if pn == "tcp" else 17), 1 if ":" in lan else 0, lp, wp
        ctypes.memmove(k.lan, _ipbytes(lan), 16)
        ctypes.memmove(k.wan, _ipbytes(wan), 16)
    return arr


class Sentinel:
    def __init__(self, lib):
        self.lib = lib
        self.efd = lib.hs_efd()
        self._ev = (Event * 512)()
        self._tb = ctypes.create_string_buffer(1 << 16)
        self._st = State()
        self.armed = False

    @classmethod
    def load(cls, reflectors, wan, hb_path, port=7000, log=None, path=None):
        log = log or (lambda m: print("[sentinel] " + m, file=sys.stderr))
        if os.environ.get("HALO_NO_SENTINEL") == "1":
            log("disabled by HALO_NO_SENTINEL=1: pure-Python calm path")
            return None
        path = path or LIB
        try:
            lib = ctypes.CDLL(path)
            for fn, res, args in (("hs_init", ctypes.c_int, [ctypes.POINTER(ctypes.c_char_p), ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]),
                                  ("hs_efd", ctypes.c_int, []), ("hs_arm", None, [ctypes.POINTER(Params)]), ("hs_ct_dump", ctypes.c_int, [ctypes.POINTER(CKey), ctypes.c_int, ctypes.POINTER(CVal)]),
                                  ("hs_ct_parse", ctypes.c_int, [ctypes.c_char_p, ctypes.c_long, ctypes.POINTER(CKey), ctypes.c_int, ctypes.POINTER(CVal)]),
                                  ("hs_set_fast", None, [ctypes.c_double, ctypes.c_double, ctypes.c_int]), ("hs_disarm", None, []),
                                  ("hs_bump", None, []), ("hs_drain", ctypes.c_int, [ctypes.POINTER(Event), ctypes.c_int]),
                                  ("hs_tel", ctypes.c_int, [ctypes.c_char_p, ctypes.c_int]), ("hs_state_get", None, [ctypes.POINTER(State)]),
                                  ("hs_ack_alert", ctypes.c_int, []), ("hs_stop", None, []),
                                  ("hs_sizeof_params", ctypes.c_int, []), ("hs_sizeof_state", ctypes.c_int, []), ("hs_sizeof_event", ctypes.c_int, [])):
                f = getattr(lib, fn)
                f.restype, f.argtypes = res, args
            if (lib.hs_sizeof_params(), lib.hs_sizeof_state(), lib.hs_sizeof_event()) != (
                    ctypes.sizeof(Params), ctypes.sizeof(State), ctypes.sizeof(Event)):
                raise OSError("struct layout mismatch between halo/csrc/sentinel.c and halo/sentinel.py (rebuild with `make`)")
            arr = (ctypes.c_char_p * max(1, len(reflectors)))(*[r.encode() for r in reflectors])
            rc = lib.hs_init(arr, len(reflectors), port, wan.encode(), (hb_path or "").encode())
            if rc != 0:
                raise OSError("hs_init failed: %s" % os.strerror(-rc))
        except (OSError, AttributeError) as e:
            log("not available (%s): pure-Python calm path" % e)
            return None
        return cls(lib)

    # ---- control -----------------------------------------------------------------------------------------------
    def arm(self, p):
        self.lib.hs_arm(ctypes.byref(p))
        self.armed = True

    def set_fast(self, fast_s, late_s=0.4, burst=False):
        """full-rate probing in the C thread (one probe per fast_s, round-robin); samples are queued for drain()"""
        self.lib.hs_set_fast(fast_s, late_s, 1 if burst else 0)

    def disarm(self):
        self.lib.hs_disarm()
        self.armed = False

    def bump(self):
        self.lib.hs_bump()

    def stop(self):
        try:
            self.lib.hs_stop()
        finally:
            self.armed = False

    # ---- results -----------------------------------------------------------------------------------------------
    def drain(self):
        out = []
        while True:
            n = self.lib.hs_drain(self._ev, len(self._ev))
            out += [(e.kind, e.t, e.a, e.b, e.ri) for e in self._ev[:n]]
            if n < len(self._ev):
                return out

    def telemetry(self):
        n = self.lib.hs_tel(self._tb, len(self._tb))
        return self._tb.raw[:n].decode() if n else ""

    def state(self):
        self.lib.hs_state_get(ctypes.byref(self._st))
        return self._st

    def ct_dump(self, keys):
        """one ctnetlink dump parsed and matched in C: {key: (up_bytes, dn_bytes, up_pkts, dn_pkts)} for the keys that exist.
        Raises OSError if ctnetlink is unavailable (the caller falls back to the Python parser)."""
        arr, vals = ct_keys(keys), (CVal * max(1, len(keys)))()
        rc = self.lib.hs_ct_dump(arr, len(keys), vals)
        if rc < 0:
            raise OSError(-rc, os.strerror(-rc))
        return {k: (v.up_b, v.dn_b, v.up_p, v.dn_p) for k, v in zip(keys, vals) if v.found}

    def ack_alert(self):
        return self.lib.hs_ack_alert()
