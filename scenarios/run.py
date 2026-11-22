#!/usr/bin/env python3
"""M8 - experiment harness: RESET -> (baseline window) -> INDUCE -> COLLECT -> per-run evidence bundle.

  run.py <scenario> <config> <rep>      scenario: S1 S1x32 S2 S3 S4 S5 S6 S7 EST<rate> DATAGEN CPU
                                        config  : C0 FIFO | C1 static CAKE | C2 autorate-only
                                                  C3 HALO-Walk heuristic | C4 HALO-Walk ML
Every impairment and traffic parameter of a run is written to meta.json (reproducibility).
"""
import json, os, random, shutil, signal, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
GEN = os.path.join(ROOT, "halo", "gen.py")
W4, W6 = "10.9.0.2", "fd00:9::2"
MAC = {}
procs = []


def sh(c, check=False):
    return subprocess.run(c, shell=True, capture_output=True, text=True, check=check).stdout


def ns(n, cmd, log=None, env=None):
    e = dict(os.environ); e.update(env or {})
    f = open(log, "w") if log else subprocess.DEVNULL
    p = subprocess.Popen("exec ip netns exec %s %s" % (n, cmd), shell=True, stdout=f, stderr=subprocess.STDOUT, env=e)
    procs.append(p)
    return p


GLOG = [None, 0]


def gen(n, args, log=None, env=None):
    if log is None and GLOG[0]:
        GLOG[1] += 1
        log = os.path.join(GLOG[0], "gen_%02d.log" % GLOG[1])
    return ns(n, "%s %s %s" % (PY, GEN, args), log, env)


def kill_all():
    for p in procs:
        try:
            p.kill()
        except Exception:
            pass
    sh(os.path.join(ROOT, "rig", "rig_down.sh"))


def rig(down, up):
    sh("%s %s %s 10" % (os.path.join(ROOT, "rig", "rig_up.sh"), down, up), check=True)
    for h in ("laptop", "gamer", "tv1", "tv2", "tv3", "pc"):
        MAC[h] = sh("ip netns exec %s cat /sys/class/net/eth0/address" % h).strip()
    shutil.rmtree("/tmp/halo_rt", ignore_errors=True)
    shutil.rmtree("/run/halo", ignore_errors=True)
    for f in ("/tmp/halo_labels.jsonl",):
        if os.path.exists(f):
            os.remove(f)
    gen("wan", "reflector")
    gen("wan", "rt_server --ports 3478 3479 16400 27015 3074 443 4500 50001 50002 50003 50004")
    gen("wan", "chunk_server --ports 80 443 8080 6881")
    for p in (5201, 5202, 5203):
        ns("wan", "iperf3 -s -p %d" % p)
    # warm ARP / ND so the first probes are not delayed
    for h in ("laptop", "gamer", "tv1", "tv2", "tv3", "pc"):
        sh("ip netns exec %s ping -c1 -W1 %s; ip netns exec %s ping -6 -c1 -W1 %s" % (h, W4, h, W6))
    sh("ip netns exec gw ping -c1 -W1 10.9.0.3; ip netns exec gw ping -c1 -W1 10.9.0.4; ip netns exec gw ping -c1 -W1 10.9.0.5; ip netns exec gw ping -6 -c1 -W1 fd00:9::6")
    time.sleep(0.5)


def set_rate(d, u):
    sh("%s %s %s" % (os.path.join(ROOT, "rig", "set_rate.sh"), d, u), check=True)


CTL = [None]


def config(cfg, plan_dl, plan_ul, out, extra="", watchdog=True, safe=None):
    """bring up the system under test"""
    safe = safe or (0.4 * plan_dl, 0.4 * plan_ul)
    if cfg == "C0":
        return
    if cfg == "C1":
        sh("ip netns exec gw %s -m halo.enforcer static %s %s" % (PY, 0.95 * plan_dl, 0.95 * plan_ul))
        return
    flags = {"C2": "--classifier none", "C3": "--classifier heur", "C4": "--classifier ml"}[cfg]
    CTL[0] = ns("gw", "%s -m halo.controller --plan-dl %s --plan-ul %s --safe-dl %s --safe-ul %s %s %s --out %s" % (
        PY, plan_dl, plan_ul, safe[0], safe[1], flags, extra, os.path.join(out, "ctl")), os.path.join(out, "ctl.log"))
    if watchdog:
        ns("gw", "%s -m halo.watchdog 2.0 %s %s" % (PY, safe[0], safe[1]), os.path.join(out, "watchdog.log"))
    ns("gw", "%s -m halo.api" % PY, os.path.join(out, "api.log"), env={"HALO_API_TOKEN": "EXAMPLE-NOT-A-SECRET-0000"})
    for _ in range(120):                       # wait for the first heartbeat (model load is slow in the emulated VM)
        if os.path.exists("/run/halo/heartbeat"):
            break
        time.sleep(0.5)
    for _ in range(120):                       # and for the intent API (FastAPI import is slow in the emulated VM)
        if '"controller_heartbeat_age_s"' in sh("ip netns exec laptop curl -s -m 2 http://10.0.0.1:8080/v1/health"):
            break
        time.sleep(0.5)
    time.sleep(1.0)


def call(host, dur, out, dst=W4, dport=3478, sid="call", seed=1):
    """video call: 1.0 Mbit/s up, 1.5 Mbit/s down"""
    return gen(host, "rt_client --dst %s --dport %d --pps_up 120 --size_up 1040 --pps_down 170 --size_down 1100 "
               "--dur %s --cls call --sid %s --seed %d --out %s" % (dst, dport, dur, sid, seed, out))


def game(host, dur, out, dst=W4, dport=27015, sid="game", seed=2):
    return gen(host, "rt_client --dst %s --dport %d --pps_up 60 --size_up 90 --pps_down 60 --size_down 140 "
               "--dur %s --cls gaming --sid %s --seed %d --out %s" % (dst, dport, dur, sid, seed, out))


def bulk(host, dur, out, n=8, dst=W4, port=5201, up=False):
    return ns(host, "iperf3 -c %s -p %d %s -P %d -t %d -i 1 -J" % (dst, port, "" if up else "-R", n, int(dur)), out)


def tv(host, dur, out, sid, ladder="1.5 3 5 8"):
    return gen(host, "tv_client --dst %s --dport 443 --dur %s --sid %s --ladder %s --out %s" % (W4, dur, sid, ladder, out))


def api(method, path, body=None, host="laptop"):
    r = _api(method, path, body, host)
    return r if r else _api(method, path, body, host)


def _api(method, path, body=None, host="laptop"):
    b = ("-d '%s'" % json.dumps(body)) if body is not None else ""
    return sh("ip netns exec %s curl -s -m 20 -X %s -H 'Authorization: Bearer EXAMPLE-NOT-A-SECRET-0000' "
              "-H 'Content-Type: application/json' %s http://10.0.0.1:8080%s" % (host, method, b, path))


OVR = [None]


def ovr_client_start(host="laptop"):
    """M10: start the override client BEFORE the measurement, inside the client's netns, waiting on a pipe. The measured
    POST -> response interval then excludes `ip netns exec` / interpreter start-up (about 1 s on the 2-vCPU TCG VM).
    Returns the process, or None (the caller falls back to the legacy per-request spawn and says so in meta)."""
    try:
        p = subprocess.Popen(["ip", "netns", "exec", host, PY, "-u", os.path.join(ROOT, "scenarios", "ovr_client.py")],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        if json.loads(p.stdout.readline()).get("ready"):
            procs.append(p)
            return p
    except Exception:
        pass
    return None


def ovr_client_request(p, method, path, body=None):
    """send one request through the running client; returns its reply dict (t_post, t_ret, status, body) or None"""
    try:
        p.stdin.write(json.dumps({"method": method, "path": path, "body": body}) + "\n")
        p.stdin.flush()
        r = json.loads(p.stdout.readline())
        return r if "t_post" in r else None
    except Exception:
        return None


def tins(dev="lan0"):
    try:
        j = json.loads(sh("ip netns exec gw tc -s -j qdisc show dev %s root" % dev))
        return [(t.get("sent_packets", 0), t.get("sent_bytes", 0)) for t in j[0].get("tins", [])]
    except Exception:
        return []


def snapshot(out, tag="end"):
    for d in ("lan0", "wan0"):
        open(os.path.join(out, "tc_%s_%s.json" % (d, tag)), "w").write(sh("ip netns exec gw tc -s -j qdisc show dev %s root" % d))
    open(os.path.join(out, "nft_%s.txt" % tag), "w").write(sh("ip netns exec gw nft list table inet halo 2>/dev/null"))
    shutil.copy("/proc/stat", os.path.join(out, "procstat_%s.txt" % tag))


def cpu_of(p):
    """(utime+stime) seconds of the controller process"""
    try:
        pid = int(sh("pgrep -f 'halo.controller' | head -1").strip())
        f = open("/proc/%d/stat" % pid).read().rsplit(")", 1)[1].split()
        return (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
    except Exception:
        return float("nan")


def cpu_threads():
    """per-thread (utime+stime) seconds of the controller process, keyed by thread name (diagnostic only; the M12
    metric is the whole-process total in cpu_of)"""
    out = {}
    try:
        pid = int(sh("pgrep -f 'halo.controller' | head -1").strip())
        for tid in os.listdir("/proc/%d/task" % pid):
            try:
                st = open("/proc/%d/task/%s/stat" % (pid, tid)).read()
                nm = st[st.index("(") + 1:st.rindex(")")]
                f = st.rsplit(")", 1)[1].split()
                out["%s:%s" % (nm, tid)] = (int(f[11]) + int(f[12])) / os.sysconf("SC_CLK_TCK")
            except Exception:
                pass
    except Exception:
        pass
    return out


def ensure_sentinel():
    """build the optional C calm-mode sentinel (Makefile) if it is missing; without it the controller logs the fallback and
    runs its pure-Python calm path"""
    if not os.path.exists(os.path.join(ROOT, "halo", "libhalo_sentinel.so")):
        sh("make -s -C %s >/dev/null 2>&1 || true" % ROOT)


def main():
    ensure_sentinel()
    scn, cfg, rep = sys.argv[1], sys.argv[2], int(sys.argv[3])
    out = os.path.join(ROOT, "results", "raw", scn, cfg, "r%02d" % rep)
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    os.makedirs(os.path.join(out, "genlog")); GLOG[0] = os.path.join(out, "genlog")
    seed = 1000 * rep + sum(map(ord, scn))
    random.seed(seed)
    meta = {"scenario": scn, "config": cfg, "rep": rep, "seed": seed, "kernel": os.uname().release,
            "emulated": True, "delay_ms_each_way": 10, "modem_buffer_bytes": 1500000, "events": []}
    T0 = [0.0]

    def mark(name, **kw):
        kw.update(name=name, t=time.time(), rel=round(time.time() - T0[0], 3))
        meta["events"].append(kw)

    try:
        if scn in ("S1", "S1x32", "S7", "S5"):
            rig(20, 4); meta.update(down=20, up=4)
            config(cfg, 20, 4, out)
            T0[0] = time.time(); mark("start")
            dst = W6 if scn == "S7" else W4
            dport = 443 if scn == "S5" else 3478          # S5: call on a non-standard port (QUIC-like UDP/443)
            dur = 36 if scn == "S5" else 30
            if scn == "S5":
                OVR[0] = ovr_client_start("laptop")
                meta["override_client"] = "netns_helper" if OVR[0] else "legacy_spawn_fallback"
            call("laptop", dur, os.path.join(out, "call.csv"), dst=dst, dport=dport)
            time.sleep(6)
            n = {"S1": 8, "S7": 8, "S1x32": 32, "S5": 16}[scn]
            mark("load_on", flows=n)
            bulk("pc", dur - 7, os.path.join(out, "bulk.json"), n=n, dst=dst)
            if scn == "S5":
                time.sleep(14)
                before = tins()
                ovr_body = {"device": "10.0.0.10", "cls": "call", "ttl": 120}
                rr = ovr_client_request(OVR[0], "POST", "/v1/overrides", ovr_body) if OVR[0] else None
                if rr:
                    # override_post = just before the request bytes were written by the client already running in the
                    # laptop netns; override_returned = the response was read (both measured by that client)
                    meta["events"].append({"name": "override_post", "t": rr["t_post"], "rel": round(rr["t_post"] - T0[0], 3),
                                           "client": "netns_helper"})
                    t1 = rr["t_ret"]
                    meta["override_resp"] = rr["body"]
                    meta["events"].append({"name": "override_returned", "t": t1, "rel": round(t1 - T0[0], 3),
                                           "curl_roundtrip_s": round(rr["t_ret"] - rr["t_post"], 3), "client": "netns_helper"})
                else:                                   # helper unavailable: legacy per-request spawn, flagged in meta
                    meta["override_client"] = "legacy_spawn_fallback"
                    mark("override_post")
                    r = api("POST", "/v1/overrides", ovr_body)
                    t1 = time.time()
                    meta["override_resp"] = r
                    mark("override_returned", curl_roundtrip_s=round(t1 - meta["events"][-1]["t"], 3))
                now = tins()
                meta["voice_tin_pkts_before_after"] = [before[3][0] if before else None, now[3][0] if now else None]
                if rr:
                    # legacy figure for comparison (deck shows both): the old harness marked override_post BEFORE spawning
                    # `ip netns exec laptop sh -c curl ...`. Measured here for real, with the same spawn path and a
                    # read-only request (GET /v1/health), so the override is not applied twice: it is the spawn-inclusive
                    # round trip of a legacy-style client under the same load, not the interval of the POST itself.
                    tl = time.time()
                    _api("GET", "/v1/health")
                    meta["override_legacy_spawn_s"] = round(time.time() - tl, 3)
                time.sleep(dur - 6 - 14 - (time.time() - t1))
            else:
                time.sleep(dur - 6)
        elif scn == "S2":
            # use case 2, scaled 2:1 (50 -> 10 -> 50 Mbit/s): the software-emulated VM cannot carry
            # 100 Mbit/s faithfully (see results/fidelity); the 5:1 step of the use case is preserved.
            rig(50, 10); meta.update(down=50, up=10, steps=[[18, 10, 2], [42, 50, 10]], scaled_from="100->20->100")
            config(cfg, 50, 10, out)
            T0[0] = time.time(); mark("start")
            call("laptop", 78, os.path.join(out, "call.csv"))
            time.sleep(3)
            bulk("pc", 75, os.path.join(out, "bulk.json"), n=6)
            time.sleep(15); set_rate(10, 2); mark("rate_down", down=10, up=2)
            time.sleep(24); set_rate(50, 10); mark("rate_up", down=50, up=10)
            time.sleep(36)
        elif scn == "S3":
            rig(20, 4); meta.update(down=20, up=4)
            config(cfg, 20, 4, out)
            T0[0] = time.time(); mark("start")
            game("gamer", 40, os.path.join(out, "game.csv"))
            time.sleep(6); mark("load_on")
            for i, h in enumerate(("tv1", "tv2", "tv3")):
                tv(h, 34, os.path.join(out, "%s.csv" % h), h)
            time.sleep(35)
        elif scn == "S4":
            # intent lease + abusive boost + starvation stress + kernel-enforced expiry with the controller dead
            rig(20, 4); meta.update(down=20, up=4)
            config(cfg, 20, 4, out, watchdog=False)
            T0[0] = time.time(); mark("start")
            bulk("pc", 28, os.path.join(out, "bulk.json"), n=4)                       # low priority victim
            for h in ("tv1", "tv2"):
                tv(h, 40, os.path.join(out, "%s.csv" % h), h)
            time.sleep(8)
            ttl = 16
            r = api("POST", "/v1/intents", {"device": "10.0.0.10", "cls": "call", "ttl": ttl, "owner": "alice", "reason": "work call"})
            mark("lease_granted", resp=r, ttl=ttl)
            t_grant = time.time()
            meta["lease_reject"] = api("POST", "/v1/intents", {"device": "10.0.0.11", "cls": "call", "ttl": 99999, "owner": "bob"})
            call("laptop", 20, os.path.join(out, "call.csv"), dport=443)
            bulk("laptop", 16, os.path.join(out, "abuse.json"), n=8, port=5202)       # boosted device abuses its lease
            time.sleep(7)
            CTL[0].kill(); sh("pkill -9 -f halo.controller"); mark("controller_killed")
            seen_gone = None
            while time.time() - t_grant < ttl + 6:
                s = sh("ip netns exec gw nft list set inet halo intent_mac")
                if "elements" not in s:
                    seen_gone = time.time(); break
                time.sleep(0.1)
            mark("lease_expired_in_kernel", after_grant_s=round((seen_gone or 0) - t_grant, 3), ttl=ttl)
            time.sleep(max(0, 34 - (time.time() - T0[0])))
        elif scn == "S6":
            rig(20, 4); meta.update(down=20, up=4)
            config(cfg, 20, 4, out)
            T0[0] = time.time(); mark("start")
            call("laptop", 40, os.path.join(out, "call.csv"))
            bulk("pc", 34, os.path.join(out, "bulk.json"), n=8)
            time.sleep(12)
            meta["shield_reject"] = api("POST", "/v1/policy", {"rate_dl": 5000})          # out of bounds -> shield rejects
            mark("bad_policy", req={"rate_dl": 2.0, "autorate": 0, "note": "bad policy: 2 Mbit/s clamp"})
            meta["bad_policy_resp"] = api("POST", "/v1/policy", {"rate_dl": 2.0, "autorate": 0, "note": "bad policy: 2 Mbit/s clamp"})
            time.sleep(12)
            snapshot(out, "after_rollback")
            mark("kill9")
            CTL[0].kill(); sh("pkill -9 -f halo.controller")
            time.sleep(6)
            snapshot(out, "after_safe")
            for f in ("watchdog_trip.json", "safe.json"):
                if os.path.exists("/run/halo/" + f):
                    shutil.copy("/run/halo/" + f, out)
            time.sleep(4)
        elif scn.startswith("EST"):
            c = float(scn[3:])
            rig(c, c / 5); meta.update(down=c, up=c / 5, plan_dl=round(1.3 * c, 2))
            config(cfg, 1.3 * c, 0.26 * c, out)     # plan 30 % above the true capacity: the estimator must find it
            T0[0] = time.time(); mark("start")
            bulk("pc", 30, os.path.join(out, "bulk.json"), n=8)
            time.sleep(31)
        elif scn == "CPU":
            rig(50, 10); meta.update(down=50, up=10)
            config(cfg, 50, 10, out)
            T0[0] = time.time(); mark("start")
            call("laptop", 30, os.path.join(out, "call.csv"))
            bulk("pc", 30, os.path.join(out, "bulk.json"), n=8)
            time.sleep(8)
            th0 = cpu_threads()
            c0, s0, t0 = cpu_of(None), open("/proc/stat").readline().split(), time.time()
            time.sleep(20)
            c1, s1, t1 = cpu_of(None), open("/proc/stat").readline().split(), time.time()
            th1 = cpu_threads()
            tot = sum(int(b) - int(a) for a, b in zip(s0[1:9], s1[1:9]))
            meta["cpu"] = {"ctl_cpu_s": c1 - c0, "wall_s": t1 - t0, "ctl_pct_of_core": 100 * (c1 - c0) / (t1 - t0),
                           "softirq_pct": 100 * (int(s1[7]) - int(s0[7])) / tot, "idle_pct": 100 * (int(s1[4]) - int(s0[4])) / tot,
                           "ncpu": os.cpu_count(),
                           "threads_pct": {k: round(100 * (th1[k] - th0.get(k, 0.0)) / (t1 - t0), 3) for k in th1}}
            time.sleep(3)
        elif scn == "DATAGEN":
            # labelled flows for the classifier: randomised parameters, ports and link conditions per batch (= session)
            link = random.choice([(10, 2), (20, 4), (20, 4), (50, 10)])
            rig(*link); meta.update(down=link[0], up=link[1])
            config("C2", link[0], link[1], out, extra="--collect")
            T0[0] = time.time()
            env = {"HALO_BATCH": "b%03d" % rep}
            n_gen0 = len(procs)                    # generators of this batch = procs[n_gen0:]
            sp = 20000
            for k in range(4):
                h = random.choice(["laptop", "gamer", "tv1", "tv2", "tv3", "pc"])
                d = random.choice([W4, W4, W6])
                std = random.random() < 0.55
                gen(h, "rt_client --dst %s --dport %d --sport %d --pps_up %d --size_up %d --pps_down %d --size_down %d --dur 12 "
                    "--cls call --sid c%d --seed %d --out /tmp/dg_c%d.csv" % (
                        d, random.choice([3478, 3479, 16400]) if std else random.choice([443, 4500, 50001, 50002]), sp + k,
                        random.choice([50, 50, 60, 100, 120, 150]), random.choice([120, 172, 220, 700, 950, 1100]),
                        random.choice([50, 50, 60, 100, 150, 170]), random.choice([120, 172, 220, 800, 1000, 1150]),
                        k, seed + k, k), env=env)
            for k in range(4):
                h = random.choice(["laptop", "gamer", "pc"])
                d = random.choice([W4, W4, W6])
                std = random.random() < 0.5
                gen(h, "rt_client --dst %s --dport %d --sport %d --pps_up %d --size_up %d --pps_down %d --size_down %d --dur 12 "
                    "--cls gaming --sid g%d --seed %d --out /tmp/dg_g%d.csv" % (
                        d, random.choice([27015, 3074]) if std else random.choice([443, 50003, 50004, 4500]), sp + 100 + k,
                        random.choice([20, 30, 60, 64, 128]), random.choice([60, 80, 90, 110]),
                        random.choice([20, 30, 60, 64, 128]), random.choice([90, 140, 200, 320]), k, seed + 10 + k, k), env=env)
            for k in range(3):
                h = random.choice(["tv1", "tv2", "tv3", "laptop"])
                gen(h, "tv_client --dst %s --dport %d --sport %d --seg %s --dur 12 --sid s%d --ladder %s --out /tmp/dg_s%d.csv" % (
                    random.choice([W4, W4, W6]), random.choice([443, 443, 8080]), sp + 200 + k, random.choice([2, 2, 3, 4]), k,
                    random.choice(["1.5 3 5", "0.8 1.5 3", "3 5 8", "1.5 3 5 8"]), k), env=env)
            for k in range(random.choice([1, 2, 3])):
                h = random.choice(["pc", "laptop", "tv3"])
                up = random.random() < 0.3
                gen(h, "bulk_client --dst %s --dport %d --sport %d --dur 12 --sid b%d %s" % (
                    random.choice([W4, W4, W6]), random.choice([443, 443, 80, 8080, 6881]), sp + 300 + k, k, "--upload" if up else ""), env=env)
            for k in range(3):
                gen(random.choice(["laptop", "pc", "gamer"]), "web_client --dst %s --dport %d --dur 12 --sid w%d --seed %d" % (
                    random.choice([W4, W6]), random.choice([443, 443, 80]), k, seed + 50 + k), env=env)
            # Generators start 10-27 s after T0 in the emulated VM (r05: 21.5 s, r23: 27 s), so a fixed 22 s window
            # copied a truncated labels.jsonl and killed the controller while flows were still running (never dumped).
            # Wait for every generator to exit, then let the controller dump idle flows (>= 2 bins and idle > 3 s,
            # with conntrack polls taking ~2-4 s in the VM) before labels are copied and everything is killed.
            deadline = time.time() + 90
            for p in procs[n_gen0:]:
                try:
                    p.wait(timeout=max(0.1, deadline - time.time()))
                except subprocess.TimeoutExpired:
                    pass
            mark("generators_done", still_running=sum(p.poll() is None for p in procs[n_gen0:]))
            time.sleep(12)
            if os.path.exists("/tmp/halo_labels.jsonl"):
                shutil.copy("/tmp/halo_labels.jsonl", os.path.join(out, "labels.jsonl"))
        else:
            raise SystemExit("unknown scenario " + scn)
        time.sleep(2.5)                            # let generators flush their logs
        mark("end")
        if cfg != "C0":
            snapshot(out)
        if os.path.exists("/run/halo/flows.json"):
            shutil.copy("/run/halo/flows.json", out)
        if os.path.isdir("/tmp/halo_rt"):
            shutil.copytree("/tmp/halo_rt", os.path.join(out, "rt_up"), dirs_exist_ok=True)
    finally:
        json.dump(meta, open(os.path.join(out, "meta.json"), "w"), indent=1)
        kill_all()
    print("done", out)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *a: (kill_all(), sys.exit(1)))
    main()
