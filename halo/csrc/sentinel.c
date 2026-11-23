/* HALO-Walk calm-mode sentinel (M12): an in-process pthread that does the controller's calm-mode housekeeping without
 * waking the Python interpreter:
 *   - the low-rate OWD probes (sendto / ppoll / recvmsg with kernel RX timestamps) on its own sockets,
 *   - per-sample OWD-vs-baseline delay detection (+ the confirmation burst of halo/probe_gov.py),
 *   - late-probe detection, the byte counters of the WAN device (arrival rate EWMA, running peak),
 *     arrival-collapse and probe-up-imminent detection,
 *   - the telemetry lines and the heartbeat (the heartbeat is GATED on a liveness counter the Python main loop bumps:
 *     a hung interpreter stops the heartbeat, so the watchdog still trips).
 * It parks (no wakeups at all) while disarmed; Python wakes only on an alert (eventfd) or on its own slow sync tick.
 * Probe samples, ach samples and telemetry text are queued and replayed by Python in batches, so the estimator sees
 * the same inputs as in the pure-Python path.  Build: `make -C <repo>` (see docs/SETUP_HALO.md).
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <endian.h>

#define MAXR 8
#define MAXPEND 64
#define RING 4096
#define TELCAP 65536
#define MAGIC 0x48414C4Fu

enum { EV_PROBE = 1, EV_ACH = 2, EV_LATE = 3, EV_BURST = 4, EV_FAST = 5, EV_LOST = 6, EV_DROP_CONFIRMED = 7 };
enum { AL_NONE = 0, AL_DELAY = 1, AL_LATE = 2, AL_COLLAPSE = 3, AL_PROBEUP = 4, AL_ERROR = 5 };

typedef struct { double t, a, b; int32_t kind, ri; } hs_event;            /* 32 bytes */

typedef struct {                                                           /* mirrored by ctypes (halo/sentinel.py) */
    double tick_s, probe_s, thresh_ms, late_s, confirm_win, base_alpha, peak_tau, gate_s;
    double ewma_alpha_ref, ewma_dt_ref;
    double rate[2], rmax[2], c_est[2], hold_until[2], ach[2], peak[2], last_delta[2];
    double probe_gate[2], collapse, sat_frac, burst_max;
    double base_ul[MAXR], base_dl[MAXR];
    int32_t has_base_ul[MAXR], has_base_dl[MAXR];
    int32_t confirm_n, rr;
    char st[2][16];
    char fsm[16];
} hs_params;

typedef struct {
    double ach[2], peak[2], last_delta[2], t_counters;
    double dl_collapse_at;
    uint64_t rx, tx;
    int32_t alert, armed;
} hs_state;

typedef struct { uint32_t seq; double ts; int ri; int late; int used; } pend_t;

static struct {
    pthread_t th; int started;
    pthread_mutex_t mu; pthread_cond_t cv;
    int armed, parked, stop, fast, burst; unsigned gen; double fast_s, late_s;
    int nsock, socks[MAXR];
    int cefd, efd;                    /* control wake (python->C), alert wake (C->python) */
    int fd_rx, fd_tx, fd_hb;
    hs_params p; hs_state st;
    hs_event ring[RING]; int rhead, rtail;
    char tel[TELCAP]; int tlen;
    volatile uint64_t live; uint64_t last_live; double last_live_t;
    int hb_len;
} G = { .mu = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER, .cefd = -1, .efd = -1,
        .fd_rx = -1, .fd_tx = -1, .fd_hb = -1, .parked = 1 };

static double rt(void) { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts); return ts.tv_sec + ts.tv_nsec * 1e-9; }

static void push(int kind, double t, double a, double b, int ri) {          /* caller holds no lock */
    pthread_mutex_lock(&G.mu);
    int nh = (G.rhead + 1) % RING;
    if (nh == G.rtail) G.rtail = (G.rtail + 1) % RING;                      /* overwrite oldest */
    G.ring[G.rhead] = (hs_event){ t, a, b, kind, ri };
    G.rhead = nh;
    pthread_mutex_unlock(&G.mu);
}

static uint64_t rd_ctr(int fd) {
    char b[32]; ssize_t n = pread(fd, b, sizeof b - 1, 0);
    if (n <= 0) return 0;
    b[n] = 0; return strtoull(b, NULL, 10);
}

static void raise_alert(int code) {
    pthread_mutex_lock(&G.mu);
    G.st.alert = code; G.armed = 0;
    pthread_mutex_unlock(&G.mu);
    uint64_t one = 1; if (write(G.efd, &one, 8) < 0) { }
}

static void send_probe(int ri, uint32_t *seqc, pend_t *pend) {
    unsigned char pk[16]; double ts = rt(); uint32_t seq = (*seqc)++;
    uint32_t m = htobe32(MAGIC), s = htobe32(seq); uint64_t tb; memcpy(&tb, &ts, 8); tb = htobe64(tb);
    memcpy(pk, &m, 4); memcpy(pk + 4, &s, 4); memcpy(pk + 8, &tb, 8);
    if (send(G.socks[ri], pk, 16, MSG_DONTWAIT) < 0) return;
    for (int i = 0; i < MAXPEND; i++) if (!pend[i].used) { pend[i] = (pend_t){ seq, ts, ri, 0, 1 }; return; }
}

static void confirm_burst(double now, uint32_t *seqc, pend_t *pend) {
    push(EV_BURST, now, 0, 0, 0);
    for (int j = 0; j < G.nsock; j++) send_probe(j, seqc, pend);
}

static double probe_deadline(const hs_params *p, int ri, double ordinary, int drop_check) {
    if (!drop_check || !p->has_base_ul[ri] || !p->has_base_dl[ri]) return ordinary;
    double baseline_rtt = (p->base_ul[ri] + p->base_dl[ri]) / 1000;
    return fmin(ordinary, fmax(0.05, baseline_rtt + 2 * p->thresh_ms / 1000));
}

/* Two modes while armed. CALM: counters and telemetry every tick_s, gated heartbeats,
 * probes at probe_s, and confirmation bursts when conditions change.
 * FAST: full-rate probing (fast_s) only; samples, late and lost probes are queued for Python, which runs the control loop
 * at its own tick and decides when calm returns (hs_arm).  An alert in CALM switches to FAST by itself, without a gap. */
void *sentinel_thread(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "halo-sentinel", 0, 0, 0);
    setpriority(PRIO_PROCESS, (id_t)syscall(SYS_gettid), -5);              /* like the rate loop; best effort */
    uint32_t seqc = 1u << 28;
    pend_t pend[MAXPEND]; memset(pend, 0, sizeof pend);
    unsigned rr_fast = 0;
    for (;;) {
        pthread_mutex_lock(&G.mu);
        while (!G.armed && !G.stop) { G.parked = 1; pthread_cond_broadcast(&G.cv); pthread_cond_wait(&G.cv, &G.mu); }
        if (G.stop) { G.parked = 1; pthread_cond_broadcast(&G.cv); pthread_mutex_unlock(&G.mu); break; }
        G.parked = 0;
        hs_params p = G.p;
        unsigned mygen = G.gen;
        int fast = G.fast;
        pthread_mutex_unlock(&G.mu);

        unsigned char junk[64];
        for (int i = 0; i < G.nsock; i++) while (recv(G.socks[i], junk, sizeof junk, MSG_DONTWAIT) > 0) { }
        memset(pend, 0, sizeof pend);
        { uint64_t x; if (read(G.cefd, &x, 8) < 0) { } }
        double now = rt(), next_tick = now + p.tick_s, last_probe = now - p.probe_s, next_fprobe = now;
        double confirm_until = 0, watch_until = 0, dl_delay_since = 0, dl_collapse_at = 0;
        double next_heartbeat = now, drop_check_until = 0, late_check_at = 0;
        int confirm_bad[2] = {0, 0};
        uint64_t rx = G.fd_rx >= 0 ? rd_ctr(G.fd_rx) : 0, tx = G.fd_tx >= 0 ? rd_ctr(G.fd_tx) : 0;
        double t_last = now, ach[2] = { p.ach[0], p.ach[1] }, peak[2] = { p.peak[0], p.peak[1] }, ld[2] = { p.last_delta[0], p.last_delta[1] };
        pthread_mutex_lock(&G.mu); G.last_live = G.live; G.last_live_t = now; pthread_mutex_unlock(&G.mu);
        int alert = 0, parked = 0;
        unsigned int delayed_reflectors = 0, late_reflectors = 0;
        double early_late[MAXR] = {0}, late_age[MAXR] = {0};

        for (;;) {
            pthread_mutex_lock(&G.mu);
            int go = G.armed && !G.stop && G.gen == mygen, gfast = G.fast, burst = G.burst;
            double fs = G.fast_s, late_s = fast || G.fast ? G.late_s : p.late_s;
            G.burst = 0;
            pthread_mutex_unlock(&G.mu);
            if (!go) { parked = !G.armed || G.stop; break; }
            now = rt();
            if (gfast && !fast) { fast = 1; next_fprobe = now; }          /* Python asked for the full rate */
            if (burst) for (int j = 0; j < G.nsock; j++) send_probe(j, &seqc, pend);
            if (fast && now >= next_fprobe && G.nsock > 0) {
                send_probe(rr_fast++ % G.nsock, &seqc, pend);
                next_fprobe += fs; if (next_fprobe < now) next_fprobe = now + fs;
            }
            double tmo = fast ? next_fprobe - now : next_tick - now;
            int drop_check = !fast && now < drop_check_until;
            int pending_by_socket[MAXR] = {0};
            for (int i = 0; i < MAXPEND; i++) {
                if (!pend[i].used) continue;
                pending_by_socket[pend[i].ri]++;
                double deadline = probe_deadline(&p, pend[i].ri, late_s, drop_check && pend[i].ts >= dl_collapse_at);
                double d = pend[i].ts + (pend[i].late ? 1.0 : deadline) - now;
                if (d < tmo) tmo = d;
            }
            if (tmo < 0) tmo = 0;
            /* CALM: replies are not waited for (their kernel RX timestamps carry the timing); they are collected at the next
             * tick, so a calm second costs tick_s^-1 wakeups, not tick + 2 x probe replies.  Only while a confirmation
             * burst is out (watch_until) or in FAST mode are the sockets polled. */
            struct pollfd pf[MAXR + 1];
            int watch = fast || now < watch_until, nf = 1;
            pf[0] = (struct pollfd){ G.cefd, POLLIN, 0 };
            if (watch) for (int i = 0; i < G.nsock; i++)
                pf[nf++] = (struct pollfd){ pending_by_socket[i] ? G.socks[i] : -1, POLLIN, 0 };
            if (!fast && watch && watch_until - now < tmo) tmo = watch_until - now;
            tmo += 0.0001;  /* avoid early timer wakes */
            struct timespec to = { (time_t)tmo, (long)((tmo - (time_t)tmo) * 1e9) };
            int rc = ppoll(pf, nf, &to, NULL);
            if (rc < 0 && errno != EINTR) { alert = AL_ERROR; break; }
            if (rc > 0 && (pf[0].revents & POLLIN)) { uint64_t x; if (read(G.cefd, &x, 8) < 0) { } continue; }
            /* a reply that is already in the socket buffer must never be taken for a late probe: collect before judging */
            now = rt();
            drop_check = !fast && now < drop_check_until;
            int collect = fast || watch || now >= next_tick - 0.002;
            for (int i = 0; i < MAXPEND && !collect; i++)
                if (pend[i].used && !pend[i].late && now - pend[i].ts > late_s - 0.05) collect = 1;
            for (int i = 0; i < G.nsock && collect; i++) {
                while (pending_by_socket[i] > 0) {
                    unsigned char d[64], cb[128]; struct iovec iv = { d, sizeof d };
                    struct msghdr mh = { .msg_iov = &iv, .msg_iovlen = 1, .msg_control = cb, .msg_controllen = sizeof cb };
                    ssize_t n = recvmsg(G.socks[i], &mh, MSG_DONTWAIT);
                    if (n < 0) break;
                    double tr = rt();
                    for (struct cmsghdr *c = CMSG_FIRSTHDR(&mh); c; c = CMSG_NXTHDR(&mh, c))
                        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_TIMESTAMPNS) {
                            struct timespec kt; memcpy(&kt, CMSG_DATA(c), sizeof kt); tr = kt.tv_sec + kt.tv_nsec * 1e-9;
                        }
                    if (n < 24) continue;
                    uint32_t m, sq; uint64_t b1, b2; double ts, tref;
                    memcpy(&m, d, 4); memcpy(&sq, d + 4, 4); memcpy(&b1, d + 8, 8); memcpy(&b2, d + 16, 8);
                    m = be32toh(m); sq = be32toh(sq); b1 = be64toh(b1); b2 = be64toh(b2); memcpy(&ts, &b1, 8); memcpy(&tref, &b2, 8);
                    if (m != MAGIC) continue;
                    int k = -1;
                    for (int j = 0; j < MAXPEND; j++) {
                        if (pend[j].used && pend[j].ri == i && pend[j].seq == sq) { k = j; break; }
                    }
                    if (k < 0) continue;
                    pend[k].used = 0;
                    pending_by_socket[i]--;
                    int ri = i;
                    double up = (tref - ts) * 1e3, dn = (tr - tref) * 1e3;
                    push(EV_PROBE, tr, up, dn, ri);
                    if (fast || now - tr > p.confirm_win) continue;
                    if (drop_check) {
                        if (pend[k].ts >= dl_collapse_at && p.has_base_dl[ri] && dn - p.base_dl[ri] > p.thresh_ms)
                            delayed_reflectors |= 1u << ri;
                        continue;
                    }
                    double du, dd;
                    /* same baseline rule as DirEstimator.on_probe (min, slow upward drift) */
                    if (!p.has_base_ul[ri] || up < p.base_ul[ri]) { p.base_ul[ri] = up; p.has_base_ul[ri] = 1; } else p.base_ul[ri] += p.base_alpha * (up - p.base_ul[ri]);
                    if (!p.has_base_dl[ri] || dn < p.base_dl[ri]) { p.base_dl[ri] = dn; p.has_base_dl[ri] = 1; } else p.base_dl[ri] += p.base_alpha * (dn - p.base_dl[ri]);
                    du = up - p.base_ul[ri]; dd = dn - p.base_dl[ri];
                    ld[1] = du; ld[0] = dd;
                    int dl_delayed = dd > p.thresh_ms;
                    int ul_delayed = du > p.thresh_ms;
                    if (!dl_delayed) dl_delay_since = 0;
                    else if (!dl_delay_since) dl_delay_since = tr;
                    /* The downlink still delivers the shaped rate. Give a brief queue the estimator's
                     * burst window to drain. A delivery collapse is checked separately on every tick. */
                    if (p.sat_frac > 0 && ach[0] >= p.sat_frac * p.rate[0] && tr - dl_delay_since < p.burst_max)
                        dl_delayed = 0;
                    if (dl_delayed || ul_delayed) {
                        double tn = rt();
                        if (tr < confirm_until) {
                            confirm_bad[0] += dl_delayed;
                            confirm_bad[1] += ul_delayed;
                            if (!alert && (confirm_bad[0] >= p.confirm_n || confirm_bad[1] >= p.confirm_n)) {
                                push(EV_FAST, tn, 0, 0, 0);
                                alert = confirm_bad[0] >= p.confirm_n && dl_collapse_at > 0 ? AL_COLLAPSE : AL_DELAY;
                            }
                        } else {
                            confirm_until = tr + p.confirm_win;
                            confirm_bad[0] = confirm_bad[1] = 0;
                            watch_until = tn + p.confirm_win;
                            dl_collapse_at = 0;
                            confirm_burst(tn, &seqc, pend);
                        }
                    }
                }
            }
            now = rt();
            /* The deadline can expire while the thread is waiting or descheduled. */
            drop_check = !fast && now < drop_check_until;
            if (late_check_at && now - late_check_at > late_s + p.confirm_win) late_check_at = 0;
            for (int i = 0; i < MAXPEND; i++) {
                if (!pend[i].used) continue;
                double age = now - pend[i].ts;
                int drop_probe = drop_check && pend[i].ts >= dl_collapse_at;
                double deadline = probe_deadline(&p, pend[i].ri, late_s, drop_probe);
                if (!pend[i].late && age > deadline) {
                    pend[i].late = 1;
                    if (deadline < late_s) {
                        early_late[pend[i].ri] = age * 1e3;
                        delayed_reflectors |= 1u << pend[i].ri;
                    } else if (fast) {
                        push(EV_LATE, now, age * 1e3, 0, pend[i].ri);
                    } else if (!drop_check && !late_check_at) {
                        /* One missing reply can be a reflector fault. Check the other paths
                         * in this thread so an isolated loss cannot create a queue vote. */
                        late_check_at = now;
                        late_reflectors = 0;
                        memset(late_age, 0, sizeof late_age);
                        watch_until = fmax(watch_until, now + late_s + 0.05);
                        confirm_burst(now, &seqc, pend);
                    } else if (!drop_check && pend[i].ts >= late_check_at) {
                        late_reflectors |= 1u << pend[i].ri;
                        late_age[pend[i].ri] = age * 1e3;
                    }
                } else if (pend[i].late && age > 1.0) {
                    push(EV_LOST, now, age * 1e3, !fast, pend[i].ri); pend[i].used = 0;
                }
            }
            if (drop_check && __builtin_popcount(delayed_reflectors) >= p.confirm_n) {
                double dt = now - t_last;
                uint64_t nrx = rx;
                double arrival = ach[0];
                if (dt >= 0.04) {
                    nrx = rd_ctr(G.fd_rx);
                    arrival = (double)(nrx - rx) * 8 / dt / 1e6;
                }
                if (arrival >= 0.5 * p.rate[0]) {
                    /* A mixed counter window can start a check. Bypassing the
                     * normal confirmation requires a severe drop in fresh bytes. */
                    drop_check_until = 0;
                    for (int i = 0; i < MAXPEND; i++)
                        if (pend[i].used && pend[i].ts >= dl_collapse_at && early_late[pend[i].ri] > 0)
                            pend[i].late = 0;
                    if (arrival >= p.collapse * p.rate[0]) {
                        dl_collapse_at = 0;
                        watch_until = 0;
                    } else {
                        confirm_until = watch_until;
                        confirm_bad[0] = confirm_bad[1] = 0;
                    }
                } else {
                    if (dt >= 0.04 && arrival >= 0.10 * p.rate[0]) {
                        /* The interval after the drop excludes the prior operating
                         * rate, which would otherwise linger in the smoothed estimate. */
                        uint64_t ntx = rd_ctr(G.fd_tx);
                        ach[0] = arrival;
                        ach[1] += (1.0 - pow(1.0 - p.ewma_alpha_ref, dt / p.ewma_dt_ref))
                                * ((double)(ntx - tx) * 8 / dt / 1e6 - ach[1]);
                        rx = nrx; tx = ntx; t_last = now;
                        push(EV_ACH, now, ach[0], ach[1], 0);
                    }
                    for (int i = 0; i < G.nsock; i++)
                        if (early_late[i] > 0) push(EV_LATE, now, early_late[i], 1, i);
                    push(EV_DROP_CONFIRMED, now, dl_collapse_at, 0, 0);
                    alert = AL_COLLAPSE;
                }
            }
            if (!fast && !alert && !drop_check && late_check_at && __builtin_popcount(late_reflectors) >= p.confirm_n) {
                for (int i = 0; i < G.nsock; i++)
                    if (late_age[i] > 0) push(EV_LATE, now, late_age[i], 0, i);
                alert = AL_LATE;
            }
            if (!fast && !alert && now >= next_tick) {
                next_tick += p.tick_s; if (next_tick < now) next_tick = now + p.tick_s;
                double dt = now - t_last; if (dt < 1e-3) dt = 1e-3;
                uint64_t nrx = G.fd_rx >= 0 ? rd_ctr(G.fd_rx) : rx, ntx = G.fd_tx >= 0 ? rd_ctr(G.fd_tx) : tx;
                double inst[2] = { (double)(nrx - rx) * 8 / dt / 1e6, (double)(ntx - tx) * 8 / dt / 1e6 };
                rx = nrx; tx = ntx; t_last = now;
                double al = 1.0 - pow(1.0 - p.ewma_alpha_ref, dt / p.ewma_dt_ref);
                for (int d = 0; d < 2; d++) {
                    ach[d] += al * (inst[d] - ach[d]);
                    double dec = peak[d] * exp(-dt / p.peak_tau); peak[d] = ach[d] > dec ? ach[d] : dec;
                }
                push(EV_ACH, now, ach[0], ach[1], 0);
                pthread_mutex_lock(&G.mu);
                if (G.tlen < TELCAP - 256)
                    G.tlen += snprintf(G.tel + G.tlen, TELCAP - G.tlen, "%.3f,%.3f,%.3f,%.3f,%.3f,%s,%s,%.3f,%.3f,%.2f,%.2f,%d,%d,%s\n",
                        now, p.rate[0], p.rate[1], p.c_est[0], p.c_est[1], p.st[0], p.st[1], ach[0], ach[1], ld[0], ld[1], 0, 0, p.fsm);
                G.st.ach[0] = ach[0]; G.st.ach[1] = ach[1]; G.st.peak[0] = peak[0]; G.st.peak[1] = peak[1];
                G.st.last_delta[0] = ld[0]; G.st.last_delta[1] = ld[1]; G.st.rx = rx; G.st.tx = tx; G.st.t_counters = now;
                uint64_t lv = G.live;
                if (lv != G.last_live) { G.last_live = lv; G.last_live_t = now; }
                int fresh = now - G.last_live_t <= p.gate_s;
                pthread_mutex_unlock(&G.mu);
                if (fresh && G.fd_hb >= 0 && now >= next_heartbeat) {
                    char hb[48]; int n = snprintf(hb, sizeof hb, "%.3f %s", now, p.fsm);
                    if (pwrite(G.fd_hb, hb, n, 0) == n) {
                        if (n != G.hb_len && ftruncate(G.fd_hb, n) == 0) G.hb_len = n;
                        next_heartbeat = now + fmin(0.5, p.gate_s / 2.0);
                    }
                }
                int drop[2] = {0, 0};
                for (int d = 0; d < 2; d++) {
                    drop[d] = peak[d] > 0.5 * p.rate[d] && ach[d] >= 0.10 * p.rate[d]
                              && ach[d] < p.collapse * p.rate[d] && ach[d] <= 0.8 * peak[d];
                    if (!drop[d] && p.rate[d] < 0.999 * p.rmax[d] && ach[d] >= p.probe_gate[d]
                            && now >= p.hold_until[d] - 0.5) alert = AL_PROBEUP;
                }
                /* Qualify a sharp delivery drop in the native watcher. A sender finishing can
                 * lower the counters without congestion and does not need the Python fast loop. */
                if (!alert && !drop_check && drop[0] && inst[0] < p.collapse * p.rate[0]
                        && (now >= watch_until || inst[0] < 0.5 * p.rate[0])) {
                    dl_collapse_at = now;
                    drop_check_until = watch_until = now + p.confirm_win;
                    delayed_reflectors = 0;
                    memset(early_late, 0, sizeof early_late);
                    confirm_burst(now, &seqc, pend);
                } else if (!alert && (drop[0] || drop[1]) && now >= watch_until) {
                    dl_collapse_at = drop[0] ? now : 0;
                    confirm_until = watch_until = now + p.confirm_win;
                    confirm_bad[0] = confirm_bad[1] = 0;
                    confirm_burst(now, &seqc, pend);
                }
                if (!alert && now - last_probe >= p.probe_s - 0.5 * p.tick_s && G.nsock > 0) {
                    last_probe = now; send_probe(p.rr % G.nsock, &seqc, pend); p.rr++;
                }
            }
            if (alert == AL_ERROR) break;
            if (alert) {                                                    /* calm -> full rate, no gap; Python decides when calm returns */
                pthread_mutex_lock(&G.mu);
                G.st.rx = rx; G.st.tx = tx; G.st.t_counters = t_last;
                G.st.ach[0] = ach[0]; G.st.ach[1] = ach[1]; G.st.peak[0] = peak[0]; G.st.peak[1] = peak[1];
                G.st.alert = alert; G.st.dl_collapse_at = dl_collapse_at; G.fast = 1; fs = G.fast_s;
                pthread_mutex_unlock(&G.mu);
                if (alert != AL_DELAY && alert != AL_COLLAPSE)
                    for (int j = 0; j < G.nsock; j++) send_probe(j, &seqc, pend);
                fast = 1; alert = 0; next_fprobe = now + fs;
                uint64_t one = 1; if (write(G.efd, &one, 8) < 0) { }
            }
        }
        pthread_mutex_lock(&G.mu);
        G.st.rx = rx; G.st.tx = tx; G.st.t_counters = t_last;
        G.st.ach[0] = ach[0]; G.st.ach[1] = ach[1]; G.st.peak[0] = peak[0]; G.st.peak[1] = peak[1];
        G.st.last_delta[0] = ld[0]; G.st.last_delta[1] = ld[1];
        pthread_mutex_unlock(&G.mu);
        if (alert) raise_alert(alert);                                      /* AL_ERROR: park, Python falls back */
        if (parked || alert) { pthread_mutex_lock(&G.mu); G.armed = 0; G.parked = 1; pthread_cond_broadcast(&G.cv); pthread_mutex_unlock(&G.mu); }
    }
    return NULL;
}

/* ------------------------------------------------------------------ conntrack accounting (slow loop)
 * One ctnetlink dump, parsed and matched against the flow keys Python is tracking, entirely in C: the Python parser of
 * halo/controller.py walks every conntrack entry attribute by attribute (ms of emulated CPU per dump).  Same orientation
 * rule as controller.ct_entry_t: counters are returned (up_bytes, dn_bytes, up_pkts, dn_pkts) LAN-first. */
typedef struct { uint8_t proto, v6, pad0, pad1; uint16_t lport, wport; uint8_t lan[16], wan[16]; } hs_ckey;   /* 40 bytes */
typedef struct { uint64_t up_b, dn_b, up_p, dn_p; int32_t found, pad; } hs_cval;                              /* 40 bytes */

static int ct_match(const hs_ckey *k, hs_cval *v, int is6, const uint8_t *src, const uint8_t *dst, int proto, int sp, int dp,
                    uint64_t po, uint64_t bo, uint64_t pr, uint64_t br) {
    if (k->proto != proto || k->v6 != is6) return 0;
    int len = is6 ? 16 : 4;
    if (!memcmp(k->lan, src, len) && !memcmp(k->wan, dst, len) && k->lport == sp && k->wport == dp) {
        v->up_b = bo; v->dn_b = br; v->up_p = po; v->dn_p = pr; v->found = 1; return 1;
    }
    if (!memcmp(k->lan, dst, len) && !memcmp(k->wan, src, len) && k->lport == dp && k->wport == sp) {
        v->up_b = br; v->dn_b = bo; v->up_p = pr; v->dn_p = po; v->found = 1; return 1;
    }
    return 0;
}

static uint64_t be64p(const uint8_t *p) { uint64_t x; memcpy(&x, p, 8); return be64toh(x); }

/* parses one recv() buffer of ctnetlink messages; returns 1 once NLMSG_DONE / NLMSG_ERROR was seen */
int hs_ct_parse(const uint8_t *buf, long len, const hs_ckey *keys, int n, hs_cval *vals) {
    int done = 0;
    for (size_t off = 0; off + 16 <= (size_t)len; ) {
        uint32_t ml; uint16_t mt; memcpy(&ml, buf + off, 4); memcpy(&mt, buf + off + 4, 2);
        if (ml < 16 || off + ml > (size_t)len) break;
        if (mt == 3 || mt == 2) { done = 1; break; }
        if (mt == 256 && ml >= 20) {
            int is6 = 0, proto = -1, sp = -1, dp = -1, have_ip = 0;
            uint8_t src[16] = { 0 }, dst[16] = { 0 };
            uint64_t po = 0, bo = 0, pr = 0, br = 0;
            size_t a = off + 20, end = off + ml;
            while (a + 4 <= end) {
                uint16_t al, at; memcpy(&al, buf + a, 2); memcpy(&at, buf + a + 2, 2); at &= 0x3FFF;
                if (al < 4) break;
                if (at == 1) {                                          /* CTA_TUPLE_ORIG */
                    for (size_t b = a + 4; b + 4 <= a + al; ) {
                        uint16_t bl, bt; memcpy(&bl, buf + b, 2); memcpy(&bt, buf + b + 2, 2); bt &= 0x3FFF;
                        if (bl < 4) break;
                        for (size_t c = b + 4; c + 4 <= b + bl; ) {
                            uint16_t cl, ct; memcpy(&cl, buf + c, 2); memcpy(&ct, buf + c + 2, 2); ct &= 0x3FFF;
                            if (cl < 4) break;
                            const uint8_t *d = buf + c + 4;
                            if (bt == 1) {                              /* CTA_TUPLE_IP */
                                if (ct == 1 && cl >= 8) { memcpy(src, d, 4); is6 = 0; have_ip = 1; }
                                else if (ct == 2 && cl >= 8) memcpy(dst, d, 4);
                                else if (ct == 3 && cl >= 20) { memcpy(src, d, 16); is6 = 1; have_ip = 1; }
                                else if (ct == 4 && cl >= 20) memcpy(dst, d, 16);
                            } else if (bt == 2) {                       /* CTA_TUPLE_PROTO */
                                uint16_t pp;
                                if (ct == 1) proto = d[0];
                                else if (ct == 2 && cl >= 6) { memcpy(&pp, d, 2); sp = ntohs(pp); }
                                else if (ct == 3 && cl >= 6) { memcpy(&pp, d, 2); dp = ntohs(pp); }
                            }
                            c += (cl + 3) & ~3u;
                        }
                        b += (bl + 3) & ~3u;
                    }
                    if (proto != 6 && proto != 17) break;               /* icmp & co: no counters wanted */
                } else if (at == 9 || at == 10) {                       /* CTA_COUNTERS_ORIG / _REPLY */
                    uint64_t pk = 0, by = 0;
                    for (size_t b = a + 4; b + 4 <= a + al; ) {
                        uint16_t bl, bt; memcpy(&bl, buf + b, 2); memcpy(&bt, buf + b + 2, 2); bt &= 0x3FFF;
                        if (bl < 4) break;
                        if (bt == 1 && bl >= 12) pk = be64p(buf + b + 4);
                        else if (bt == 2 && bl >= 12) by = be64p(buf + b + 4);
                        b += (bl + 3) & ~3u;
                    }
                    if (at == 9) { po = pk; bo = by; } else { pr = pk; br = by; break; }
                }
                a += (al + 3) & ~3u;
            }
            if ((proto == 6 || proto == 17) && have_ip && sp >= 0 && dp >= 0)
                for (int i = 0; i < n; i++) ct_match(&keys[i], &vals[i], is6, src, dst, proto, sp, dp, po, bo, pr, br);
        }
        off += (ml + 3) & ~3u;
    }
    return done;
}

int hs_ct_dump(const hs_ckey *keys, int n, hs_cval *vals) {
    for (int i = 0; i < n; i++) memset(&vals[i], 0, sizeof vals[i]);
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, 12 /* NETLINK_NETFILTER */);
    if (s < 0) return -errno;
    struct timeval tv = { 2, 0 }; setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    int rb = 1 << 21; setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rb, sizeof rb);
    struct { uint32_t len; uint16_t type, flags; uint32_t seq, pid; uint8_t fam, ver; uint16_t res; } rq = { 20, (1 << 8) | 1, 0x301, 1, 0, 0, 0, 0 };
    if (send(s, &rq, sizeof rq, 0) < 0) { int e = errno; close(s); return -e; }
    static __thread uint8_t buf[1 << 17];
    int done = 0, rc = 0;
    while (!done) {
        ssize_t len = recv(s, buf, sizeof buf, 0);
        if (len <= 0) { rc = len < 0 ? -errno : -EIO; break; }
        done = hs_ct_parse(buf, len, keys, n, vals);
    }
    close(s);
    return rc;
}

/* ------------------------------------------------------------------ API (called through ctypes) */
int hs_sizeof_params(void) { return (int)sizeof(hs_params); }
int hs_sizeof_state(void) { return (int)sizeof(hs_state); }
int hs_sizeof_event(void) { return (int)sizeof(hs_event); }

/* reflectors: n NUL-terminated address strings; wan: device name for the byte counters; hb_path: heartbeat file */
int hs_init(const char **refl, int n, int port, const char *wan, const char *hb_path) {
    if (G.started) return 0;
    if (n < 0 || n > MAXR) return -EINVAL;
    G.rhead = G.rtail = 0; G.tlen = 0; G.live = G.last_live = 0; G.hb_len = 0; memset(&G.st, 0, sizeof G.st);
    G.nsock = 0; G.armed = 0; G.stop = 0; G.parked = 1; G.fast = G.burst = 0; G.gen = 0; G.fast_s = 0.05; G.late_s = 0.4;
    G.efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC); G.cefd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (G.efd < 0 || G.cefd < 0) return -errno;
    char path[160];
    snprintf(path, sizeof path, "/sys/class/net/%s/statistics/rx_bytes", wan); G.fd_rx = open(path, O_RDONLY | O_CLOEXEC);
    snprintf(path, sizeof path, "/sys/class/net/%s/statistics/tx_bytes", wan); G.fd_tx = open(path, O_RDONLY | O_CLOEXEC);
    if (G.fd_rx < 0 || G.fd_tx < 0) return -ENODEV;
    G.fd_hb = hb_path && *hb_path ? open(hb_path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644) : -1;
    for (int i = 0; i < n; i++) {
        int v6 = strchr(refl[i], ':') != NULL;
        int s = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (s < 0) return -errno;
        int one = 1; setsockopt(s, SOL_SOCKET, SO_TIMESTAMPNS, &one, sizeof one);
        int rc;
        if (v6) {
            struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(port) };
            if (inet_pton(AF_INET6, refl[i], &a.sin6_addr) != 1) return -EINVAL;
            rc = connect(s, (struct sockaddr *)&a, sizeof a);
        } else {
            struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };
            if (inet_pton(AF_INET, refl[i], &a.sin_addr) != 1) return -EINVAL;
            rc = connect(s, (struct sockaddr *)&a, sizeof a);
        }
        if (rc < 0) return -errno;
        G.socks[G.nsock++] = s;
    }
    G.stop = 0; G.armed = 0; G.parked = 1;
    if (pthread_create(&G.th, NULL, sentinel_thread, NULL) != 0) return -EAGAIN;
    G.started = 1;
    return 0;
}

int hs_efd(void) { return G.efd; }

/* full-rate probing (one probe per fast_s round-robin, late after late_s); from CALM this only flips the mode, from parked it starts the thread */
void hs_set_fast(double fast_s, double late_s, int burst) {
    pthread_mutex_lock(&G.mu);
    G.fast_s = fast_s; G.late_s = late_s; G.fast = 1; G.burst = burst;
    if (!G.armed) { G.armed = 1; G.gen++; G.parked = 0; G.st.armed = 1; }
    pthread_cond_broadcast(&G.cv);
    pthread_mutex_unlock(&G.mu);
    uint64_t one = 1; if (G.cefd >= 0 && write(G.cefd, &one, 8) < 0) { }
}

/* calm mode: hs_arm (from FAST or parked) */
void hs_arm(const hs_params *p) {
    pthread_mutex_lock(&G.mu);
    G.p = *p; G.st.alert = 0; G.st.armed = 1; G.fast = 0; G.burst = 0; G.gen++;
    G.st.ach[0] = p->ach[0]; G.st.ach[1] = p->ach[1]; G.st.peak[0] = p->peak[0]; G.st.peak[1] = p->peak[1];
    G.armed = 1; G.parked = 0;
    pthread_cond_broadcast(&G.cv);
    pthread_mutex_unlock(&G.mu);
    uint64_t one = 1; if (G.cefd >= 0 && write(G.cefd, &one, 8) < 0) { }
}

/* Python-initiated stop of calm mode; returns once the thread is parked (idempotent) */
void hs_disarm(void) {
    pthread_mutex_lock(&G.mu);
    G.armed = 0;
    uint64_t one = 1;
    if (!G.parked && G.cefd >= 0) { if (write(G.cefd, &one, 8) < 0) { } }
    while (G.started && !G.parked) pthread_cond_wait(&G.cv, &G.mu);
    G.st.armed = 0;
    pthread_mutex_unlock(&G.mu);
}

void hs_bump(void) { __sync_fetch_and_add(&G.live, 1); }

int hs_drain(hs_event *out, int max) {
    int n = 0;
    pthread_mutex_lock(&G.mu);
    while (G.rtail != G.rhead && n < max) { out[n++] = G.ring[G.rtail]; G.rtail = (G.rtail + 1) % RING; }
    pthread_mutex_unlock(&G.mu);
    return n;
}

int hs_tel(char *buf, int cap) {
    pthread_mutex_lock(&G.mu);
    int n = G.tlen < cap ? G.tlen : cap;
    memcpy(buf, G.tel, n);
    if (n < G.tlen) memmove(G.tel, G.tel + n, G.tlen - n);
    G.tlen -= n;
    pthread_mutex_unlock(&G.mu);
    return n;
}

void hs_state_get(hs_state *o) {
    pthread_mutex_lock(&G.mu);
    *o = G.st; o->armed = G.armed;
    pthread_mutex_unlock(&G.mu);
}

int hs_ack_alert(void) {                         /* returns and clears the alert code */
    pthread_mutex_lock(&G.mu);
    int a = G.st.alert; G.st.alert = 0;
    pthread_mutex_unlock(&G.mu);
    uint64_t x; if (G.efd >= 0 && read(G.efd, &x, 8) < 0) { }
    return a;
}

void hs_stop(void) {
    if (!G.started) return;
    pthread_mutex_lock(&G.mu); G.stop = 1; G.armed = 0; pthread_cond_broadcast(&G.cv); pthread_mutex_unlock(&G.mu);
    uint64_t one = 1; if (write(G.cefd, &one, 8) < 0) { }
    pthread_join(G.th, NULL);
    G.started = 0;
    for (int i = 0; i < G.nsock; i++) close(G.socks[i]);
    G.nsock = 0;
    if (G.fd_hb >= 0) { close(G.fd_hb); G.fd_hb = -1; }
    if (G.fd_rx >= 0) { close(G.fd_rx); G.fd_rx = -1; }
    if (G.fd_tx >= 0) { close(G.fd_tx); G.fd_tx = -1; }
    close(G.efd); close(G.cefd); G.efd = G.cefd = -1;
}
