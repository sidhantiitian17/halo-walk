"""M10 harness: the S5 override client must already be running when the request is timed (no process spawn inside the
POST -> response interval)."""
import json, os, socket, subprocess, sys, threading, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT = os.path.join(ROOT, "scenarios", "ovr_client.py")
sys.path.insert(0, os.path.join(ROOT, "scenarios"))


def _server(delay=0.0, status=200, body='{"ok":true}'):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    seen = {}

    def run():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            time.sleep(delay)                                   # accepted but not read yet: the handler is slow
            data = b""
            while b"\r\n\r\n" not in data:
                data += c.recv(4096)
            hdr, _, rest = data.partition(b"\r\n\r\n")
            cl = [l.split(b":")[1] for l in hdr.split(b"\r\n") if l.lower().startswith(b"content-length")]
            n = int(cl[0]) if cl else 0
            while len(rest) < n:
                rest += c.recv(4096)
            seen["t_rx"], seen["hdr"], seen["body"] = time.time(), hdr, rest
            payload = body.encode()
            c.sendall(("HTTP/1.1 %d X\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % (status, len(payload))).encode() + payload)
            c.close()
    threading.Thread(target=run, daemon=True).start()
    return srv, srv.getsockname()[1], seen


def test_post_timestamps_bracket_the_request_not_the_client_startup():
    import ovr_client
    srv, port, seen = _server(delay=0.3)
    try:
        t0 = time.time()
        r = ovr_client.request("POST", "/v1/overrides", {"device": "10.0.0.10", "cls": "call"}, "127.0.0.1", port, "TOK")
    finally:
        srv.close()
    assert t0 <= r["t_post"] <= seen["t_rx"] <= r["t_ret"]
    assert r["t_ret"] - r["t_post"] >= 0.3                      # the server-side delay IS inside the interval
    assert r["status"] == 200 and json.loads(r["body"]) == {"ok": True}
    assert b"Authorization: Bearer TOK" in seen["hdr"] and json.loads(seen["body"])["cls"] == "call"


def test_running_client_serves_many_requests_without_a_new_process():
    srv, port, seen = _server()
    p = subprocess.Popen([sys.executable, "-u", CLIENT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        assert json.loads(p.stdout.readline()) == {"ready": True}
        pid = p.pid
        for _ in range(3):
            p.stdin.write(json.dumps({"method": "GET", "path": "/v1/health", "host": "127.0.0.1", "port": port}) + "\n")
            p.stdin.flush()
            r = json.loads(p.stdout.readline())
        assert p.pid == pid and p.poll() is None and r["status"] == 200 and r["t_ret"] >= r["t_post"]
    finally:
        p.kill()
        srv.close()


def test_client_reports_errors_and_keeps_serving():
    p = subprocess.Popen([sys.executable, "-u", CLIENT], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        p.stdout.readline()
        p.stdin.write(json.dumps({"method": "GET", "path": "/x", "host": "127.0.0.1", "port": 1}) + "\n")   # refused
        p.stdin.flush()
        assert "error" in json.loads(p.stdout.readline())
        assert p.poll() is None
    finally:
        p.kill()


def test_run_py_s5_uses_the_running_client_and_keeps_the_legacy_figure():
    src = open(os.path.join(ROOT, "scenarios", "run.py")).read()
    s5 = src[src.index('if scn == "S5":\n                time.sleep(14)'):src.index("        elif scn == \"S2\"")]
    assert "ovr_client_request(OVR[0]" in s5                    # POST goes through the already-running helper
    assert '"override_post", "t": rr["t_post"]' in s5            # marked from the client's own pre-write timestamp
    assert "override_legacy_spawn_s" in s5
    # the only per-request spawn left in the S5 branch is the labelled fallback / the legacy comparison
    assert s5.index("ovr_client_request") < s5.index('mark("override_post")')
    assert 'OVR[0] = ovr_client_start("laptop")' in src         # started at scenario setup, before the load


def test_analysis_inputs_unchanged():
    """analyze.py reads override_post / override_returned.curl_roundtrip_s; the helper emits exactly those names"""
    src = open(os.path.join(ROOT, "scenarios", "run.py")).read()
    assert '"name": "override_returned"' in src and '"curl_roundtrip_s": round(rr["t_ret"] - rr["t_post"], 3)' in src
