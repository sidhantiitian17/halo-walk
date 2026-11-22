#!/usr/bin/env python3
"""S5 override client (M10 harness): a long-running HTTP client that is ALREADY RUNNING inside the client's network
namespace, so the measured POST -> response interval does not include process start-up.

Protocol (one JSON object per line on stdin, one JSON reply per line on stdout):
    {"method": "POST", "path": "/v1/overrides", "body": {...}, "host": "10.0.0.1", "port": 8080, "token": "..."}
 -> {"t_post": <epoch s just before the request bytes are written>,
     "t_ret": <epoch s when the complete response has been read>, "status": 200, "body": "..."}
The TCP connection is opened first (the 3-way handshake with the API's listen socket is not part of the request), then
t_post is taken, then the request is written with a single sendall(). Timestamps are time.time() of the same host clock
the harness uses for its other marks.
"""
import json, socket, sys, time


def request(method, path, body=None, host="10.0.0.1", port=8080, token="EXAMPLE-NOT-A-SECRET-0000", timeout=20.0):
    data = json.dumps(body).encode() if body is not None else b""
    head = ["%s %s HTTP/1.1" % (method, path), "Host: %s:%d" % (host, port), "Authorization: Bearer %s" % token,
            "Content-Type: application/json", "Accept: */*", "Connection: close"]
    if body is not None:
        head.append("Content-Length: %d" % len(data))
    raw = ("\r\n".join(head) + "\r\n\r\n").encode() + data
    s = socket.create_connection((host, port), timeout=timeout)
    try:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        t_post = time.time()                        # immediately before the request bytes are written
        s.sendall(raw)
        buf = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        t_ret = time.time()                         # the response has been read (server closed the connection)
    finally:
        s.close()
    hdr, _, payload = buf.partition(b"\r\n\r\n")
    try:
        status = int(hdr.split(b" ", 2)[1])
    except (IndexError, ValueError):
        status = None
    return {"t_post": t_post, "t_ret": t_ret, "status": status, "body": payload.decode("utf-8", "replace")}


def main():
    print(json.dumps({"ready": True}), flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            q = json.loads(line)
            r = request(q.get("method", "GET"), q["path"], q.get("body"), q.get("host", "10.0.0.1"),
                        q.get("port", 8080), q.get("token", "EXAMPLE-NOT-A-SECRET-0000"))
        except Exception as e:                      # keep serving; the harness decides what a failure means
            r = {"error": repr(e)[:200]}
        print(json.dumps(r), flush=True)


if __name__ == "__main__":
    main()
