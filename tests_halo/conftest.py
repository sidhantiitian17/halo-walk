"""Shared fixtures for the HALO-Walk unit tests.

Runs without root, network namespaces or the VM:
  * HALO_STATE points at a throw-away directory BEFORE any halo module is imported
    (enforcer.STATE_DIR is read at import time; the default /run/halo needs root).
  * HALO_API_TOKEN is a fictitious, obviously-fake token.
  * every test gets a guard that makes any un-mocked subprocess call in halo.* fail loudly,
    so no tc / nft / ip / conntrack command can ever reach the host kernel.
"""
import json, os, re, sys, tempfile, types

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STATE = tempfile.mkdtemp(prefix="halo_state_")
os.environ["HALO_STATE"] = _STATE
os.environ["HALO_API_TOKEN"] = "EXAMPLE-NOT-A-SECRET-0000"
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import pytest  # noqa: E402

FAKE_TOKEN = os.environ["HALO_API_TOKEN"]


class _NoSubprocess(types.SimpleNamespace):
    def run(self, *a, **k):
        raise AssertionError("un-mocked subprocess call from halo code: %r" % (a[0] if a else k))


@pytest.fixture(autouse=True)
def no_real_shell(monkeypatch):
    """safety net: halo.enforcer.sh / controller shadow-check would hit subprocess.run -> forbid it"""
    import halo.enforcer as enf
    guard = _NoSubprocess(PIPE=-1)
    monkeypatch.setattr(enf, "subprocess", guard)
    try:
        import halo.controller as ctl
        monkeypatch.setattr(ctl, "subprocess", guard)
    except Exception:
        pass
    yield


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    """a fresh per-test STATE_DIR patched into every module that captured it at import time"""
    d = str(tmp_path / "state")
    os.makedirs(d)
    for name in ("halo.enforcer", "halo.watchdog", "halo.api", "halo.controller"):
        m = sys.modules.get(name)
        if m is not None and hasattr(m, "STATE_DIR"):
            monkeypatch.setattr(m, "STATE_DIR", d)
    return d


class FakeKernel:
    """records every rendered shell command and emulates just enough tc/nft read-back.

    fault modes:
      ignore_change : `tc qdisc change` returns success but the kernel keeps the old rate
                      (models a silently failed / partial apply -> read-back mismatch)
      fail          : regex; matching commands raise RuntimeError like sh(check=True) would
    """
    BW = re.compile(r"dev (\S+) root.*?cake bandwidth (\d+)kbit(.*)$")

    def __init__(self):
        self.calls = []            # (cmd, inp)
        self.qdisc = {}            # dev -> {"mbit":..., "opts":...}
        self.ignore_change = False
        self.fail = None
        self.nft_text = "table inet halo {\n}\n"
        self.responses = {}        # regex -> canned stdout (e.g. `ip neigh show`)

    # --- helpers for assertions
    def cmds(self):
        return [c for c, _ in self.calls]

    def inputs(self):
        return [i for _, i in self.calls if i]

    def matching(self, pat):
        return [c for c in self.cmds() if re.search(pat, c)]

    # --- the sh() replacement
    def __call__(self, cmd, check=True, inp=None):
        if isinstance(cmd, (list, tuple)):        # sh(["tc", "-batch", "-"], inp=...) form
            cmd = " ".join(cmd)
        self.calls.append((cmd, inp))
        if self.fail and re.search(self.fail, cmd + " " + (inp or "")):
            if check:
                raise RuntimeError("cmd failed: %s" % cmd)
            return ""
        for pat, out in self.responses.items():
            if re.search(pat, cmd):
                return out
        if cmd.startswith("tc qdisc replace") or cmd.startswith("tc qdisc change"):
            m = self.BW.search(cmd)
            if m and not (cmd.startswith("tc qdisc change") and self.ignore_change):
                dev = m.group(1)
                opts = m.group(3).strip() or self.qdisc.get(dev, {}).get("opts", "")
                self.qdisc[dev] = {"mbit": int(m.group(2)) / 1000.0, "opts": opts}
            return ""
        if cmd == "tc -batch -":
            for line in (inp or "").splitlines():
                m = self.BW.search(line)
                if m:
                    self.qdisc[m.group(1)] = {"mbit": int(m.group(2)) / 1000.0, "opts": m.group(3).strip()}
            return ""
        if cmd == "tc -j qdisc show":
            return json.dumps([{"kind": "cake", "dev": d, "root": True, "handle": "1:",
                                "options": {"bandwidth": q["mbit"] * 1e6 / 8}} for d, q in self.qdisc.items()])
        m = re.match(r"tc (?:-s )?-j qdisc show dev (\S+) root", cmd)
        if m:
            q = self.qdisc.get(m.group(1))
            if not q:
                return "[]"
            return json.dumps([{"kind": "cake", "dev": m.group(1), "root": True,
                                "options": {"bandwidth": q["mbit"] * 1e6 / 8},
                                "tins": [{"sent_bytes": 10 * i, "backlog_bytes": 0, "drops": i,
                                          "ecn_mark": 0, "peak_delay_us": 100 * i, "avg_delay_us": 50 * i}
                                         for i in range(4)]}])
        m = re.match(r"tc qdisc show dev (\S+) root", cmd)
        if m:
            q = self.qdisc.get(m.group(1))
            return "qdisc cake 1: root bandwidth %dKbit %s" % (q["mbit"] * 1000, q["opts"]) if q else ""
        if cmd == "nft list table inet halo":
            return self.nft_text
        if cmd.startswith("nft -j list set inet halo intent_mac"):
            return json.dumps({"nftables": [{"set": {"elem": [{"elem": {"val": "02:00:00:00:00:01", "expires": 42}}]}}]})
        return ""


@pytest.fixture
def fake_sh(monkeypatch):
    """replace halo.enforcer.sh (and every module that imported it by name) with a FakeKernel"""
    k = FakeKernel()
    import halo.enforcer as enf
    monkeypatch.setattr(enf, "sh", k)
    for name in ("halo.api", "halo.controller"):
        m = sys.modules.get(name)
        if m is not None and hasattr(m, "sh"):
            monkeypatch.setattr(m, "sh", k)
    return k
