"""M8/M11 watchdog (halo/watchdog.py): stale controller heartbeat -> KNOWN SAFE STATE.

The watchdog's infinite loop is driven by a patched time.sleep that scripts the heartbeat age per
iteration and stops the loop; safe_state is the real enforcer.safe_state with the shell mocked.
"""
import json, os, sys

import pytest

from halo import watchdog


class Stop(Exception):
    pass


def drive(monkeypatch, state_dir, ages, timeout=1.0):
    """ages[i] = heartbeat age (s) seen in loop iteration i; None = file missing"""
    hb = os.path.join(state_dir, "heartbeat")
    it = {"i": 0}
    now = 1_000_000.0
    monkeypatch.setattr(watchdog.time, "time", lambda: now)

    def fake_sleep(dt):
        assert dt == pytest.approx(0.1)          # watchdog polls every 100 ms
        i = it["i"]
        if i >= len(ages):
            raise Stop
        it["i"] += 1
        if ages[i] is None:
            if os.path.exists(hb):
                os.remove(hb)
        else:
            open(hb, "w").write("x")
            os.utime(hb, (now - ages[i], now - ages[i]))

    monkeypatch.setattr(watchdog.time, "sleep", fake_sleep)
    monkeypatch.setattr(sys, "argv", ["watchdog.py", str(timeout), "8", "1.6"])
    with pytest.raises(Stop):
        watchdog.main()


def trips(fake_sh):
    """safe_state() always starts with exactly one `tc -batch -` (even when it then falls back)"""
    return len(fake_sh.matching(r"^tc -batch -$"))


def test_stale_heartbeat_forces_safe_state(monkeypatch, fake_sh, state_dir):
    drive(monkeypatch, state_dir, [0.1, 0.2, 5.0])
    assert trips(fake_sh) == 1
    tcb = [i for c, i in fake_sh.calls if c == "tc -batch -"][0]
    assert "qdisc replace dev lan0 root handle 1: cake bandwidth 8000kbit" in tcb
    assert "qdisc replace dev wan0 root handle 1: cake bandwidth 1600kbit" in tcb
    nft = [i for c, i in fake_sh.calls if c == "nft -f -"][0]
    for m in ("flow4", "flow6", "dev4", "dev6"):
        assert "flush map inet halo %s" % m in nft
    rec = json.load(open(os.path.join(state_dir, "watchdog_trip.json")))
    assert rec["hb_age"] == pytest.approx(5.0, abs=0.01)
    assert os.path.exists(os.path.join(state_dir, "safe.json"))


def test_fresh_heartbeat_never_trips(monkeypatch, fake_sh, state_dir):
    drive(monkeypatch, state_dir, [0.1, 0.5, 0.9, 0.2] * 5)
    assert fake_sh.calls == []


def test_missing_heartbeat_does_not_trip(monkeypatch, fake_sh, state_dir):
    drive(monkeypatch, state_dir, [None] * 10)
    assert fake_sh.calls == []


def test_not_armed_until_first_fresh_heartbeat(monkeypatch, fake_sh, state_dir):
    """a stale file left over from a previous run must not trip before the controller ever beat"""
    drive(monkeypatch, state_dir, [50.0, 50.0, 0.1, 3.0])
    assert trips(fake_sh) == 1


def test_trips_once_per_outage_and_rearms(monkeypatch, fake_sh, state_dir):
    drive(monkeypatch, state_dir, [0.1, 2.0, 3.0, 4.0, 0.1, 2.5])
    assert trips(fake_sh) == 2


def test_safe_state_survives_shell_errors(monkeypatch, fake_sh, state_dir):
    fake_sh.fail = r"."                     # every command fails (e.g. table already gone)
    drive(monkeypatch, state_dir, [0.1, 9.0])
    assert trips(fake_sh) == 1
    assert "nft flush set inet halo intent_mac" in fake_sh.cmds()   # batch failed -> per-command fallback ran
    assert os.path.exists(os.path.join(state_dir, "watchdog_trip.json"))
