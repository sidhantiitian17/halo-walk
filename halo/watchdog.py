#!/usr/bin/env python3
"""M6 watchdog: if the controller heartbeat goes stale, force the KNOWN SAFE STATE.
(prototype supervisor; in production the same script is the systemd unit's WatchdogSec/ExecStopPost action)"""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from halo.enforcer import NFT, STATE_DIR, _fast_ok, safe_state

def prepare():
    """everything the trip path needs is ready BEFORE the trip: scheduling priority above the data-plane load, and the
    in-process nft library loaded (safe_state then needs no nft exec, only one `tc -batch`)"""
    if not _fast_ok():                       # unit tests (mocked shell) must not renice the test runner
        return
    try:
        os.setpriority(os.PRIO_PROCESS, 0, int(os.environ.get("HALO_WATCHDOG_NICE", "-15")))
    except (OSError, PermissionError, ValueError):
        pass
    NFT.available()


def main():
    timeout, dl, ul = float(sys.argv[1]), float(sys.argv[2]), float(sys.argv[3])
    prepare()
    hb = os.path.join(STATE_DIR, "heartbeat")
    armed = False
    while True:
        time.sleep(0.1)
        try:
            age = time.time() - os.path.getmtime(hb)
        except OSError:
            continue
        if age < timeout:
            armed = True
        elif armed:
            t0 = time.time()
            safe_state(dl, ul)
            json.dump({"t_detect": t0, "t_safe": time.time(), "hb_age": age}, open(os.path.join(STATE_DIR, "watchdog_trip.json"), "w"))
            armed = False

if __name__ == "__main__":
    main()
