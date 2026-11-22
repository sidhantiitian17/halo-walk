"""M4 intent / override / policy API (halo/api.py) via FastAPI TestClient.

All nft/tc/ip calls go to the FakeKernel (conftest); state files go to a per-test STATE_DIR;
override training labels go to a tmp DATA dir (never into the repo).
"""
import json, os

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from conftest import FAKE_TOKEN  # noqa: E402
from halo import api  # noqa: E402

NEIGH = ("10.0.0.2 lladdr 02:00:00:00:00:02 REACHABLE\n"
         "fd00::2 lladdr 02:00:00:00:00:02 STALE\n"
         "fe80::2 lladdr 02:00:00:00:00:02 STALE\n"
         "10.0.0.3 lladdr 02:00:00:00:00:03 REACHABLE\n")
AUTH = {"Authorization": "Bearer " + FAKE_TOKEN}


@pytest.fixture
def client(fake_sh, state_dir, tmp_path, monkeypatch):
    monkeypatch.setattr(api, "LEASES", os.path.join(state_dir, "leases.json"))
    monkeypatch.setattr(api, "OVR", os.path.join(state_dir, "overrides.json"))
    monkeypatch.setattr(api, "DATA", str(tmp_path / "data"))
    fake_sh.responses[r"^ip neigh show dev lan0"] = NEIGH
    fake_sh.qdisc = {"lan0": {"mbit": 95.0, "opts": ""}, "wan0": {"mbit": 19.0, "opts": ""}}
    return TestClient(api.app)


def test_token_comes_from_env_and_is_fictitious():
    assert api.TOKEN == FAKE_TOKEN and "EXAMPLE" in api.TOKEN


# --------------------------------------------------------------------------- auth
@pytest.mark.parametrize("method,path,body", [
    ("post", "/v1/intents", {"device": "10.0.0.2"}),
    ("get", "/v1/intents", None),
    ("delete", "/v1/intents/02:00:00:00:00:02", None),
    ("post", "/v1/overrides", {"device": "10.0.0.2", "cls": "bulk"}),
    ("get", "/v1/flows", None),
    ("post", "/v1/policy", {"rate_dl": 50}),
    ("get", "/v1/state", None),
])
@pytest.mark.parametrize("hdr", [None, {"Authorization": "Bearer wrong"}, {"Authorization": FAKE_TOKEN},
                                 {"Authorization": "Basic " + FAKE_TOKEN}])
def test_auth_required(client, fake_sh, method, path, body, hdr):
    kw = {"headers": hdr} if hdr else {}
    if body is not None:
        kw["json"] = body
    r = getattr(client, method)(path, **kw)
    assert r.status_code == 401
    assert not any(c.startswith("nft") for c in fake_sh.cmds())       # nothing reached the data plane


def test_auth_fails_closed_without_configured_token(client, monkeypatch):
    monkeypatch.setattr(api, "TOKEN", "")
    assert client.get("/v1/flows", headers={"Authorization": "Bearer "}).status_code == 401


def test_health_is_public(client):
    r = client.get("/v1/health")
    assert r.status_code == 200 and set(r.json()) == {"controller_heartbeat_age_s", "safe_state"}


# --------------------------------------------------------------------------- intents
def test_intent_admitted_writes_kernel_lease(client, fake_sh, state_dir):
    r = client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.2", "cls": "call", "ttl": 600, "owner": "alice"})
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["admitted"] and j["lease_id"] == "02:00:00:00:00:02"
    assert j["ips"] == ["10.0.0.2", "fd00::2"]                         # link-local excluded
    batch = [i for c, i in fake_sh.calls if c == "nft -f -"][-1]
    assert "add element inet halo intent_mac { 02:00:00:00:00:02 timeout 599s }" in batch
    assert "intent_v4 { 10.0.0.2 timeout 599s }" in batch and "intent_v6 { fd00::2 timeout 599s }" in batch
    assert json.load(open(api.LEASES))[0]["owner"] == "alice"


@pytest.mark.parametrize("ttl", [0, -5, 7201, 86400])
def test_intent_ttl_cap(client, fake_sh, ttl):
    r = client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.2", "ttl": ttl})
    assert r.status_code == 409
    assert any(x.startswith("ttl_out_of_bounds") for x in r.json()["reasons"])
    assert not fake_sh.matching(r"^nft")


def test_intent_ttl_at_cap_ok(client):
    assert client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.2", "ttl": 7200}).status_code == 201


@pytest.mark.parametrize("body", [{}, {"device": "10.0.0.2", "ttl": "forever"}, {"device": ["x"]},
                                  {"device": "10.0.0.2", "ttl": 1.5}])
def test_intent_input_validation(client, body):
    assert client.post("/v1/intents", headers=AUTH, json=body).status_code == 422


def test_intent_non_interactive_class_rejected(client):
    r = client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.2", "cls": "bulk"})
    assert r.status_code == 409 and "only_interactive_boost" in r.json()["reasons"]


def test_intent_unknown_device_404(client):
    r = client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.99"})
    assert r.status_code == 404


def test_intent_one_per_owner_and_max_leases(client):
    assert client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.2", "owner": "a"}).status_code == 201
    r = client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.3", "owner": "a"})
    assert r.status_code == 409 and "owner_quota" in r.json()["reasons"]
    assert client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.3", "owner": "b"}).status_code == 201
    r = client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.3", "owner": "c"})
    assert r.status_code == 409 and "max_concurrent_leases(2)" in r.json()["reasons"]


def test_intent_list_and_revoke(client, fake_sh):
    client.post("/v1/intents", headers=AUTH, json={"device": "10.0.0.2"})
    j = client.get("/v1/intents", headers=AUTH).json()
    assert j["kernel"] and len(j["registry"]) == 1
    r = client.delete("/v1/intents/02:00:00:00:00:02", headers=AUTH)
    assert r.status_code == 200
    assert "nft delete element inet halo intent_mac { 02:00:00:00:00:02 }" in fake_sh.cmds()
    assert "nft delete element inet halo intent_v4 { 10.0.0.2 }" in fake_sh.cmds()
    assert json.load(open(api.LEASES)) == []


# --------------------------------------------------------------------------- overrides
def test_override_flow(client, fake_sh, tmp_path):
    r = client.post("/v1/overrides", headers=AUTH,
                    json={"flow": ["udp", "10.0.0.2", 5000, "198.51.100.1", 443], "cls": "bulk", "ttl": 120})
    assert r.status_code == 200, r.text
    assert r.json()["tin"] == "Bulk" and r.json()["applied"]
    assert "destroy element inet halo flow4 { udp . 10.0.0.2 . 5000 . 198.51.100.1 . 443 }" in fake_sh.inputs()[-1]   # one atomic replace
    assert "flow4 { udp . 10.0.0.2 . 5000 . 198.51.100.1 . 443 timeout 120s : 0x1 }" in fake_sh.inputs()[-1]
    ov = json.load(open(api.OVR))
    assert ov["udp|10.0.0.2|5000|198.51.100.1|443"]["cls"] == "bulk"
    labels = (tmp_path / "data" / "override_labels.jsonl").read_text().splitlines()
    assert json.loads(labels[-1])["cls"] == "bulk"                     # kept as a training label


def test_override_device(client, fake_sh):
    r = client.post("/v1/overrides", headers=AUTH, json={"device": "10.0.0.2", "cls": "call", "ttl": 60})
    assert r.status_code == 200 and r.json()["tin"] == "Voice"
    assert "dev4 { 10.0.0.2 timeout 60s : 0x4 }" in fake_sh.inputs()[-1]


@pytest.mark.parametrize("body", [{"device": "10.0.0.2", "cls": "vip"}, {"cls": "bulk"}, {"device": "10.0.0.2"}])
def test_override_validation(client, fake_sh, body):
    assert client.post("/v1/overrides", headers=AUTH, json=body).status_code == 422
    assert not fake_sh.matching(r"^nft")


# --------------------------------------------------------------------------- policy push / state / metrics
def test_policy_valid_queues_transaction(client, state_dir):
    r = client.post("/v1/policy", headers=AUTH, json={"rate_dl": 50.0, "promote_p": 0.95})
    assert r.status_code == 202
    assert json.load(open(os.path.join(state_dir, "txn_request.json"))) == {"rate_dl": 50.0, "promote_p": 0.95}


@pytest.mark.parametrize("body,reason", [({"rate_dl": 500}, "rate_dl_out_of_bounds"),
                                         ({"tin_mode": "besteffort"}, "tin_mode_must_be_diffserv4"),
                                         ({"promote_p": 0.1}, "promote_p_out_of_bounds")])
def test_policy_shield_rejects(client, state_dir, body, reason):
    r = client.post("/v1/policy", headers=AUTH, json=body)
    assert r.status_code == 409 and any(x.startswith(reason) for x in r.json()["reasons"])
    assert not os.path.exists(os.path.join(state_dir, "txn_request.json"))


def test_policy_unknown_fields_never_reach_transaction(client, state_dir):
    client.post("/v1/policy", headers=AUTH, json={"rate_dl": 50.0, "max_up_step": 9})
    req = json.load(open(os.path.join(state_dir, "txn_request.json")))
    assert "max_up_step" not in req


def test_state_and_metrics(client):
    s = client.get("/v1/state", headers=AUTH).json()
    assert s["rate_dl"] == pytest.approx(95.0) and s["rate_ul"] == pytest.approx(19.0)
    m = client.get("/metrics").text
    assert 'halo_shaper_rate_mbit{dir="download"} 95.000' in m
    assert 'halo_tin_drops{dir="upload",tin="voice"} 3' in m
