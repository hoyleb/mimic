"""Contract inference, real HTTP round trips, offline replay and state transitions."""
import base64
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest
import requests
from jsonschema import Draft202012Validator

from mimic import App, DeviceEmulator, RecordingSession, Session
from mimic.cli import main
from mimic.device import (infer_schema, make_profile, observation, openapi,
                          profile_from_har, profile_from_mitm, save_profile)


def obs(method="GET", path="/status", request=b"", response=b'{"value":20}', status=200):
    return observation(method, "http://device.local" + path, request, response, status,
                       [("Content-Type", "application/json"), ("Authorization", "secret")],
                       [("Content-Type", "application/json"), ("Set-Cookie", "secret")])


def profile(*samples):
    return make_profile("device.local", samples or [obs()])


@contextmanager
def running(p):
    emulator = DeviceEmulator(p)
    server = emulator.server(port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield emulator, f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_schema_accepts_all_samples_and_preserves_optional_nullable_fields():
    samples = [{"n": 1, "optional": "yes", "items": []},
               {"n": 1.5, "items": [True, 1, None]}, {"n": None, "items": ["x"]}]
    schema = infer_schema(samples)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for sample in samples:
        validator.validate(sample)
    assert schema["required"] == ["items", "n"]
    assert schema["properties"]["items"]["items"]["anyOf"]
    assert schema["properties"]["n"]["anyOf"] == [{"type": "null"}, {"type": "number"}]
    assert infer_schema([[]]) == {"type": "array", "items": {}}


def test_openapi_includes_error_responses_optional_query_and_request_body():
    p = profile(obs("POST", "/command?mode=a", b'{"value":1}', b'{"ok":true}'),
                obs("POST", "/command", b'{"value":2,"extra":true}', b'{"error":"busy"}', 409))
    doc = openapi(p)
    operation = doc["paths"]["/command"]["post"]
    assert doc["openapi"] == "3.1.0"
    assert operation["parameters"][0]["required"] is False
    assert set(operation["responses"]) == {"200", "409"}
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert schema["required"] == ["value"]
    assert operation["x-mimic-sample-count"] == 2
    assert operation["x-mimic-unseen-behavior"] == "unknown"


def test_redaction_excludes_auth_headers_nested_json_and_query():
    p = profile(obs("POST", "/command?api_key=secret&x=1", b'{"password":"secret","nested":{"access_token":"secret"}}', b'{"refreshToken":"secret"}'))
    assert "secret" not in json.dumps(p)
    assert p["observations"][0]["request"]["value"]["nested"]["access_token"] == "<redacted>"


def test_strict_replay_query_order_json_order_sequences_and_unknown():
    p = profile(obs("POST", "/command?a=1&b=2", b'{"x":1,"y":2}', b'{"result":1}'),
                obs("POST", "/command?b=2&a=1", b'{"y":2,"x":1}', b'{"result":2}'))
    with running(p) as (_, url):
        for expected in [1, 2, 2]:
            r = requests.post(url + "/command?b=2&a=1", json={"y": 2, "x": 1}, timeout=2)
            assert r.json() == {"result": expected}
            assert r.headers["X-Mimic-Source"] == "captured-replay"
        assert requests.post(url + "/command?a=9&b=2", json={"x": 1, "y": 2}, timeout=2).status_code == 409
        assert requests.get(url + "/unseen", timeout=2).status_code == 404


def test_binary_text_head_and_no_content_roundtrips():
    samples = [obs("GET", "/binary", response=b'\x00\xff\x80'),
               obs("GET", "/text", response=b'plain response'),
               obs("HEAD", "/head", response=b''),
               obs("DELETE", "/delete", response=b'', status=204)]
    with running(profile(*samples)) as (_, url):
        assert requests.get(url + "/binary", timeout=2).content == b'\x00\xff\x80'
        assert requests.get(url + "/text", timeout=2).text == "plain response"
        assert requests.head(url + "/head", timeout=2).content == b''
        assert requests.delete(url + "/delete", timeout=2).status_code == 204


def state_profile():
    p = profile()
    p["initial_state"] = {"value": 20}
    p["rules"] = [
        {"method": "PUT", "path": "/value", "request_json": {},
         "set_state": {"value": {"$ref": "/request/value"}},
         "response_json": {"value": {"$ref": "/state/value"}}},
        {"method": "GET", "path": "/value", "response_json": {"value": {"$ref": "/state/value"}}},
    ]
    return p


def test_stateful_set_read_and_reset_and_no_state_commit_on_invalid_template():
    with running(state_profile()) as (emulator, url):
        client = Session(url)
        assert client.put("/value", {"value": 31}) == {"value": 31}
        assert client.get("/value") == {"value": 31}
        assert emulator.state == {"value": 31}
        assert requests.put(url + "/value", json={"missing": 1}, timeout=2).status_code == 422
        assert client.get("/value") == {"value": 31}
        emulator.reset()
        assert client.get("/value") == {"value": 20}


def test_state_rules_conditions_query_and_type_matching():
    p = profile()
    p["initial_state"] = {"ready": False}
    p["rules"] = [{"method": "POST", "path": "/go", "when_state": {"ready": False},
                  "request_json": {"value": 1}, "query": [["mode", "manual"]],
                  "set_state": {"ready": True}, "response_json": {"ok": True}}]
    emulator = DeviceEmulator(p)
    assert emulator.dispatch("POST", "/go?mode=manual", b'{"value":true}')[0]["status"] == 404
    assert emulator.dispatch("POST", "/go?mode=wrong", b'{"value":1}')[0]["status"] == 404
    assert emulator.dispatch("POST", "/go?mode=manual", b'{"value":1}')[0]["status"] == 200
    assert emulator.dispatch("POST", "/go?mode=manual", b'{"value":1}')[0]["status"] == 404


def test_concurrent_replay_updates_are_atomic():
    p = profile(*[obs(response=json.dumps({"value": n}).encode()) for n in range(60)])
    emulator = DeviceEmulator(p)
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _: emulator.dispatch("GET", "/status")[0]["body"]["value"]["value"], range(60)))
    assert sorted(values) == list(range(60))


def test_recording_session_real_roundtrip_errors_and_origin_restrictions(tmp_path):
    with running(profile(obs(), obs("POST", "/bad", response=b'{"error":"bad"}', status=400))) as (_, url):
        recorder = RecordingSession(url, {"Authorization": "Bearer private"})
        assert recorder.get("/status") == {"value": 20}
        with pytest.raises(requests.HTTPError):
            recorder.post("/bad")
        assert len(recorder.observations) == 2
        assert recorder.observations[1]["response"]["status"] == 400
        for path in ["https://elsewhere.invalid/", "//elsewhere.invalid/"]:
            with pytest.raises(ValueError):
                recorder.get(path)
        with pytest.raises(ValueError):
            recorder.get("/status", allow_redirects=True)
        recorder.save(tmp_path / "profile.json")
        assert "private" not in (tmp_path / "profile.json").read_text()


def test_recording_does_not_follow_redirects():
    p = profile(obs(status=302))
    with running(p) as (_, url):
        recorder = RecordingSession(url)
        recorder.get("/status")
        assert recorder.observations[0]["response"]["status"] == 302


def test_existing_app_can_use_local_emulator():
    with running(profile()) as (_, url):
        app = App(base_url=url)
        assert app.get("/status") == {"value": 20}


def make_har(tmp_path, contents):
    entries = []
    for content in contents:
        entries.append({"request": {"method": "GET", "url": "http://device.local/status"},
                        "response": {"status": 200, "content": content}})
    path = tmp_path / "device.har"
    path.write_text(json.dumps({"log": {"entries": entries}}))
    return path


def test_har_keeps_all_examples_full_body_and_base64(tmp_path):
    large = {"payload": "x" * 8000}
    path = make_har(tmp_path, [{"text": json.dumps(large), "mimeType": "application/json"},
                               {"text": base64.b64encode(b'\xff\x00').decode(), "encoding": "base64"}])
    p = profile_from_har(path, "device.local")
    assert len(p["observations"]) == 2
    assert p["observations"][0]["response"]["body"]["value"] == large
    assert p["observations"][1]["response"]["body"]["kind"] == "base64"


def test_har_missing_content_and_invalid_base64_fail(tmp_path):
    with pytest.raises(ValueError, match="omitted"):
        profile_from_har(make_har(tmp_path, [{"size": 42}]), "device.local")
    with pytest.raises(ValueError, match="base64"):
        profile_from_har(make_har(tmp_path, [{"text": "???", "encoding": "base64"}]), "device.local")
    with pytest.raises(ValueError, match="no completed"):
        profile_from_har(make_har(tmp_path, [{"text": "abc"}]), "other.local")


def test_mitm_import_full_bodies_multiple_responses_and_port():
    class Capture:
        def body(self, id, side):
            return b'' if side == "request" else json.dumps({"id": id, "large": "x" * 5000}).encode()
    flows = [{"id": str(n), "request": {"host": "device.local", "port": 8123, "scheme": "http", "path": "/status", "method": "GET"}, "response": {"status_code": 200}} for n in range(2)]
    p = profile_from_mitm(Capture(), flows, "device.local")
    assert len(p["observations"]) == 2
    assert len(p["observations"][0]["response"]["body"]["value"]["large"]) == 5000


def test_form_redaction_and_order_independent_query_replay():
    o = observation("POST", "http://device.local/login?a=&a=2", b'user=ben&password=private', b'ok', 200,
                    [("Content-Type", "application/x-www-form-urlencoded")])
    assert "private" not in json.dumps(o)
    emulator = DeviceEmulator(profile(o))
    reply, source = emulator.dispatch("POST", "/login?a=2&a=", b'user=ben&password=other', "application/x-www-form-urlencoded")
    assert reply["status"] == 200
    assert source == "captured-replay"


def test_cli_har_to_profile_and_contract(tmp_path, capsys):
    path = make_har(tmp_path, [{"text": '{"value":1}', "mimeType": "application/json"}])
    main(["device", "learn", "device.local", "--har", str(path), "-o", str(tmp_path / "p.json"), "--openapi", str(tmp_path / "api.json")])
    assert json.loads((tmp_path / "p.json").read_text())["evidence"]["sample_count"] == 1
    assert "/status" in json.loads((tmp_path / "api.json").read_text())["paths"]
    assert "Unseen behaviour is unknown" in capsys.readouterr().out


def test_invalid_profiles_rules_and_observations():
    with pytest.raises(ValueError):
        DeviceEmulator({"format": "wrong"})
    with pytest.raises(ValueError):
        observation("GET", "usb://device", b'', b'', 200)
    with pytest.raises(ValueError):
        observation("GET", "http://device.local", b'', b'', 101)
    p = profile()
    p["rules"] = [{"method": "GET", "path": "/bad", "status": 0}]
    with pytest.raises(ValueError):
        DeviceEmulator(p)


def test_har_unknown_missing_body_fails_but_explicit_empty_is_supported(tmp_path):
    with pytest.raises(ValueError, match="omitted"):
        profile_from_har(make_har(tmp_path, [{}]), "device.local")
    p = profile_from_har(make_har(tmp_path, [{"size": 0}]), "device.local")
    assert p["observations"][0]["response"]["body"]["kind"] == "empty"


def test_duplicate_query_parameters_are_arrays_in_contract():
    p = profile(obs(path="/status?channel=a&channel=b"))
    schema = openapi(p)["paths"]["/status"]["get"]["parameters"][0]["schema"]
    assert schema == {"type": "array", "items": {"type": "string"}}


def test_profiles_are_not_mutated_by_caller_after_emulator_creation():
    p = profile()
    emulator = DeviceEmulator(p)
    p["observations"][0]["response"]["body"]["value"]["value"] = 100
    assert emulator.dispatch("GET", "/status")[0]["body"]["value"]["value"] == 20


def test_invalid_pointer_does_not_use_negative_array_index():
    p = state_profile()
    p["rules"][0]["set_state"]["value"] = {"$ref": "/request/values/-1"}
    emulator = DeviceEmulator(p)
    assert emulator.dispatch("PUT", "/value", b'{"values":[1,2]}')[0]["status"] == 422
    assert emulator.state == {"value": 20}


def test_cli_contract_from_saved_profile(tmp_path):
    save_profile(profile(), tmp_path / "p.json")
    main(["device", "contract", str(tmp_path / "p.json"), "-o", str(tmp_path / "api.json")])
    assert "/status" in json.loads((tmp_path / "api.json").read_text())["paths"]
