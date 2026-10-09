"""Startup capture evidence, TCP reassembly, and real-socket load-gate tests."""
import copy
import json
import socket
import subprocess
import threading
from contextlib import contextmanager

import pytest

from mimic.cli import main
from mimic.startup import (CAPTURE_FORMAT, WIRE_FORMAT, capture, compare, diagnose,
                           learn_wire, normalize_tshark, read_capture, write_json)
from mimic.wire import WireEmulator

M, A, PORT = "192.0.2.10", "192.0.2.40", 9876


def packet(side="client", transport="tcp", payload=b"", seq=1, **extra):
    p = {"frame": 1, "time": 1.0, "src": M if side == "client" else A,
         "dst": A if side == "client" else M, "src_port": 45000 if side == "client" else PORT,
         "dst_port": PORT if side == "client" else 45000, "transport": transport,
         "protocols": ["ip", transport], "payload_hex": payload.hex(), "truncated": False,
         "dns_queries": [], "dns_addresses": []}
    if transport == "tcp":
        p.update(stream="0", seq=seq, payload_len=len(payload), syn=False, ack=False, reset=False, fin=False)
    p.update(extra)
    return p


def trace(*packets):
    return {"format": CAPTURE_FORMAT, "packets": list(packets)}


def tcp_trace():
    return trace(packet(seq=0, syn=True), packet("server", seq=0, syn=True, ack=True),
                 packet(payload=b"HELLO-A?"), packet("server", payload=b"A-READY"),
                 packet(payload=b"VERSION?", seq=9), packet("server", payload=b"1.0", seq=8),
                 packet(seq=17, fin=True))


def tcp_profile():
    return learn_wire(tcp_trace(), [M], A, PORT, "tcp")


def udp_trace():
    return trace(packet(transport="udp", payload=b"FIND-A"), packet("server", "udp", b"A-READY"))


@contextmanager
def running(profile, timeout=1):
    emulator = WireEmulator(profile)
    server = emulator.server(port=0, timeout=timeout)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield emulator, server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_successful_tcp_trace_to_conversation():
    p = tcp_profile()
    assert p["format"] == WIRE_FORMAT
    assert p["events"] == [{"direction": "client", "hex": b"HELLO-A?".hex()},
                           {"direction": "server", "hex": b"A-READY".hex()},
                           {"direction": "client", "hex": b"VERSION?".hex()},
                           {"direction": "server", "hex": b"1.0".hex()}]
    assert p["evidence"]["software_load_success"] == "not verified"


def test_tcp_reassembly_ignores_identical_retransmission_and_merges_fragments():
    original = tcp_trace()
    original["packets"][2:3] = [packet(payload=b"HEL", seq=1), packet(payload=b"HEL", seq=1),
                               packet(payload=b"ELLO-A?", seq=2)]
    p = learn_wire(original, [M], A, PORT, "tcp")
    assert p["events"][0]["hex"] == b"HELLO-A?".hex()


@pytest.mark.parametrize("modify,match", [
    (lambda p: p.pop(0), "SYN missing"),
    (lambda p: p.pop(1), "SYN-ACK"),
    (lambda p: p.pop(), "still open"),
    (lambda p: p[2].update(seq=3), "gap/out-of-order"),
    (lambda p: p[2].update(payload_len=100), "missing"),
    (lambda p: p[3].update(protocols=["ip", "tcp", "tls"]), "encrypted"),
    (lambda p: p[3].update(truncated=True), "truncated"),
    (lambda p: p[3].update(reset=True), "reset"),
])
def test_bad_tcp_evidence_is_rejected(modify, match):
    t = tcp_trace()
    modify(t["packets"])
    with pytest.raises(ValueError, match=match):
        learn_wire(t, [M], A, PORT, "tcp")


def test_conflicting_retransmissions_are_rejected():
    t = tcp_trace()
    t["packets"].insert(3, packet(payload=b"WRONG", seq=1))
    with pytest.raises(ValueError, match="conflicting"):
        learn_wire(t, [M], A, PORT, "tcp")


def test_multiple_streams_need_explicit_selection():
    t = tcp_trace()
    other = copy.deepcopy(t["packets"])
    for p in other:
        p["stream"] = "1"
        p["src_port" if p["src"] == M else "dst_port"] = 46000
    t["packets"].extend(other)
    with pytest.raises(ValueError, match="multiple TCP streams"):
        learn_wire(t, [M], A, PORT, "tcp")
    assert learn_wire(t, [M], A, PORT, "tcp", "1")["evidence"]["stream"] == "1"


def test_failed_startup_produces_candidate_report_but_no_emulator():
    failed = trace(packet(seq=0, syn=True), packet(seq=0, syn=True))
    report = diagnose(failed, [M])
    assert report["peers"][0]["syn_attempts"] == 2
    assert "without captured SYN-ACK" in report["peers"][0]["observation"]
    with pytest.raises(ValueError, match="SYN-ACK"):
        learn_wire(failed, [M], A, PORT, "tcp")
    difference = compare(tcp_trace(), failed, [M])
    assert len(difference["changes"]) == 1
    assert difference["changes"][0]["present"]["syn_ack_packets"] == 1
    assert "not causal proof" in difference["changes"][0]["interpretation"]


def test_diagnosis_encrypted_and_discovery_candidates_without_payloads():
    p = packet(transport="udp", dst="239.255.255.250", dst_port=1900, protocols=["ip", "udp", "ssdp"])
    tls = packet(protocols=["ip", "tcp", "tls"], payload=b"privatebytes", dns_queries=["a.device.test"])
    report = diagnose(trace(p, tls), [M])
    assert any(r["group_destination"] for r in report["peers"])
    assert any(r["encrypted"] for r in report["peers"])
    assert report["dns_queries"] == ["a.device.test"]
    assert "privatebytes" not in json.dumps(report)
    assert "payload_hex" not in json.dumps(report)


def test_udp_complete_exchanges_and_unanswered_rejection():
    p = learn_wire(udp_trace(), [M], A, PORT, "udp")
    assert p["exchanges"] == [{"request_hex": b"FIND-A".hex(), "responses_hex": [b"A-READY".hex()]}]
    with pytest.raises(ValueError, match="complete UDP exchange"):
        learn_wire(trace(packet(transport="udp", payload=b"FIND-A")), [M], A, PORT, "udp")
    with pytest.raises(ValueError, match="unsolicited"):
        learn_wire(trace(packet("server", "udp", b"hello")), [M], A, PORT, "udp")
    with pytest.raises(ValueError, match="overlapping"):
        learn_wire(trace(packet(transport="udp", payload=b"one"), packet(transport="udp", payload=b"two")), [M], A, PORT, "udp")


def test_udp_reply_sequences_are_independent_per_client():
    t = udp_trace()
    t["packets"].extend([packet(transport="udp", payload=b"FIND-A"), packet("server", "udp", b"A-READY-2")])
    p = learn_wire(t, [M], A, PORT, "udp")
    with running(p) as (emulator, address):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c1, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as c2:
            for client, expected in [(c1, b"A-READY"), (c1, b"A-READY-2"), (c1, b"A-READY-2"), (c2, b"A-READY")]:
                client.settimeout(1)
                client.sendto(b"FIND-A", address)
                assert client.recv(100) == expected
            c1.sendto(b"UNKNOWN", address)
            c1.settimeout(0.1)
            with pytest.raises(socket.timeout):
                c1.recv(100)
        assert emulator.stats["unmatched"] == 1


def test_tcp_emulator_satisfies_a_synthetic_software_startup_gate():
    # This toy C loads only after two expected replies; it is not the user's C.
    def software_load(address):
        with socket.create_connection(address, timeout=1) as connection:
            connection.sendall(b"HELLO-A?")
            if connection.recv(100) != b"A-READY":
                return False
            connection.sendall(b"VERSION?")
            return connection.recv(100) == b"1.0"
    with running(tcp_profile()) as (emulator, address):
        assert software_load(address) is True
        assert software_load(address) is True  # each connection starts a fresh conversation
        assert emulator.stats["connections"] == 2
    with pytest.raises(OSError):
        software_load(address)  # server shut down: same gate fails without A


def test_tcp_fragmented_client_reads_and_unknown_handshake():
    with running(tcp_profile()) as (emulator, address):
        with socket.create_connection(address, timeout=1) as connection:
            connection.sendall(b"HE")
            connection.sendall(b"LLO-A?")
            assert connection.recv(100) == b"A-READY"
            connection.sendall(b"VERSION?")
            assert connection.recv(100) == b"1.0"
        with socket.create_connection(address, timeout=1) as connection:
            connection.sendall(b"WRONG-A!")
            assert connection.recv(100) == b""
        assert emulator.stats["unmatched"] == 1


def test_tcp_server_greeting_and_timeout():
    p = tcp_profile()
    p["events"] = [{"direction": "server", "hex": b"WELCOME".hex()}, {"direction": "client", "hex": b"ACK".hex()}]
    with running(p, timeout=0.1) as (emulator, address):
        with socket.create_connection(address, timeout=1) as connection:
            assert connection.recv(100) == b"WELCOME"
            assert connection.recv(100) == b""
        assert emulator.stats["timeouts"] == 1


def test_connection_only_profile_needs_successful_handshake_and_close():
    t = trace(packet(seq=0, syn=True), packet("server", seq=0, syn=True, ack=True), packet(seq=1, fin=True))
    p = learn_wire(t, [M], A, PORT, "tcp")
    assert p["evidence"]["connection_only"] is True
    with running(p) as (_, address):
        with socket.create_connection(address, timeout=1):
            pass
    with pytest.raises(ValueError, match="connection_only"):
        WireEmulator({"format": WIRE_FORMAT, "transport": "tcp", "events": []})


def tshark_rows():
    return [{"_source": {"layers": {"frame.number": ["1"], "frame.time_epoch": ["12.5"],
            "frame.len": ["60"], "frame.cap_len": ["60"], "frame.protocols": ["eth:ip:udp"],
            "ip.src": [M], "ip.dst": [A], "udp.srcport": ["45000"], "udp.dstport": [str(PORT)],
            "udp.payload": ["46:49:4e:44:2d:41"], "dns.qry.name": ["a.test", "b.test"]}}}]


def test_tshark_json_field_import_and_nested_full_export(tmp_path):
    rows = tshark_rows()
    normalized = normalize_tshark(rows)
    p = normalized["packets"][0]
    assert p["payload_hex"] == b"FIND-A".hex()
    assert p["dns_queries"] == ["a.test", "b.test"]
    assert normalized["evidence"]["process_attribution"] == "unknown"
    fields = rows[0]["_source"]["layers"]
    rows[0]["_source"]["layers"] = {"frame": {k:v[0] for k,v in fields.items() if k.startswith("frame.")},
                                   "ip": {"ip.src": M, "ip.dst": A},
                                   "udp": {"udp.srcport": "45000", "udp.dstport": str(PORT), "udp.payload": "46:49"}}
    path = tmp_path / "export.json"
    path.write_text(json.dumps(rows))
    assert read_capture(path)["packets"][0]["payload_hex"] == b"FI".hex()


def test_capture_command_is_passive_bounded_and_avoids_shell(monkeypatch, tmp_path):
    def run(cmd, **kw):
        assert cmd[:4] == ["/tools/tshark", "-n", "-p", "-s"]
        assert ["-a", "duration:5"] == cmd[cmd.index("-a"):cmd.index("-a")+2]
        assert ["-f", "host 192.0.2.40"] == cmd[-2:]
        assert "shell" not in kw
        kw["stdout"].write(json.dumps(tshark_rows()))
        return subprocess.CompletedProcess(cmd, 0, stderr="")
    monkeypatch.setattr(subprocess, "run", run)
    path = tmp_path / "startup.json"
    capture("loopback", path, 5, "host 192.0.2.40", "/tools/tshark")
    assert read_capture(path)["format"] == CAPTURE_FORMAT


def test_capture_failure_does_not_overwrite_previous_output(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 1, stderr="permission denied"))
    path = tmp_path / "old.json"
    path.write_text("original")
    with pytest.raises(RuntimeError, match="capture failed"):
        capture("x", path, executable="tshark")
    assert path.read_text() == "original"


def test_json_analysis_needs_no_tshark_and_invalid_input_fails(tmp_path):
    path = tmp_path / "capture.json"
    write_json(tcp_trace(), path)
    assert read_capture(path)["format"] == CAPTURE_FORMAT
    path.write_text('{"format":"wrong"}')
    with pytest.raises(ValueError):
        read_capture(path)
    with pytest.raises(ValueError):
        diagnose(tcp_trace(), [])


def test_cli_analyze_compare_and_learn_end_to_end(tmp_path):
    success, failure = tmp_path / "present.json", tmp_path / "absent.json"
    write_json(tcp_trace(), success)
    write_json(trace(packet(seq=0, syn=True)), failure)
    main(["startup", "analyze", str(success), "--machine", M, "-o", str(tmp_path / "report.json")])
    main(["startup", "compare", "--present", str(success), "--absent", str(failure), "--machine", M, "-o", str(tmp_path / "comparison.json")])
    main(["startup", "learn", str(success), "--machine", M, "--device", A, "--port", str(PORT), "--transport", "tcp", "-o", str(tmp_path / "profile.json")])
    assert json.loads((tmp_path / "report.json").read_text())["peers"]
    assert json.loads((tmp_path / "comparison.json").read_text())["changes"]
    assert json.loads((tmp_path / "profile.json").read_text())["events"]


def test_loopback_service_report_identifies_service_not_ephemeral_client_port():
    t = tcp_trace()
    for p in t["packets"]:
        p["src"] = p["dst"] = "127.0.0.1"
    r = diagnose(t, ["127.0.0.1"])
    assert len(r["peers"]) == 1
    assert r["peers"][0]["port"] == PORT
    assert r["peers"][0]["syn_ack_packets"] == 1
    p = learn_wire(t, ["127.0.0.1"], "127.0.0.1", PORT, "tcp")
    assert p["events"] == tcp_profile()["events"]


def test_tls_on_nonstandard_port_is_not_mistaken_for_plaintext():
    t = tcp_trace()
    t["packets"][2]["payload_hex"] = "1603030003aabbcc"
    with pytest.raises(ValueError, match="encrypted"):
        learn_wire(t, [M], A, PORT, "tcp")


def test_group_ip_cannot_be_used_as_a_device_identity():
    with pytest.raises(ValueError, match="unicast"):
        learn_wire(udp_trace(), [M], "239.255.255.250", PORT, "udp")


def test_ipv6_tshark_addresses_import():
    rows = tshark_rows()
    f = rows[0]["_source"]["layers"]
    f.pop("ip.src")
    f.pop("ip.dst")
    f["ipv6.src"], f["ipv6.dst"] = ["2001:db8::10"], ["2001:db8::40"]
    p = normalize_tshark(rows)["packets"][0]
    assert p["src"] == "2001:db8::10"
    assert p["dst"] == "2001:db8::40"


def test_cli_invalid_capture_has_concise_error(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"format":"wrong"}')
    with pytest.raises(SystemExit) as error:
        main(["startup", "analyze", str(path), "--machine", M, "-o", str(tmp_path / "report.json")])
    assert error.value.code == 2
    assert "mimic startup:" in capsys.readouterr().err
