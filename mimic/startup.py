"""Passive startup network evidence and conservative, selected-peer learning.

Run capture on the machine running the target software. Raw capture payloads
stay local; no device responses, process attribution or load success are guessed.
"""
import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

CAPTURE_FORMAT = "mimic-network/v1"
WIRE_FORMAT = "mimic-wire/v1"
FIELDS = ["frame.number", "frame.time_epoch", "frame.len", "frame.cap_len", "frame.protocols",
          "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.stream", "tcp.srcport", "tcp.dstport",
          "tcp.seq", "tcp.len", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.reset", "tcp.flags.fin",
          "tcp.payload", "udp.srcport", "udp.dstport", "udp.payload", "dns.qry.name", "dns.a", "dns.aaaa"]


def _tshark(executable=None):
    executable = executable or shutil.which("tshark")
    if not executable:
        raise RuntimeError("TShark is required for live/pcap capture. Install Wireshark with TShark on M, or supply --tshark PATH. JSON analysis/replay does not need TShark.")
    return executable


def _field_args():
    return [arg for name in FIELDS for arg in ("-e", name)]


def write_json(value, path):
    """Atomically write private capture/profile output without logging its bytes."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".mimic-", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, indent=2)
            f.write("\n")
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _flatten(value, target):
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, dict):
                _flatten(item, target)
            else:
                target[key] = item if isinstance(item, list) else [item]


def _hex(value):
    try:
        return bytes.fromhex(value.replace(":", "")).hex()
    except (ValueError, AttributeError) as exc:
        raise ValueError("capture contains invalid payload hex") from exc


def normalize_tshark(rows):
    if not isinstance(rows, list):
        raise ValueError("expected a TShark JSON packet array")
    packets = []
    for row in rows:
        fields = {}
        _flatten(row.get("_source", {}).get("layers", {}), fields)

        def get(key, default=""):
            values = fields.get(key) or []
            return str(values[0]) if values else default

        protocol = "tcp" if get("tcp.srcport") else "udp" if get("udp.srcport") else None
        src, dst = get("ip.src") or get("ipv6.src"), get("ip.dst") or get("ipv6.dst")
        if not protocol or not src or not dst:
            continue
        packet = {"frame": int(get("frame.number", "0")), "time": float(get("frame.time_epoch", "0")),
                  "src": src, "dst": dst, "src_port": int(get(f"{protocol}.srcport")),
                  "dst_port": int(get(f"{protocol}.dstport")), "transport": protocol,
                  "protocols": get("frame.protocols").split(":"),
                  "payload_hex": _hex(get(f"{protocol}.payload")),
                  "truncated": int(get("frame.cap_len", "0")) < int(get("frame.len", "0")),
                  "dns_queries": fields.get("dns.qry.name", []),
                  "dns_addresses": fields.get("dns.a", []) + fields.get("dns.aaaa", [])}
        if protocol == "tcp":
            packet.update({"stream": get("tcp.stream"), "seq": int(get("tcp.seq", "0")),
                           "payload_len": int(get("tcp.len", "0")),
                           "syn": get("tcp.flags.syn") in ("1", "True"),
                           "ack": get("tcp.flags.ack") in ("1", "True"),
                           "reset": get("tcp.flags.reset") in ("1", "True"),
                           "fin": get("tcp.flags.fin") in ("1", "True")})
        packets.append(packet)
    return {"format": CAPTURE_FORMAT, "packets": packets,
            "evidence": {"source": "TShark packet capture", "process_attribution": "unknown", "software_load_success": "unknown"}}


def capture(interface, out, seconds=30, capture_filter=None, executable=None):
    if not interface or not 1 <= seconds <= 3600:
        raise ValueError("supply an interface and a duration from 1 to 3600 seconds")
    cmd = [_tshark(executable), "-n", "-p", "-s", "0", "-i", interface,
           "-a", f"duration:{seconds}", "-T", "json"] + _field_args()
    if capture_filter:
        cmd.extend(["-f", capture_filter])
    # Dumpcap/TShark handle capture privileges; never silently elevate or change M.
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        proc = subprocess.run(cmd, stdout=output, stderr=subprocess.PIPE, text=True,
                              timeout=seconds + 30, check=False)
        if proc.returncode:
            raise RuntimeError("TShark capture failed: " + proc.stderr.strip()[-2000:])
        output.seek(0)
        result = normalize_tshark(json.load(output))
    write_json(result, out)
    return result


def read_capture(path, executable=None):
    path = Path(path)
    if path.suffix.lower() == ".json":
        with path.open(encoding="utf-8") as f:
            value = json.load(f)
        if isinstance(value, list):
            return normalize_tshark(value)
        if value.get("format") != CAPTURE_FORMAT or not isinstance(value.get("packets"), list):
            raise ValueError(f"expected {CAPTURE_FORMAT} or a TShark JSON array")
        return value
    cmd = [_tshark(executable), "-n", "-2", "-r", str(path), "-T", "json"] + _field_args()
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as output:
        proc = subprocess.run(cmd, stdout=output, stderr=subprocess.PIPE, text=True, timeout=120, check=False)
        if proc.returncode:
            raise RuntimeError("TShark import failed: " + proc.stderr.strip()[-2000:])
        output.seek(0)
        return normalize_tshark(json.load(output))


def _machine_addresses(machine):
    addresses = {str(ipaddress.ip_address(address)) for address in machine}
    if not addresses:
        raise ValueError("at least one --machine IP is required, including loopback if needed")
    return addresses


def _encrypted(packet):
    protocols = {p.lower() for p in packet.get("protocols", [])}
    raw = bytes.fromhex(_hex(packet.get("payload_hex", "")))
    tls_record = len(raw) >= 5 and raw[0] in (20, 21, 22, 23) and raw[1] == 3 and raw[2] in range(5)
    ssh_banner = raw.startswith(b"SSH-")
    return bool(protocols & {"tls", "ssl", "dtls", "quic", "ssh"}) or tls_record or ssh_banner


def _group_address(address):
    ip = ipaddress.ip_address(address)
    return ip.is_multicast or str(ip) == "255.255.255.255"


def diagnose(trace, machine):
    addresses = _machine_addresses(machine)
    peers = {}
    queries = set()
    initiators = {}
    for packet in trace["packets"]:
        if packet["transport"] == "tcp" and packet.get("syn") and not packet.get("ack") and packet["src"] in addresses:
            initiators[packet.get("stream", "")] = ((packet["src"], packet["src_port"]), (packet["dst"], packet["dst_port"]))
    for packet in trace["packets"]:
        endpoints = initiators.get(packet.get("stream", "")) if packet["transport"] == "tcp" else None
        if endpoints and {(packet["src"], packet["src_port"]), (packet["dst"], packet["dst_port"])} == set(endpoints):
            outbound = (packet["src"], packet["src_port"]) == endpoints[0]
            address, port = endpoints[1]
        elif packet["src"] in addresses and packet["dst"] not in addresses:
            outbound, address, port = True, packet["dst"], packet["dst_port"]
        elif packet["dst"] in addresses:
            outbound, address, port = False, packet["src"], packet["src_port"]
        elif packet["src"] in addresses:  # local service, e.g. 127.0.0.1 -> 127.0.0.1
            outbound, address, port = True, packet["dst"], packet["dst_port"]
        else:
            continue
        key = (packet["transport"], address, port)
        row = peers.setdefault(key, {"transport": key[0], "address": address, "port": port,
                                    "outbound_packets": 0, "inbound_packets": 0,
                                    "syn_attempts": 0, "syn_ack_packets": 0, "reset_packets": 0,
                                    "encrypted": False, "group_destination": _group_address(address),
                                    "protocols": set(), "streams": set()})
        row["outbound_packets" if outbound else "inbound_packets"] += 1
        row["protocols"].update(packet.get("protocols", []))
        row["encrypted"] |= _encrypted(packet)
        if packet["transport"] == "tcp":
            row["syn_attempts"] += int(outbound and packet.get("syn", False) and not packet.get("ack", False))
            row["syn_ack_packets"] += int(not outbound and packet.get("syn", False) and packet.get("ack", False))
            row["reset_packets"] += int(packet.get("reset", False))
            row["streams"].add(packet.get("stream", ""))
        queries.update(packet.get("dns_queries", []))
    out = []
    for key, row in sorted(peers.items()):
        row["protocols"] = sorted(row["protocols"])
        row["streams"] = sorted(row["streams"])
        row["observation"] = ("encrypted protocol; ciphertext is not replayable" if row["encrypted"]
                              else "group/broadcast discovery candidate; protocol-specific handling may be needed" if row["group_destination"]
                              else "TCP connection attempts without captured SYN-ACK" if row["syn_attempts"] and not row["syn_ack_packets"]
                              else "bidirectional traffic observed" if row["inbound_packets"] and row["outbound_packets"]
                              else "one direction observed")
        out.append(row)
    return {"format": "mimic-startup-report/v1", "machine_addresses": sorted(addresses),
            "peers": out, "dns_queries": sorted(queries),
            "limits": ["Packets are not automatically attributed to C; other programs may generate them.",
                       "Peer differences are candidates, not proof that C depends on A.",
                       "A missing network exchange cannot establish expected device replies.",
                       "No traffic can also mean wrong interface/filter, another local IP, or a non-network check.",
                       "Filesystem/package, registry, SDK and OS USB/Bluetooth/serial checks need separate tracing."]}


def compare(present, absent, machine):
    before, after = diagnose(present, machine), diagnose(absent, machine)
    def index(report):
        return {(r["transport"], r["address"], r["port"]): r for r in report["peers"]}
    good, bad = index(before), index(after)
    changes = []
    for key in sorted(set(good) | set(bad)):
        a, b = good.get(key), bad.get(key)
        counts = ("inbound_packets", "outbound_packets", "syn_ack_packets", "reset_packets")
        if a is None or b is None or any(a[c] != b[c] for c in counts):
            changes.append({"transport": key[0], "address": key[1], "port": key[2],
                            "present": a, "absent": b, "interpretation": "candidate difference; not causal proof"})
    return {"format": "mimic-startup-comparison/v1", "changes": changes,
            "dns_only_present": sorted(set(before["dns_queries"]) - set(after["dns_queries"])),
            "dns_only_absent": sorted(set(after["dns_queries"]) - set(before["dns_queries"])),
            "limits": before["limits"]}


def _select_packets(trace, machine, device, port, transport):
    addresses = _machine_addresses(machine)
    device = str(ipaddress.ip_address(device))
    if _group_address(device):
        raise ValueError("select the device's unicast IP; multicast/broadcast discovery needs a protocol-specific adapter")
    if not 1 <= port <= 65535 or transport not in ("tcp", "udp"):
        raise ValueError("select tcp/udp and a device port in 1..65535")
    packets = []
    for packet in trace["packets"]:
        if packet["transport"] != transport:
            continue
        if packet["src"] in addresses and packet["dst"] == device and packet["dst_port"] == port:
            side = "client"
        elif packet["src"] == device and packet["src_port"] == port and packet["dst"] in addresses:
            side = "server"
        else:
            continue
        packet = dict(packet, side=side)
        if _encrypted(packet):
            raise ValueError("selected traffic is encrypted; ciphertext cannot establish a reusable emulator. Use a supported HTTP capture, SDK trace, or a protocol implementation.")
        if packet.get("truncated"):
            raise ValueError("selected packets are truncated; recapture with full packet length")
        packet["payload_hex"] = _hex(packet.get("payload_hex", ""))
        packets.append(packet)
    if not packets:
        raise ValueError("no selected device traffic; check interface, IPs, port and transport")
    return packets


def learn_wire(trace, machine, device, port, transport, stream=None):
    packets = _select_packets(trace, machine, device, port, transport)
    profile = {"format": WIRE_FORMAT, "transport": transport, "peer": {"address": device, "port": port},
               "evidence": {"source": "selected captured exchanges", "unseen_behavior": "unknown",
                            "software_load_success": "not verified", "redaction": "none; raw protocol bytes must stay private"}}
    if transport == "udp":
        pending = {}
        exchanges = []
        for packet in packets:
            client = (packet["src"], packet["src_port"]) if packet["side"] == "client" else (packet["dst"], packet["dst_port"])
            if packet["side"] == "client":
                old = pending.get(client)
                if old and not old["responses_hex"]:
                    raise ValueError("overlapping/unanswered UDP requests; cannot infer response pairing")
                item = {"request_hex": packet["payload_hex"], "responses_hex": []}
                exchanges.append(item)
                pending[client] = item
            else:
                if client not in pending:
                    raise ValueError("unsolicited UDP response; a protocol-specific adapter is needed")
                pending[client]["responses_hex"].append(packet["payload_hex"])
        if not exchanges or any(not e["responses_hex"] for e in exchanges):
            raise ValueError("no complete UDP exchange for each request; failed-startup traces cannot invent replies")
        profile["exchanges"] = exchanges
        profile["evidence"]["pairing"] = "ordered per-client request/reply assumption; review for asynchronous protocols"
        return profile

    streams = sorted({p.get("stream", "") for p in packets})
    if "" in streams:
        raise ValueError("TCP stream metadata is missing; export using TShark with tcp.stream")
    if stream is None:
        if len(streams) != 1:
            raise ValueError("multiple TCP streams: select --stream from " + ", ".join(streams))
        stream = streams[0]
    packets = [p for p in packets if p.get("stream", "") == str(stream)]
    if not packets:
        raise ValueError("selected TCP stream was not captured")
    if not any(p.get("syn") and not p.get("ack") and p["side"] == "client" for p in packets):
        raise ValueError("TCP capture must begin before C connects (client SYN missing)")
    if not any(p.get("syn") and p.get("ack") and p["side"] == "server" for p in packets):
        raise ValueError("no successful server SYN-ACK; an absent device gives no replayable baseline")
    if any(p.get("reset") for p in packets):
        raise ValueError("TCP stream contains a reset; select a successful, complete startup exchange")
    events, by_side = [], {}
    for packet in packets:
        side = packet["side"]
        if packet.get("syn") and side not in by_side:
            by_side[side] = {"origin": packet["seq"] + 1, "data": bytearray()}
        raw = bytes.fromhex(packet["payload_hex"])
        if packet.get("payload_len", len(raw)) != len(raw):
            raise ValueError("TCP payload bytes are missing; cannot replay an incomplete capture")
        if not raw:
            continue
        state = by_side[side]
        offset = packet["seq"] - state["origin"]
        if offset < 0 or offset > len(state["data"]):
            raise ValueError("TCP gap/out-of-order data; recapture or use a protocol-aware reassembler")
        overlap = min(len(raw), len(state["data"]) - offset)
        if state["data"][offset:offset + overlap] != raw[:overlap]:
            raise ValueError("conflicting TCP retransmission bytes")
        raw = raw[overlap:]
        if not raw:
            continue
        state["data"].extend(raw)
        if events and events[-1]["direction"] == side:
            events[-1]["hex"] += raw.hex()
        else:
            events.append({"direction": side, "hex": raw.hex()})
    if not any(p.get("fin") for p in packets):
        raise ValueError("TCP stream is still open; capture through close or author/review an explicit conversation profile")
    if events and not any(e["direction"] == "server" for e in events):
        raise ValueError("no captured application response; cannot infer an application handshake")
    profile["events"] = events
    profile["evidence"]["stream"] = str(stream)
    profile["evidence"]["connection_only"] = not events
    return profile


def add_parser(sub):
    p = sub.add_parser("startup", help="observe startup dependencies and replay selected TCP/UDP exchanges")
    commands = p.add_subparsers(dest="startup_cmd", required=True)
    interfaces = commands.add_parser("interfaces", help="list TShark capture interfaces")
    interfaces.add_argument("--tshark")
    interfaces.set_defaults(func=lambda args: _list_interfaces(args))
    cp = commands.add_parser("capture", help="passively capture a bounded startup window on M")
    cp.add_argument("--interface", required=True)
    cp.add_argument("--seconds", type=int, default=30)
    cp.add_argument("--capture-filter")
    cp.add_argument("--tshark")
    cp.add_argument("-o", "--out", required=True)
    cp.set_defaults(func=_capture_cmd)
    dp = commands.add_parser("analyze", help="identify network dependency candidates, not causal proof")
    dp.add_argument("capture")
    _machine_args(dp)
    dp.set_defaults(func=_analyze_cmd)
    comparison = commands.add_parser("compare", help="compare startup with A present and absent")
    comparison.add_argument("--present", required=True)
    comparison.add_argument("--absent", required=True)
    _machine_args(comparison)
    comparison.set_defaults(func=_compare_cmd)
    learn = commands.add_parser("learn", help="build a strict selected-peer wire replay profile")
    learn.add_argument("capture")
    _machine_args(learn)
    learn.add_argument("--device", required=True)
    learn.add_argument("--port", type=int, required=True)
    learn.add_argument("--transport", choices=["tcp", "udp"], required=True)
    learn.add_argument("--stream", help="TCP stream ID if several were captured")
    learn.set_defaults(func=_learn_cmd)
    serve = commands.add_parser("serve", help="serve a reviewed TCP or UDP wire profile")
    serve.add_argument("profile")
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, help="override captured port")
    serve.add_argument("--timeout", type=float, default=10)
    serve.add_argument("--stats-out", help="write payload-free replay counters on shutdown")
    serve.set_defaults(func=_serve_cmd)


def _machine_args(parser):
    parser.add_argument("--machine", action="append", required=True, help="M IP; repeat for other interfaces/loopback")
    parser.add_argument("--tshark", help="used only when reading pcap/pcapng")
    parser.add_argument("-o", "--out", required=True)


def _list_interfaces(args):
    subprocess.run([_tshark(args.tshark), "-D"], check=True)


def _capture_cmd(args):
    print("Capturing on M now; start C during this window. Raw bytes stay in the output file.", flush=True)
    result = capture(args.interface, args.out, args.seconds, args.capture_filter, args.tshark)
    print(f"wrote {args.out}: {len(result['packets'])} packets")


def _analyze_cmd(args):
    report = diagnose(read_capture(args.capture, args.tshark), args.machine)
    write_json(report, args.out)
    print(f"wrote {args.out}: {len(report['peers'])} network peer candidates; process attribution and startup success are unknown")


def _compare_cmd(args):
    report = compare(read_capture(args.present, args.tshark), read_capture(args.absent, args.tshark), args.machine)
    write_json(report, args.out)
    print(f"wrote {args.out}: {len(report['changes'])} candidate differences")


def _learn_cmd(args):
    profile = learn_wire(read_capture(args.capture, args.tshark), args.machine, args.device, args.port, args.transport, args.stream)
    write_json(profile, args.out)
    print(f"wrote {args.out}: selected {args.transport} exchanges; C load success must be tested on M")


def _serve_cmd(args):
    from .wire import WireEmulator
    with open(args.profile, encoding="utf-8") as f:
        profile = json.load(f)
    emulator = WireEmulator(profile)
    server = emulator.server(args.bind, args.port, args.timeout)
    print(f"{profile['transport']} stand-in at {args.bind}:{server.server_address[1]}; configure C to reach it before starting C", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("replay counters: " + json.dumps(emulator.stats), flush=True)
        if args.stats_out:
            write_json({"format": "mimic-replay-stats/v1", "counters": emulator.stats,
                        "software_load_success": "not verified"}, args.stats_out)
