# Make a startup dependency observable, then emulate the observed interface

Let **C** be the software, **M** the machine running it, and **A** the device or
package C expects while starting. The objective is to let C complete its normal
startup when a stand-in supplies A's expected interface.

This extension adds passive network capture and startup diagnostics, followed by
selected TCP/UDP byte replay. The existing HTTP emulator remains available for
semantic API responses and explicit state rules. These tools run **on M**; a cloud
assistant cannot see M's traffic merely because it has a copy of this repository.

## Choose the actual interface

| What C checks | What to observe | What to emulate |
| --- | --- | --- |
| HTTP/HTTPS endpoint on A or a local service | Full HTTP requests/replies, using HAR/mitmweb/RecordingSession | Existing `mimic device` HTTP profiles |
| Plain TCP startup handshake | Connection establishment plus application bytes | New selected TCP conversation replay |
| Plain UDP query/reply | Complete, ordered request/reply datagrams | New exact UDP exchange replay |
| Broadcast/multicast discovery (mDNS, SSDP or proprietary) | Startup packets and discovery protocol | Diagnose here; discovery/address-advertisement adapter still required |
| A local package, DLL, registry key, named pipe or SDK | Process-level file/registry/library/IPC trace | Package/API/IPC shim; not provided by network replay |
| OS USB/HID/serial/Bluetooth device enumeration | SDK/driver/system calls | Transport/SDK shim or virtual device driver; not provided here |
| Encrypted or signed challenge-response | Protocol specification, legitimate credentials and decoded application exchanges where available | Real protocol implementation; captured ciphertext is not a reusable server |

A startup run that fails with A absent usually reveals **where C looks**, not
**what A should reply**. Capture at least one successful startup with A present,
or obtain its documented startup contract. Use repeated successful and failed
runs to separate the dependency from background traffic and variable session data.

## Install on M

```sh
git clone --branch codex/device-api-emulation https://github.com/hoyleb/mimic.git
cd mimic
python -m pip install -e .
```

Live packet capture and pcap/pcapng import need **TShark**, supplied with Wireshark
(TShark 3.4+ fields are used). Install it through the official Wireshark distribution
or your OS package manager. Windows captures also need the capture driver from the
Wireshark installation. If TShark is not on PATH, use `--tshark PATH` on the relevant
commands. JSON analysis and socket replay need no TShark or new Python dependency.

Capture permissions depend on M's operating system and capture-driver setup.
The tool does not silently elevate privileges, install drivers, modify firewall
rules, redirect traffic or weaken TLS validation.

## 1. Capture startup with A present and absent

```sh
mimic startup interfaces
```

Select the interface that carries C's traffic. If C calls a local service, capture
loopback too. Run capture in one terminal and start C normally during the window:

```sh
mimic startup capture --interface INTERFACE --seconds 30 \
  -o .mimic-device/startup-present.json
```

After that run, disconnect A or stop the relevant local service, then repeat the
same C startup into `.mimic-device/startup-absent.json`.

A narrow `--capture-filter 'host DEVICE_IP'` is useful once A's network address is
known. Initially it can hide discovery or a local dependency, so choose the filter
based on the check being investigated. `-n` avoids generating DNS lookups during
capture; `-p` disables promiscuous capture; full packet length is requested.
The selected capture duration is bounded and the capture command does not launch C.

Raw packet payloads are retained because replacing fields can break binary
protocols. They are **not redacted**. Keep capture/profile files private in the
ignored `.mimic-device/` directory; do not upload them to the public repo. Reports
omit payload bytes but may still include internal IP addresses and DNS names.

Existing TShark JSON arrays and Wireshark pcap/pcapng files can also be supplied
to `analyze`, `compare`, and `learn`. pcap imports invoke TShark locally; JSON imports
work without it. Normalized captures use the `mimic-network/v1` format.

## 2. Identify startup dependency candidates

```sh
mimic startup analyze .mimic-device/startup-present.json \
  --machine 192.168.1.10 --machine 127.0.0.1 \
  -o .mimic-device/startup-report.json

mimic startup compare \
  --present .mimic-device/startup-present.json \
  --absent .mimic-device/startup-absent.json \
  --machine 192.168.1.10 --machine 127.0.0.1 \
  -o .mimic-device/startup-comparison.json
```

Repeat `--machine` for the IPs on M that matter, including IPv6 if used. Reports
list transport, peer IP/port, packet counts, TCP streams, SYN/SYN-ACK/reset counts,
encrypted protocol indications, discovery candidates and observed DNS queries.
TCP connection initiators help identify a loopback service's port rather than its
client's ephemeral port.

The comparison shows candidate changes between the runs. A SYN without a captured
SYN-ACK may indicate a missing endpoint, but also packet loss, a wrong capture
interface, filtering or another network problem. Different packet counts do not
prove causality. An inbound reply does not prove that C loaded. Packet captures
are **not automatically attributed to C's process**; narrow the window, correlate
with C's logs or a process tracer, and repeat trials.

If there is no relevant network traffic, do not conclude that A is unnecessary.
The interface/filter/IP can be wrong, or C may be checking package installation,
a file, a driver, OS device presence or local IPC. For Windows, Process Monitor
can identify file/registry/process activity. For Linux, `strace` can identify
file and network system calls. This repo does not automate or parse these traces.

## 3. Learn a selected plaintext startup exchange

Choose the device IP, server port and transport from a successful baseline:

```sh
mimic startup learn .mimic-device/startup-present.json \
  --machine 192.168.1.10 --device 192.168.1.40 --port 9876 \
  --transport tcp --stream 0 \
  -o .mimic-device/startup-device.json
```

For a simple UDP service use `--transport udp` and omit `--stream`.
Multiple TCP streams require explicit selection. A profile models **one selected
service/conversation**, not every interface of A. If startup contacts several
ports, build and run separate reviewed profiles, or implement a coherent protocol
adapter when their state is linked.

TCP learning requires a captured client SYN, server SYN-ACK and connection close.
It merges contiguous payload fragments and removes byte-identical retransmissions.
Missing payloads, conflicting retransmissions, gaps/out-of-order bytes, resets,
truncated packets or an unfinished connection fail conservatively. A stream with
only a successful connection and close can be recorded as `connection_only`; that
models a connect check, not an inferred application handshake.

UDP learning uses an explicit **ordered request/reply assumption per client**.
Unanswered/overlapping requests and unsolicited responses fail. Multiple replies
between successive requests are grouped into that request's reply sequence;
review this assumption if A sends asynchronous telemetry. Learning selects a
unicast peer; multicast/broadcast discovery is diagnostic only in this version.

Recognized TLS, DTLS, QUIC and SSH traffic is rejected for byte learning. An
additional TLS-record/SSH-banner check catches common traffic on unusual ports.
Opaque proprietary encryption may not be recognizable; review the protocol before
replaying raw bytes. Decryption of one capture does not supply the keys or state
needed to run an authenticated TLS server in another session.

## 4. Run the stand-in before C starts

```sh
mimic startup serve .mimic-device/startup-device.json \
  --bind 127.0.0.1 --port 9876
```

Point C's device/service setting at `127.0.0.1:9876`, then start C. If C is in a VM
or container, its loopback refers to that environment; run the emulator there or
use the correctly reachable address.

If C hardcodes A's hostname/IP/port, launching a localhost server is insufficient.
Use C's supported configuration or an appropriate explicitly configured test
network mapping. This tool does not silently change hosts files, DNS, routes,
firewalls or C's binaries. An emulator bound to an address M does not own cannot
receive C's traffic. Discovery advertisements containing A's original address also
need a protocol-aware replacement.

The default bind is loopback. The server supports an explicit IPv4/IPv6 bind and
port override. Its own listeners are ordinary sockets: the OS supplies transport
handshakes, while the emulator handles captured application bytes. It neither
spoofs packet source addresses nor forwards unknown traffic to the real device.

### TCP replay semantics

Each connection starts the same captured script. Server greetings are supported;
client bytes are read independently of packet/read fragmentation. Only the expected
client bytes advance the script. Unknown bytes or premature close terminate that
connection without fabricating a response. There is an overall connection deadline
(default 10 seconds, configurable with `--timeout`). The server closes after the
script's final event.

Direction changes in a capture define script turns; they do **not** establish
semantic message delimiters. Request pipelining, variable message lengths,
server push, live sessions, keepalives, connection-close timing and real-time
constraints may need a protocol implementation. Bytes that happen to start with
a recorded turn can receive that turn's reply before a later mismatch is detected.
No masks, random substitutions or nonce inference are applied.

### UDP replay semantics

Exact datagrams match recorded requests. Response sequences advance independently
per sender and request, then repeat the final recorded response. Unknown datagrams
receive no fabricated reply. There is no inferred causal device state or timing
model. Fresh transaction IDs, timestamps or challenges require a protocol adapter;
blind substitution can corrupt checksums, encodings or signed data.

Programmatic users can inspect `WireEmulator.stats` (connections, matched,
unmatched, timeouts) and call `reset()`. The CLI prints these counters on shutdown;
`--stats-out .mimic-device/replay-stats.json` also saves them. A matched script
still does not establish that C completed loading. There is no payload access logging.

## Try a complete fictional startup gate without A

The example models a toy C that requires `HELLO-A? -> A-READY`, then
`VERSION? -> 1.0`. It is not evidence about your actual software/device.

```sh
# Analyze fictional present/absent captures:
mimic startup compare --present examples/startup-present.json \
  --absent examples/startup-absent.json --machine 192.0.2.10 \
  -o .mimic-device/demo-comparison.json

# Build the replay profile from the fictional successful trace:
mimic startup learn examples/startup-present.json --machine 192.0.2.10 \
  --device 192.0.2.40 --port 9876 --transport tcp \
  -o .mimic-device/demo-device.json

# Start the stand-in:
mimic startup serve .mimic-device/demo-device.json
```

In another terminal:

```sh
python examples/startup_loader.py --host 127.0.0.1 --port 9876
```

The loader prints that its startup gate passed. Stop the stand-in and rerun the
loader: it fails. Tests exercise this mechanism through real localhost sockets,
as well as HTTP replay, UDP replies, TCP fragmentation and failure handling.

## Verify the actual objective on M

1. Record C's startup result and error/log with real A present and absent.
2. Identify the interface C checks; select the relevant captures/trace.
3. Build a stand-in at that interface and direct C to it before startup.
4. Start the actual C and verify it reaches the intended loaded state.
5. Observe traffic after loading; passing presence detection does not establish
   that later commands, hardware functions or background checks will work.

The repo reports `software_load_success: not verified` for learned profiles.
Only an actual run of C can establish the desired outcome. The next device-specific
implementation needs M's OS, C's name/version, A's model/package, the connection
or SDK, an A-present baseline or documented contract, and the startup failure.

## Primary references

- [TShark capture/export options](https://www.wireshark.org/docs/man-pages/tshark.html)
- [TCP field reference](https://www.wireshark.org/docs/dfref/t/tcp.html)
- [UDP field reference](https://www.wireshark.org/docs/dfref/u/udp.html)
- [Wireshark TLS requirements](https://wiki.wireshark.org/TLS/)
- [Microsoft Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [strace project's manual](https://github.com/strace/strace/blob/master/doc/strace.1.in)
