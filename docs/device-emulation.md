# Device API learning and offline emulation

This extension lets a coding harness learn the **observed HTTP inputs and outputs**
of a device, then test against a local stand-in after that device is disconnected.
It adds no new runtime dependencies. OpenAPI export is deterministic, so Codex,
GitHub Copilot, Claude, or any other harness can consume the same contract.

## What is supported

| Connection | Support |
| --- | --- |
| Device exposes an HTTP/HTTPS API over LAN or a USB network interface | Direct recording, contract inference and local replay |
| Vendor app talks HTTP to a local device service or cloud service | HAR or mitmweb capture, then local replay if the client endpoint can be changed |
| USB HID, USB vendor transfers, serial/COM, Bluetooth GATT, proprietary SDK | Requires a transport adapter or SDK shim; not implemented by this HTTP extension |
| OS discovery, USB VID/PID, Bluetooth advertising, mDNS/SSDP | Not emulated |
| WebSocket streams, real-time control, physical sensor dynamics | Not inferred or emulated |

A cloud API capture can model the cloud endpoint, but does not establish that the
physical device's own protocol or behaviour has been captured.

Emulation here means that software configured to use the localhost endpoint gets
recorded responses or explicitly authored state rules. It does not make Windows
Device Manager or macOS enumerate an imaginary peripheral. Existing clients must
allow their base URL to be overridden, or use a separate adapter/shim.

## Install

```sh
python -m pip install -e .
# For contributors:
python -m pip install -e '.[dev]'
python -m pytest -q
```

## Capture through the existing proxy or a HAR

Use the vendor app normally while capturing its HTTP traffic. Export HAR **with
response content**, or use the existing `mimic record` and mitmweb workflow.
No credentials are required for inference of unauthenticated local device APIs.

```sh
mkdir -p .mimic-device
mimic device learn 192.168.1.40 --har device.har \
  -o .mimic-device/device.json --openapi .mimic-device/openapi.json

# Alternatively, read all completed matching flows from live mitmweb:
mimic device learn 192.168.1.40 \
  -o .mimic-device/device.json --openapi .mimic-device/openapi.json
```

The host is an exact hostname or IP without scheme/port. Each exchange is kept,
including errors and repeated calls. Unlike the client-generation digest, device
profiles do not deduplicate endpoints or truncate bodies. Missing HAR response
content fails rather than silently turning it into a fabricated empty response.

Captures can contain personal data. Auth/cookie headers are not exported; common
credential fields in JSON, query strings and form bodies are redacted. This is
best-effort redaction by field name: arbitrary text, binary payloads, unusual
credential names, path segments and other personal data still need review.
The `.mimic-device/` directory is ignored by git. Raw HAR files are not automatically
redacted by this feature; keep them private too.

## Record explicit calls directly from Python

When the device has an HTTP API, instrument the calls you actually intend to make.
The recorder does not scan endpoints, invent commands, or retry operations.

```python
from mimic import RecordingSession

recorder = RecordingSession('http://192.168.1.40:8080', timeout=10)
recorder.get('/api/device')
recorder.get('/api/status')
# Exercise more known operations only when you want the real device to execute them.
recorder.save('.mimic-device/device.json')

from mimic.device import openapi, save_profile
save_profile(openapi(recorder.profile()), '.mimic-device/openapi.json')
```

Or export the contract from a previously saved profile:

```sh
mimic device contract .mimic-device/device.json -o .mimic-device/openapi.json
```

The normal `get`, `post`, `put`, `patch`, `delete`, `head`, and `options` helpers work.
HTTP error responses are captured before raising `requests.HTTPError`. Network
failures raise normally and do not create invented response observations. Each
recorded request stays on the configured origin; redirects are disabled. Supply
needed credentials with `headers=...` to `RecordingSession`, just as with `Session`.

## Start the emulator and disconnect the real device

```sh
mimic device serve .mimic-device/device.json --port 8090
```

```python
from mimic import Session

fake_device = Session(base_url='http://127.0.0.1:8090')
print(fake_device.get('/api/status'))
```

Generated clients that subclass `mimic.App` can also be pointed to this endpoint:
`Client(base_url='http://127.0.0.1:8090')`. The override avoids pulling real
credentials from mitmweb. This requires the generated methods to use relative
paths; methods with hardcoded absolute URLs need editing.

The server binds to loopback by default. `--bind` deliberately exposes it to another
interface; there is no emulator authentication. It never forwards unmatched calls
to the real device. Ctrl-C stops it.

## Matching and replay semantics

- Match exact method, literal path, query name/value pairs and body.
- Query pair order and JSON object key order are ignored. Duplicate query keys
  are retained. Paths with IDs are not automatically generalized.
- Captured request headers (including auth) are not matching requirements. JSON
  and form credential fields are redacted consistently before matching.
- JSON bodies retain type distinctions. Other text/form/binary bodies replay as
  captured (form pair order remains significant).
- Repeated identical requests replay their captured responses in order, per
  request signature. Once exhausted, the final response is repeated.
- This sequence is a fixture. It is not automatically inferred device state or
  a global ordering guarantee across different endpoints.
- An unknown method/path returns 404. A known method/path with unmatched input
  returns 409. Both explain that unseen behaviour is unknown.
- Replies preserve status and body. Response headers are limited to Content-Type,
  recomputed Content-Length and `X-Mimic-Source`; cookies, auth challenges, redirect
  Location headers and arbitrary vendor headers are not reproduced.
- `X-Mimic-Source` identifies `captured-replay`, `manual-rule`, `manual-rule-error`
  or `unmatched`. HTTP 204/304 and HEAD obey no-body semantics.

## Add explicit state behaviour

A capture can show different results after a write, but that alone does not prove
a general causal rule. Declare the behaviours you want to test in the profile.
These rules take precedence over captured fixtures, in array order.

```json
{
  "initial_state": {"target_c": 20},
  "rules": [
    {
      "method": "PUT", "path": "/api/target", "request_json": {},
      "set_state": {"target_c": {"$ref": "/request/target_c"}},
      "response_json": {"target_c": {"$ref": "/state/target_c"}}
    },
    {
      "method": "GET", "path": "/api/target",
      "response_json": {"target_c": {"$ref": "/state/target_c"}}
    }
  ]
}
```

Merge these fields into an existing profile, retaining `format`, `host`, and
`observations`. Or run the included fictional example:

```sh
mimic device serve examples/thermostat.device.json
curl http://127.0.0.1:8090/api/device
curl -X PUT http://127.0.0.1:8090/api/target \
  -H 'Content-Type: application/json' -d '{"target_c":23}'
curl http://127.0.0.1:8090/api/target
```

`request_json` is a recursive subset match; `{}` requires an object body. Omit it
to accept any body. `when_state` similarly filters the current state. Optional
`query` matches the exact array of query name/value pairs. `status` defaults to
200. `set_state` updates top-level state keys; `response_json` creates a JSON
response. No Python code is evaluated from profiles.

`{"$ref":"/request/field"}` reads from the current body.
`{"$ref":"/state/field"}` reads state. During `set_state` resolution, state is the
old state; during response resolution it is the updated state. JSON Pointer
escaping (`~0`, `~1`) and array indices are supported. If resolution fails, the
reply is 422 and no state update is committed. There is no automatic schema,
range or physical validation of authored rules. Add explicit match rules for
known error cases, and use the contract to validate inputs in your harness.

`DeviceEmulator.reset()` resets state and replay counters in Python; restarting
the CLI does the same. State updates and replay counters are synchronized.

## What the coding harness can infer

The observational OpenAPI 3.1 document includes literal endpoints, query inputs,
request body schemas, response schemas separated by status/content type, sample
counts and the explicit marker `x-mimic-unseen-behavior: unknown`.

Schema inference uses all captured examples, including nullable fields,
heterogeneous arrays, optional object fields and integer/number variation.
"Required" means present in every observed sample, not proven required by the
real API. Empty arrays do not reveal their item type. Captures do not reveal
all endpoints, allowed enum values, ranges, authentication rules, timing,
unobserved errors, protocol handshakes or hardware behaviour. No LLM is used
for these contracts, and no guess is silently treated as evidence.

Suggested harness workflow:

1. Capture discovery, reads, writes and known errors on the real device.
2. Review `.mimic-device/openapi.json` to design the integration/client.
3. Point that client to the emulator while developing without hardware.
4. Add explicit state/error rules for behaviour beyond exact captured requests.
5. Compare the integration with the real device and expand observations.

For USB/serial/Bluetooth, the next step depends on the actual device and OS:
record the SDK/transport calls, export them into a suitable transport-specific
contract, and inject a shim at that boundary. An HTTP profile cannot substitute
for a binary protocol, OS driver, device authentication key or signed firmware.
