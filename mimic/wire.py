"""Exact application-byte TCP/UDP replay; no packet spoofing or live forwarding."""
import copy
import socket
import socketserver
import threading
import time
from collections import defaultdict

from .startup import WIRE_FORMAT


class WireEmulator:
    def __init__(self, profile):
        if profile.get("format") != WIRE_FORMAT or profile.get("transport") not in ("tcp", "udp"):
            raise ValueError(f"expected {WIRE_FORMAT} TCP/UDP profile")
        self.profile = copy.deepcopy(profile)
        self.transport = profile["transport"]
        self.events = []
        self.exchanges = defaultdict(list)
        self._counts = defaultdict(int)
        self._lock = threading.Lock()
        self.stats = {"connections": 0, "matched": 0, "unmatched": 0, "timeouts": 0}
        if self.transport == "tcp":
            for event in profile.get("events", []):
                if event.get("direction") not in ("client", "server"):
                    raise ValueError("TCP directions must be client/server")
                raw = bytes.fromhex(event["hex"])
                if not raw or len(raw) > 16 * 1024 * 1024:
                    raise ValueError("TCP events must contain 1..16 MiB bytes")
                self.events.append((event["direction"], raw))
            if not self.events and not profile.get("evidence", {}).get("connection_only"):
                raise ValueError("an empty conversation needs explicit connection_only evidence")
        else:
            for item in profile.get("exchanges", []):
                request = bytes.fromhex(item["request_hex"])
                responses = [bytes.fromhex(value) for value in item["responses_hex"]]
                if not responses or any(len(value) > 65507 for value in [request] + responses):
                    raise ValueError("UDP exchanges need replies and payloads no larger than 65507 bytes")
                self.exchanges[request].append(responses)
            if not self.exchanges:
                raise ValueError("UDP profile needs at least one complete exchange")

    def _count(self, name):
        with self._lock:
            self.stats[name] += 1

    def reset(self):
        with self._lock:
            self._counts.clear()
            self.stats = dict.fromkeys(self.stats, 0)

    def server(self, bind="127.0.0.1", port=None, timeout=10):
        port = self.profile["peer"]["port"] if port is None else port
        if not 0 <= port <= 65535 or not 0 < timeout <= 3600:
            raise ValueError("invalid port or connection timeout")
        emulator = self

        class TCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                emulator._count("connections")
                deadline = time.monotonic() + timeout
                self.request.settimeout(timeout)
                try:
                    for direction, expected in emulator.events:
                        remaining_time = deadline - time.monotonic()
                        if remaining_time <= 0:
                            raise socket.timeout()
                        self.request.settimeout(remaining_time)
                        if direction == "server":
                            self.request.sendall(expected)
                            continue
                        # TCP has no message boundaries: receive the full expected
                        # client turn independent of packet/read fragmentation.
                        remaining = len(expected)
                        pieces = []
                        while remaining:
                            remaining_time = deadline - time.monotonic()
                            if remaining_time <= 0:
                                raise socket.timeout()
                            self.request.settimeout(remaining_time)
                            piece = self.request.recv(min(remaining, 65536))
                            if not piece:
                                emulator._count("unmatched")
                                return
                            pieces.append(piece)
                            remaining -= len(piece)
                        if b"".join(pieces) != expected:
                            emulator._count("unmatched")
                            return  # unknown requests close; no plausible replies
                    emulator._count("matched")
                except socket.timeout:
                    emulator._count("timeouts")
                except OSError:
                    emulator._count("unmatched")

        class UDPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                request, server_socket = self.request
                # UDP has no connection: independent replay counts per sender
                # and request. Each request's final captured response repeats.
                key = (self.client_address, request)
                with emulator._lock:
                    choices = emulator.exchanges.get(request)
                    if not choices:
                        emulator.stats["unmatched"] += 1
                        return  # unknown UDP datagram receives no fabricated reply
                    index = min(emulator._counts[key], len(choices) - 1)
                    emulator._counts[key] += 1
                    responses = choices[index]
                    emulator.stats["matched"] += 1
                for reply in responses:
                    server_socket.sendto(reply, self.client_address)

        server_base = socketserver.ThreadingTCPServer if self.transport == "tcp" else socketserver.ThreadingUDPServer

        class Server(server_base):
            daemon_threads = True
            allow_reuse_address = True
            address_family = socket.AF_INET6 if ":" in bind else socket.AF_INET

        return Server((bind, port), TCPHandler if self.transport == "tcp" else UDPHandler)
