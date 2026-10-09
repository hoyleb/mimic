"""Fictional C: startup fails unless the expected A handshake is available."""
import argparse
import socket
import sys


def read_exact(connection, size):
    result = b""
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise RuntimeError("device closed before completing the startup handshake")
        result += part
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9876)
    args = parser.parse_args()
    try:
        with socket.create_connection((args.host, args.port), timeout=3) as connection:
            for request, expected in [(b"HELLO-A?", b"A-READY"), (b"VERSION?", b"1.0")]:
                connection.sendall(request)
                if read_exact(connection, len(expected)) != expected:
                    raise RuntimeError("unexpected device startup reply")
    except (OSError, RuntimeError) as exc:
        print(f"Startup failed: {exc}", file=sys.stderr)
        return 1
    print("Startup gate passed; fictional software C loaded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
