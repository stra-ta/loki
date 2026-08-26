#!/usr/bin/env python3
"""Loki throughput and fault-behavior probe.

Measures, against a local Python echo server over loopback TCP:

1. Passthrough throughput: 128 MiB echoed directly vs through a rule-free
   Loki proxy. Client-side Python costs are identical in both cases, so the
   ratio is meaningful; absolute MB/s is not a Loki ceiling.
2. Latency-fault RTT: configured mean 50 ms +/- 20 ms one-way per direction,
   so nominal RTT is 100 ms. Reports median/min/max over 60 single-ping
   round trips.
3. Throttle accuracy: configured 50 KiB/s with 8 KiB burst on a 256 KiB
   transfer; reports achieved KiB/s.

Usage: python3 scripts/bench.py [path-to-loki-binary]
Requires the default-preset RelWithDebInfo build. Writes nothing into the repository.
"""

import os
import socket
import statistics
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOKI = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    REPO, "build", "default", "src", "cli", "loki")
WORKDIR = "/tmp/loki-bench"

THROUGHPUT_BYTES = 128 * 1024 * 1024
WARMUP_BYTES = 8 * 1024 * 1024
RTT_ROUNDS = 60
THROTTLE_BYTES = 256 * 1024
THROUGHPUT_ROUNDS = 5


def echo_server():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(16)

    def echo(c):
        try:
            while True:
                d = c.recv(262144)
                if not d:
                    break
                c.sendall(d)
        finally:
            c.close()

    def loop():
        while True:
            c, _ = srv.accept()
            threading.Thread(target=echo, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv.getsockname()[1]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def run_loki(scenario_text):
    os.makedirs(WORKDIR, exist_ok=True)
    path = os.path.join(WORKDIR, "scenario.yaml")
    with open(path, "w") as f:
        f.write(scenario_text)
    proc = subprocess.Popen([LOKI, "run", path], cwd=WORKDIR,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    return proc


def transfer(sock, payload):
    got = bytearray()

    def sender():
        view = memoryview(payload)
        sent = 0
        while sent < len(payload):
            sent += sock.send(view[sent:sent + 262144])

    t = threading.Thread(target=sender)
    t.start()
    sock.settimeout(120)
    t0 = time.perf_counter()
    while len(got) < len(payload):
        d = sock.recv(262144)
        if not d:
            break
        got += d
    dt = time.perf_counter() - t0
    t.join()
    assert bytes(got) == payload, "data mismatch"
    return dt


def throughput_case(upstream_port, listen_port=None, size=THROUGHPUT_BYTES):
    """Echo `size` bytes either direct or through a running proxy."""
    payload = bytes((i * 131 + 17) & 0xFF for i in range(size))
    port = listen_port if listen_port else upstream_port
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    transfer(s, payload[:WARMUP_BYTES])  # warm buffers and allocator paths
    dt = transfer(s, payload)
    s.close()
    return size / dt


def main():
    print(f"binary                : {LOKI}")
    up = echo_server()

    direct = []
    proxied = []
    for _ in range(THROUGHPUT_ROUNDS):
        direct.append(throughput_case(up))
        lp = free_port()
        proc = run_loki(f"version: 1\nseed: 1\nlisten: 127.0.0.1:{lp}\n"
                        f"upstream: 127.0.0.1:{up}\n")
        proxied.append(throughput_case(up, lp))
        proc.terminate(); proc.wait()
    direct.sort()
    proxied.sort()

    lat_p = free_port()
    proc = run_loki(f"version: 1\nseed: 11\nlisten: 127.0.0.1:{lat_p}\n"
                    f"upstream: 127.0.0.1:{up}\n"
                    "rules:\n  - name: slow\n    inject:\n      latency:\n"
                    "        mean: 50ms\n        jitter: 20ms\n")
    s = socket.create_connection(("127.0.0.1", lat_p), timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    time.sleep(0.2)
    rtts = []
    for _ in range(RTT_ROUNDS):
        t0 = time.perf_counter()
        s.sendall(b"ping")
        got = b""
        while len(got) < 4:
            got += s.recv(4)
        rtts.append((time.perf_counter() - t0) * 1000)
    s.close()
    proc.terminate(); proc.wait()
    rtts.sort()

    th_p = free_port()
    proc = run_loki(f"version: 1\nseed: 13\nlisten: 127.0.0.1:{th_p}\n"
                    f"upstream: 127.0.0.1:{up}\n"
                    "rules:\n  - name: bw\n    inject:\n      bandwidth:\n"
                    "        rate: 51200\n        burst: 8192\n")
    s = socket.create_connection(("127.0.0.1", th_p), timeout=30)
    payload = bytes(THROTTLE_BYTES)
    t0 = time.perf_counter()
    s.sendall(payload)
    got = bytearray()
    s.settimeout(30)
    while len(got) < len(payload):
        d = s.recv(65536)
        if not d:
            break
        got += d
    dt = time.perf_counter() - t0
    s.close()
    proc.terminate(); proc.wait()

    gbit = lambda bps: bps * 8 / 1e9
    print(f"passthrough direct   : "
          f"{statistics.median(direct)/1e6:.0f} MB/s "
          f"({', '.join(f'{gbit(x):.2f}' for x in direct)} Gbit/s)")
    print(f"passthrough via loki : "
          f"{statistics.median(proxied)/1e6:.0f} MB/s "
          f"({', '.join(f'{gbit(x):.2f}' for x in proxied)} Gbit/s)")
    print(f"latency RTT (50ms+/-20ms x2): median "
          f"{statistics.median(rtts):.1f} ms, min {rtts[0]:.1f}, max {rtts[-1]:.1f}")
    print(f"throttle achieved    : {len(got)/1024/dt:.0f} KiB/s (configured 50)")


if __name__ == "__main__":
    main()
