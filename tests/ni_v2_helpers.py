#!/usr/bin/env python3
"""Traffic helpers for run_ni_validation_v2.py. Executed inside Mininet host namespaces.
Every subcommand prints exactly one JSON object on stdout."""
import argparse, json, selectors, socket, struct, sys, threading, time


def parse_ports(spec):
    out = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            out.extend(range(int(a), int(b) + 1))
        elif part:
            out.append(int(part))
    return out


def cmd_listen(a):
    sel = selectors.DefaultSelector()
    for p in parse_ports(a.ports):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a.ip, p)); s.listen(128); s.setblocking(False)
        sel.register(s, selectors.EVENT_READ, "listen")
    print(json.dumps({"listening": a.ports}), flush=True)
    while True:
        for key, _ in sel.select(1.0):
            sock = key.fileobj
            if key.data == "listen":
                c, _ = sock.accept(); c.setblocking(False); sel.register(c, selectors.EVENT_READ, "conn")
            else:
                try:
                    d = sock.recv(65536)
                except OSError:
                    d = b""
                if not d:
                    sel.unregister(sock); sock.close()


def cmd_scan(a):
    res = {"attempted": 0, "open": 0, "refused": 0, "timeout": 0, "other": 0}
    t0 = time.time()
    for p in parse_ports(a.ports):
        s = socket.socket(); s.settimeout(a.timeout)
        r = s.connect_ex((a.target, p)); res["attempted"] += 1
        if r == 0: res["open"] += 1
        elif r == 111: res["refused"] += 1
        elif r in (11, 110): res["timeout"] += 1
        else: res["other"] += 1
        s.close()
    res["duration_s"] = round(time.time() - t0, 3)
    print(json.dumps(res))


def cmd_fanout(a):
    ok = 0; t0 = time.time()
    for ip in a.targets.split(","):
        try:
            s = socket.create_connection((ip, a.port), timeout=2)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for _ in range(a.payload_packets):
                s.sendall(b"x" * 64); time.sleep(0.002)
            s.close(); ok += 1
        except OSError:
            pass
    print(json.dumps({"targets": len(a.targets.split(",")), "connected": ok,
                      "payload_packets_each": a.payload_packets, "duration_s": round(time.time() - t0, 3)}))


def cmd_abort(a):
    ok = 0; n = 0; t0 = time.time()
    for p in parse_ports(a.ports):
        n += 1
        try:
            s = socket.create_connection((a.target, p), timeout=2)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close(); ok += 1   # abortive close -> RST emitted by THIS host
        except OSError:
            pass
        time.sleep(0.01)
    print(json.dumps({"attempted": n, "connected_then_reset": ok, "duration_s": round(time.time() - t0, 3)}))


def cmd_bulk(a):
    t0 = time.time(); total = 0
    s = socket.create_connection((a.target, a.port), timeout=5)
    s.sendall(f"GET /big.bin HTTP/1.0\r\nHost: {a.target}\r\n\r\n".encode())
    while True:
        d = s.recv(65536)
        if not d: break
        total += len(d)
    s.close()
    print(json.dumps({"bytes": total, "duration_s": round(time.time() - t0, 3)}))


def main():
    ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="c", required=True)
    p = sp.add_parser("listen"); p.add_argument("--ip", required=True); p.add_argument("--ports", required=True); p.set_defaults(f=cmd_listen)
    p = sp.add_parser("scan"); p.add_argument("--target", required=True); p.add_argument("--ports", required=True); p.add_argument("--timeout", type=float, default=0.5); p.set_defaults(f=cmd_scan)
    p = sp.add_parser("fanout"); p.add_argument("--targets", required=True); p.add_argument("--port", type=int, default=80); p.add_argument("--payload-packets", type=int, default=30); p.set_defaults(f=cmd_fanout)
    p = sp.add_parser("abort"); p.add_argument("--target", required=True); p.add_argument("--ports", required=True); p.set_defaults(f=cmd_abort)
    p = sp.add_parser("bulk"); p.add_argument("--target", required=True); p.add_argument("--port", type=int, default=8080); p.set_defaults(f=cmd_bulk)
    a = ap.parse_args(); a.f(a)


if __name__ == "__main__":
    main()
