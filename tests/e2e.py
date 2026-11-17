#!/usr/bin/env python3
"""Exercise NetCrow's real TLS, relay, TCP proxy and lifecycle paths.

Run after `cargo build`: python3 tests/e2e.py [path/to/netcrow].
Uses only Python's standard library and loopback services; no public network.
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import http.server
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

PAYLOAD = bytes(range(256)) * 512
# Short UTF-8 input with TOML-sensitive characters and control bytes exercises
# raw configuration decoding before the client and relay derive SHA-256 tokens.
TOKEN = '密钥"\\\n\t\x00\x7f🔑'
STOP_KEYWORD = "STOP[网].*"
CONTROL = {"body": b"RUN", "status": 200}
CONTROL_PAGES = {"/control": CONTROL}


class TargetHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        control = CONTROL_PAGES.get(self.path)
        body = control["body"] if control is not None else PAYLOAD * (64 if self.path == "/slow" else 32 if self.path == "/large" else 1)
        status = control["status"] if control is not None else 200
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, *_):
        pass


class HalfCloseHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(20)
        digest = hashlib.sha256()
        while data := self.request.recv(16384):
            digest.update(data)
        self.request.sendall(digest.hexdigest().encode("ascii"))


class ThreadServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def receive(sock, count):
    result = bytearray()
    while len(result) < count:
        block = sock.recv(count - len(result))
        if not block:
            raise EOFError(f"expected {count} bytes, received {len(result)}")
        result.extend(block)
    return bytes(result)


def receive_all(sock):
    parts = []
    while block := sock.recv(65536):
        parts.append(block)
    return b"".join(parts)


def wait_until(fn, label, timeout=15):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            result = fn()
            if result:
                return result
        except (OSError, EOFError, AssertionError) as error:
            last_error = error
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {label}; last error: {last_error}")


def socks_connect(port, destination, destination_port, *, timeout=12):
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert receive(sock, 2) == b"\x05\x00", "SOCKS5 no-auth negotiation failed"
        try:
            packed = socket.inet_pton(socket.AF_INET, destination)
            address = b"\x01" + packed
        except OSError:
            name = destination.encode("ascii")
            address = b"\x03" + bytes([len(name)]) + name
        sock.sendall(b"\x05\x01\x00" + address + struct.pack("!H", destination_port))
        prefix = receive(sock, 4)
        assert prefix[0] == 5 and prefix[2] == 0, f"invalid SOCKS response: {prefix!r}"
        if prefix[3] == 1:
            receive(sock, 6)
        elif prefix[3] == 4:
            receive(sock, 18)
        elif prefix[3] == 3:
            receive(sock, receive(sock, 1)[0] + 2)
        else:
            raise AssertionError(f"invalid SOCKS address type: {prefix!r}")
        if prefix[1] != 0:
            raise OSError(f"SOCKS connect rejected: {prefix[1]}")
        return sock
    except BaseException:
        sock.close()
        raise


def verify_http(response, expected=PAYLOAD):
    headers, separator, body = response.partition(b"\r\n\r\n")
    assert separator, f"missing HTTP response headers: {response[:200]!r}"
    assert headers.startswith(b"HTTP/1.1 200") or headers.startswith(b"HTTP/1.0 200"), headers
    assert body == expected, f"response corruption: got {len(body)}, expected {len(expected)} bytes"
    return True


def get_via_socks(proxy_port, target_port, host="127.0.0.1"):
    with socks_connect(proxy_port, host, target_port) as sock:
        sock.sendall(b"GET /payload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        return verify_http(receive_all(sock))


def assert_rejected(fn):
    try:
        connection = fn()
    except (OSError, EOFError):
        return True
    if hasattr(connection, "close"):
        connection.close()
    raise AssertionError("connection unexpectedly succeeded")


class Harness:
    def __init__(self, binary, directory):
        self.binary = binary
        self.directory = Path(directory)
        self.processes = []
        self.logs = {}
        self.handles = []

    def write(self, name, text):
        path = self.directory / f"{name}.toml"
        path.write_text(text, encoding="utf-8")
        return path

    def start(self, name, mode, config):
        logfile = self.directory / f"{name}.log"
        handle = logfile.open("wb")
        self.handles.append(handle)
        process = subprocess.Popen(
            [self.binary, mode, "--config", str(config)],
            stdout=handle, stderr=subprocess.STDOUT,
            env={**os.environ, "RUST_LOG": "netcrow=info"},
        )
        self.processes.append(process)
        self.logs[name] = logfile
        return process

    def log(self, name):
        return self.logs[name].read_text(encoding="utf-8", errors="replace")

    def wait_log(self, name, phrase, *, after=0, timeout=15):
        return wait_until(lambda: phrase in self.log(name)[after:], f"{name}: {phrase}", timeout)

    def check_running(self):
        for process in self.processes:
            assert process.poll() is None, f"NetCrow process exited with {process.returncode}"

    def close(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        for handle in self.handles:
            handle.close()

    def diagnostics(self):
        for name in self.logs:
            print(f"\n--- {name} log ---\n{self.log(name)[-20000:]}", file=sys.stderr)


def toml_string(value):
    # JSON's string escapes are also TOML basic-string escapes. Keep Unicode
    # literal (including non-BMP scalars), and escape TOML's forbidden DEL byte.
    return json.dumps(value, ensure_ascii=False).replace("\x7f", "\\u007f")


def client_config(peer, relay_port, pin, *, socks=None, http=None, shares=False,
                  token=TOKEN, idle=0, control_port=None, open_timeout=12,
                  proxy_subnets=None, sleep_secs=4, control_mode="both",
                  initially_disabled=False, relay_host="localhost", relay_sni=None,
                  ca_cert_path=None):
    lines = [
        f'id = "{peer}"', f'token = {toml_string(token)}',
        f'relay_addr = {toml_string(f"{relay_host}:{relay_port}/netcrow")}',
        f'shared_subnets = {["127.0.0.1/32"] if shares else []!r}'.replace("'", '"'),
    ]
    if relay_sni is not None:
        lines.append(f"relay_sni = {toml_string(relay_sni)}")
    if proxy_subnets is not None:
        lines.append(f"proxy_subnets = {proxy_subnets!r}".replace("'", '"'))
    if socks:
        lines.append(f'socks5_listen = "127.0.0.1:{socks}"')
    if http:
        lines.append(f'http_listen = "127.0.0.1:{http}"')
    lines += ["[tls]"]
    if ca_cert_path is None:
        lines.append(f"spki_sha256 = {toml_string(pin)}")
    else:
        lines.append(f"ca_cert_path = {toml_string(ca_cert_path)}")
    lines += [
        "[connection]",
        f"idle_secs = {idle}", f"sleep_secs = {sleep_secs}", "probe_secs = 1",
        "heartbeat_secs = 1", "heartbeat_timeout_secs = 4", "reconnect_secs = 1",
        f"open_timeout_secs = {open_timeout}", "connect_timeout_secs = 2", "max_streams = 128",
    ]
    if control_port:
        if control_mode not in ("both", "disable", "enable"):
            raise ValueError(f"unknown control mode: {control_mode}")
        control_path = "/control" if control_mode == "both" else f"/control-{control_mode}"
        control_url = f'url = "http://127.0.0.1:{control_port}{control_path}"'
        lines += [
            "[control]", "interval_secs = 1", "timeout_secs = 2", "max_body_bytes = 1024",
            f"initially_disabled = {str(initially_disabled).lower()}",
        ]
        if control_mode in ("both", "disable"):
            lines += ["[[control.disable]]", control_url, f'keyword = {toml_string(STOP_KEYWORD)}']
        if control_mode in ("both", "enable"):
            lines += ["[[control.enable]]", control_url, 'regex = "RUN"']
    return "\n".join(lines) + "\n"


def check_single_control_lists(harness, relay_port, pin, target_port):
    # Dedicated pages prevent these transitions from changing the existing
    # office/home pair, which continues exercising the two-list behavior.
    for mode in ("disable", "enable"):
        peer = f"{mode}only"
        page = {"body": b"RUN", "status": 200}
        CONTROL_PAGES[f"/control-{mode}"] = page
        proxy_port = free_port()
        config = harness.write(peer, client_config(
            peer, relay_port, pin, socks=proxy_port, control_port=target_port,
            control_mode=mode, initially_disabled=True,
            proxy_subnets=["127.0.0.1/32"],
        ))
        process = harness.start(peer, "client", config)
        try:
            # A successful disable nonmatch / enable match must release the
            # explicit startup-disabled state and permit an actual relay request.
            harness.wait_log(peer, "WSS connected")
            assert get_via_socks(proxy_port, target_port)
            offset = len(harness.log(peer))
            page["body"] = STOP_KEYWORD.encode("utf-8") if mode == "disable" else b"NO MATCH"
            harness.wait_log(peer, "remote control disabled client", after=offset)
            assert_rejected(lambda: socks_connect(proxy_port, "127.0.0.1", target_port, timeout=4))
            offset = len(harness.log(peer))
            page["body"] = b"NO MATCH" if mode == "disable" else b"RUN"
            harness.wait_log(peer, "WSS connected", after=offset)
            assert get_via_socks(proxy_port, target_port)
            print(f"PASS {mode}-only polling releases startup state, stops, and reconnects")
        finally:
            process.terminate()
            process.wait(timeout=5)


def run(binary):
    with tempfile.TemporaryDirectory(prefix="netcrow-e2e-") as directory:
        harness = Harness(binary, directory)
        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        halfclose = ThreadServer(("127.0.0.1", 0), HalfCloseHandler)
        outside = http.server.ThreadingHTTPServer(("127.0.0.2", 0), TargetHandler)
        for server in (httpd, halfclose, outside):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        target_port = httpd.server_port
        halfclose_port = halfclose.server_address[1]
        relay_port, socks_port, http_port = (free_port() for _ in range(3))
        try:
            peers = "\n".join(
                f'[[peers]]\nid = "{peer}"\ntoken = {toml_string(TOKEN)}'
                for peer in ("office", "home", "pinbad", "authbad", "ca", "selected", "sleepy",
                             "disableonly", "enableonly", "pinsilent", "pincustom",
                             "casilent", "caname", "namebad")
            )
            relay = harness.write("relay", f'''
listen = "127.0.0.1:{relay_port}"
pending_timeout_secs = 15
peer_timeout_secs = 6
max_streams_per_peer = 128
[tls]
cert_path = "relay-cert.pem"
key_path = "relay-key.pem"
names = ["localhost"]
{peers}
''')
            relay_process = harness.start("relay", "relay", relay)
            cert = harness.directory / "relay-cert.pem"
            wait_until(lambda: cert.exists() and cert.stat().st_size > 100, "relay certificate")
            output = subprocess.check_output(
                [binary, "fingerprint", "--cert", str(cert)], text=True, timeout=10
            )
            match = re.search(r"sha256/[A-Za-z0-9+/]{43}=", output)
            assert match, f"invalid fingerprint command output: {output!r}"
            pin = match.group(0)
            office = harness.write("office", client_config("office", relay_port, pin, shares=True, idle=2, control_port=target_port))
            home = harness.write("home", client_config("home", relay_port, pin, socks=socks_port,
                                                       http=http_port, control_port=target_port))
            harness.start("office", "client", office)
            # Ensure the first automatic policy snapshot already includes this route.
            harness.wait_log("office", "WSS connected")
            harness.start("home", "client", home)
            wait_until(lambda: get_via_socks(socks_port, target_port), "SOCKS routed request", timeout=20)
            print("PASS short Unicode/control-character token authentication + SOCKS5 IPv4 + large payload")
            assert get_via_socks(socks_port, target_port, host="localhost")
            print("PASS SOCKS5 DNS name + route selection")

            with socket.create_connection(("127.0.0.1", http_port), timeout=12) as sock:
                # Send CONNECT and the next protocol's data together: neither can be lost.
                sock.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode()
                             + b"GET /payload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                result = receive_all(sock)
                connect_headers, _, tunneled = result.partition(b"\r\n\r\n")
                assert b" 200 " in connect_headers, connect_headers
                verify_http(tunneled)
            print("PASS HTTP CONNECT + coalesced tunnel bytes")

            with socket.create_connection(("127.0.0.1", http_port), timeout=12) as sock:
                sock.sendall(f"GET http://127.0.0.1:{target_port}/payload HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nProxy-Connection: keep-alive\r\n\r\n".encode())
                verify_http(receive_all(sock))
            post_body = b"request body after headers\x00" * 3000
            with socket.create_connection(("127.0.0.1", http_port), timeout=12) as sock:
                sock.sendall(f"POST http://127.0.0.1:{target_port}/echo HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\nContent-Length: {len(post_body)}\r\n\r\n".encode() + post_body)
                verify_http(receive_all(sock), post_body)
            print("PASS absolute-form HTTP GET/POST + body preservation")

            with socks_connect(socks_port, "127.0.0.1", halfclose_port) as sock:
                sock.sendall(PAYLOAD * 64)
                sock.shutdown(socket.SHUT_WR)
                assert receive_all(sock) == hashlib.sha256(PAYLOAD * 64).hexdigest().encode()
            print("PASS TCP half-close + 8 MiB binary upload across bounded queues")
            with socks_connect(socks_port, "127.0.0.1", target_port) as sock:
                sock.sendall(b"GET /large HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                verify_http(receive_all(sock), PAYLOAD * 32)
            print("PASS 4 MiB download across bounded queues")

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                assert all(pool.map(lambda _: get_via_socks(socks_port, target_port), range(8)))
            print("PASS concurrent multiplexed streams")

            # Fill one destination's receive window while another stream remains live.
            # A connection-wide blocked send would stall the independent GET below.
            slow_started = threading.Event()
            drain_slow = threading.Event()

            def slow_download():
                with socks_connect(socks_port, "127.0.0.1", target_port) as sock:
                    sock.sendall(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                    header = bytearray()
                    while not header.endswith(b"\r\n\r\n"):
                        header.extend(receive(sock, 1))
                        assert len(header) <= 8192, "oversized slow response headers"
                    assert b" 200 " in header
                    body = bytearray(receive(sock, 16384))
                    slow_started.set()
                    assert drain_slow.wait(timeout=8), "independent request stalled behind slow stream"
                    while block := sock.recv(16384):
                        body.extend(block)
                        time.sleep(0.003)
                    assert body == PAYLOAD * 64, "slow stream was truncated or corrupted"
                    return True

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                slow_future = pool.submit(slow_download)
                assert slow_started.wait(timeout=10), "slow stream never started"
                time.sleep(0.3)  # Give the sender enough time to exhaust this stream's credit.
                independent = pool.submit(get_via_socks, socks_port, target_port)
                try:
                    assert independent.result(timeout=5), "unrelated stream failed"
                finally:
                    drain_slow.set()
                assert slow_future.result(timeout=20)
            print("PASS slow 8 MiB reader preserves unrelated stream + all payload bytes")

            with socket.create_connection(("127.0.0.2", outside.server_port), timeout=5) as sock:
                sock.sendall(b"GET /payload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                verify_http(receive_all(sock))
            assert get_via_socks(socks_port, outside.server_port, host="127.0.0.2")
            with socket.create_connection(("127.0.0.1", socks_port), timeout=5) as sock:
                sock.sendall(b"\x05\x01\x00")
                assert receive(sock, 2) == b"\x05\x00"
                sock.sendall(b"\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x35")
                assert receive(sock, 2) == b"\x05\x07", "UDP ASSOCIATE must be unsupported"
            print("PASS default direct routing outside remote subnets + SOCKS UDP rejection")

            offset = len(harness.log("office"))
            harness.wait_log("office", "entering sleep", after=offset)
            assert get_via_socks(socks_port, target_port)
            harness.wait_log("office", "checking pending requests", after=offset)
            print("PASS control polls do not reset idle + offline queued request + scheduled wake")

            # A chosen but unadvertised address must fail, without falling back to direct.
            # Conversely, an advertised address excluded by this filter must go direct.
            selected_port = free_port()
            selected_config = harness.write("selected", client_config(
                "selected", relay_port, pin, socks=selected_port,
                proxy_subnets=["127.0.0.2/32"], control_port=target_port, open_timeout=3,
            ))
            harness.start("selected", "client", selected_config)
            harness.wait_log("selected", "WSS connected")
            assert_rejected(lambda: socks_connect(selected_port, "127.0.0.2", outside.server_port, timeout=5))
            assert get_via_socks(selected_port, target_port)
            print("PASS explicit selection rejects missing route and excludes advertised subnet")

            active_direct = socks_connect(socks_port, "127.0.0.2", outside.server_port)
            active = socks_connect(socks_port, "127.0.0.1", halfclose_port)
            active.sendall(b"unfinished request")
            home_offset = len(harness.log("home"))
            # Keyword is literal, including regex syntax; disable still wins
            # when both the keyword and the legacy regex enable rule match.
            CONTROL["body"] = f"before {STOP_KEYWORD} RUN after".encode("utf-8")
            harness.wait_log("home", "remote control disabled client", after=home_offset)
            active.settimeout(5)
            try:
                assert active.recv(1) == b"", "disabled client left a TCP stream alive"
            except ConnectionResetError:
                pass
            finally:
                active.close()
            assert_rejected(lambda: socks_connect(socks_port, "127.0.0.1", target_port, timeout=4))
            assert get_via_socks(socks_port, outside.server_port, host="127.0.0.2")
            with active_direct:
                active_direct.sendall(b"GET /payload HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                verify_http(receive_all(active_direct))
            harness.wait_log("selected", "remote control disabled client")
            assert get_via_socks(selected_port, target_port)
            assert_rejected(lambda: socks_connect(selected_port, "127.0.0.2", outside.server_port, timeout=4))
            print("PASS literal keyword disables with priority over regex enable; direct streams continue")

            CONTROL["body"] = b"NO MATCH"
            # With both lists present, a successful nonmatch preserves the
            # disabled state instead of treating the missing match as revival.
            stop = time.monotonic() + 1.5
            while time.monotonic() < stop:
                assert_rejected(lambda: socks_connect(socks_port, "127.0.0.1", target_port, timeout=4))
                time.sleep(0.1)
            print("PASS two-list successful nonmatch preserves disabled state")

            CONTROL["body"] = b"RUN"
            CONTROL["status"] = 500
            # A full control interval with HTTP errors must not revive a disabled client.
            stop = time.monotonic() + 1.5
            while time.monotonic() < stop:
                assert_rejected(lambda: socks_connect(socks_port, "127.0.0.1", target_port, timeout=4))
                time.sleep(0.1)
            CONTROL["status"] = 200
            wait_until(lambda: get_via_socks(socks_port, target_port), "control revival", timeout=20)
            print("PASS control HTTP failure preserves disabled state + recovery reconnects")

            check_single_control_lists(harness, relay_port, pin, target_port)

            # These use the real NetCrow WSS listener, not only a TLS handshake:
            # no SNI and a custom SNI must still reach the /netcrow endpoint.
            # The certificate has only a localhost SAN, so the IP dial with a
            # localhost override also proves CA verification uses the TLS name.
            for peer, connection, description in (
                ("ca", {"ca_cert_path": "relay-cert.pem"}, "default TLS name with custom CA"),
                ("pinsilent", {"relay_sni": ""}, "pinned WSS without SNI"),
                ("pincustom", {"relay_host": "127.0.0.1", "relay_sni": "unlisted.example"},
                 "pinned WSS with custom SNI independent of address/certificate names"),
                ("casilent", {"relay_sni": "", "ca_cert_path": "relay-cert.pem"},
                 "CA verification still checks address hostname without SNI"),
                ("caname", {"relay_host": "127.0.0.1", "relay_sni": "localhost",
                            "ca_cert_path": "relay-cert.pem"},
                 "IP dial with CA verification against overridden TLS name"),
            ):
                tls_proxy_port = free_port()
                tls_config = client_config(peer, relay_port, pin, socks=tls_proxy_port,
                                           proxy_subnets=["127.0.0.1/32"], **connection)
                tls_process = harness.start(peer, "client", harness.write(peer, tls_config))
                try:
                    wait_until(lambda: get_via_socks(tls_proxy_port, target_port), description)
                    print(f"PASS {description}")
                finally:
                    tls_process.terminate()
                    tls_process.wait(timeout=5)

            for peer, candidate_pin, token, connection in (
                ("pinbad", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", TOKEN, {}),
                ("authbad", pin, "wrong-test-token-000000000000000000000", {}),
                ("namebad", pin, TOKEN, {"relay_host": "127.0.0.1", "relay_sni": "wrong.example",
                                        "ca_cert_path": "relay-cert.pem"}),
            ):
                rejected_port = free_port()
                config = harness.write(peer, client_config(peer, relay_port, candidate_pin,
                                                           socks=rejected_port, token=token, open_timeout=3,
                                                           proxy_subnets=["127.0.0.1/32"], **connection))
                process = harness.start(peer, "client", config)
                # Listener availability is independent of TLS/auth success.
                wait_until(lambda: listener_open(rejected_port), f"{peer} proxy listener")
                assert_rejected(lambda: socks_connect(rejected_port, "127.0.0.1", target_port, timeout=6))
                process.terminate()
                process.wait(timeout=5)
            print("PASS incorrect SPKI pin, peer token, or CA TLS name cannot forward")
            # An explicit empty list works before any successful relay handshake.
            unavailable_port = free_port()
            direct_port = free_port()
            direct_config = harness.write("direct", client_config(
                "direct", unavailable_port, pin, socks=direct_port, proxy_subnets=[], open_timeout=3,
            ))
            harness.start("direct", "client", direct_config)
            wait_until(lambda: get_via_socks(direct_port, target_port), "cold all-direct client")
            assert get_via_socks(direct_port, outside.server_port, host="127.0.0.2")
            print("PASS empty selection is all-direct even before contacting unavailable relay")

            # Without an explicit list or a learned route table, do not guess direct.
            unknown_port = free_port()
            unknown_config = harness.write("unknown", client_config(
                "unknown", unavailable_port, pin, socks=unknown_port, open_timeout=2,
            ))
            unknown_process = harness.start("unknown", "client", unknown_config)
            wait_until(lambda: listener_open(unknown_port), "uninitialized default proxy")
            assert_rejected(lambda: socks_connect(unknown_port, "127.0.0.2", outside.server_port, timeout=5))
            unknown_process.terminate()
            unknown_process.wait(timeout=5)
            print("PASS default selection waits for first route table before classifying direct")

            sleepy_port = free_port()
            sleepy_config = harness.write("sleepy", client_config(
                "sleepy", relay_port, pin, socks=sleepy_port, idle=2, sleep_secs=10,
            ))
            harness.start("sleepy", "client", sleepy_config)
            harness.wait_log("sleepy", "WSS connected")
            before_sleep = len(harness.log("sleepy"))
            deadline = time.monotonic() + 5
            while "entering sleep" not in harness.log("sleepy")[before_sleep:]:
                assert time.monotonic() < deadline, "direct traffic extended WSS activity"
                assert get_via_socks(sleepy_port, outside.server_port, host="127.0.0.2")
                time.sleep(0.1)
            sleeping_offset = len(harness.log("sleepy"))
            stop = time.monotonic() + 1
            while time.monotonic() < stop:
                assert get_via_socks(sleepy_port, outside.server_port, host="127.0.0.2")
                time.sleep(0.1)
            sleeping_log = harness.log("sleepy")[sleeping_offset:]
            assert "WSS connected" not in sleeping_log, "direct traffic woke sleeping WSS"
            assert "checking pending requests" not in sleeping_log, "direct traffic triggered an early probe"
            assert get_via_socks(sleepy_port, target_port)
            harness.wait_log("sleepy", "WSS connected", after=sleeping_offset)
            print("PASS direct traffic neither delays idle sleep nor wakes WSS; shared traffic wakes")

            # Learned remote routes stay selected after relay loss; only other IPs go direct.
            relay_process.terminate()
            relay_process.wait(timeout=5)
            assert get_via_socks(socks_port, outside.server_port, host="127.0.0.2")
            assert_rejected(lambda: socks_connect(socks_port, "127.0.0.1", target_port, timeout=15))
            assert get_via_socks(selected_port, target_port)
            assert get_via_socks(direct_port, target_port)
            print("PASS cached routes prevent fallback after relay loss; excluded addresses stay direct")

            for name in ("relay", "home", "office", "selected", "sleepy", "direct", "disableonly", "enableonly"):
                assert "panicked at" not in harness.log(name), f"panic in {name}"
            print("All NetCrow end-to-end checks passed.")
        except BaseException:
            harness.diagnostics()
            raise
        finally:
            harness.close()
            for server in (httpd, halfclose, outside):
                server.shutdown()
                server.server_close()


def listener_open(port):
    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
        return True


if __name__ == "__main__":
    candidate = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("NETCROW_BIN", "target/debug/netcrow")
    executable = Path(candidate).resolve()
    if not executable.is_file():
        raise SystemExit(f"Build NetCrow first: binary not found at {executable}")
    run(str(executable))
