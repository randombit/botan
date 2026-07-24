# TLS-Anvil calls a trigger script before each test handshake to make the
# client-under-test initiate a new TLS connection. This server listens for
# HTTP GET /trigger requests and spawns a fresh Botan tls_client process
# for each one.
#
# (C) 2026 Jack Lloyd
#
# Botan is released under the Simplified BSD License (see license.txt)

import argparse
import os
import signal
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Populated from command-line arguments in main()
botan_cli = None
tls_anvil_policy = None
tls_anvil_host = None
tls_anvil_port = None
client_log_dir = None
client_timeout = 30

# Track spawned client processes so we can clean them up
client_processes = []
trigger_count = 0


def reap_client(proc):
    """Wait for the timeout, then kill the process if still running.

    While waiting, periodically write to stdin so that tls_client calls
    send() and flushes any deferred KeyUpdate response."""
    import time
    deadline = time.monotonic() + client_timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if proc.stdin:
            try:
                proc.stdin.write(b".\n")
                proc.stdin.flush()
            except OSError:
                break
        try:
            proc.wait(timeout=1)
            break
        except subprocess.TimeoutExpired:
            pass
    if proc.poll() is None:
        proc.kill()
        proc.wait()
    if proc.stdin:
        try:
            proc.stdin.close()
        except OSError:
            pass


def cleanup_finished_clients():
    """Remove completed client processes from the tracking list."""
    still_running = []
    for proc in client_processes:
        if proc.poll() is None:
            still_running.append(proc)
    client_processes[:] = still_running


def kill_all_clients():
    """Terminate all tracked client processes."""
    for proc in client_processes:
        try:
            proc.kill()
            proc.wait()
            if proc.stdin:
                proc.stdin.close()
        except OSError:
            pass
    client_processes.clear()


class TriggerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/trigger":
            global trigger_count
            cleanup_finished_clients()

            log_file = None
            if client_log_dir:
                log_path = os.path.join(client_log_dir, f"client_{trigger_count}.log")
                log_file = open(log_path, 'w', encoding='utf-8')

            trigger_count += 1

            proc = subprocess.Popen(
                [botan_cli, "tls_client", tls_anvil_host,
                 f"--port={tls_anvil_port}",
                 f"--policy={tls_anvil_policy}",
                 "--ignore-cert-error"],
                stdin=subprocess.PIPE,
                stdout=log_file or subprocess.DEVNULL,
                stderr=log_file or subprocess.DEVNULL,
            )
            client_processes.append(proc)

            # Close the log file in this process; the child has its own fd
            if log_file:
                log_file.close()

            # Start a reaper thread that kills the process after the timeout
            threading.Thread(target=reap_client, args=(proc,), daemon=True).start()

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK\n")

        elif self.path == "/shutdown":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK\n")

            def shutdown():
                self.server.shutdown()
            threading.Thread(target=shutdown, daemon=True).start()

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress request logging noise
        pass


def main(args=None):
    global botan_cli, tls_anvil_policy, tls_anvil_host, tls_anvil_port, client_log_dir, client_timeout

    if args is None:
        args = sys.argv[1:]

    parser = argparse.ArgumentParser(description="TLS-Anvil trigger server for Botan client testing")
    parser.add_argument("--botan-cli", required=True, help="Path to botan executable")
    parser.add_argument("--tls-anvil-policy", default="default", help="Policy to use for TLS-Anvil testing")
    parser.add_argument("--tls-anvil-host", default="127.0.0.1", help="Host where TLS-Anvil listens")
    parser.add_argument("--tls-anvil-port", type=int, required=True, help="Port where TLS-Anvil listens")
    parser.add_argument("--listen-port", type=int, default=8090, help="Port for this trigger server")
    parser.add_argument("--log-dir", default=None, help="Directory for client log files")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Kill client processes after this many seconds (default: %(default)s)")

    parsed = parser.parse_args(args)

    botan_cli = parsed.botan_cli
    tls_anvil_policy = parsed.tls_anvil_policy
    tls_anvil_host = parsed.tls_anvil_host
    tls_anvil_port = parsed.tls_anvil_port
    client_log_dir = parsed.log_dir
    client_timeout = parsed.timeout

    if client_log_dir:
        os.makedirs(client_log_dir, exist_ok=True)

    server = HTTPServer(("127.0.0.1", parsed.listen_port), TriggerHandler)
    print(f"Trigger server listening on 127.0.0.1:{parsed.listen_port}", flush=True)

    def handle_signal(signum, frame):
        kill_all_clients()
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        server.serve_forever()
    finally:
        kill_all_clients()
        server.server_close()


if __name__ == "__main__":
    main()
