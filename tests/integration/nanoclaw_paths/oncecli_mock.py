"""Minimal OneCLI Agent Vault simulator.

OneCLI (https://onecli.sh) is NanoClaw's credential-gateway dependency.
We don't have a real OneCLI to test against, so this is a deliberately
minimal stand-in that exercises the part of OneCLI's shape that
matters for our integration story: a forward HTTPS proxy that container
traffic flows through, which can OPTIONALLY chain to a further upstream
proxy (gbounce, in Path A).

Per [[don't-tailor-to-lighthouse]]: this mock simulates the GENERIC
"system-proxy" shape (HTTP CONNECT tunneling, optional upstream-proxy
chaining) — NOT OneCLI-specific protocol quirks. If a real OneCLI
deviates from the generic shape, that's OneCLI's problem to document.

Two modes:

  1. ``upstream=None`` (Path B baseline): on CONNECT, directly opens a
     TCP socket to the target host:port and splices client <-> upstream.
     This simulates OneCLI tunneling "the rest of the internet" without
     a chain.

  2. ``upstream="http://127.0.0.1:PORT"`` (Path A): on CONNECT, opens a
     TCP socket to the upstream PROXY (gbounce), sends a CONNECT line to
     IT, and splices once the upstream returns 200. This simulates
     OneCLI's chain mode where gbounce is the OneCLI agent's upstream
     proxy.

Logs every CONNECT to ``log_path`` as a JSONL line so the test harness
can verify a given request did or did NOT flow through the mock.

The mock binds to 127.0.0.1 ONLY (this is a test harness, never any
public surface). Pick a free port via ``port=0`` + read back from
``serve_until_idle.actual_port`` if you don't want to manage port
allocation by hand.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class MockConfig:
    """OneCLI-mock configuration."""

    listen_host: str = "127.0.0.1"
    listen_port: int = 0  # 0 = OS-assign a free port
    upstream: str | None = None  # ``http://HOST:PORT`` or None
    log_path: Path | None = None  # JSONL log file (or None = no log)


class OneCLIMock:
    """Threaded HTTP-CONNECT-only proxy."""

    def __init__(self, config: MockConfig) -> None:
        self._cfg = config
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._actual_port = 0

    @property
    def actual_port(self) -> int:
        """Port the mock is listening on (after .start())."""
        return self._actual_port

    @property
    def url(self) -> str:
        return f"http://{self._cfg.listen_host}:{self._actual_port}"

    def start(self) -> None:
        """Start the proxy in a background thread. Returns once listening."""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self._cfg.listen_host, self._cfg.listen_port))
        self._sock.listen(8)
        self._sock.settimeout(0.25)  # poll for stop
        self._actual_port = self._sock.getsockname()[1]
        self._thread = threading.Thread(
            target=self._serve, name="oncecli-mock-accept", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    # ----- internals -----

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                client, _addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._handle_client,
                args=(client,),
                name="oncecli-mock-conn",
                daemon=True,
            ).start()

    def _handle_client(self, client: socket.socket) -> None:
        try:
            client.settimeout(5.0)
            request_line = b""
            while b"\r\n\r\n" not in request_line:
                chunk = client.recv(4096)
                if not chunk:
                    return
                request_line += chunk
                if len(request_line) > 8192:
                    return
            head = request_line.split(b"\r\n\r\n", 1)[0].decode("latin-1")
            first = head.splitlines()[0]
            parts = first.split()
            if len(parts) < 3 or parts[0].upper() != "CONNECT":
                client.sendall(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                return
            target = parts[1]
            self._log_request(method="CONNECT", target=target, head=head)
            # Decide forwarding
            if self._cfg.upstream:
                self._forward_via_upstream(client, target, head)
            else:
                self._forward_direct(client, target)
        except Exception as exc:  # pragma: no cover - best-effort
            self._log_request(
                method="ERROR", target="", head=f"exception: {exc!r}"
            )
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _forward_direct(self, client: socket.socket, target: str) -> None:
        host, _, port_s = target.partition(":")
        port = int(port_s) if port_s else 443
        try:
            upstream = socket.create_connection((host, port), timeout=10.0)
        except OSError as exc:
            client.sendall(
                f"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n".encode()
            )
            self._log_request(
                method="CONNECT_DIRECT_FAIL", target=target, head=str(exc)
            )
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self._splice(client, upstream)

    def _forward_via_upstream(
        self, client: socket.socket, target: str, head: str
    ) -> None:
        u = self._cfg.upstream
        assert u is not None
        # Parse upstream URL — accept only http://HOST:PORT
        if not u.startswith("http://"):
            raise ValueError(f"upstream must be http://...; got {u!r}")
        host_port = u[len("http://") :].rstrip("/")
        u_host, _, u_port_s = host_port.partition(":")
        u_port = int(u_port_s) if u_port_s else 80
        try:
            upstream = socket.create_connection((u_host, u_port), timeout=10.0)
        except OSError as exc:
            client.sendall(
                b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
            )
            self._log_request(
                method="CONNECT_UPSTREAM_FAIL",
                target=target,
                head=f"upstream={u} err={exc!r}",
            )
            return
        # Forward CONNECT to upstream. Preserve any agent identity headers.
        connect_lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
        for line in head.splitlines()[1:]:
            ll = line.lower()
            if ll.startswith("x-agent-") or ll.startswith("user-agent:"):
                connect_lines.append(line)
        connect_lines.append("")
        connect_lines.append("")
        upstream.sendall(("\r\n".join(connect_lines)).encode("latin-1"))
        # Read upstream response head, mirror back to client.
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = upstream.recv(4096)
            if not chunk:
                upstream.close()
                client.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
                )
                return
            resp += chunk
        client.sendall(resp)
        # Splice both ways.
        self._splice(client, upstream)

    def _splice(self, a: socket.socket, b: socket.socket) -> None:
        def pipe(src: socket.socket, dst: socket.socket) -> None:
            try:
                src.settimeout(60.0)
                while True:
                    data = src.recv(8192)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

        t1 = threading.Thread(target=pipe, args=(a, b), daemon=True)
        t2 = threading.Thread(target=pipe, args=(b, a), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        try:
            b.close()
        except OSError:
            pass

    def _log_request(self, *, method: str, target: str, head: str) -> None:
        if self._cfg.log_path is None:
            return
        rec = {
            "ts": time.time(),
            "method": method,
            "target": target,
            "upstream": self._cfg.upstream,
            "head_preview": head[:512],
        }
        try:
            self._cfg.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._cfg.log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
        except OSError:
            pass


def start_mock(
    *,
    upstream: str | None = None,
    log_path: Path | None = None,
    port: int = 0,
) -> OneCLIMock:
    """Convenience factory. Returns a STARTED mock."""
    mock = OneCLIMock(
        MockConfig(listen_port=port, upstream=upstream, log_path=log_path)
    )
    mock.start()
    return mock


if __name__ == "__main__":  # pragma: no cover - manual smoke
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--upstream", default=None)
    p.add_argument("--log", default=None)
    args = p.parse_args()
    m = start_mock(
        port=args.port,
        upstream=args.upstream,
        log_path=Path(args.log) if args.log else None,
    )
    print(f"OneCLI-mock listening on {m.url}; upstream={args.upstream}")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        m.stop()
