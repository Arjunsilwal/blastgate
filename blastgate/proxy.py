"""Egress enforcement point.

Terminates CONNECT requests from the install container, asks the policy engine,
and either tunnels or refuses. Every decision is logged.

This process parses hostile input by design, so it holds no credentials of its
own. Compromising it yields egress, not secrets.

It does not intercept TLS. It sees the CONNECT target and nothing else - no
request contents, no headers, no method, no path. That limitation is a
deliberate v0 decision and is recorded in docs/threat-model.md section 8, not
hidden here.
"""

import asyncio
from pathlib import Path
from dataclasses import dataclass
import re
from typing import Optional, Set, Tuple

from blastgate.audit import AuditLog
from blastgate.policy import Policy


# Ports the proxy will tunnel to. Registry traffic is HTTPS, and restricting
# the set closes an evasion the policy engine cannot see: policy strips the
# port and decides on hostname alone, so without this an allowlisted host would
# be reachable on any port at all.
DEFAULT_ALLOWED_PORTS = frozenset({443})

# Bounds on what is read before a decision is made. A client that never sends a
# complete request line must not be able to hold memory or a slot open.
MAX_REQUEST_LINE = 8192
REQUEST_TIMEOUT_SECONDS = 30

_CONNECT_RE = re.compile(r"^CONNECT[ \t]+(?P<target>[^\s]+)[ \t]+HTTP/1\.[01]$")


class ProxyError(Exception):
    """Base error for proxy failures."""


class MalformedRequestError(ProxyError):
    """Raised when a request cannot be parsed as a CONNECT."""


@dataclass(frozen=True)
class ConnectTarget:
    host: str
    port: int


def parse_connect_request(line: str) -> ConnectTarget:
    """Parse a CONNECT request line into a host and port.

    Only CONNECT is accepted. An absolute-URI request (plain HTTP through the
    proxy) is refused rather than forwarded, because forwarding it would mean
    parsing and rewriting attacker-controlled HTTP, and because registry
    traffic does not need it.
    """
    if not isinstance(line, str):
        raise MalformedRequestError("request line must be text")

    line = line.rstrip("\r\n")
    if not line:
        raise MalformedRequestError("empty request line")
    if len(line) > MAX_REQUEST_LINE:
        raise MalformedRequestError("request line too long")

    match = _CONNECT_RE.match(line)
    if not match:
        raise MalformedRequestError("not a well-formed CONNECT request")

    target = match.group("target")
    if ":" not in target:
        raise MalformedRequestError("CONNECT target must include a port")

    host_part, _, port_part = target.rpartition(":")
    if not host_part:
        raise MalformedRequestError("CONNECT target has no host")
    if not port_part.isdigit():
        raise MalformedRequestError(f"invalid port: {port_part!r}")

    port = int(port_part)
    if not (1 <= port <= 65535):
        raise MalformedRequestError(f"port out of range: {port}")

    return ConnectTarget(host=host_part, port=port)


class EgressProxy:
    """A CONNECT proxy that enforces an allowlist.

    The only decision it makes comes from the policy engine. It contains no
    allow path of its own.
    """

    def __init__(
        self,
        policy: Policy,
        audit_log: Optional[AuditLog] = None,
        enabled_conditions: Optional[Set[str]] = None,
        allowed_ports: frozenset = DEFAULT_ALLOWED_PORTS,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        self.policy = policy
        self.audit_log = audit_log
        self.enabled_conditions = set(enabled_conditions or ())
        self.allowed_ports = frozenset(allowed_ports)
        self.host = host
        self.port = port
        self._server: Optional[asyncio.AbstractServer] = None

    @property
    def bound_port(self) -> int:
        if self._server is None:
            raise ProxyError("proxy is not running")
        return self._server.sockets[0].getsockname()[1]

    def _record(self, host: str, allowed: bool, rule: Optional[str], reason: str) -> None:
        if self.audit_log is None:
            return
        self.audit_log.append(
            ecosystem=self.policy.ecosystem,
            host=host,
            allowed=allowed,
            rule=rule,
            reason=reason,
        )

    async def handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            await self._handle(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionResetError, asyncio.TimeoutError):
            pass
        except ProxyError:
            pass
        finally:
            if not writer.is_closing():
                writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw = await asyncio.wait_for(
                reader.readline(), timeout=REQUEST_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            await self._refuse(writer, 408, "Request Timeout")
            return

        if len(raw) > MAX_REQUEST_LINE:
            await self._refuse(writer, 414, "Request-URI Too Long")
            return

        try:
            target = parse_connect_request(raw.decode("latin-1"))
        except MalformedRequestError:
            # Nothing is recorded: there is no trustworthy hostname to record.
            await self._refuse(writer, 400, "Bad Request")
            return

        # Drain the remaining request headers. They are read to keep the
        # connection coherent and are never used for the decision - in
        # particular the Host header is ignored, so it cannot contradict the
        # CONNECT target.
        try:
            while True:
                header = await asyncio.wait_for(
                    reader.readline(), timeout=REQUEST_TIMEOUT_SECONDS
                )
                if header in (b"\r\n", b"\n", b""):
                    break
        except asyncio.TimeoutError:
            await self._refuse(writer, 408, "Request Timeout")
            return

        if target.port not in self.allowed_ports:
            self._record(
                target.host, False, None,
                f"port {target.port} not permitted (allowed: "
                f"{sorted(self.allowed_ports)})",
            )
            await self._refuse(writer, 403, "Forbidden")
            return

        decision = self.policy.evaluate(
            target.host, enabled_conditions=self.enabled_conditions
        )
        self._record(decision.host, decision.allowed, decision.rule, decision.reason)

        if not decision.allowed:
            await self._refuse(writer, 403, "Forbidden")
            return

        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(decision.host, target.port),
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
        except (OSError, asyncio.TimeoutError):
            await self._refuse(writer, 502, "Bad Gateway")
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        await self._tunnel(reader, writer, upstream_reader, upstream_writer)

    async def _refuse(self, writer: asyncio.StreamWriter, code: int, text: str) -> None:
        writer.write(
            f"HTTP/1.1 {code} {text}\r\n"
            f"Content-Length: 0\r\n"
            f"Connection: close\r\n\r\n".encode("ascii")
        )
        try:
            await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass

    async def _tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        """Move bytes in both directions without inspecting them.

        The proxy does not intercept TLS, so there is nothing here to inspect
        even if it wanted to.
        """

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            finally:
                if not dst.is_closing():
                    dst.close()

        await asyncio.gather(
            pipe(client_reader, upstream_writer),
            pipe(upstream_reader, client_writer),
            return_exceptions=True,
        )

    async def start(self) -> "EgressProxy":
        self._server = await asyncio.start_server(
            self.handle_client, self.host, self.port
        )
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def serve_forever(self) -> None:
        """Run until cancelled. The entrypoint when the proxy is a sidecar."""
        if self._server is None:
            await self.start()
        async with self._server:
            await self._server.serve_forever()


def run_proxy_server(
    policy: Policy,
    port: int,
    audit_path: Optional["Path"] = None,
    enabled_conditions: Optional[Set[str]] = None,
    host: str = "0.0.0.0",
) -> None:
    """Blocking entrypoint used inside the proxy container.

    Binds 0.0.0.0 because the clients are other containers, not this one. That
    is only safe because of where this runs: the proxy sits on an internal
    network whose sole other member is the install container. Running it this
    way anywhere else would expose an open proxy.
    """
    audit_log = AuditLog(audit_path) if audit_path is not None else None
    proxy = EgressProxy(
        policy,
        audit_log=audit_log,
        enabled_conditions=enabled_conditions,
        host=host,
        port=port,
    )
    try:
        asyncio.run(proxy.serve_forever())
    except KeyboardInterrupt:
        pass
