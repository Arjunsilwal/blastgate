"""The credential store and the broker.

The property under test is not "authentication works". It is that an
authenticated install happens with no credential anywhere the payload can
reach, which is the opposite of the status quo where the token sits in
~/.npmrc for any postinstall script to read.
"""

import json
import os
import stat
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from blastgate.credentials import (
    CredentialError,
    CredentialStore,
    normalise_host,
)
from blastgate.proxy import BROKER_METHODS, make_broker


@pytest.fixture
def store(tmp_path):
    return CredentialStore(tmp_path / "credentials.json")


class TestStore:
    def test_a_stored_secret_round_trips(self, store):
        store.put("registry.npmjs.org", "tok-abc")
        assert store.get("registry.npmjs.org").header == "Bearer tok-abc"

    @pytest.mark.parametrize("spelling", [
        "registry.npmjs.org", "https://registry.npmjs.org",
        "https://registry.npmjs.org/", "  REGISTRY.NPMJS.ORG  ",
        "https://registry.npmjs.org/some/path",
    ])
    def test_hosts_are_matched_however_they_are_spelled(self, store, spelling):
        # A credential attached to a host the user thinks they configured, but
        # spelled differently, is a credential that silently never applies.
        store.put("registry.npmjs.org", "tok")
        assert store.get(spelling) is not None
        assert normalise_host(spelling) == "registry.npmjs.org"

    def test_the_file_is_created_owner_only(self, store):
        store.put("registry.npmjs.org", "tok")
        mode = stat.S_IMODE(os.stat(store.path).st_mode)
        assert mode == 0o600, f"credential store is mode {mode:04o}"

    def test_a_readable_store_is_refused_not_read(self, store):
        # Fail closed. Reading it anyway would mean the tool is comfortable
        # with a secret anyone on the box can open.
        store.put("registry.npmjs.org", "tok")
        os.chmod(store.path, 0o644)
        with pytest.raises(CredentialError, match="readable by others"):
            store.hosts()

    def test_the_secret_is_never_in_the_displayed_form(self, store):
        store.put("registry.npmjs.org", "super-secret-value")
        rendered = json.dumps(store.get("registry.npmjs.org").redacted())
        assert "super-secret-value" not in rendered
        assert "<redacted>" in rendered

    def test_an_empty_secret_is_refused(self, store):
        with pytest.raises(CredentialError, match="empty secret"):
            store.put("registry.npmjs.org", "   ")

    def test_removing_a_credential(self, store):
        store.put("a.test", "x")
        assert store.remove("a.test") is True
        assert store.remove("a.test") is False
        assert store.hosts() == []

    def test_a_missing_store_is_empty_not_an_error(self, tmp_path):
        assert CredentialStore(tmp_path / "absent.json").hosts() == []


class _Upstream(BaseHTTPRequestHandler):
    """Stands in for a private registry. Records what it was sent."""

    seen = []
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        type(self).seen.append((self.command, self.path, self.headers.get("Authorization")))
        body = json.dumps({
            "name": "demo",
            "dist": {"tarball": "https://upstream.test/demo/-/demo-1.0.0.tgz"},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def broker(monkeypatch):
    """A broker whose upstream is a local server rather than a real registry."""
    _Upstream.seen = []
    upstream = HTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    upstream_port = upstream.server_address[1]

    real_urlopen = urllib.request.urlopen

    def redirected(request, *args, **kwargs):
        # Patching the module patches it for everyone, including this test's
        # own calls to the broker, so anything not aimed at the pretend
        # registry passes straight through.
        if isinstance(request, str) or "upstream.test" not in request.full_url:
            return real_urlopen(request, *args, **kwargs)
        # Rewrite only the scheme and authority; the broker still believes it
        # is talking to upstream.test over TLS.
        url = request.full_url.replace(
            "https://upstream.test", f"http://127.0.0.1:{upstream_port}"
        )
        rebuilt = urllib.request.Request(url, method=request.get_method())
        for name, value in request.header_items():
            rebuilt.add_header(name, value)
        return real_urlopen(rebuilt, *args, **kwargs)

    monkeypatch.setattr("blastgate.proxy.urllib.request.urlopen", redirected)

    server = make_broker(
        upstream_host="upstream.test",
        auth_header="Bearer secret-token",
        local_origin="http://blastgate-proxy:3129",
        host="127.0.0.1", port=0,
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server, upstream
    server.shutdown()
    upstream.shutdown()


def broker_url(server, path="/demo"):
    return f"http://127.0.0.1:{server.server_address[1]}{path}"


class TestBroker:
    def test_the_credential_is_added_upstream(self, broker):
        server, _ = broker
        with urllib.request.urlopen(broker_url(server), timeout=10) as response:
            assert response.status == 200
        assert _Upstream.seen, "upstream was never called"
        assert _Upstream.seen[0][2] == "Bearer secret-token"

    def test_the_client_never_sends_a_credential(self, broker):
        # The whole point: the sandbox has nothing to send.
        server, _ = broker
        request = urllib.request.Request(broker_url(server))
        with urllib.request.urlopen(request, timeout=10):
            pass
        # Whatever the client sent, the Authorization upstream came from the
        # broker's own configuration.
        assert _Upstream.seen[0][2] == "Bearer secret-token"

    def test_absolute_upstream_urls_are_rewritten_to_the_broker(self, broker):
        # A registry answers with absolute URLs to itself. Left alone, the
        # client would fetch tarballs straight from upstream, unauthenticated,
        # and a private registry would refuse them.
        server, _ = broker
        with urllib.request.urlopen(broker_url(server), timeout=10) as response:
            body = json.loads(response.read())
        assert body["dist"]["tarball"].startswith("http://blastgate-proxy:3129/")
        assert "upstream.test" not in body["dist"]["tarball"]

    @pytest.mark.parametrize("method", ["PUT", "POST", "DELETE", "PATCH"])
    def test_writes_are_refused(self, broker, method):
        # The broker is authenticated. Without this a payload could publish
        # through it, which is precisely Shai-Hulud's propagation step.
        server, _ = broker
        request = urllib.request.Request(broker_url(server), method=method, data=b"{}")
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        assert caught.value.code == 405
        assert not any(m == method for m, _, _ in _Upstream.seen)

    def test_only_reads_are_declared_forwardable(self):
        assert BROKER_METHODS == {"GET", "HEAD"}

    def test_every_response_closes_its_connection(self, broker):
        # Keep-alive let the client reuse a socket the server might close
        # first, which surfaced as an intermittent ECONNRESET on CI. Closing
        # each exchange removes the race entirely.
        server, _ = broker
        with urllib.request.urlopen(broker_url(server), timeout=10) as response:
            assert response.headers.get("Connection", "").lower() == "close"

    def test_a_refused_write_also_closes(self, broker):
        server, _ = broker
        request = urllib.request.Request(broker_url(server), method="PUT", data=b"{}")
        with pytest.raises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=10)
        assert caught.value.headers.get("Connection", "").lower() == "close"

    def test_repeated_requests_all_succeed(self, broker):
        # The install makes many; one reset fails the whole thing.
        server, _ = broker
        for _ in range(15):
            with urllib.request.urlopen(broker_url(server), timeout=10) as response:
                assert response.status == 200
