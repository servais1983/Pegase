"""ReconSphere tests — DNS/WHOIS/crt.sh are mocked, no real network use."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule
from pegase.modules.recon import ReconSphere, _host_only, _stringify


def _guard(target: str = "example.com") -> ScopeGuard:
    scope = Scope(
        rules=[ScopeRule(target)],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


class _FakeAnswerRecord:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeResolver:
    """Stands in for dns.asyncresolver.Resolver."""

    def __init__(self) -> None:
        self.lifetime = 0.0

    async def resolve(self, host: str, rrtype: str):
        if rrtype == "A":
            return [_FakeAnswerRecord("93.184.216.34")]
        if rrtype == "MX":
            return [_FakeAnswerRecord("10 mail.example.com.")]
        import dns.exception

        raise dns.exception.DNSException("no such record")


@pytest.mark.asyncio
async def test_recon_collects_dns_whois_and_ct(monkeypatch):
    monkeypatch.setattr("pegase.modules.recon.dns.asyncresolver.Resolver", _FakeResolver)
    monkeypatch.setattr("pegase.modules.recon.whois", None)  # skip real whois lib

    def handler(request: httpx.Request) -> httpx.Response:
        assert "crt.sh" in str(request.url)
        payload = [{"name_value": "sub.example.com\nwww.example.com"}]
        return httpx.Response(200, content=json.dumps(payload).encode())

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.recon.httpx.AsyncClient", _Patched)

    result = await ReconSphere().run(targets=["example.com"], guard=_guard())

    titles = [f.title for f in result.findings]
    assert any("DNS records collected" in t for t in titles)
    assert any("subdomains from CT logs" in t for t in titles)
    assert "example.com" in result.raw["ct"]
    assert set(result.raw["ct"]["example.com"]) == {"sub.example.com", "www.example.com"}


@pytest.mark.asyncio
async def test_recon_handles_dns_failure(monkeypatch):
    class _AllFailResolver:
        def __init__(self) -> None:
            self.lifetime = 0.0

        async def resolve(self, host: str, rrtype: str):
            import dns.exception

            raise dns.exception.DNSException("nxdomain")

    monkeypatch.setattr("pegase.modules.recon.dns.asyncresolver.Resolver", _AllFailResolver)
    monkeypatch.setattr("pegase.modules.recon.whois", None)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[]")

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.recon.httpx.AsyncClient", _Patched)

    result = await ReconSphere().run(
        targets=["nx.example.com"], guard=_guard("nx.example.com")
    )
    titles = [f.title for f in result.findings]
    assert any("DNS resolution failed" in t for t in titles)


@pytest.mark.asyncio
async def test_recon_ip_literal_target_skips_dns_lookup(monkeypatch):
    # No resolver should even be constructed for a literal IP.
    def _boom(*a, **kw):
        raise AssertionError("resolver should not be used for IP literals")

    monkeypatch.setattr("pegase.modules.recon.dns.asyncresolver.Resolver", _boom)
    monkeypatch.setattr("pegase.modules.recon.whois", None)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[]")

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.recon.httpx.AsyncClient", _Patched)

    guard = _guard("203.0.113.5")
    result = await ReconSphere().run(targets=["203.0.113.5"], guard=guard)
    assert result.raw["dns"]["203.0.113.5"]["ip_literal"] is True


def test_host_only_strips_scheme_and_lowercases():
    assert _host_only("HTTPS://Example.COM/path") == "example.com"
    assert _host_only("plain.HOST") == "plain.host"


def test_stringify_handles_list_and_none():
    assert _stringify(["A", "B"]) == ["A", "B"]
    assert _stringify(None) is None
    assert _stringify(42) == "42"


@pytest.mark.asyncio
async def test_recon_ipv6_literal_target_skips_dns_lookup(monkeypatch):
    def _boom(*a, **kw):
        raise AssertionError("resolver should not be used for IPv6 literals")

    monkeypatch.setattr("pegase.modules.recon.dns.asyncresolver.Resolver", _boom)
    monkeypatch.setattr("pegase.modules.recon.whois", None)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[]")

    transport = httpx.MockTransport(handler)
    real_client_cls = httpx.AsyncClient

    class _Patched(real_client_cls):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.recon.httpx.AsyncClient", _Patched)

    guard = _guard("2001:db8::1")
    result = await ReconSphere().run(targets=["2001:db8::1"], guard=guard)
    assert result.raw["dns"]["2001:db8::1"]["ip_literal"] is True
    assert result.raw["dns"]["2001:db8::1"]["records"] == {"AAAA": ["2001:db8::1"]}


@pytest.mark.asyncio
async def test_recon_whois_success_adds_finding(monkeypatch):
    class _FakeWhoisResult(dict):
        pass

    class _FakeWhoisModule:
        @staticmethod
        def whois(host):
            return _FakeWhoisResult(
                registrar="Example Registrar",
                creation_date="2001-01-01",
                expiration_date="2030-01-01",
                name_servers=["ns1.example.com", "ns2.example.com"],
                org="Example Org",
                country="US",
            )

    monkeypatch.setattr("pegase.modules.recon.whois", _FakeWhoisModule())
    monkeypatch.setattr("pegase.modules.recon.dns.asyncresolver.Resolver", _FakeResolver)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[]")

    class _Patched(httpx.AsyncClient):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.recon.httpx.AsyncClient", _Patched)

    result = await ReconSphere().run(targets=["example.com"], guard=_guard())
    titles = [f.title for f in result.findings]
    assert "WHOIS metadata" in titles
    whois_finding = next(f for f in result.findings if f.title == "WHOIS metadata")
    assert whois_finding.evidence["registrar"] == "Example Registrar"
    assert whois_finding.evidence["name_servers"] == ["ns1.example.com", "ns2.example.com"]


@pytest.mark.asyncio
async def test_recon_whois_exception_is_recorded_as_error(monkeypatch):
    class _RaisingWhoisModule:
        @staticmethod
        def whois(host):
            raise ConnectionError("whois server unreachable")

    monkeypatch.setattr("pegase.modules.recon.whois", _RaisingWhoisModule())
    monkeypatch.setattr("pegase.modules.recon.dns.asyncresolver.Resolver", _FakeResolver)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"[]")

    class _Patched(httpx.AsyncClient):  # type: ignore[misc]
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr("pegase.modules.recon.httpx.AsyncClient", _Patched)

    result = await ReconSphere().run(targets=["example.com"], guard=_guard())
    assert result.raw["whois"]["example.com"]["error"] == "whois server unreachable"


@pytest.mark.asyncio
async def test_crtsh_subdomains_http_error_returns_empty(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    from pegase.modules.recon import _crtsh_subdomains

    result = await _crtsh_subdomains(client, "example.com")
    await client.aclose()
    assert result == []


@pytest.mark.asyncio
async def test_crtsh_subdomains_non_200_returns_empty():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    from pegase.modules.recon import _crtsh_subdomains

    result = await _crtsh_subdomains(client, "example.com")
    await client.aclose()
    assert result == []


@pytest.mark.asyncio
async def test_crtsh_subdomains_malformed_json_returns_empty():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"not json")

    transport = httpx.MockTransport(handler)
    client = httpx.AsyncClient(transport=transport)
    from pegase.modules.recon import _crtsh_subdomains

    result = await _crtsh_subdomains(client, "example.com")
    await client.aclose()
    assert result == []
