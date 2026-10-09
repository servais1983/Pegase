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
