"""MobileHunter tests — builds small real zip/APK fixtures, no androguard needed.

The binary-AXML fallback decoder treats any blob whose first two bytes don't
match the AXML magic (0x0003) as plain UTF-8 text, so writing the manifest as
ordinary XML text exercises the full ``_analyze_manifest`` heuristics without
needing a real compiled Android manifest.
"""

from __future__ import annotations

import zipfile
from datetime import UTC, datetime

import pytest

from pegase.core.scope import ActionType, Scope, ScopeGuard, ScopeRule, ScopeViolation
from pegase.modules.mobilehunter import MobileHunter

_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <uses-permission android:name="android.permission.READ_SMS" />
  <uses-permission android:name="android.permission.CAMERA" />
  <application android:debuggable="true" android:allowBackup="true"
               android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity" android:exported="true" />
    <service android:name=".GuardedService" android:exported="true"
              android:permission="com.example.PERM" />
  </application>
</manifest>
"""


def _guard(pattern: str = "com.example.app") -> ScopeGuard:
    scope = Scope(
        rules=[ScopeRule(pattern)],
        allowed_actions={ActionType.PASSIVE},
        authorization_token="t",
        starts_at=datetime.now(UTC),
    )
    return ScopeGuard(scope)


def _build_apk(path, manifest: str = _MANIFEST, extra_files: dict | None = None) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        for name, content in (extra_files or {}).items():
            zf.writestr(name, content)


@pytest.mark.asyncio
async def test_mobilehunter_requires_apk_path():
    with pytest.raises(ValueError, match="requires parameters"):
        await MobileHunter().run(targets=["com.example.app"], guard=_guard(), parameters={})


@pytest.mark.asyncio
async def test_mobilehunter_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        await MobileHunter().run(
            targets=["com.example.app"],
            guard=_guard(),
            parameters={"apk_path": str(tmp_path / "nope.apk")},
        )


@pytest.mark.asyncio
async def test_mobilehunter_flags_manifest_issues(tmp_path):
    apk = tmp_path / "app.apk"
    _build_apk(apk)

    result = await MobileHunter().run(
        targets=["com.example.app"],
        guard=_guard(),
        parameters={"apk_path": str(apk)},
    )

    titles = [f.title for f in result.findings]
    assert any("READ_SMS" in t for t in titles)
    assert any("CAMERA" in t for t in titles)
    assert any("debuggable" in t.lower() for t in titles)
    assert any("allowBackup" in t for t in titles)
    assert any("Cleartext traffic" in t for t in titles)
    # The exported activity has no permission guard -> flagged.
    assert any("Exported activity without permission guard" in t for t in titles)
    # The exported service DOES declare a permission -> not flagged.
    assert not any("Exported service" in t for t in titles)


@pytest.mark.asyncio
async def test_mobilehunter_detects_embedded_secrets(tmp_path):
    apk = tmp_path / "secrets.apk"
    _build_apk(
        apk,
        manifest="<manifest package=\"com.example.app\"></manifest>",
        extra_files={
            "res/raw/config.json": '{"aws_key": "AKIAABCDEFGHIJKLMNOP"}',
            "assets/keys.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n",
        },
    )

    result = await MobileHunter().run(
        targets=["com.example.app"],
        guard=_guard(),
        parameters={"apk_path": str(apk)},
    )
    kinds = {f.evidence.get("kind") for f in result.findings if f.evidence}
    assert "AWS access key id" in kinds
    assert "private key" in kinds


@pytest.mark.asyncio
async def test_mobilehunter_handles_missing_manifest(tmp_path):
    apk = tmp_path / "no_manifest.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("res/raw/dummy.txt", "nothing interesting")

    result = await MobileHunter().run(
        targets=["com.example.app"],
        guard=_guard(),
        parameters={"apk_path": str(apk)},
    )
    assert any("Could not decode AndroidManifest.xml" in f.title for f in result.findings)


@pytest.mark.asyncio
async def test_mobilehunter_enforces_scope_guard(tmp_path):
    apk = tmp_path / "app.apk"
    _build_apk(apk)
    with pytest.raises(ScopeViolation):
        await MobileHunter().run(
            targets=["com.other.app"],
            guard=_guard("com.example.app"),
            parameters={"apk_path": str(apk)},
        )


# --- androguard present (success path) -------------------------------------


@pytest.mark.asyncio
async def test_mobilehunter_uses_androguard_when_available(tmp_path, monkeypatch):
    """When androguard IS importable, MobileHunter must use its richer
    AXMLPrinter instead of the builtin fallback decoder."""
    import sys
    import types

    manifest_xml = b'<manifest package="com.example.app"></manifest>'

    class _FakeAXMLPrinter:
        def __init__(self, raw: bytes) -> None:
            self._raw = raw

        def get_xml(self) -> bytes:
            return manifest_xml

    fake_apk_mod = types.ModuleType("androguard.core.bytecodes.apk")
    fake_apk_mod.AXMLPrinter = _FakeAXMLPrinter  # type: ignore[attr-defined]
    for name in ("androguard", "androguard.core", "androguard.core.bytecodes"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "androguard.core.bytecodes.apk", fake_apk_mod)

    apk = tmp_path / "androguard_app.apk"
    _build_apk(apk, manifest=manifest_xml.decode())

    result = await MobileHunter().run(
        targets=["com.example.app"], guard=_guard(), parameters={"apk_path": str(apk)}
    )
    # The fake AXMLPrinter's output carries no dangerous permissions/flags,
    # so no manifest findings - but it must not report a decode failure.
    assert not any("Could not decode" in f.title for f in result.findings)


@pytest.mark.asyncio
async def test_mobilehunter_falls_back_when_androguard_raises(tmp_path, monkeypatch):
    """androguard installed but failing to parse this particular manifest
    must fall back to the builtin decoder rather than crash the module."""
    import sys
    import types

    class _BrokenAXMLPrinter:
        def __init__(self, raw: bytes) -> None:
            raise ValueError("not a real binary manifest")

    fake_apk_mod = types.ModuleType("androguard.core.bytecodes.apk")
    fake_apk_mod.AXMLPrinter = _BrokenAXMLPrinter  # type: ignore[attr-defined]
    for name in ("androguard", "androguard.core", "androguard.core.bytecodes"):
        monkeypatch.setitem(sys.modules, name, types.ModuleType(name))
    monkeypatch.setitem(sys.modules, "androguard.core.bytecodes.apk", fake_apk_mod)

    apk = tmp_path / "androguard_broken.apk"
    _build_apk(apk)  # the default plain-text _MANIFEST fixture

    result = await MobileHunter().run(
        targets=["com.example.app"], guard=_guard(), parameters={"apk_path": str(apk)}
    )
    # Fell back to the builtin decoder, which handles the plain-text fixture
    # exactly as in test_mobilehunter_flags_manifest_issues.
    assert any("READ_SMS" in f.title for f in result.findings)


@pytest.mark.asyncio
async def test_mobilehunter_handles_secret_scan_read_error(tmp_path, monkeypatch):
    """A file listed in the archive that raises on read() must be skipped,
    not crash the secret scan."""
    apk = tmp_path / "unreadable_entry.apk"
    _build_apk(apk, extra_files={"res/raw/config.json": "nothing interesting"})

    import zipfile as zipfile_mod

    real_read = zipfile_mod.ZipFile.read

    def flaky_read(self, name, *a, **kw):
        if name == "res/raw/config.json":
            raise RuntimeError("corrupt entry")
        return real_read(self, name, *a, **kw)

    monkeypatch.setattr(zipfile_mod.ZipFile, "read", flaky_read)

    result = await MobileHunter().run(
        targets=["com.example.app"], guard=_guard(), parameters={"apk_path": str(apk)}
    )
    # Must complete without raising, and without a spurious secret finding.
    assert not any(f.evidence.get("file") == "res/raw/config.json" for f in result.findings)


# --- binary AXML string-pool parser (the builtin fallback's real path) ----


def _build_axml(strings: list[str], *, is_utf8: bool) -> bytes:
    """Construct a minimal binary AXML buffer carrying exactly the fields
    ``_axml_to_text`` reads, so the real string-pool walking logic (not just
    its "not actually binary" fallback) gets exercised."""
    import struct

    header = struct.pack("<H", 0x0003) + b"\x00\x00" + struct.pack("<I", 0)
    pool_type = struct.pack("<H", 0x0001)
    pool_header_rest = b"\x00" * 6  # header_size/chunk_size, unused by the parser
    string_count = struct.pack("<I", len(strings))
    unused_style_count = struct.pack("<I", 0)
    flags = struct.pack("<I", (1 << 8) if is_utf8 else 0)

    encoded: list[bytes] = []
    for s in strings:
        if is_utf8:
            b = s.encode("utf-8")
            encoded.append(bytes([len(s), len(b)]) + b)
        else:
            b = s.encode("utf-16-le")
            encoded.append(struct.pack("<H", len(s)) + b)

    offsets: list[int] = []
    running = 0
    for e in encoded:
        offsets.append(running)
        running += len(e)
    strings_blob = b"".join(encoded)

    offsets_table = b"".join(struct.pack("<I", o) for o in offsets)
    # strings_start is relative to the +8 base, matching the parser's
    # `strings_base = 8 + strings_start` computation. offsets_base is fixed
    # by the parser at 8+28=36, i.e. 4 bytes *after* strings_start ends (an
    # unused styles_start slot it never reads) - that padding must be
    # present or every offset after it is misaligned.
    strings_start_value = 28 + len(offsets_table)
    strings_start = struct.pack("<I", strings_start_value)
    unused_styles_start = struct.pack("<I", 0)

    body = (
        pool_type + pool_header_rest + string_count + unused_style_count
        + flags + strings_start + unused_styles_start + offsets_table + strings_blob
    )
    return header + body


def test_axml_to_text_parses_utf8_string_pool():
    from pegase.modules.mobilehunter import _axml_to_text

    data = _build_axml(["hello", "world"], is_utf8=True)
    assert _axml_to_text(data) == "hello\nworld"


def test_axml_to_text_parses_utf16_string_pool():
    from pegase.modules.mobilehunter import _axml_to_text

    data = _build_axml(["hi", "there"], is_utf8=False)
    assert _axml_to_text(data) == "hi\nthere"


def test_axml_to_text_too_short_returns_empty():
    from pegase.modules.mobilehunter import _axml_to_text

    assert _axml_to_text(b"\x03") == ""


def test_axml_to_text_non_axml_magic_decodes_as_plain_text():
    from pegase.modules.mobilehunter import _axml_to_text

    assert _axml_to_text(b"not binary at all!!") == "not binary at all!!"


def test_axml_to_text_wrong_pool_type_decodes_as_plain_text():
    import struct

    from pegase.modules.mobilehunter import _axml_to_text

    header = struct.pack("<H", 0x0003) + b"\x00\x00\x00\x00\x00\x00"
    bogus_pool_type = struct.pack("<H", 0x0099) + b"hello there"
    data = header + bogus_pool_type
    assert "hello there" in _axml_to_text(data)


def test_axml_to_text_skips_out_of_range_string_offset():
    """An offset pointing past the end of the buffer must be skipped rather
    than raising."""
    import struct

    from pegase.modules.mobilehunter import _axml_to_text

    header = struct.pack("<H", 0x0003) + b"\x00\x00" + struct.pack("<I", 0)
    pool_type = struct.pack("<H", 0x0001) + b"\x00" * 6
    string_count = struct.pack("<I", 1)
    flags = struct.pack("<I", 0) + struct.pack("<I", 0)  # style_count + flags(utf16)
    strings_start = struct.pack("<I", 4)  # one offset entry = 4 bytes
    unused_styles_start = struct.pack("<I", 0)
    huge_offset = struct.pack("<I", 1_000_000)  # way out of range
    data = (
        header + pool_type + string_count + flags + strings_start
        + unused_styles_start + huge_offset
    )
    assert _axml_to_text(data) == ""


def test_decode_len_u8_handles_extended_length():
    from pegase.modules.mobilehunter import _decode_len_u8

    # High bit set on both length bytes -> the 2-byte extended-length form.
    data = bytes([0x80, 0x05, 0x80, 0x05]) + b"x" * 5
    c, b, pos = _decode_len_u8(data, 0)
    assert (c, b, pos) == (5, 5, 4)


def test_decode_len_u16_handles_extended_length():
    import struct

    from pegase.modules.mobilehunter import _decode_len_u16

    data = struct.pack("<H", 0x8000 | 0) + struct.pack("<H", 5)
    n, pos = _decode_len_u16(data, 0)
    assert (n, pos) == (5, 4)


def test_axml_to_text_skips_string_whose_length_decode_raises():
    """A length byte with the extended-form high bit set but no continuation
    byte available must be skipped (caught per-string), not crash the whole
    parse."""
    import struct

    header = struct.pack("<H", 0x0003) + b"\x00\x00" + struct.pack("<I", 0)
    pool_type = struct.pack("<H", 0x0001) + b"\x00" * 6
    string_count = struct.pack("<I", 1)
    flags = struct.pack("<I", 0) + struct.pack("<I", 1 << 8)  # style_count + utf8 flag
    # offsets_base is fixed at 8+28=36; with one 4-byte offset entry the
    # string blob physically starts at byte 40, so strings_base (8+val)
    # must equal 40.
    strings_start = struct.pack("<I", 32)
    unused_styles_start = struct.pack("<I", 0)
    offset_entry = struct.pack("<I", 0)
    # The string blob is a single byte with the extended-length high bit
    # set and nothing after it: _decode_len_u8 will index past the end.
    truncated_string_blob = bytes([0x80])
    data = (
        header + pool_type + string_count + flags + strings_start
        + unused_styles_start + offset_entry + truncated_string_blob
    )
    from pegase.modules.mobilehunter import _axml_to_text

    assert _axml_to_text(data) == ""


def test_axml_to_text_outer_exception_falls_back_to_utf8_decode():
    """A buffer that passes the magic/pool-type checks but is too short for
    the later unpack_from() header reads must hit the outer catch-all and
    decode as plain text instead of raising struct.error."""
    import struct

    from pegase.modules.mobilehunter import _axml_to_text

    header = struct.pack("<H", 0x0003) + b"\x00\x00\x00\x00\x00\x00"
    pool_type = struct.pack("<H", 0x0001)
    # Nothing else: unpack_from("<I", data, 16) will raise struct.error.
    data = header + pool_type + b"short"
    assert _axml_to_text(data) == data.decode("utf-8", "replace")
