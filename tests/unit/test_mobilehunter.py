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
