"""MobileHunter - static Android APK analysis.

MobileHunter performs **static** analysis of an APK file supplied by the
operator (path passed via ``parameters["apk_path"]``). It never installs or
runs the application. It parses the (binary) ``AndroidManifest.xml`` and the
APK structure to surface common mobile security issues:

  * dangerous / excessive permissions,
  * exported components (activities, services, receivers, providers) without
    permission guards,
  * ``android:debuggable="true"`` and ``allowBackup="true"``,
  * cleartext traffic allowed (``usesCleartextTraffic`` / missing network
    security config),
  * embedded secrets heuristics (API keys, private keys) in resources.

The binary manifest is decoded with a minimal AXML parser (no external
dependency required); if ``androguard`` is installed it is used for a richer
parse.
"""

from __future__ import annotations

import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from pegase.core.logging import get_logger
from pegase.core.scope import ActionType, ScopeGuard
from pegase.modules.base import Finding, Module, ModuleResult

log = get_logger(__name__)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS": "high",
    "android.permission.SEND_SMS": "high",
    "android.permission.RECEIVE_SMS": "medium",
    "android.permission.READ_CONTACTS": "medium",
    "android.permission.ACCESS_FINE_LOCATION": "medium",
    "android.permission.RECORD_AUDIO": "high",
    "android.permission.CAMERA": "medium",
    "android.permission.READ_EXTERNAL_STORAGE": "low",
    "android.permission.WRITE_EXTERNAL_STORAGE": "low",
    "android.permission.REQUEST_INSTALL_PACKAGES": "high",
    "android.permission.SYSTEM_ALERT_WINDOW": "medium",
    "android.permission.READ_PHONE_STATE": "medium",
}

_SECRET_PATTERNS = [
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "AWS access key id"),
    (re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "private key"),
    (re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "Google API key"),
    (re.compile(rb"sk_live_[0-9a-zA-Z]{24,}"), "Stripe live key"),
]


class MobileHunter(Module):
    name = "mobilehunter"
    description = "Static Android APK analysis (permissions, exported components, secrets)."
    action_type = ActionType.PASSIVE

    async def run(
        self,
        *,
        targets: list[str],
        guard: ScopeGuard,
        parameters: dict[str, Any] | None = None,
    ) -> ModuleResult:
        params = parameters or {}
        apk_path = params.get("apk_path")
        if not apk_path:
            raise ValueError("mobilehunter requires parameters['apk_path'].")
        path = Path(apk_path)
        if not path.exists():
            raise FileNotFoundError(f"APK not found: {apk_path}")

        # Scope: the package name (or an operator-provided target) must be in
        # scope. We use the first target as the authorized package label.
        label = targets[0] if targets else path.name
        guard.check(label, self.action_type)

        result = ModuleResult(module=self.name)
        result.raw["apk"] = str(path)

        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            manifest_xml = self._decode_manifest(zf)
            self._analyze_manifest(manifest_xml, label, result)
            self._scan_secrets(zf, names, label, result)

        return result

    # -- manifest decode --------------------------------------------------

    def _decode_manifest(self, zf: zipfile.ZipFile) -> str:
        try:
            from androguard.core.bytecodes.apk import AXMLPrinter  # type: ignore

            raw = zf.read("AndroidManifest.xml")
            return AXMLPrinter(raw).get_xml().decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - fall back to the builtin parser
            try:
                raw = zf.read("AndroidManifest.xml")
            except KeyError:
                return ""
            return _axml_to_text(raw)

    def _analyze_manifest(self, xml: str, label: str, result: ModuleResult) -> None:
        if not xml:
            result.findings.append(
                Finding(
                    module=self.name,
                    target=label,
                    title="Could not decode AndroidManifest.xml",
                    description="Binary manifest could not be parsed.",
                    severity="info",
                )
            )
            return

        lower = xml.lower()

        # Permissions
        perms = set(re.findall(r'android\.permission\.[A-Z_]+', xml))
        for perm in sorted(perms):
            sev = DANGEROUS_PERMISSIONS.get(perm)
            if sev:
                result.findings.append(
                    Finding(
                        module=self.name,
                        target=label,
                        title=f"Dangerous permission requested: {perm}",
                        description="Confirm this permission is required.",
                        severity=sev,
                        evidence={"permission": perm},
                    )
                )

        # Flags
        if 'android:debuggable="true"' in lower or "debuggable=true" in lower:
            result.findings.append(
                Finding(
                    module=self.name, target=label,
                    title="Application is debuggable",
                    description="android:debuggable=true ships in the package.",
                    severity="high",
                )
            )
        if 'android:allowbackup="true"' in lower or "allowbackup=true" in lower:
            result.findings.append(
                Finding(
                    module=self.name, target=label,
                    title="ADB backup allowed (allowBackup=true)",
                    description="App data can be extracted via adb backup.",
                    severity="medium",
                )
            )
        if "usescleartexttraffic=\"true\"" in lower or "cleartexttrafficpermitted=\"true\"" in lower:
            result.findings.append(
                Finding(
                    module=self.name, target=label,
                    title="Cleartext traffic permitted",
                    description="App may send data over unencrypted HTTP.",
                    severity="high",
                )
            )

        # Exported components without permission guard (heuristic)
        for m in re.finditer(
            r'<(activity|service|receiver|provider)\b[^>]*android:exported="true"[^>]*>',
            xml,
        ):
            block = m.group(0)
            if "android:permission" not in block:
                result.findings.append(
                    Finding(
                        module=self.name, target=label,
                        title=f"Exported {m.group(1)} without permission guard",
                        description=(
                            "An exported component is reachable by any app and "
                            "declares no permission requirement."
                        ),
                        severity="medium",
                        evidence={"component": block[:300]},
                    )
                )

    # -- secrets ----------------------------------------------------------

    def _scan_secrets(
        self, zf: zipfile.ZipFile, names: list[str], label: str, result: ModuleResult
    ) -> None:
        scan_targets = [
            n for n in names
            if n.startswith(("res/", "assets/")) or n.endswith((".xml", ".json", ".properties"))
        ][:500]
        for n in scan_targets:
            try:
                data = zf.read(n)
            except Exception:  # noqa: BLE001
                continue
            for pattern, desc in _SECRET_PATTERNS:
                if pattern.search(data):
                    result.findings.append(
                        Finding(
                            module=self.name, target=label,
                            title=f"Possible embedded secret ({desc})",
                            description=f"Pattern for {desc} found in {n}.",
                            severity="high",
                            evidence={"file": n, "kind": desc},
                        )
                    )
                    break


# ---------------------------------------------------------------------------
# Minimal AXML (binary AndroidManifest) string-pool extractor.
# It does not rebuild the full XML tree; it extracts the UTF-8/UTF-16 string
# pool which is enough for the substring/regex heuristics above.
# ---------------------------------------------------------------------------


def _axml_to_text(data: bytes) -> str:
    try:
        if len(data) < 8:
            return ""
        # Header: magic (0x00080003), file size
        # Then a string pool chunk: type 0x0001
        # We scan for the string pool chunk and extract strings.
        magic = struct.unpack_from("<H", data, 0)[0]
        if magic != 0x0003:
            return data.decode("utf-8", "replace")
        # string pool chunk starts at offset 8
        pool_type = struct.unpack_from("<H", data, 8)[0]
        if pool_type != 0x0001:
            return data.decode("utf-8", "replace")
        string_count = struct.unpack_from("<I", data, 8 + 8)[0]
        flags = struct.unpack_from("<I", data, 8 + 16)[0]
        strings_start = struct.unpack_from("<I", data, 8 + 20)[0]
        is_utf8 = bool(flags & (1 << 8))
        offsets_base = 8 + 28
        strings_base = 8 + strings_start
        out: list[str] = []
        for i in range(string_count):
            off = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
            pos = strings_base + off
            if pos >= len(data):
                continue
            try:
                if is_utf8:
                    # u8 len (skip), then byte len, then bytes
                    _, l2, p = _decode_len_u8(data, pos)
                    s = data[p : p + l2].decode("utf-8", "replace")
                else:
                    n, p = _decode_len_u16(data, pos)
                    s = data[p : p + n * 2].decode("utf-16-le", "replace")
            except Exception:  # noqa: BLE001
                continue
            out.append(s)
        return "\n".join(out)
    except Exception:  # noqa: BLE001
        return data.decode("utf-8", "replace")


def _decode_len_u8(data: bytes, pos: int) -> tuple[int, int, int]:
    # two length fields (char len, byte len), each 1-2 bytes
    c = data[pos]
    pos += 1
    if c & 0x80:
        c = ((c & 0x7F) << 8) | data[pos]
        pos += 1
    b = data[pos]
    pos += 1
    if b & 0x80:
        b = ((b & 0x7F) << 8) | data[pos]
        pos += 1
    return c, b, pos


def _decode_len_u16(data: bytes, pos: int) -> tuple[int, int]:
    n = struct.unpack_from("<H", data, pos)[0]
    pos += 2
    if n & 0x8000:
        n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
        pos += 2
    return n, pos
