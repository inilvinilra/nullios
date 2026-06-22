import io
import plistlib
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from nullios.errors import AnalysisError, MissingDependencyError
from nullios.ipa import BinaryInfo, IpaBundle, extract_strings


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str


@dataclass
class AnalysisResult:
    bundle_id: str | None = None
    display_name: str | None = None
    version: str | None = None
    platform: str | None = None
    min_ios: str | None = None
    architectures: list[str] = field(default_factory=list)
    encrypted: bool = False
    pie: bool = False
    stack_canary: bool = False
    arc: bool = False
    url_schemes: list[str] = field(default_factory=list)
    universal_links: list[str] = field(default_factory=list)
    ats_disabled: bool = False
    ats_details: list[str] = field(default_factory=list)
    entitlements: dict = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    raw_info_plist: dict = field(default_factory=dict)


ProgressCallback = Callable[[str], None]


def _noop(message: str) -> None:
    return None


def analyze(bundle: IpaBundle, on_progress: ProgressCallback = _noop) -> AnalysisResult:
    result = AnalysisResult(
        bundle_id=bundle.bundle_id,
        display_name=bundle.display_name,
        version=bundle.version,
        raw_info_plist=bundle.info_plist,
    )

    on_progress("Parsing bundle metadata")
    _collect_metadata(bundle, result)

    on_progress("Reading entitlements")
    _collect_entitlements(bundle, result)

    on_progress("Inspecting URL schemes and deep links")
    _collect_url_schemes(bundle, result)
    _collect_universal_links(result)

    on_progress("Evaluating App Transport Security")
    _collect_ats(bundle, result)

    on_progress("Listing frameworks and libraries")
    _collect_frameworks(bundle, result)

    on_progress("Scanning permissions")
    _collect_permissions(bundle, result)

    on_progress("Extracting interesting strings")
    _collect_strings(bundle, result)

    on_progress("Running external binary analysis")
    _run_radare_summary(bundle, result)

    on_progress("Generating findings")
    _generate_findings(result)

    return result


def _collect_metadata(bundle: IpaBundle, result: AnalysisResult) -> None:
    result.bundle_id = bundle.bundle_id
    result.display_name = bundle.display_name
    result.version = bundle.version
    result.platform = bundle.info_plist.get("DTPlatformName") or bundle.info_plist.get("DTPlatformVersion")

    if bundle.binary is not None:
        binary = bundle.binary
        result.architectures = binary.architectures
        result.encrypted = binary.encrypted
        result.pie = binary.pie
        result.stack_canary = binary.has_canary
        result.arc = binary.has_arc
        result.min_ios = binary.min_ios


def _collect_url_schemes(bundle: IpaBundle, result: AnalysisResult) -> None:
    schemes: set[str] = set()
    handlers = bundle.info_plist.get("CFBundleURLTypes", [])
    for handler in handlers:
        for scheme in handler.get("CFBundleURLSchemes", []):
            if scheme:
                schemes.add(scheme)
    result.url_schemes = sorted(schemes)


def _collect_universal_links(result: AnalysisResult) -> None:
    domains: set[str] = set()
    associated = result.entitlements.get("com.apple.developer.associated-domains")
    if isinstance(associated, list):
        for entry in associated:
            if isinstance(entry, str):
                domains.add(entry)
    elif isinstance(associated, str):
        domains.add(associated)

    aasa = result.raw_info_plist.get("com.apple.developer.associated-domains")
    if isinstance(aasa, list):
        for entry in aasa:
            if isinstance(entry, str):
                domains.add(entry)

    result.universal_links = sorted(domains)


def _collect_ats(bundle: IpaBundle, result: AnalysisResult) -> None:
    ats = bundle.info_plist.get("NSAppTransportSecurity", {})
    if not isinstance(ats, dict):
        return

    disabled = False
    details: list[str] = []

    if ats.get("NSAllowsArbitraryLoads") is True:
        disabled = True
        details.append("NSAllowsArbitraryLoads is enabled")
    if ats.get("NSAllowsArbitraryLoadsForMedia") is True:
        disabled = True
        details.append("NSAllowsArbitraryLoadsForMedia is enabled")
    if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
        disabled = True
        details.append("NSAllowsArbitraryLoadsInWebContent is enabled")
    if ats.get("NSAllowsLocalNetworking") is True:
        disabled = True
        details.append("NSAllowsLocalNetworking is enabled")

    exceptions = ats.get("NSExceptionDomains", {})
    if isinstance(exceptions, dict):
        for domain, config in exceptions.items():
            if isinstance(config, dict):
                if config.get("NSExceptionAllowsInsecureHTTPLoads") is True:
                    disabled = True
                    details.append(f"Insecure HTTP allowed for {domain}")
                if config.get("NSExceptionMinimumTLSVersion") == "TLSv1.0":
                    details.append(f"Weak TLS for {domain}")

    result.ats_disabled = disabled
    result.ats_details = details


def _collect_entitlements(bundle: IpaBundle, result: AnalysisResult) -> None:
    if bundle.embedded_provision is not None:
        try:
            data = bundle.embedded_provision.read_bytes()
            start = data.find(b"<?xml")
            end = data.find(b"</plist>")
            if start != -1 and end != -1:
                plist_data = data[start:end + 8]
                provision = plistlib.loads(plist_data)
                entitlements = provision.get("Entitlements", {})
                result.entitlements = dict(entitlements) if isinstance(entitlements, dict) else {}
        except Exception:
            pass

    if not result.entitlements and bundle.main_binary_path:
        result.entitlements = _extract_entitlements_from_binary(bundle.main_binary_path)


def _extract_entitlements_from_binary(binary_path: Path) -> dict:
    try:
        output = subprocess.check_output(
            ["codesign", "-d", "--entitlements", "-", str(binary_path)],
            stderr=subprocess.STDOUT,
        )
        if output.startswith(b"<?xml"):
            return plistlib.loads(output)
    except Exception:
        pass
    return {}


def _collect_frameworks(bundle: IpaBundle, result: AnalysisResult) -> None:
    result.frameworks = sorted(str(f.name) for f in bundle.frameworks)


def _collect_permissions(bundle: IpaBundle, result: AnalysisResult) -> None:
    permission_keys = [
        "NSCameraUsageDescription",
        "NSMicrophoneUsageDescription",
        "NSLocationWhenInUseUsageDescription",
        "NSLocationAlwaysUsageDescription",
        "NSLocationAlwaysAndWhenInUseUsageDescription",
        "NSPhotoLibraryUsageDescription",
        "NSPhotoLibraryAddUsageDescription",
        "NSContactsUsageDescription",
        "NSBluetoothAlwaysUsageDescription",
        "NSBluetoothPeripheralUsageDescription",
        "NSFaceIDUsageDescription",
        "NSCalendarsUsageDescription",
        "NSRemindersUsageDescription",
        "NSAppleMusicUsageDescription",
        "NSMotionUsageDescription",
        "NSSpeechRecognitionUsageDescription",
    ]
    result.permissions = sorted(k for k in permission_keys if k in bundle.info_plist)


def _collect_strings(bundle: IpaBundle, result: AnalysisResult) -> None:
    if bundle.main_binary_path is None or result.encrypted:
        return

    strings = extract_strings(bundle.main_binary_path, min_length=6, limit=10000)
    patterns = [
        re.compile(r"https?://[^\s\"'<>]+"),
        re.compile(r"api[_-]?key[^\s\"'<>]{0,20}[\"']?[A-Za-z0-9_\-]{16,}"),
        re.compile(r"[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{20,}"),
    ]

    interesting: set[str] = set()
    for s in strings:
        for pattern in patterns:
            if pattern.search(s):
                interesting.add(s)
                break

    result.interesting_strings = sorted(interesting)[:250]


def _run_radare_summary(bundle: IpaBundle, result: AnalysisResult) -> None:
    if bundle.main_binary_path is None or result.encrypted:
        return
    if shutil.which("rabin2") is None:
        return

    try:
        output = subprocess.check_output(
            ["rabin2", "-I", str(bundle.main_binary_path)],
            stderr=subprocess.DEVNULL,
            text=True,
        )
        for line in output.splitlines():
            if line.startswith("canary"):
                result.stack_canary = "true" in line.lower()
            elif line.startswith("pic"):
                result.pie = "true" in line.lower()
            elif line.startswith("endian"):
                pass
    except Exception:
        pass


def _generate_findings(result: AnalysisResult) -> None:
    if result.encrypted:
        result.findings.append(
            Finding("high", "binary", "Encrypted binary", "Main executable is FairPlay encrypted; static analysis requires a decrypted dump from a jailbroken device.")
        )
    if not result.pie:
        result.findings.append(
            Finding("medium", "binary", "PIE disabled", "Main executable is not position-independent, making ROP exploitation easier.")
        )
    if not result.stack_canary:
        result.findings.append(
            Finding("medium", "binary", "Stack canaries disabled", "Main executable appears to lack stack canary protection.")
        )
    if not result.arc:
        result.findings.append(
            Finding("low", "binary", "ARC not detected", "Automatic Reference Counting not confirmed; manual memory management may exist.")
        )
    if result.ats_disabled:
        result.findings.append(
            Finding("high", "network", "ATS globally or partially disabled", "; ".join(result.ats_details) or "Arbitrary loads are allowed.")
        )
    if result.url_schemes:
        result.findings.append(
            Finding("info", "deeplink", "Custom URL schemes registered", ", ".join(result.url_schemes))
        )
    if result.universal_links:
        result.findings.append(
            Finding("info", "deeplink", "Associated domains / universal links", ", ".join(result.universal_links))
        )
    if "com.apple.developer.associated-domains" in result.entitlements:
        domains = result.entitlements["com.apple.developer.associated-domains"]
        if isinstance(domains, list):
            detail = ", ".join(str(d) for d in domains)
        else:
            detail = str(domains)
        result.findings.append(
            Finding("info", "entitlement", "Associated domains entitlement", detail)
        )
    if result.entitlements.get("get-task-allow") is True:
        result.findings.append(
            Finding("high", "entitlement", "get-task-allow enabled", "Debuggable build; lldb can attach without restrictions.")
        )
    if result.entitlements.get("com.apple.security.cs.allow-unsigned-executable-memory") is True:
        result.findings.append(
            Finding("medium", "entitlement", "Unsigned executable memory allowed", "JIT/unsigned memory entitlement may ease code injection.")
        )
    if result.interesting_strings:
        result.findings.append(
            Finding("info", "strings", "Interesting strings detected", f"{len(result.interesting_strings)} candidate URLs/tokens/secrets found.")
        )
