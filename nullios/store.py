import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Self
from urllib.parse import urlparse

import requests

from nullios.errors import MissingDependencyError, StoreError

_BUNDLE_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")
_APP_STORE_URL_RE = re.compile(r"/id(\d+)")
_ITUNES_LOOKUP_URL = "https://itunes.apple.com/lookup"


@dataclass(frozen=True)
class StoreCredentials:
    apple_id: str
    password: str

    @classmethod
    def from_env(cls) -> Self | None:
        apple_id = os.getenv("NULLIOS_APPLE_ID")
        password = os.getenv("NULLIOS_APPLE_PASSWORD")
        if apple_id and password:
            return cls(apple_id=apple_id, password=password)
        return None


def _lookup_bundle_id_by_store_id(store_id: str) -> str:
    try:
        response = requests.get(_ITUNES_LOOKUP_URL, params={"id": store_id}, timeout=20)
    except requests.RequestException as exc:
        raise StoreError(f"iTunes lookup failed: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise StoreError(f"iTunes lookup returned invalid JSON: {exc}") from exc

    results = payload.get("results", [])
    if not results:
        raise StoreError(f"No App Store result for id {store_id}")

    bundle_id = results[0].get("bundleId")
    if not bundle_id:
        raise StoreError(f"iTunes result missing bundleId for id {store_id}")
    return bundle_id


def resolve_target(target: str) -> str:
    target = target.strip().strip("'\"")
    if not target:
        raise StoreError("Target is empty")

    if _BUNDLE_ID_RE.match(target):
        return target

    if target.isdigit():
        return _lookup_bundle_id_by_store_id(target)

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https") and "apps.apple.com" in parsed.netloc:
        match = _APP_STORE_URL_RE.search(parsed.path)
        if match:
            return _lookup_bundle_id_by_store_id(match.group(1))

    raise StoreError(f"Could not resolve App Store target: {target}")


def validate_bundle_id(value: str) -> str:
    value = value.strip().strip("'\"")
    if not value:
        raise StoreError("Bundle ID is empty")
    if not _BUNDLE_ID_RE.match(value):
        raise StoreError(f"Invalid bundle ID: {value}")
    return value


def _find_ipatool() -> str | None:
    for name in ("ipatool-py", "ipatool"):
        path = shutil.which(name)
        if path:
            return name
    return None


def _use_ipatool_cli(bundle_id: str, credentials: StoreCredentials, output_dir: Path) -> Path:
    tool = shutil.which("ipatool")
    if tool is None:
        raise MissingDependencyError("ipatool CLI not found on PATH")

    output_dir.mkdir(parents=True, exist_ok=True)
    auth_cmd = [
        tool, "auth", "login",
        "--email", credentials.apple_id,
        "--password", credentials.password,
    ]
    result = subprocess.run(auth_cmd, capture_output=True, text=True)
    if result.returncode != 0 and "already" not in result.stdout.lower():
        raise StoreError(f"ipatool auth failed: {result.stderr or result.stdout}")

    download_cmd = [
        tool, "download",
        "--bundle-identifier", bundle_id,
        "--output", str(output_dir),
    ]
    result = subprocess.run(download_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise StoreError(f"ipatool download failed: {result.stderr or result.stdout}")

    ipas = sorted(output_dir.glob("*.ipa"))
    if not ipas:
        raise StoreError("ipatool reported success but no IPA was written")
    return ipas[-1]


def _use_ipatool_py(bundle_id: str, credentials: StoreCredentials, output_dir: Path) -> Path:
    try:
        from ipatool import authenticate, purchase, download
    except ImportError as exc:
        raise MissingDependencyError("ipatool-py is not installed; install with: pip install ipatool-py") from exc

    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        auth = authenticate(credentials.apple_id, credentials.password)
        purchase(auth["guid"], auth["dsid"], auth["mmeAuthToken"], bundle_id)
        saved_path = download(
            auth["guid"],
            auth["dsid"],
            auth["mmeAuthToken"],
            bundle_id,
            str(output_dir),
        )
        return Path(saved_path)
    except Exception as exc:
        raise StoreError(f"App Store download failed: {exc}") from exc


def download_ipa(bundle_id: str, credentials: StoreCredentials | None = None, output_dir: Path | None = None) -> Path:
    bundle_id = validate_bundle_id(bundle_id)
    if credentials is None:
        credentials = StoreCredentials.from_env()
    if credentials is None:
        raise StoreError("App Store credentials required. Set NULLIOS_APPLE_ID and NULLIOS_APPLE_PASSWORD, or pass credentials.")

    output_dir = output_dir or Path.home() / "Desktop" / "nullios" / "ipa"

    tool_name = _find_ipatool()
    if tool_name == "ipatool":
        return _use_ipatool_cli(bundle_id, credentials, output_dir)
    return _use_ipatool_py(bundle_id, credentials, output_dir)
