import io
import plistlib
import shutil
import struct
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from nullios.errors import IpaError

MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_MAGIC_32 = 0xFEEDFACE
CPU_TYPE_ARM = 0x0000000C
CPU_TYPE_ARM64 = 0x0100000C


@dataclass
class BinaryInfo:
    path: Path
    architectures: list[str] = field(default_factory=list)
    encrypted: bool = False
    pie: bool = False
    has_canary: bool = False
    has_arc: bool = False
    min_ios: str | None = None
    entitlements: dict = field(default_factory=dict)


@dataclass
class IpaBundle:
    ipa_path: Path
    extract_root: Path
    payload_path: Path
    app_dir: Path
    info_plist: dict
    binary: BinaryInfo | None = None
    frameworks: list[Path] = field(default_factory=list)
    embedded_provision: Path | None = None

    @property
    def bundle_id(self) -> str | None:
        return self.info_plist.get("CFBundleIdentifier")

    @property
    def display_name(self) -> str | None:
        return self.info_plist.get("CFBundleDisplayName") or self.info_plist.get("CFBundleName")

    @property
    def version(self) -> str | None:
        return self.info_plist.get("CFBundleShortVersionString")

    @property
    def main_binary_path(self) -> Path | None:
        if self.binary is None:
            return None
        return self.binary.path

    @classmethod
    def load(cls, ipa_path: Path) -> Self:
        ipa_path = Path(ipa_path).expanduser().resolve()
        if not ipa_path.exists():
            raise IpaError(f"IPA not found: {ipa_path}")
        if not zipfile.is_zipfile(ipa_path):
            raise IpaError(f"File is not a valid ZIP/IPA: {ipa_path}")

        extract_root = Path(tempfile.mkdtemp(prefix="nullios-"))
        try:
            with zipfile.ZipFile(ipa_path, "r") as zf:
                zf.extractall(extract_root)
        except zipfile.BadZipFile as exc:
            shutil.rmtree(extract_root, ignore_errors=True)
            raise IpaError(f"Failed to extract IPA: {exc}") from exc

        payload_path = extract_root / "Payload"
        if not payload_path.exists():
            shutil.rmtree(extract_root, ignore_errors=True)
            raise IpaError("IPA does not contain a Payload directory")

        app_dirs = [p for p in payload_path.iterdir() if p.suffix == ".app" and p.is_dir()]
        if not app_dirs:
            shutil.rmtree(extract_root, ignore_errors=True)
            raise IpaError("No .app bundle found inside Payload")

        app_dir = app_dirs[0]
        info_plist_path = app_dir / "Info.plist"
        if not info_plist_path.exists():
            shutil.rmtree(extract_root, ignore_errors=True)
            raise IpaError("Info.plist missing from app bundle")

        try:
            with info_plist_path.open("rb") as fh:
                info_plist = plistlib.load(fh)
        except plistlib.InvalidFileException as exc:
            shutil.rmtree(extract_root, ignore_errors=True)
            raise IpaError(f"Cannot parse Info.plist: {exc}") from exc

        embedded_provision = app_dir / "embedded.mobileprovision"
        if not embedded_provision.exists():
            embedded_provision = None

        bundle = cls(
            ipa_path=ipa_path,
            extract_root=extract_root,
            payload_path=payload_path,
            app_dir=app_dir,
            info_plist=info_plist,
            embedded_provision=embedded_provision,
        )

        bundle._discover_frameworks()
        bundle._load_binary_info()
        return bundle

    def _discover_frameworks(self) -> None:
        frameworks_dir = self.app_dir / "Frameworks"
        if frameworks_dir.exists():
            self.frameworks = sorted(p for p in frameworks_dir.iterdir() if p.is_dir() or p.suffix == ".dylib")
        plug_ins_dir = self.app_dir / "PlugIns"
        if plug_ins_dir.exists():
            self.frameworks.extend(sorted(p for p in plug_ins_dir.iterdir() if p.is_dir()))

    def _load_binary_info(self) -> None:
        binary_name = self.info_plist.get("CFBundleExecutable")
        if not binary_name:
            return
        binary_path = self.app_dir / binary_name
        if not binary_path.exists():
            return
        self.binary = analyze_macho(binary_path)

    def cleanup(self) -> None:
        if self.extract_root.exists():
            shutil.rmtree(self.extract_root, ignore_errors=True)


class IpaBundleManager:
    def __init__(self) -> None:
        self._active: IpaBundle | None = None

    def open(self, ipa_path: Path) -> IpaBundle:
        if self._active is not None:
            self._active.cleanup()
        self._active = IpaBundle.load(ipa_path)
        return self._active

    def close(self) -> None:
        if self._active is not None:
            self._active.cleanup()
            self._active = None

    @property
    def current(self) -> IpaBundle | None:
        return self._active


def analyze_macho(binary_path: Path) -> BinaryInfo:
    info = BinaryInfo(path=binary_path)
    data = binary_path.read_bytes()
    if len(data) < 4:
        return info

    magic = struct.unpack("<I", data[:4])[0]
    if magic == MACHO_MAGIC_64:
        info.architectures = _parse_fat_or_macho64(data)
        info.encrypted = _detect_encryption(data)
        info.pie = _detect_pie(data)
        info.has_canary = _detect_canary(data)
        info.has_arc = _detect_arc(data)
        info.min_ios = _detect_min_version(data)
    elif magic == MACHO_MAGIC_32:
        info.architectures = _parse_fat_or_macho32(data)
        info.pie = _detect_pie(data)
        info.has_canary = _detect_canary(data)
        info.has_arc = _detect_arc(data)
    elif struct.unpack(">I", data[:4])[0] == 0xCAFEBABE or struct.unpack("<I", data[:4])[0] == 0xCAFEBABE:
        info.architectures = _parse_fat_archs(data)
        info.encrypted = _detect_encryption(data)
    return info


def _parse_fat_or_macho64(data: bytes) -> list[str]:
    magic = struct.unpack("<I", data[:4])[0]
    if magic == MACHO_MAGIC_64:
        cputype = struct.unpack("<i", data[4:8])[0]
        return [_cpu_name(cputype)]
    return _parse_fat_archs(data)


def _parse_fat_or_macho32(data: bytes) -> list[str]:
    magic = struct.unpack("<I", data[:4])[0]
    if magic == MACHO_MAGIC_32:
        cputype = struct.unpack("<i", data[4:8])[0]
        return [_cpu_name(cputype)]
    return _parse_fat_archs(data)


def _parse_fat_archs(data: bytes) -> list[str]:
    archs: list[str] = []
    magic = struct.unpack(">I", data[:4])[0]
    big_endian = magic == 0xCAFEBABE
    endian = ">" if big_endian else "<"
    nfat = struct.unpack(f"{endian}I", data[4:8])[0]
    offset = 8
    for _ in range(nfat):
        cputype = struct.unpack(f"{endian}i", data[offset:offset + 4])[0]
        archs.append(_cpu_name(cputype))
        offset += 20
    return archs


def _cpu_name(cputype: int) -> str:
    mapping = {
        CPU_TYPE_ARM: "armv7",
        CPU_TYPE_ARM64: "arm64",
        0x01000007: "x86_64",
        0x00000007: "i386",
    }
    return mapping.get(cputype, f"cpu_{cputype:08x}")


def _detect_encryption(data: bytes) -> bool:
    magic = struct.unpack("<I", data[:4])[0]
    if magic == MACHO_MAGIC_64:
        return _check_encryption_at(data, 0, "<")
    if magic == MACHO_MAGIC_32:
        return _check_encryption_at(data, 0, "<")
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        return _scan_fat_for_encryption(data)
    return False


def _check_encryption_at(data: bytes, base: int, endian: str) -> bool:
    is64 = struct.unpack(f"{endian}I", data[base:base + 4])[0] == MACHO_MAGIC_64
    ncmds = struct.unpack(f"{endian}I", data[base + 16:base + 20])[0]
    sizeof_hdr = 32 if is64 else 28
    off = base + sizeof_hdr
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", data[off:off + 8])
        if cmd in (0x21, 0x2C):
            cryptoff, cryptsize = struct.unpack(f"{endian}II", data[off + 8:off + 16])
            return cryptsize > 0
        off += cmdsize
    return False


def _scan_fat_for_encryption(data: bytes) -> bool:
    magic = struct.unpack(">I", data[:4])[0]
    big_endian = magic == 0xCAFEBABE
    endian = ">" if big_endian else "<"
    nfat = struct.unpack(f"{endian}I", data[4:8])[0]
    off = 8
    for _ in range(nfat):
        cputype, cpusubtype, offset, size, align = struct.unpack(f"{endian}5I", data[off:off + 20])
        if _check_encryption_at(data, offset, endian):
            return True
        off += 20
    return False


def _detect_pie(data: bytes) -> bool:
    return _has_macho_flag(data, 0x200000)


def _detect_canary(data: bytes) -> bool:
    markers = (b"__stack_chk_fail", b"__stack_chk_guard")
    return any(marker in data for marker in markers)


def _detect_arc(data: bytes) -> bool:
    markers = (b"_objc_storeStrong", b"_objc_release", b"_objc_retainAutorelease")
    return any(marker in data for marker in markers)


def _detect_min_version(data: bytes) -> str | None:
    magic = struct.unpack("<I", data[:4])[0]
    if magic == MACHO_MAGIC_64:
        return _min_version_at(data, 0, "<")
    if magic == MACHO_MAGIC_32:
        return _min_version_at(data, 0, "<")
    if magic in (0xCAFEBABE, 0xBEBAFECA):
        return _fat_min_version(data)
    return None


def _min_version_at(data: bytes, base: int, endian: str) -> str | None:
    is64 = struct.unpack(f"{endian}I", data[base:base + 4])[0] == MACHO_MAGIC_64
    sizeof_hdr = 32 if is64 else 28
    ncmds = struct.unpack(f"{endian}I", data[base + 16:base + 20])[0]
    off = base + sizeof_hdr
    for _ in range(ncmds):
        if off + 8 > len(data):
            break
        cmd, cmdsize = struct.unpack(f"{endian}II", data[off:off + 8])
        if cmd == 0x25:
            # LC_VERSION_MIN_IPHONEOS: version, sdk
            version = struct.unpack(f"{endian}I", data[off + 8:off + 12])[0]
            return _version_to_string(version)
        if cmd == 0x32:
            # LC_BUILD_VERSION: platform, minos, sdk, ntools
            version = struct.unpack(f"{endian}I", data[off + 12:off + 16])[0]
            return _version_to_string(version)
        if cmd == 0x33:
            # LC_SOURCE_VERSION
            version = struct.unpack(f"{endian}I", data[off + 8:off + 12])[0]
            return _version_to_string(version)
        off += cmdsize
    return None


def _fat_min_version(data: bytes) -> str | None:
    magic = struct.unpack(">I", data[:4])[0]
    big_endian = magic == 0xCAFEBABE
    endian = ">" if big_endian else "<"
    nfat = struct.unpack(f"{endian}I", data[4:8])[0]
    off = 8
    versions: list[str] = []
    for _ in range(nfat):
        offset = struct.unpack(f"{endian}I", data[off + 8:off + 12])[0]
        ver = _min_version_at(data, offset, endian)
        if ver:
            versions.append(ver)
        off += 20
    return versions[0] if versions else None


def _version_to_string(version: int) -> str:
    patch = version & 0xFF
    minor = (version >> 8) & 0xFF
    major = (version >> 16) & 0xFFFF
    return f"{major}.{minor}.{patch}"


def _has_macho_flag(data: bytes, flag: int) -> bool:
    magic = struct.unpack("<I", data[:4])[0]
    if magic == MACHO_MAGIC_64:
        flags = struct.unpack("<I", data[24:28])[0]
        return bool(flags & flag)
    if magic == MACHO_MAGIC_32:
        flags = struct.unpack("<I", data[20:24])[0]
        return bool(flags & flag)
    return False




def extract_strings(binary_path: Path, min_length: int = 4, limit: int = 5000) -> list[str]:
    data = binary_path.read_bytes()
    strings: list[str] = []
    current = bytearray()
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode("ascii", errors="ignore"))
                if len(strings) >= limit:
                    break
            current = bytearray()
    if len(current) >= min_length and len(strings) < limit:
        strings.append(current.decode("ascii", errors="ignore"))
    return strings
