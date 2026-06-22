import struct
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from nullios.ipa import (
    MACHO_MAGIC_32,
    MACHO_MAGIC_64,
    _check_encryption_at,
    _detect_arc,
    _detect_canary,
    _detect_min_version,
    _detect_pie,
    _has_macho_flag,
    _version_to_string,
    analyze_macho,
)


def _build_macho64_header(ncmds: int, flags: int = 0) -> bytes:
    header = struct.pack(
        "<IIIIIIII",
        MACHO_MAGIC_64,
        0x0100000C,  # arm64
        0,  # cpusubtype
        2,  # MH_EXECUTE
        ncmds,
        0,  # sizeofcmds (not used by our parsers)
        flags,
        0,  # reserved
    )
    return header


def _build_load_command(cmd: int, cmdsize: int, payload: bytes) -> bytes:
    return struct.pack("<II", cmd, cmdsize) + payload.ljust(cmdsize - 8, b"\x00")


class MachOEncryptionTests(unittest.TestCase):
    def test_unencrypted_macho64(self):
        data = _build_macho64_header(0)
        self.assertFalse(_check_encryption_at(data, 0, "<"))

    def test_encrypted_macho64(self):
        header = _build_macho64_header(1)
        # LC_ENCRYPTION_INFO_64 (0x2C), cryptsize > 0
        cmd = _build_load_command(0x2C, 24, struct.pack("<III", 4096, 65536, 1) + b"\x00" * 4)
        data = header + cmd
        self.assertTrue(_check_encryption_at(data, 0, "<"))

    def test_encrypted_macho32(self):
        # 32-bit header: magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = 28 bytes
        header = struct.pack(
            "<IIIIIII",
            MACHO_MAGIC_32,
            0x0000000C,  # arm
            0,
            2,
            1,
            0,
            0,
        )
        cmd = _build_load_command(0x21, 20, struct.pack("<III", 4096, 65536, 1))
        data = header + cmd
        self.assertTrue(_check_encryption_at(data, 0, "<"))


class MachOFlagTests(unittest.TestCase):
    def test_pie_flag_64(self):
        header = _build_macho64_header(0, flags=0x200000)
        self.assertTrue(_detect_pie(header))

    def test_no_pie_flag_64(self):
        header = _build_macho64_header(0, flags=0)
        self.assertFalse(_detect_pie(header))

    def test_canary_marker(self):
        data = b"padding__stack_chk_failpadding"
        self.assertTrue(_detect_canary(data))

    def test_arc_marker(self):
        data = b"padding_objc_releasepadding"
        self.assertTrue(_detect_arc(data))


class MachOMinVersionTests(unittest.TestCase):
    def test_build_version_64(self):
        header = _build_macho64_header(1)
        # LC_BUILD_VERSION (0x32): platform, minos, sdk, ntools
        version_payload = struct.pack("<IIII", 2, 0x000E0000, 0x000E0100, 0)
        cmd = _build_load_command(0x32, 24, version_payload)
        data = header + cmd
        self.assertEqual(_detect_min_version(data), "14.0.0")

    def test_version_min_iphoneos_32(self):
        header = struct.pack(
            "<IIIIIII",
            MACHO_MAGIC_32,
            0x0000000C,
            0,
            2,
            1,
            0,
            0,
        )
        # LC_VERSION_MIN_IPHONEOS (0x25): version, sdk
        version_payload = struct.pack("<II", 0x000D0000, 0x000D0100)
        cmd = _build_load_command(0x25, 16, version_payload)
        data = header + cmd
        self.assertEqual(_detect_min_version(data), "13.0.0")


class VersionStringTests(unittest.TestCase):
    def test_version_to_string(self):
        self.assertEqual(_version_to_string(0x000E0102), "14.1.2")


class AnalyzeMachoTests(unittest.TestCase):
    def test_analyze_macho64_arm64(self):
        header = _build_macho64_header(0, flags=0x200000)
        # ARC marker + canary marker in the binary
        data = header + b"_objc_release" + b"__stack_chk_fail"
        # analyze_macho reads from disk, so we mock read_bytes
        with patch.object(Path, "read_bytes", return_value=data):
            info = analyze_macho(Path("/fake/binary"))
        self.assertEqual(info.architectures, ["arm64"])
        self.assertTrue(info.pie)
        self.assertTrue(info.has_canary)
        self.assertTrue(info.has_arc)


if __name__ == "__main__":
    unittest.main()
