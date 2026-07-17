#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify the exact executable payload used by Windows release packages."""

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import zipfile


EXPECTED_EXECUTABLES = (
    "blackcoin-cli.exe",
    "blackcoin-qt.exe",
    "blackcoin-tx.exe",
    "blackcoin-util.exe",
    "blackcoin-wallet.exe",
    "blackcoind.exe",
)
FORBIDDEN_EXECUTABLES = frozenset({"test_blackcoin.exe"})
PE32_MAGIC = 0x010B
PE32_PLUS_MAGIC = 0x020B
CERTIFICATE_DIRECTORY_INDEX = 4
RESOURCE_DIRECTORY_INDEX = 2
AMD64_MACHINE = 0x8664
VERSION_RESOURCE_TYPE = 16
MAX_RESOURCE_ENTRIES = 4096


def _require_exact_names(names, context):
    names = list(names)
    duplicates = sorted({name for name in names if names.count(name) > 1})
    if duplicates:
        raise RuntimeError(f"{context} contains duplicate entries: {', '.join(duplicates)}")

    actual = set(names)
    expected = set(EXPECTED_EXECUTABLES)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    if missing:
        raise RuntimeError(f"{context} is missing required executables: {', '.join(missing)}")
    if unexpected:
        raise RuntimeError(f"{context} contains unexpected entries: {', '.join(unexpected)}")


def verify_directory(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise RuntimeError(f"portable payload is not a directory: {root}")

    names = []
    for entry in sorted(root.iterdir()):
        if entry.is_symlink() or not entry.is_file():
            raise RuntimeError(f"portable payload entry must be a regular file: {entry.name}")
        names.append(entry.name)
    _require_exact_names(names, "portable payload directory")
    return tuple(root / name for name in EXPECTED_EXECUTABLES)


def verify_archive(archive):
    archive = Path(archive).resolve(strict=True)
    with zipfile.ZipFile(archive) as zipped:
        names = []
        for entry in zipped.infolist():
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if entry.is_dir() or stat.S_ISLNK(mode):
                raise RuntimeError(f"portable archive entry must be a regular file: {entry.filename}")
            if path.is_absolute() or len(path.parts) != 1 or path.name != entry.filename:
                raise RuntimeError(f"portable archive entry must be a flat filename: {entry.filename}")
            names.append(entry.filename)
    _require_exact_names(names, "portable archive")
    return tuple(EXPECTED_EXECUTABLES)


def verify_no_authenticode_bytes(data, context):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise RuntimeError(f"{context}: invalid DOS header")
    pe_offset, = struct.unpack_from("<I", data, 0x3C)
    if pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise RuntimeError(f"{context}: invalid PE header")

    coff = pe_offset + 4
    optional_size, = struct.unpack_from("<H", data, coff + 16)
    optional = coff + 20
    optional_end = optional + optional_size
    if optional_end > len(data) or optional_size < 2:
        raise RuntimeError(f"{context}: truncated PE optional header")
    magic, = struct.unpack_from("<H", data, optional)
    if magic == PE32_PLUS_MAGIC:
        directory_count_offset = 108
        directories_offset = 112
    elif magic == PE32_MAGIC:
        directory_count_offset = 92
        directories_offset = 96
    else:
        raise RuntimeError(f"{context}: unsupported PE optional-header magic {magic:#x}")
    if optional_size < directory_count_offset + 4:
        raise RuntimeError(f"{context}: PE data-directory count is missing")
    directory_count, = struct.unpack_from("<I", data, optional + directory_count_offset)
    if directory_count <= CERTIFICATE_DIRECTORY_INDEX:
        return
    certificate_entry = optional + directories_offset + CERTIFICATE_DIRECTORY_INDEX * 8
    if certificate_entry > optional_end - 8:
        raise RuntimeError(f"{context}: PE certificate directory is truncated")
    certificate_offset, certificate_size = struct.unpack_from("<II", data, certificate_entry)
    if certificate_offset != 0 or certificate_size != 0:
        raise RuntimeError(f"{context}: Authenticode certificate table is present")


def _require_range(start, size, lower, upper, context):
    if start < lower or size < 0 or start > upper or size > upper - start:
        raise RuntimeError(f"{context}: data lies outside its declared bounds")
    return start, start + size


def _pe32_plus_resource(data, context):
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise RuntimeError(f"{context}: invalid DOS header")
    pe_offset, = struct.unpack_from("<I", data, 0x3C)
    if pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise RuntimeError(f"{context}: invalid PE header")

    coff = pe_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    if machine != AMD64_MACHINE:
        raise RuntimeError(f"{context}: expected x86-64 PE machine, found {machine:#x}")
    if section_count < 1 or section_count > 96:
        raise RuntimeError(f"{context}: invalid PE section count {section_count}")
    optional_size, = struct.unpack_from("<H", data, coff + 16)
    optional = coff + 20
    optional_end = optional + optional_size
    _require_range(optional, optional_size, 0, len(data), context)
    if optional_size < 112 + (RESOURCE_DIRECTORY_INDEX + 1) * 8:
        raise RuntimeError(f"{context}: truncated PE32+ optional header")
    magic, = struct.unpack_from("<H", data, optional)
    if magic != PE32_PLUS_MAGIC:
        raise RuntimeError(f"{context}: expected PE32+ optional header, found {magic:#x}")
    directory_count, = struct.unpack_from("<I", data, optional + 108)
    if directory_count <= RESOURCE_DIRECTORY_INDEX:
        raise RuntimeError(f"{context}: PE resource directory is missing")
    resource_entry = optional + 112 + RESOURCE_DIRECTORY_INDEX * 8
    if resource_entry > optional_end - 8:
        raise RuntimeError(f"{context}: PE resource directory entry is truncated")
    resource_rva, resource_size = struct.unpack_from("<II", data, resource_entry)
    if resource_rva == 0 or resource_size < 16:
        raise RuntimeError(f"{context}: PE resource directory is empty")

    section_table = optional_end
    _require_range(section_table, section_count * 40, 0, len(data), context)
    resource_sections = []
    for index in range(section_count):
        section = section_table + index * 40
        raw_name = data[section:section + 8]
        name = raw_name.split(b"\0", 1)[0]
        virtual_size, virtual_rva, raw_size, raw_offset = struct.unpack_from(
            "<IIII", data, section + 8
        )
        if name != b".rsrc":
            continue
        mapped_size = max(virtual_size, raw_size)
        if (resource_rva >= virtual_rva and
                resource_rva - virtual_rva <= mapped_size and
                resource_size <= mapped_size - (resource_rva - virtual_rva)):
            resource_sections.append((virtual_rva, raw_offset, raw_size))
    if len(resource_sections) != 1:
        raise RuntimeError(
            f"{context}: resource directory must be contained in exactly one .rsrc section"
        )
    section_rva, section_raw, section_raw_size = resource_sections[0]
    delta = resource_rva - section_rva
    if delta > section_raw_size or resource_size > section_raw_size - delta:
        raise RuntimeError(f"{context}: resource directory exceeds .rsrc raw data")
    resource_offset = section_raw + delta
    _require_range(resource_offset, resource_size, section_raw,
                   section_raw + section_raw_size, context)
    _require_range(resource_offset, resource_size, 0, len(data), context)
    return resource_rva, resource_offset, resource_size


def _version_resource_blobs(data, context):
    resource_rva, resource_offset, resource_size = _pe32_plus_resource(data, context)
    resource_end = resource_offset + resource_size

    def resource_range(relative, size, label):
        if relative < 0 or relative > resource_size or size > resource_size - relative:
            raise RuntimeError(f"{context}: {label} exceeds the declared .rsrc directory")
        return resource_offset + relative, resource_offset + relative + size

    def directory_entries(relative, label):
        start, _ = resource_range(relative, 16, label)
        named_count, id_count = struct.unpack_from("<HH", data, start + 12)
        count = named_count + id_count
        if count > MAX_RESOURCE_ENTRIES:
            raise RuntimeError(f"{context}: {label} has too many entries")
        entries, _ = resource_range(relative + 16, count * 8, label)
        return [struct.unpack_from("<II", data, entries + index * 8)
                for index in range(count)]

    roots = []
    for name, child in directory_entries(0, "root resource directory"):
        if name & 0x80000000:
            continue
        if name == VERSION_RESOURCE_TYPE:
            if not child & 0x80000000:
                raise RuntimeError(f"{context}: version resource root is not a directory")
            roots.append(child & 0x7FFFFFFF)
    if len(roots) != 1:
        raise RuntimeError(f"{context}: expected exactly one version-resource root")

    blobs = []
    visited = set()

    def walk(relative, depth):
        if depth > 4 or relative in visited:
            raise RuntimeError(f"{context}: malformed version-resource directory tree")
        visited.add(relative)
        for _name, child in directory_entries(relative, "version resource directory"):
            if child & 0x80000000:
                walk(child & 0x7FFFFFFF, depth + 1)
                continue
            entry, _ = resource_range(child, 16, "version resource data entry")
            blob_rva, blob_size, _codepage, reserved = struct.unpack_from("<IIII", data, entry)
            if reserved != 0 or blob_size == 0:
                raise RuntimeError(f"{context}: malformed version resource data entry")
            if blob_rva < resource_rva:
                raise RuntimeError(f"{context}: version resource data precedes .rsrc")
            blob_relative = blob_rva - resource_rva
            blob_start, blob_end = resource_range(
                blob_relative, blob_size, "version resource data"
            )
            _require_range(blob_start, blob_size, resource_offset, resource_end, context)
            blobs.append(bytes(data[blob_start:blob_end]))

    walk(roots[0], 1)
    if len(blobs) != 1:
        raise RuntimeError(f"{context}: expected exactly one version resource payload")
    return blobs[0]


def _align4(value):
    return (value + 3) & ~3


def _read_utf16_key(data, start, end, context):
    cursor = start
    while cursor <= end - 2:
        code_unit, = struct.unpack_from("<H", data, cursor)
        cursor += 2
        if code_unit == 0:
            try:
                return data[start:cursor - 2].decode("utf-16le"), cursor
            except UnicodeDecodeError as error:
                raise RuntimeError(f"{context}: invalid UTF-16 version-resource key") from error
    raise RuntimeError(f"{context}: unterminated version-resource key")


def _parse_version_block(data, start, limit, context):
    if start > limit - 6:
        raise RuntimeError(f"{context}: truncated version-resource block")
    length, value_length, value_type = struct.unpack_from("<HHH", data, start)
    if length < 6 or length > limit - start:
        raise RuntimeError(f"{context}: invalid version-resource block length")
    end = start + length
    key, cursor = _read_utf16_key(data, start + 6, end, context)
    value_start = _align4(cursor)
    if value_start > end:
        raise RuntimeError(f"{context}: version-resource value alignment exceeds block")
    value_size = value_length * 2 if value_type == 1 else value_length
    if value_size > end - value_start:
        raise RuntimeError(f"{context}: version-resource value exceeds block")
    value = data[value_start:value_start + value_size]
    child_start = _align4(value_start + value_size)
    children = []
    cursor = child_start
    while cursor < end:
        cursor = _align4(cursor)
        if cursor >= end:
            break
        if end - cursor < 6:
            if any(data[cursor:end]):
                raise RuntimeError(f"{context}: nonzero trailing version-resource bytes")
            break
        child = _parse_version_block(data, cursor, end, context)
        children.append(child)
        cursor = child["end"]
    return {
        "key": key,
        "type": value_type,
        "value": value,
        "children": children,
        "end": end,
    }


def _decode_version_string(block, context):
    if block["type"] != 1 or len(block["value"]) % 2:
        raise RuntimeError(f"{context}: version string has an invalid type or length")
    try:
        value = block["value"].decode("utf-16le")
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{context}: version string is not valid UTF-16") from error
    if not value.endswith("\0") or "\0" in value[:-1]:
        raise RuntimeError(f"{context}: version string is not exactly NUL terminated")
    return value[:-1]


def verify_source_identity(path, configured_version, source_sha):
    path = Path(path).resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"Windows daemon must be a regular file: {path}")
    if not configured_version or "\0" in configured_version:
        raise RuntimeError("configured version must be nonempty")
    if (len(source_sha) != 40 or any(character not in "0123456789abcdef"
                                     for character in source_sha)):
        raise RuntimeError("source SHA must be exactly 40 lowercase hexadecimal characters")

    context = path.name
    blob = _version_resource_blobs(path.read_bytes(), context)
    root = _parse_version_block(blob, 0, len(blob), context)
    if root["end"] != len(blob) or root["key"] != "VS_VERSION_INFO":
        raise RuntimeError(f"{context}: malformed VS_VERSION_INFO root")
    string_info = [child for child in root["children"] if child["key"] == "StringFileInfo"]
    if len(string_info) != 1:
        raise RuntimeError(f"{context}: expected exactly one StringFileInfo block")

    values = {}
    for table in string_info[0]["children"]:
        for string in table["children"]:
            if string["key"] in values:
                raise RuntimeError(f"{context}: duplicate VERSIONINFO key {string['key']}")
            values[string["key"]] = _decode_version_string(string, context)
    expected = {
        "ConfiguredVersion": configured_version,
        "FileVersion": configured_version,
        "ProductVersion": configured_version,
        "SourceCommit": source_sha,
        "SourceDirty": "0",
    }
    for key, expected_value in expected.items():
        if values.get(key) != expected_value:
            raise RuntimeError(
                f"{context}: VERSIONINFO {key} does not match the requested clean source"
            )
    return path


def verify_unsigned_archive(archive):
    archive = Path(archive).resolve(strict=True)
    verify_archive(archive)
    with zipfile.ZipFile(archive) as zipped:
        for name in EXPECTED_EXECUTABLES:
            verify_no_authenticode_bytes(zipped.read(name), f"{archive.name}:{name}")
    return tuple(EXPECTED_EXECUTABLES)


def verify_unsigned_file(path):
    path = Path(path).resolve(strict=True)
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"Windows artifact must be a regular file: {path}")
    verify_no_authenticode_bytes(path.read_bytes(), path.name)
    return path


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_installer_extraction(extracted_root, portable_root):
    extracted_root = Path(extracted_root).resolve(strict=True)
    portable_root = Path(portable_root).resolve(strict=True)
    portable_paths = {path.name: path for path in verify_directory(portable_root)}

    found = {}
    for entry in sorted(extracted_root.rglob("*")):
        if entry.is_symlink():
            raise RuntimeError(f"installer extraction contains a symbolic link: {entry}")
        if not entry.is_file():
            continue
        lower_name = entry.name.lower()
        if lower_name in FORBIDDEN_EXECUTABLES:
            raise RuntimeError(f"installer contains forbidden test executable: {entry}")
        if lower_name not in EXPECTED_EXECUTABLES:
            if lower_name.startswith("blackcoin") and lower_name.endswith(".exe"):
                raise RuntimeError(f"installer contains unexpected Blackcoin executable: {entry}")
            continue
        if entry.name != lower_name:
            raise RuntimeError(f"installer executable has unexpected case: {entry}")
        if lower_name in found:
            raise RuntimeError(f"installer contains duplicate executable {lower_name}")
        found[lower_name] = entry

    _require_exact_names(found, "installer payload")
    for name in EXPECTED_EXECUTABLES:
        portable = portable_paths[name]
        installed = found[name]
        if portable.stat().st_size != installed.stat().st_size or _sha256(portable) != _sha256(installed):
            raise RuntimeError(f"installer payload differs from portable executable: {name}")
    return tuple(found[name] for name in EXPECTED_EXECUTABLES)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("names", help="print the required portable executable names")
    directory = subparsers.add_parser("directory", help="verify an extracted portable payload")
    directory.add_argument("path", type=Path)
    archive = subparsers.add_parser("archive", help="verify a portable zip inventory")
    archive.add_argument("path", type=Path)
    unsigned_archive = subparsers.add_parser(
        "unsigned-archive", help="verify a portable zip has no Authenticode certificates"
    )
    unsigned_archive.add_argument("path", type=Path)
    unsigned_file = subparsers.add_parser(
        "unsigned-file", help="verify a PE artifact has no Authenticode certificate"
    )
    unsigned_file.add_argument("path", type=Path)
    identity = subparsers.add_parser(
        "identity", help="verify the Windows daemon VERSIONINFO source identity"
    )
    identity.add_argument("path", type=Path)
    identity.add_argument("--version", required=True)
    identity.add_argument("--source-sha", required=True)
    installer = subparsers.add_parser("installer", help="verify extracted installer payload bytes")
    installer.add_argument("path", type=Path)
    installer.add_argument("--portable-dir", required=True, type=Path)
    args = parser.parse_args()

    if args.command == "names":
        print("\n".join(EXPECTED_EXECUTABLES))
    elif args.command == "directory":
        verify_directory(args.path)
        print(f"Verified {len(EXPECTED_EXECUTABLES)} portable executable(s)")
    elif args.command == "archive":
        verify_archive(args.path)
        print(f"Verified {len(EXPECTED_EXECUTABLES)} portable archive member(s)")
    elif args.command == "unsigned-archive":
        verify_unsigned_archive(args.path)
        print(f"Verified {len(EXPECTED_EXECUTABLES)} publisher-unsigned executable(s)")
    elif args.command == "unsigned-file":
        verified = verify_unsigned_file(args.path)
        print(f"Verified publisher-unsigned PE artifact: {verified.name}")
    elif args.command == "identity":
        verified = verify_source_identity(args.path, args.version, args.source_sha)
        print(f"Verified clean x86-64 PE VERSIONINFO source identity: {verified.name}")
    else:
        print("\n".join(str(path) for path in verify_installer_extraction(args.path, args.portable_dir)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
