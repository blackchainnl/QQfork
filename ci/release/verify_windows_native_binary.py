#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fail closed on Windows vector architecture, imports, and artifact drift."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys


EXPECTED_REPOSITORY = "Blackcoin-Dev/Blackcoin"
EXPECTED_BINARY_NAMES = {"test_blackcoin.exe", "bench_blackcoin.exe"}
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DLL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\.dll$", re.IGNORECASE)
PE_MACHINE_AMD64 = 0x8664
PE32_PLUS_MAGIC = 0x020B
IMPORT_DIRECTORY_INDEX = 1
DELAY_IMPORT_DIRECTORY_INDEX = 13
MAX_IMPORT_DESCRIPTORS = 1024
MAX_IMPORT_DIRECTORY_BYTES = 16 * 1024 * 1024

# Exact Windows system DLL names accepted by the walletless vector binaries.
# Third-party runtimes and libraries must be statically linked.
ALLOWED_SYSTEM_DLLS = {
    "advapi32.dll", "bcrypt.dll", "cfgmgr32.dll", "combase.dll",
    "comctl32.dll", "comdlg32.dll", "crypt32.dll", "cryptbase.dll",
    "cryptsp.dll", "dbghelp.dll", "dnsapi.dll", "dwmapi.dll", "gdi32.dll",
    "gdiplus.dll", "imm32.dll", "iphlpapi.dll", "kernel32.dll", "mpr.dll",
    "msimg32.dll", "msvcrt.dll", "mswsock.dll", "ncrypt.dll",
    "netapi32.dll", "normaliz.dll", "ntdll.dll", "ole32.dll",
    "oleaut32.dll", "powrprof.dll", "propsys.dll", "psapi.dll",
    "rpcrt4.dll", "secur32.dll", "setupapi.dll", "shell32.dll",
    "shlwapi.dll", "user32.dll", "userenv.dll", "uxtheme.dll",
    "version.dll", "winhttp.dll", "wininet.dll", "winmm.dll",
    "wintrust.dll", "ws2_32.dll", "wtsapi32.dll",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def unpack_from(fmt: str, data: bytes, offset: int, label: str):
    size = struct.calcsize(fmt)
    require(0 <= offset <= len(data) - size, f"{label} is out of bounds")
    return struct.unpack_from(fmt, data, offset)


def rva_to_offset(rva: int, data: bytes, sections: list[dict],
                  size_of_headers: int) -> int:
    if rva < size_of_headers:
        require(rva < len(data), f"header RVA {rva:#x} is out of bounds")
        return rva
    for section in sections:
        start = section["virtual_address"]
        span = max(section["virtual_size"], section["raw_size"])
        if start <= rva < start + span:
            delta = rva - start
            require(delta < section["raw_size"],
                    f"RVA {rva:#x} points into zero-filled section data")
            offset = section["raw_offset"] + delta
            require(offset < len(data), f"RVA {rva:#x} maps outside the file")
            return offset
    raise RuntimeError(f"RVA {rva:#x} is not mapped by a PE section")


def read_dll_name(data: bytes, offset: int) -> str:
    end = data.find(b"\0", offset, min(len(data), offset + 261))
    require(end >= 0, "import DLL name is unterminated or longer than 260 bytes")
    try:
        name = data[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError("import DLL name is not ASCII") from error
    require(DLL_NAME_RE.fullmatch(name) is not None,
            f"import DLL name is not a basename: {name!r}")
    return name.lower()


def inspect_pe(path: Path) -> dict:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise RuntimeError(f"cannot read {path}: {error}") from error
    require(len(data) >= 0x40 and data[:2] == b"MZ",
            f"{path.name}: invalid DOS header")
    pe_offset, = unpack_from("<I", data, 0x3c, f"{path.name} PE offset")
    require(data[pe_offset:pe_offset + 4] == b"PE\0\0",
            f"{path.name}: invalid PE signature")

    coff = pe_offset + 4
    machine, section_count = unpack_from("<HH", data, coff, f"{path.name} COFF header")
    optional_size, characteristics = unpack_from(
        "<HH", data, coff + 16, f"{path.name} COFF trailer"
    )
    require(machine == PE_MACHINE_AMD64,
            f"{path.name}: PE machine is {machine:#06x}, expected AMD64")
    require(0 < section_count <= 96, f"{path.name}: invalid PE section count")
    require(characteristics & 0x0002, f"{path.name}: PE is not executable")

    optional = coff + 20
    optional_end = optional + optional_size
    require(optional_end <= len(data), f"{path.name}: optional header is truncated")
    magic, = unpack_from("<H", data, optional, f"{path.name} optional magic")
    require(magic == PE32_PLUS_MAGIC,
            f"{path.name}: optional header is not PE32+")
    require(optional_size >= 112 + 16 * 8,
            f"{path.name}: PE32+ data directories are incomplete")
    size_of_headers, = unpack_from(
        "<I", data, optional + 60, f"{path.name} SizeOfHeaders"
    )
    directory_count, = unpack_from(
        "<I", data, optional + 108, f"{path.name} directory count"
    )
    require(directory_count >= 16, f"{path.name}: PE data-directory count is incomplete")

    sections = []
    section_table = optional_end
    require(section_table + section_count * 40 <= len(data),
            f"{path.name}: PE section table is truncated")
    for index in range(section_count):
        entry = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_offset = unpack_from(
            "<IIII", data, entry + 8, f"{path.name} section {index}"
        )
        require(raw_size == 0 or raw_offset + raw_size <= len(data),
                f"{path.name}: section {index} raw data is out of bounds")
        sections.append({
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
        })

    directories = optional + 112
    import_rva, import_size = unpack_from(
        "<II", data, directories + IMPORT_DIRECTORY_INDEX * 8,
        f"{path.name} import directory",
    )
    delay_rva, delay_size = unpack_from(
        "<II", data, directories + DELAY_IMPORT_DIRECTORY_INDEX * 8,
        f"{path.name} delay-import directory",
    )
    require(delay_rva == 0 and delay_size == 0,
            f"{path.name}: delay imports are not permitted")
    require(import_rva != 0 and import_size >= 40,
            f"{path.name}: PE import directory is missing")
    # IMAGE_DATA_DIRECTORY.Size covers the complete import-table region, not
    # only its fixed-width IMAGE_IMPORT_DESCRIPTOR prefix. Real linkers include
    # lookup tables, address tables, and DLL names, so this byte count need not
    # be descriptor-aligned. The descriptor array is bounded independently and
    # must end with its specified all-zero entry.
    require(import_size <= MAX_IMPORT_DIRECTORY_BYTES,
            f"{path.name}: PE import directory exceeds the reviewed byte limit")
    descriptor_slots = import_size // 20
    require(descriptor_slots >= 2,
            f"{path.name}: PE import directory cannot contain an import and terminator")

    imports = set()
    terminated = False
    for index in range(min(descriptor_slots, MAX_IMPORT_DESCRIPTORS + 1)):
        descriptor_rva = import_rva + index * 20
        descriptor = rva_to_offset(descriptor_rva, data, sections, size_of_headers)
        fields = unpack_from("<IIIII", data, descriptor,
                             f"{path.name} import descriptor {index}")
        if not any(fields):
            terminated = True
            break
        require(index < MAX_IMPORT_DESCRIPTORS,
                f"{path.name}: PE import directory exceeds the reviewed descriptor limit")
        name_rva = fields[3]
        require(name_rva != 0, f"{path.name}: import descriptor has no DLL name")
        name_offset = rva_to_offset(name_rva, data, sections, size_of_headers)
        name = read_dll_name(data, name_offset)
        require(name in ALLOWED_SYSTEM_DLLS,
                f"{path.name}: non-system or unreviewed DLL import: {name}")
        imports.add(name)
    if not terminated and descriptor_slots > MAX_IMPORT_DESCRIPTORS:
        raise RuntimeError(
            f"{path.name}: PE import directory exceeds the reviewed descriptor limit")
    require(terminated, f"{path.name}: import descriptor table is unterminated")
    require(imports, f"{path.name}: PE import set is empty")

    return {
        "name": path.name,
        "sha256": sha256_file(path),
        "size": len(data),
        "machine": "AMD64",
        "optional_header": "PE32+",
        "imports": sorted(imports),
    }


def build_manifest(paths: list[Path], source_sha: str, repository: str) -> dict:
    require(FULL_SHA_RE.fullmatch(source_sha) is not None,
            "source SHA must be a full lowercase commit identifier")
    require(repository == EXPECTED_REPOSITORY,
            f"repository must be exactly {EXPECTED_REPOSITORY}")
    by_name = {path.name: path for path in paths}
    require(len(by_name) == len(paths), "Windows vector binary names are duplicated")
    require(set(by_name) == EXPECTED_BINARY_NAMES,
            "Windows vector binary inventory differs: "
            f"missing={sorted(EXPECTED_BINARY_NAMES - set(by_name))}, "
            f"unexpected={sorted(set(by_name) - EXPECTED_BINARY_NAMES)}")
    return {
        "schema": 1,
        "source": {"repository": repository, "commit": source_sha},
        "policy": {
            "machine": "AMD64",
            "optional_header": "PE32+",
            "imports": "windows-system-allowlist-v1",
            "delay_imports": "forbidden",
        },
        "binaries": [inspect_pe(by_name[name]) for name in sorted(by_name)],
    }


def verify_expected(manifest: dict, expected_path: Path) -> None:
    try:
        expected = json.loads(expected_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"cannot read expected Windows vector manifest: {error}") from error
    require(expected == manifest,
            "downloaded Windows vector binaries differ from the cross-build manifest")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--repository", required=True)
    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument("--output-manifest", type=Path)
    output_group.add_argument("--expected-manifest", type=Path)
    args = parser.parse_args()

    manifest = build_manifest(args.binary, args.source_sha, args.repository)
    if args.expected_manifest:
        verify_expected(manifest, args.expected_manifest)
        print("Downloaded Windows vector binaries match the reviewed manifest")
    else:
        args.output_manifest.parent.mkdir(parents=True, exist_ok=True)
        args.output_manifest.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"Wrote Windows vector manifest to {args.output_manifest}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as error:
        print(f"Windows vector verification failed: {error}", file=sys.stderr)
        sys.exit(1)
