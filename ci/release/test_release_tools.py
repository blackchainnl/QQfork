#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regression tests for fail-closed release metadata and identity tooling."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile


TOOLS = Path(__file__).resolve().parent
MIXED_VERSION_TOOLS = TOOLS.parent / "mixed-version"
SOURCE_SHA = "d161e279be86b3bc20a8c59d3e08e66cbacbeeaa"
FINGERPRINT = "A" * 40


def load_module(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_mixed_version_module(name):
    spec = importlib.util.spec_from_file_location(
        name, MIXED_VERSION_TOOLS / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseToolTests(unittest.TestCase):
    def test_manpage_generator_accepts_source_commit_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in (
                "src/blackcoind",
                "src/blackcoin-cli",
                "src/blackcoin-tx",
                "src/blackcoin-wallet",
                "src/blackcoin-util",
                "src/qt/blackcoin-qt",
            ):
                binary = root / relative
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_text(
                    "#!/bin/sh\n"
                    "printf '%s\\n' 'Blackcoin version v30.1.1' "
                    "'Source commit: 0123456789abcdef0123456789abcdef01234567' "
                    "'Copyright (C) 2026 Blackcoin Developers'\n",
                    encoding="utf-8",
                )
                binary.chmod(0o755)

            help2man = root / "help2man"
            help2man.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                "import sys\n"
                "output = Path(sys.argv[sys.argv.index('-o') + 1])\n"
                "output.write_text('.TH BLACKCOIN 1\\nSource commit: "
                "0123456789abcdef0123456789abcdef01234567\\n', "
                "encoding='utf-8')\n",
                encoding="utf-8",
            )
            help2man.chmod(0o755)
            mandir = root / "man"
            mandir.mkdir()
            environment = os.environ.copy()
            environment.update({
                "TOPDIR": str(root),
                "BUILDDIR": str(root),
                "MANDIR": str(mandir),
                "HELP2MAN": str(help2man),
            })
            script = TOOLS.parent.parent / "contrib/devtools/gen-manpages.py"
            subprocess.run(
                [sys.executable, str(script)],
                check=True,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            generated = sorted(mandir.glob("*.1"))
            self.assertEqual(len(generated), 6)
            for manpage in generated:
                self.assertNotIn("Source commit:", manpage.read_text(encoding="utf-8"))

    def write_native_binary(self, path, platform, architecture):
        if platform == "linux":
            machine = {"x86_64": 62, "arm64": 183}[architecture]
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", header, 18, machine)
        elif platform == "macos":
            machine = {"x86_64": 0x01000007, "arm64": 0x0100000c}[architecture]
            header = bytearray(64)
            header[:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<I", header, 4, machine)
        elif platform == "windows":
            machine = {"x86_64": 0x8664, "arm64": 0xaa64}[architecture]
            header = bytearray(0x88)
            header[:2] = b"MZ"
            struct.pack_into("<I", header, 0x3c, 0x80)
            header[0x80:0x84] = b"PE\0\0"
            struct.pack_into("<H", header, 0x84, machine)
        else:
            raise AssertionError(f"unsupported test platform: {platform}")
        path.write_bytes(header)
        path.chmod(0o755)

    def write_windows_test_pe(self, path, imports=("KERNEL32.dll",),
                              machine=0x8664, optional_magic=0x020B,
                              delay_imports=False, import_directory_size=None):
        data = bytearray(0x800)
        pe_offset = 0x80
        optional_offset = pe_offset + 24
        optional_size = 0xF0
        section_table = optional_offset + optional_size
        section_rva = 0x1000
        section_raw = 0x200

        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, pe_offset)
        data[pe_offset:pe_offset + 4] = b"PE\0\0"
        struct.pack_into(
            "<HHIIIHH", data, pe_offset + 4,
            machine, 1, 0, 0, 0, optional_size, 0x0022,
        )
        struct.pack_into("<H", data, optional_offset, optional_magic)
        struct.pack_into("<I", data, optional_offset + 60, section_raw)
        struct.pack_into("<I", data, optional_offset + 108, 16)
        import_size = import_directory_size or (len(imports) + 1) * 20
        struct.pack_into(
            "<II", data, optional_offset + 112 + 8,
            section_rva, import_size,
        )
        if delay_imports:
            struct.pack_into(
                "<II", data, optional_offset + 112 + 13 * 8,
                section_rva + 0x380, 32,
            )

        data[section_table:section_table + 8] = b".idata\0\0"
        struct.pack_into(
            "<IIII", data, section_table + 8,
            0x500, section_rva, 0x600, section_raw,
        )
        for index, dll in enumerate(imports):
            name_rva = section_rva + 0x100 + index * 0x40
            struct.pack_into(
                "<IIIII", data, section_raw + index * 20,
                0, 0, 0, name_rva, section_rva + 0x300 + index * 8,
            )
            encoded = dll.encode("ascii") + b"\0"
            name_offset = section_raw + 0x100 + index * 0x40
            data[name_offset:name_offset + len(encoded)] = encoded
        path.write_bytes(data)

    def make_resource_bundle(self, directory, source_sha, repository,
                             provenance_manifest):
        verifier = load_module("verify_resource_benchmark_bundle")
        manifest_hash = verifier.sha256_file(provenance_manifest)
        for runner, (platform, architecture) in verifier.EXPECTED_RUNNERS.items():
            raw = directory / f"quantum-resource-{runner}-nanobench.json"
            raw.write_text('{"results": []}\n', encoding="utf-8")
            reported_platform = {
                "linux": "Linux", "windows": "Windows", "macos": "Darwin",
            }[platform]
            reported_architecture = {
                "x86_64": "AMD64" if platform == "windows" else "x86_64",
                "arm64": "arm64",
            }[architecture]
            evidence = {
                "schema": 1,
                "source": {"repository": repository, "commit": source_sha},
                "runner": {
                    "platform": platform,
                    "architecture": architecture,
                    "reported_platform": reported_platform,
                    "reported_architecture": reported_architecture,
                    "native_execution_verified": True,
                    "binary_format": {
                        "linux": "elf", "windows": "pe", "macos": "mach-o",
                    }[platform],
                    "binary_architecture": architecture,
                    "process_translation": (
                        "not-translated" if platform == "macos" else "not-applicable"
                    ),
                },
                "inputs": {
                    "benchmark_binary_sha256": "ab" * 32,
                    "nanobench_json_sha256": verifier.sha256_file(raw),
                    "quantum_crypto_provenance_manifest_sha256": manifest_hash,
                },
                "coverage": {
                    "crypto": True,
                    "large-block": True,
                    "synthetic-state": True,
                },
                "release_resource_evidence_complete": True,
            }
            (directory / f"quantum-resource-{runner}-evidence.json").write_text(
                json.dumps(evidence), encoding="utf-8"
            )

    def test_resource_bundle_requires_exact_native_platform_set(self):
        verifier = load_module("verify_resource_benchmark_bundle")
        repository = "Blackcoin-Dev/Blackcoin"
        source_sha = "12" * 20
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = directory.parent / f"{directory.name}-manifest.json"
            manifest.write_text('{"schema": 1}\n', encoding="utf-8")
            try:
                self.make_resource_bundle(directory, source_sha, repository, manifest)
                verifier.verify_bundle(directory, source_sha, repository, manifest)

                missing = directory / "quantum-resource-linux-arm64-evidence.json"
                missing.unlink()
                with self.assertRaisesRegex(RuntimeError, "inventory differs"):
                    verifier.verify_bundle(directory, source_sha, repository, manifest)
            finally:
                manifest.unlink(missing_ok=True)

    def test_resource_bundle_rejects_mislabeled_or_substituted_evidence(self):
        verifier = load_module("verify_resource_benchmark_bundle")
        repository = "Blackcoin-Dev/Blackcoin"
        source_sha = "34" * 20
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = directory.parent / f"{directory.name}-manifest.json"
            manifest.write_text('{"schema": 1}\n', encoding="utf-8")
            try:
                self.make_resource_bundle(directory, source_sha, repository, manifest)
                evidence_path = directory / "quantum-resource-linux-arm64-evidence.json"
                evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
                evidence["runner"]["architecture"] = "x86_64"
                evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "runner mismatch"):
                    verifier.verify_bundle(directory, source_sha, repository, manifest)

                self.make_resource_bundle(directory, source_sha, repository, manifest)
                raw_path = directory / "quantum-resource-windows-x86_64-nanobench.json"
                raw_path.write_text('{"substituted": true}\n', encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "nanobench input hash mismatch"):
                    verifier.verify_bundle(directory, source_sha, repository, manifest)
            finally:
                manifest.unlink(missing_ok=True)

    def test_windows_native_binary_gate_is_allowlisted_and_artifact_bound(self):
        verifier = load_module("verify_windows_native_binary")
        repository = "Blackcoin-Dev/Blackcoin"
        source_sha = "56" * 20
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            test_binary = root / "test_blackcoin.exe"
            bench_binary = root / "bench_blackcoin.exe"
            self.write_windows_test_pe(test_binary, ("KERNEL32.dll", "WS2_32.dll"))
            self.write_windows_test_pe(bench_binary, ("KERNEL32.dll",))
            paths = [test_binary, bench_binary]

            manifest = verifier.build_manifest(paths, source_sha, repository)
            self.assertEqual(
                {record["name"] for record in manifest["binaries"]},
                {"test_blackcoin.exe", "bench_blackcoin.exe"},
            )
            expected = root / "windows-native-inputs.json"
            expected.write_text(json.dumps(manifest), encoding="utf-8")
            verifier.verify_expected(
                verifier.build_manifest(paths, source_sha, repository), expected
            )

            bench_binary.write_bytes(bench_binary.read_bytes() + b"changed")
            with self.assertRaisesRegex(RuntimeError, "differ from the cross-build"):
                verifier.verify_expected(
                    verifier.build_manifest(paths, source_sha, repository), expected
                )

            self.write_windows_test_pe(bench_binary, ("zlib1.dll",))
            with self.assertRaisesRegex(RuntimeError, "non-system or unreviewed"):
                verifier.build_manifest(paths, source_sha, repository)

            self.write_windows_test_pe(bench_binary, machine=0xAA64)
            with self.assertRaisesRegex(RuntimeError, "expected AMD64"):
                verifier.build_manifest(paths, source_sha, repository)

            self.write_windows_test_pe(bench_binary, delay_imports=True)
            with self.assertRaisesRegex(RuntimeError, "delay imports"):
                verifier.build_manifest(paths, source_sha, repository)

            self.write_windows_test_pe(
                bench_binary,
                import_directory_size=44,
            )
            verifier.build_manifest(paths, source_sha, repository)

            self.write_windows_test_pe(
                bench_binary,
                import_directory_size=verifier.MAX_IMPORT_DIRECTORY_BYTES + 1,
            )
            with self.assertRaisesRegex(RuntimeError, "byte limit"):
                verifier.build_manifest(paths, source_sha, repository)

            self.write_windows_test_pe(
                bench_binary,
                imports=("KERNEL32.dll", "WS2_32.dll"),
            )
            with mock.patch.object(verifier, "MAX_IMPORT_DESCRIPTORS", 1):
                with self.assertRaisesRegex(RuntimeError, "descriptor limit"):
                    verifier.build_manifest(paths, source_sha, repository)

            self.write_windows_test_pe(
                bench_binary,
                import_directory_size=40,
            )
            data = bytearray(bench_binary.read_bytes())
            struct.pack_into(
                "<IIIII", data, 0x200 + 20,
                0, 0, 0, 0x1100, 0x1308,
            )
            bench_binary.write_bytes(data)
            with self.assertRaisesRegex(RuntimeError, "unterminated"):
                verifier.build_manifest(paths, source_sha, repository)

            self.write_windows_test_pe(bench_binary)
            bench_binary.write_bytes(bench_binary.read_bytes()[:0x190])
            with self.assertRaisesRegex(RuntimeError, "section table is truncated"):
                verifier.build_manifest(paths, source_sha, repository)

    def test_resource_benchmark_evidence_is_source_bound_and_fail_closed(self):
        generator = load_module("generate_resource_benchmark_evidence")
        native_platform, native_architecture, _, _ = generator.native_runner_identity()
        repository = TOOLS.parent.parent
        source_sha = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        def result(name, unit, median, batch=1):
            return {
                "name": name,
                "unit": unit,
                "batch": batch,
                "epochs": 11,
                "minEpochTime": 0.25 / 11,
                "median(elapsed)": median,
                "medianAbsolutePercentError(elapsed)": 0.01,
                "totalTime": median * 11,
                "measurements": [
                    {"iterations": 1, "elapsed": median} for _ in range(11)
                ],
            }

        document = {
            "results": [
                result("QuantumArgon2id1MiB", "op", 0.00025),
                result("QuantumArgon2id64ClaimBlock", "proof", 0.016, 64),
                result("QuantumMLDSA44Verify", "op", 0.00005),
                result(
                    "QuantumMLDSA44MaxWeightBlock", "signature", 0.41075, 8215
                ),
                result("QuantumLargeBlockValidation32MiB", "block", 0.75),
                result(
                    "QuantumSyntheticStateApplyUndoMaxMarkers",
                    "state-transition",
                    0.2,
                ),
            ]
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "nanobench.json"
            binary = root / "bench_blackcoin"
            raw.write_text(json.dumps(document), encoding="utf-8")
            self.write_native_binary(binary, native_platform, native_architecture)
            evidence = generator.generate_evidence(
                nanobench_json=raw,
                binary=binary,
                source_sha=source_sha,
                repo_root=repository,
                repository="Blackcoin-Dev/Blackcoin",
                platform=native_platform,
                architecture=native_architecture,
                toolchain="GCC 11.4.0",
                compiler_flags="-O2 -g",
                build_profile="native-test",
                minimum_runtime_ms=250,
                provenance_manifest=(
                    TOOLS.parent.parent /
                    "contrib" / "devtools" / "quantum-crypto-provenance.json"
                ),
                required_domains={"crypto", "large-block", "synthetic-state"},
            )
            self.assertTrue(evidence["coverage"]["crypto"])
            self.assertTrue(evidence["coverage"]["large-block"])
            self.assertTrue(evidence["coverage"]["synthetic-state"])
            self.assertTrue(evidence["release_resource_evidence_complete"])
            self.assertTrue(evidence["runner"]["native_execution_verified"])
            self.assertEqual(
                evidence["runner"]["binary_architecture"], native_architecture
            )

            binary.write_bytes(b"not-an-executable")
            with self.assertRaisesRegex(RuntimeError, "binary format"):
                generator.generate_evidence(
                    nanobench_json=raw,
                    binary=binary,
                    source_sha=source_sha,
                    repo_root=repository,
                    repository="Blackcoin-Dev/Blackcoin",
                    platform=native_platform,
                    architecture=native_architecture,
                    toolchain="GCC 11.4.0",
                    compiler_flags="-O2 -g",
                    build_profile="native-test",
                    minimum_runtime_ms=250,
                    provenance_manifest=(
                        TOOLS.parent.parent / "contrib" / "devtools" /
                        "quantum-crypto-provenance.json"
                    ),
                    required_domains={"crypto", "large-block", "synthetic-state"},
                )
            self.write_native_binary(binary, native_platform, native_architecture)
            argon_bound = evidence["derived_upper_bounds"]["shadow_pow_argon2_block"]
            mldsa_bound = evidence["derived_upper_bounds"]["quantum_mldsa_block"]
            self.assertEqual(
                argon_bound["maximum_evaluations"], 64
            )
            self.assertEqual(
                mldsa_bound["maximum_verifications"], 8215
            )
            large_block_bound = evidence["derived_upper_bounds"][
                "large_block_validation"
            ]
            self.assertEqual(large_block_bound["maximum_weight"], 32_000_000)
            self.assertEqual(
                large_block_bound["maximum_serialized_size"], 32_000_000
            )
            self.assertEqual(
                large_block_bound["measured_fixture_quantum_inputs"], 8198
            )
            self.assertEqual(
                large_block_bound["measured_fixture_weight"], 31_997_596
            )
            self.assertEqual(
                large_block_bound["measured_fixture_serialized_size"],
                30_988_642,
            )
            self.assertIn(evidence["runner"]["endianness"], ("little", "big"))
            self.assertEqual(evidence["build"]["compiler_flags"], "-O2 -g")
            self.assertEqual(evidence["build"]["profile"], "native-test")
            self.assertEqual(evidence["build"]["minimum_benchmark_runtime_ms"], 250)
            self.assertRegex(
                evidence["inputs"]["quantum_crypto_provenance_manifest_sha256"],
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                evidence["consensus_limits"]["minimum_quantum_input_weight"], 3903
            )
            synthetic_bound = evidence["derived_upper_bounds"][
                "synthetic_state_apply_undo"
            ]
            self.assertEqual(
                synthetic_bound["authenticated_whitelist_snapshot_height"],
                5_945_000,
            )
            self.assertEqual(
                synthetic_bound["authenticated_whitelist_entries"], 687
            )
            self.assertEqual(synthetic_bound["maximum_pow_claims"], 64)
            self.assertEqual(synthetic_bound["maximum_synthetic_claims"], 751)
            self.assertEqual(synthetic_bound["maximum_claim_family_coins"], 2253)
            self.assertEqual(synthetic_bound["maximum_muhash_insertions"], 1502)
            self.assertEqual(synthetic_bound["measured_median_seconds"], 0.2)
            self.assertEqual(
                synthetic_bound["measured_maximum_epoch_seconds"], 0.2
            )
            self.assertEqual(synthetic_bound["maximum_allowed_seconds"], 2.0)
            epoch = evidence["derived_upper_bounds"]["full_gold_rush_epoch"]
            self.assertEqual(epoch["schedule"]["blocks"], 243_000)
            self.assertEqual(
                epoch["schedule"]["legacy_allocation_blocks"], 43_200
            )
            self.assertEqual(
                epoch["schedule"]["canonical_reimbursement_blocks"], 199_800
            )
            self.assertEqual(
                epoch["claim_operations"]["canonical_687_entry_fixture"]
                ["maximum_claims"],
                179_771_400,
            )
            self.assertEqual(
                epoch["claim_operations"]["canonical_687_entry_fixture"]
                ["maximum_claim_family_records"],
                539_314_200,
            )
            self.assertEqual(
                epoch["claim_operations"]["canonical_687_entry_fixture"]
                ["maximum_muhash_insertions"],
                359_542_800,
            )
            protocol_claims = epoch["claim_operations"] \
                ["protocol_source_envelope"]
            self.assertEqual(
                protocol_claims["maximum_claims_per_block"], 133_335
            )
            self.assertEqual(
                protocol_claims["maximum_claims"], 32_400_405_000
            )
            footprint = epoch["serialized_chainstate_batch_payload"]
            self.assertEqual(footprint["claim_family_bytes"], 509)
            logical_buckets = footprint["logical_proof_bucket"]
            self.assertEqual(logical_buckets["retained_blocks"], 199_800)
            self.assertEqual(
                logical_buckets["empty"]["batch_payload_bytes"], 98
            )
            self.assertEqual(
                logical_buckets["one_id"]["batch_payload_bytes"], 130
            )
            self.assertEqual(
                logical_buckets["maximum_64_ids"]["batch_payload_bytes"],
                2_150,
            )
            self.assertEqual(
                logical_buckets["maximum_full_epoch_batch_payload_bytes"],
                429_570_000,
            )
            self.assertEqual(
                footprint["canonical_p2pkh_fixture"]
                ["full_epoch_retained_append_only_payload_bytes"],
                103_622_484_600,
            )
            self.assertEqual(
                footprint["protocol_source_envelope"]
                ["full_epoch_retained_append_only_payload_bytes"],
                24_754_927_050_000,
            )
            self.assertFalse(footprint["physical_leveldb_disk_bound_established"])
            self.assertFalse(
                epoch["replay"]["full_replay_wall_clock_bound_established"]
            )
            self.assertEqual(
                epoch["replay"]
                ["protocol_source_envelope_maximum_claim_applications"],
                32_400_405_000,
            )
            self.assertEqual(epoch["issue_13_disposition"], "partial")
            self.assertEqual(
                set(evidence["inputs"]["epoch_source_contract_sha256"]),
                {
                    "src/shadow.h",
                    "src/shadow.cpp",
                    "src/serialize.h",
                    "src/consensus/consensus.h",
                    "src/consensus/quantum_witness.h",
                    "src/consensus/amount.h",
                    "src/script/script.h",
                    "src/coins.h",
                    "src/txdb.cpp",
                    "src/txdb.h",
                    "src/compressor.h",
                    "src/compressor.cpp",
                    "src/kernel/chainparams.cpp",
                    "src/bench/quantum_crypto.cpp",
                    "src/dbwrapper.cpp",
                    "src/node/caches.cpp",
                    "src/test/shadow_tests.cpp",
                },
            )

            synthetic_result = document["results"].pop()
            raw.write_text(json.dumps(document), encoding="utf-8")
            partial_evidence = generator.generate_evidence(
                nanobench_json=raw,
                binary=binary,
                source_sha=source_sha,
                repo_root=repository,
                repository="Blackcoin-Dev/Blackcoin",
                platform=native_platform,
                architecture=native_architecture,
                toolchain="GCC 11.4.0",
                compiler_flags="-O2 -g",
                build_profile="native-test",
                minimum_runtime_ms=250,
                provenance_manifest=(
                    TOOLS.parent.parent /
                    "contrib" / "devtools" / "quantum-crypto-provenance.json"
                ),
                required_domains={"crypto", "large-block"},
            )
            self.assertFalse(partial_evidence["coverage"]["synthetic-state"])
            self.assertFalse(
                partial_evidence["release_resource_evidence_complete"]
            )
            with self.assertRaisesRegex(RuntimeError, "synthetic-state"):
                generator.generate_evidence(
                    nanobench_json=raw,
                    binary=binary,
                    source_sha=source_sha,
                    repo_root=repository,
                    repository="Blackcoin-Dev/Blackcoin",
                    platform=native_platform,
                    architecture=native_architecture,
                    toolchain="GCC 11.4.0",
                    compiler_flags="-O2 -g",
                    build_profile="native-test",
                    minimum_runtime_ms=250,
                    provenance_manifest=(
                        TOOLS.parent.parent /
                        "contrib" / "devtools" / "quantum-crypto-provenance.json"
                    ),
                    required_domains={"crypto", "large-block", "synthetic-state"},
                )
            document["results"].append(synthetic_result)

            rejected_seconds = 2.000001
            synthetic_result["median(elapsed)"] = rejected_seconds
            synthetic_result["totalTime"] = rejected_seconds * 11
            for measurement in synthetic_result["measurements"]:
                measurement["elapsed"] = rejected_seconds
            raw.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exceeds the enforced"):
                generator.generate_evidence(
                    nanobench_json=raw,
                    binary=binary,
                    source_sha=source_sha,
                    repo_root=repository,
                    repository="Blackcoin-Dev/Blackcoin",
                    platform=native_platform,
                    architecture=native_architecture,
                    toolchain="GCC 11.4.0",
                    compiler_flags="-O2 -g",
                    build_profile="native-test",
                    minimum_runtime_ms=250,
                    provenance_manifest=(
                        TOOLS.parent.parent /
                        "contrib" / "devtools" /
                        "quantum-crypto-provenance.json"
                    ),
                    required_domains={
                        "crypto", "large-block", "synthetic-state"
                    },
                )
            synthetic_result["median(elapsed)"] = 0.2
            synthetic_result["totalTime"] = 0.2 * 11
            for measurement in synthetic_result["measurements"]:
                measurement["elapsed"] = 0.2

            # A fast median cannot hide one transition beyond the hard ceiling.
            rejected_seconds = 2.000001
            synthetic_result["measurements"][0]["elapsed"] = rejected_seconds
            synthetic_result["totalTime"] = rejected_seconds + 0.2 * 10
            raw.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "maximum epoch"):
                generator.generate_evidence(
                    nanobench_json=raw,
                    binary=binary,
                    source_sha=source_sha,
                    repo_root=repository,
                    repository="Blackcoin-Dev/Blackcoin",
                    platform=native_platform,
                    architecture=native_architecture,
                    toolchain="GCC 11.4.0",
                    compiler_flags="-O2 -g",
                    build_profile="native-test",
                    minimum_runtime_ms=250,
                    provenance_manifest=(
                        TOOLS.parent.parent /
                        "contrib" / "devtools" /
                        "quantum-crypto-provenance.json"
                    ),
                    required_domains={
                        "crypto", "large-block", "synthetic-state"
                    },
                )
            synthetic_result["measurements"][0]["elapsed"] = 0.2
            synthetic_result["totalTime"] = 0.2 * 11

            document["results"].append(document["results"][0])
            raw.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "duplicate nanobench result"):
                generator.parse_measurements(
                    raw, {"crypto", "large-block", "synthetic-state"}, 250
                )

            document["results"].pop()
            document["results"][1]["batch"] = 63
            raw.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "expected 64"):
                generator.parse_measurements(
                    raw, {"crypto", "large-block", "synthetic-state"}, 250
                )

            document["results"][1]["batch"] = 64
            document["results"][0]["median(elapsed)"] *= 2
            raw.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "median does not match"):
                generator.parse_measurements(
                    raw, {"crypto", "large-block", "synthetic-state"}, 250
                )

            document["results"][0]["median(elapsed)"] /= 2
            document["results"][0]["totalTime"] *= 2
            raw.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "total time does not match"):
                generator.parse_measurements(
                    raw, {"crypto", "large-block", "synthetic-state"}, 250
                )

            document["results"][0]["totalTime"] /= 2
            document["results"].append(result("UnexpectedQuantumBenchmark", "op", 1.0))
            raw.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "benchmark set mismatch"):
                generator.parse_measurements(
                    raw, {"crypto", "large-block", "synthetic-state"}, 250
                )

            with self.assertRaisesRegex(RuntimeError, "repository must be exactly"):
                generator.verify_source_checkout(repository, "fork/Blackcoin", source_sha)
            with self.assertRaisesRegex(RuntimeError, "source commit mismatch"):
                generator.verify_source_checkout(
                    repository, "Blackcoin-Dev/Blackcoin", "f" * 40
                )

    def test_resource_benchmark_source_checkout_rejects_dirty_inputs(self):
        generator = load_module("generate_resource_benchmark_evidence")
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            subprocess.run(["git", "init", "-q", str(repository)], check=True)
            tracked = repository / "tracked.cpp"
            tracked.write_text("committed\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repository), "add", "tracked.cpp"], check=True)
            subprocess.run(
                [
                    "git", "-C", str(repository),
                    "-c", "user.name=Blackcoin-Dev",
                    "-c", "user.email=298119138+Blackcoin-Dev@users.noreply.github.com",
                    "commit", "-q", "-m", "fixture",
                ],
                check=True,
            )
            source_sha = subprocess.run(
                ["git", "-C", str(repository), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            generator.verify_source_checkout(
                repository, "Blackcoin-Dev/Blackcoin", source_sha
            )

            tracked.write_text("modified\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "tracked changes"):
                generator.verify_source_checkout(
                    repository, "Blackcoin-Dev/Blackcoin", source_sha
                )

            tracked.write_text("committed\n", encoding="utf-8")
            raw = repository / "nanobench.json"
            raw.write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unexpected untracked"):
                generator.verify_source_checkout(
                    repository, "Blackcoin-Dev/Blackcoin", source_sha
                )
            generator.verify_source_checkout(
                repository, "Blackcoin-Dev/Blackcoin", source_sha,
                allowed_untracked=(raw,),
            )

    def test_full_epoch_bound_arithmetic_is_fail_closed(self):
        generator = load_module("generate_resource_benchmark_evidence")
        bounds = generator.calculate_full_epoch_bounds()
        self.assertEqual(
            bounds["serialized_chainstate_batch_payload"]
            ["canonical_p2pkh_fixture"]["maximum_active_undo"],
            {"blob_bytes": 46_890, "shards": 6,
             "batch_payload_bytes": 47_696},
        )
        self.assertEqual(
            bounds["serialized_chainstate_batch_payload"]
            ["protocol_source_envelope"]["maximum_active_undo"],
            {"blob_bytes": 33_553_408, "shards": 4_195,
             "batch_payload_bytes": 34_002_437},
        )
        self.assertEqual(
            bounds["replay"]
            ["sum_of_per_block_apply_undo_thresholds_seconds"],
            486_000.0,
        )
        source_hashes = generator.verify_epoch_source_contract(
            TOOLS.parent.parent
        )
        self.assertTrue(all(re.fullmatch(r"[0-9a-f]{64}", digest)
                            for digest in source_hashes.values()))

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for relative in source_hashes:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((TOOLS.parent.parent / relative).read_bytes())
            shadow = root / "src" / "shadow.h"
            shadow.write_text(
                shadow.read_text(encoding="utf-8").replace(
                    "MAINNET_SHADOW_HALVING_INTERVAL_BLOCKS = 43200",
                    "MAINNET_SHADOW_HALVING_INTERVAL_BLOCKS = 43201",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                    RuntimeError, "epoch-bound source contract changed"):
                generator.verify_epoch_source_contract(root)
    def test_resource_benchmark_rejects_emulated_platform_identity(self):
        generator = load_module("generate_resource_benchmark_evidence")
        native_platform, native_architecture, _, _ = generator.native_runner_identity()
        self.assertEqual(
            generator.verify_native_runner(native_platform, native_architecture),
            (generator.host_platform.system(), generator.host_platform.machine()),
        )
        wrong_architecture = "arm64" if native_architecture == "x86_64" else "x86_64"
        with self.assertRaisesRegex(RuntimeError, "is not native"):
            generator.verify_native_runner(native_platform, wrong_architecture)
        wrong_platform = "windows" if native_platform != "windows" else "linux"
        with self.assertRaisesRegex(RuntimeError, "is not native"):
            generator.verify_native_runner(wrong_platform, native_architecture)

        for value in ("", "0"):
            with self.subTest(macos_translation=value or "intel-oid-absent"):
                completed = subprocess.CompletedProcess(
                    ["sysctl"], 0, stdout=value + "\n", stderr=""
                )
                with mock.patch.object(generator.subprocess, "run",
                                       return_value=completed):
                    self.assertEqual(
                        generator.verify_process_not_translated("macos"),
                        "not-translated",
                    )
        completed = subprocess.CompletedProcess(
            ["sysctl"], 0, stdout="1\n", stderr=""
        )
        with mock.patch.object(generator.subprocess, "run", return_value=completed):
            with self.assertRaisesRegex(RuntimeError, "Rosetta"):
                generator.verify_process_not_translated("macos")

    def test_resource_benchmark_normalizes_supported_native_runners(self):
        generator = load_module("generate_resource_benchmark_evidence")
        cases = (
            ("Linux", "aarch64", "linux", "arm64"),
            ("Linux", "x86_64", "linux", "x86_64"),
            ("Darwin", "arm64", "macos", "arm64"),
            ("Darwin", "x86_64", "macos", "x86_64"),
            ("Windows", "AMD64", "windows", "x86_64"),
        )
        for system, machine, expected_platform, expected_architecture in cases:
            with self.subTest(system=system, machine=machine):
                with mock.patch.object(generator.host_platform, "system",
                                       return_value=system):
                    with mock.patch.object(generator.host_platform, "machine",
                                           return_value=machine):
                        self.assertEqual(
                            generator.native_runner_identity(),
                            (expected_platform, expected_architecture,
                             system, machine),
                        )

        with mock.patch.object(generator.host_platform, "system",
                               return_value="UnknownOS"):
            with self.assertRaisesRegex(RuntimeError,
                                        "unsupported native benchmark platform"):
                generator.native_runner_identity()
    def test_resource_benchmark_workflow_measures_and_does_not_overclaim(self):
        root = TOOLS.parent.parent
        gate = (root / ".github" / "workflows" / "pr-gate.yml").read_text(
            encoding="utf-8"
        )
        release = (root / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        benchmark_source = (root / "src" / "bench" / "quantum_crypto.cpp").read_text(
            encoding="utf-8"
        )
        for benchmark in (
            "QuantumArgon2id1MiB",
            "QuantumArgon2id64ClaimBlock",
            "QuantumMLDSA44Verify",
            "QuantumMLDSA44MaxWeightBlock",
            "QuantumLargeBlockValidation32MiB",
            "QuantumSyntheticStateApplyUndoMaxMarkers",
        ):
            with self.subTest(benchmark=benchmark):
                self.assertIn(f"BENCHMARK({benchmark}", benchmark_source)
        self.assertIn("GetSizeOfCompactSize(ML_DSA::SIGNATURE_BYTES)", benchmark_source)
        self.assertIn("GetSizeOfCompactSize(ML_DSA::PUBLICKEY_BYTES)", benchmark_source)
        self.assertIn("static_assert(MIN_QUANTUM_INPUT_WEIGHT == 3903)", benchmark_source)
        self.assertIn("SHADOW_ARGON2_TIME_COST", benchmark_source)
        self.assertIn("SHADOW_ARGON2_MEMORY_KIB", benchmark_source)
        self.assertIn("SHADOW_ARGON2_LANES", benchmark_source)
        self.assertIn("bench.batch(MAX_SHADOW_POW_EVALS_PER_BLOCK)", benchmark_source)
        self.assertIn("bench.batch(MAX_BLOCK_MLDSA_VERIFICATIONS)", benchmark_source)
        self.assertIn("V4_MAX_BLOCK_WEIGHT - block_weight", benchmark_source)
        self.assertIn("CheckInputScripts", benchmark_source)
        self.assertIn("Argon2 single-operation benchmark failed", benchmark_source)
        self.assertIn("ML-DSA single-operation benchmark failed", benchmark_source)
        self.assertIn("resource-benchmarks-linux:", gate)
        self.assertIn("native-linux-arm64-crypto:", gate)
        self.assertIn("native-linux-arm64-ubsan:", gate)
        self.assertIn("runs-on: ubuntu-24.04-arm", gate)
        self.assertIn("native-windows-crypto:", gate)
        self.assertIn("runs-on: windows-2025", gate)
        self.assertEqual(gate.count("verify_windows_native_binary.py"), 2)
        self.assertIn("windows-native-inputs.json", gate)
        self.assertNotIn("libstdc\\+\\+-6", gate)
        self.assertIn("--platform windows", gate)
        self.assertIn("--architecture arm64", gate)
        self.assertIn("--architecture x86_64", gate)
        self.assertIn("crc32c_accepts_unaligned_arm64_input", gate)
        self.assertIn("--require-domain large-block", gate)
        self.assertIn("--require-domain synthetic-state", gate)
        self.assertIn("MAXIMUM_MAINNET_SYNTHETIC_CLAIMS == 751", benchmark_source)
        self.assertIn("ApplyShadowBlockResult", benchmark_source)
        self.assertIn("UndoShadowBlock", benchmark_source)
        self.assertIn("SyntheticStateIdentity", benchmark_source)
        self.assertIn("quantum-resource-benchmarks-macos-", gate)
        self.assertIn('--compiler-flags="$cxxflags"', gate)
        self.assertIn('--repository "$GITHUB_REPOSITORY"', gate)
        self.assertIn("--repo-root .", gate)
        self.assertIn("--build-profile native-debug-lockorder", gate)
        self.assertIn("--build-profile native-walletless-default", gate)
        self.assertIn("--minimum-runtime-ms 250", gate)
        self.assertIn("--provenance-manifest", gate)
        self.assertIn("pattern: quantum-resource-benchmarks-*", release)
        self.assertIn("verify_resource_benchmark_bundle.py", release)
        self.assertIn("test \"${#resource_evidence[@]}\" -eq 5", release)
        self.assertIn("test \"${#resource_raw[@]}\" -eq 5", release)

    def test_quantum_crypto_provenance_is_mandatory_and_retained(self):
        root = TOOLS.parent.parent
        workflow = (root / ".github" / "workflows" / "pr-gate.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("crypto-source-provenance:", workflow)
        self.assertIn("--fetch-upstream", workflow)
        self.assertIn("--require-upstream", workflow)
        self.assertIn('--repository "$GITHUB_REPOSITORY"', workflow)
        self.assertIn('--source-commit "$TARGET_SHA"', workflow)
        self.assertIn("quantum-crypto-provenance-${{ env.TARGET_SHA }}", workflow)
        release_workflow = (root / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "name: quantum-crypto-provenance-${{ needs.resolve-target.outputs.target_sha }}",
            release_workflow,
        )
        self.assertIn("Blackcoin-$VERSION-quantum-crypto-provenance.json", release_workflow)
        self.assertIn("Blackcoin-$VERSION-quantum-crypto-manifest.json", release_workflow)

        manifest = json.loads(
            (root / "contrib" / "devtools" / "quantum-crypto-provenance.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn(manifest["wycheproof"]["commit"], manifest["wycheproof"]["source_url"])
        self.assertTrue(manifest["wycheproof"]["source_url"].startswith("https://"))
        self.assertEqual(
            manifest["liboqs"]["upstream_files"]["src/common/rand/rand.c"],
            "744cf859858fbf0591138f6921e10f910bcdcc4a4a6a7defc871f8d085647b19",
        )
        self.assertEqual(
            manifest["liboqs"]["upstream_files"]["src/common/rand/rand.h"],
            "e38e720b1680d51f6f87b9a2985b97e1530b476cc5f9c68dc62e4d7682915457",
        )

    def test_quantum_crypto_downloader_rejects_untrusted_or_wrong_bytes(self):
        verifier = load_path(
            "verify_quantum_crypto_sources",
            TOOLS.parent.parent / "contrib" / "devtools" / "verify-quantum-crypto-sources.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "source.bin"
            with self.assertRaisesRegex(SystemExit, "untrusted upstream URL"):
                verifier.download_pinned(
                    "http://raw.githubusercontent.com/example/source",
                    hashlib.sha256(b"expected").hexdigest(),
                    destination,
                )

            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.__exit__.return_value = False
            response.geturl.return_value = "https://raw.githubusercontent.com/example/source"
            response.headers = {"Content-Length": "5"}
            response.read.side_effect = [b"wrong", b""]
            with mock.patch.object(verifier.urllib.request, "urlopen", return_value=response):
                with self.assertRaisesRegex(SystemExit, "expected"):
                    verifier.download_pinned(
                        "https://raw.githubusercontent.com/example/source",
                        hashlib.sha256(b"expected").hexdigest(),
                        destination,
                    )
            self.assertFalse(destination.exists())

    def test_quantum_crypto_rng_policy_rejects_production_hook_mutation(self):
        verifier = load_path(
            "verify_quantum_crypto_rng_policy",
            TOOLS.parent.parent / "contrib" / "devtools" / "verify-quantum-crypto-sources.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src" / "test").mkdir(parents=True)
            (root / "src" / "good.cpp").write_text(
                "void UsePinnedRandomness() {}\n", encoding="utf-8"
            )
            (root / "src" / "test" / "fixture.cpp").write_text(
                "void OQS_randombytes_switch_algorithm();\n", encoding="utf-8"
            )
            policy = verifier.verify_no_rng_hook_mutation(root)
            self.assertEqual(policy["files_scanned"], 1)
            self.assertEqual(policy["violations"], [])

            (root / "src" / "bad.cpp").write_text(
                "void f() { OQS_randombytes_custom_algorithm(nullptr); }\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(SystemExit, "may not replace or switch"):
                verifier.verify_no_rng_hook_mutation(root)

    def test_quantum_crypto_kat_must_match_fresh_regeneration(self):
        verifier = load_path(
            "verify_quantum_crypto_kat",
            TOOLS.parent.parent / "contrib" / "devtools" / "verify-quantum-crypto-sources.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "contrib" / "devtools"
            crypto = root / "src" / "crypto"
            tools.mkdir(parents=True)
            crypto.mkdir(parents=True)
            source = root / "pinned.json"
            source.write_bytes(b"freshly-generated-header\n")
            (tools / "gen-mldsa44-kat.py").write_text(
                "from pathlib import Path\n"
                "import sys\n"
                "Path(sys.argv[2]).write_bytes(Path(sys.argv[1]).read_bytes())\n",
                encoding="utf-8",
            )
            checked_in = crypto / "mldsa_kat.h"
            checked_in.write_bytes(source.read_bytes())
            self.assertEqual(
                verifier.verify_generated_kat(root, source),
                hashlib.sha256(source.read_bytes()).hexdigest(),
            )

            checked_in.write_bytes(b"stale-or-tampered-header\n")
            with self.assertRaisesRegex(SystemExit, "differs from the freshly regenerated"):
                verifier.verify_generated_kat(root, source)

    def test_quantum_crypto_evidence_rejects_repository_or_commit_mismatch(self):
        verifier = load_path(
            "verify_quantum_crypto_source_binding",
            TOOLS.parent.parent / "contrib" / "devtools" / "verify-quantum-crypto-sources.py",
        )
        clean = (
            subprocess.CompletedProcess([], 0, stdout=SOURCE_SHA + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        )
        with mock.patch.object(verifier.subprocess, "run", side_effect=clean):
            self.assertEqual(
                verifier.verify_source_checkout(
                    Path("/checkout"), "Blackcoin-Dev/Blackcoin", SOURCE_SHA
                ),
                {"repository": "Blackcoin-Dev/Blackcoin", "commit": SOURCE_SHA},
            )
        with self.assertRaisesRegex(SystemExit, "repository must be exactly"):
            verifier.verify_source_checkout(Path("/checkout"), "fork/Blackcoin", SOURCE_SHA)
        mismatch = (
            subprocess.CompletedProcess([], 0, stdout="f" * 40 + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="", stderr=""),
        )
        with mock.patch.object(verifier.subprocess, "run", side_effect=mismatch):
            with self.assertRaisesRegex(SystemExit, "source commit mismatch"):
                verifier.verify_source_checkout(
                    Path("/checkout"), "Blackcoin-Dev/Blackcoin", SOURCE_SHA
                )
        dirty = (
            subprocess.CompletedProcess([], 0, stdout=SOURCE_SHA + "\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=" M src/crypto/mldsa.cpp\n", stderr=""),
        )
        with mock.patch.object(verifier.subprocess, "run", side_effect=dirty):
            with self.assertRaisesRegex(SystemExit, "not clean"):
                verifier.verify_source_checkout(
                    Path("/checkout"), "Blackcoin-Dev/Blackcoin", SOURCE_SHA
                )

    def test_quantum_crypto_evidence_records_exact_source_identity(self):
        verifier = load_path(
            "verify_quantum_crypto_evidence_writer",
            TOOLS.parent.parent / "contrib" / "devtools" / "verify-quantum-crypto-sources.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "manifest.json"
            evidence = root / "evidence.json"
            manifest.write_text("{}\n", encoding="utf-8")
            source = {"repository": "Blackcoin-Dev/Blackcoin", "commit": SOURCE_SHA}
            verifier.write_evidence(evidence, manifest, root, source, {}, {})
            document = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(document["source"], source)

    def test_release_runbook_is_blackcoin_specific_and_covers_immutable_rollback(self):
        root = TOOLS.parent.parent
        runbook = (root / "doc" / "release-process.md").read_text(encoding="utf-8")
        forbidden = (
            "bitcoin-core/guix.sigs",
            "bitcoin-detached-sigs",
            "guix-codesign",
            "bitcoincore.org/bin",
        )
        for stale_reference in forbidden:
            with self.subTest(stale_reference=stale_reference):
                self.assertNotIn(stale_reference, runbook.lower())

        required = (
            "initially unpublished",
            "optional public alpha prerelease",
            "`v30.1.1-alpha1`",
            "get /repos/blackcoin-dev/blackcoin/immutable-releases",
            "`enabled=true`",
            "github `prerelease` is true and `latest` remains false",
            "`signed=false`, `notarized=false`",
            "never be marked latest",
            "signed annotated `v30.1.1` tag",
            "production-release",
            "independent rebuilder",
            "signed `sha256sums.txt`",
            "spdx sbom",
            "in-toto provenance",
            "release rollback and revocation",
            "never delete,",
            "or recreate the `v30.1.1` tag",
            "human-held production credentials",
        )
        lowered = runbook.lower()
        for release_control in required:
            with self.subTest(release_control=release_control):
                self.assertIn(release_control, lowered)
        self.assertNotIn("an alpha is an unpublished", lowered)
        self.assertNotIn("do not upload an alpha to a production release page", lowered)

    def test_every_third_party_workflow_action_is_commit_pinned(self):
        workflows = TOOLS.parent.parent / ".github" / "workflows"
        action = re.compile(r"^\s*uses:\s*([^\s#]+)")
        immutable = re.compile(r"^[^/@\s]+/[^@\s]+@[0-9a-f]{40}$")
        for workflow in sorted(workflows.glob("*.yml")):
            for line_number, line in enumerate(
                workflow.read_text(encoding="utf-8").splitlines(), start=1
            ):
                match = action.match(line)
                if match is None or match.group(1).startswith("./"):
                    continue
                with self.subTest(workflow=workflow.name, line=line_number):
                    self.assertRegex(match.group(1), immutable)

    def test_final_release_requires_exact_mainnet_witness_artifact(self):
        root = TOOLS.parent.parent
        witness = (
            root / ".github" / "workflows" / "quantum-witness-inventory.yml"
        ).read_text(encoding="utf-8")
        release = (
            root / ".github" / "workflows" / "build.yml"
        ).read_text(encoding="utf-8")

        # A dispatch from another ref cannot attest the requested candidate.
        self.assertIn("ref: ${{ inputs.target_sha }}", witness)
        self.assertIn('test "$(git rev-parse HEAD)" = "$TARGET_SHA"', witness)
        self.assertIn('test "$GITHUB_WORKFLOW_SHA" = "$TARGET_SHA"', witness)
        self.assertIn("environment: production-resource-evidence", witness)
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, blackcoin-shadow-resource]",
            witness,
        )

        artifact_name = "quantum-witness-mainnet-inventory-$TARGET_SHA"
        self.assertIn(artifact_name, release)
        self.assertIn(
            "sort -t $'\\t' -k2,2nr -k1,1nr",
            release,
        )
        self.assertIn('test -n "$artifact" || {', release)
        self.assertIn(
            'test "$run_path" = '
            '".github/workflows/quantum-witness-inventory.yml"',
            release,
        )
        self.assertIn('test "$run_result" = success', release)
        self.assertIn('test "$run_sha" = "$TARGET_SHA"', release)
        self.assertIn('test "$run_event" = workflow_dispatch', release)
        self.assertIn('test "$run_actor" = Blackcoin-Dev', release)
        self.assertIn('test "$triggering_actor" = Blackcoin-Dev', release)
        self.assertIn("--maximum-age-seconds 86400", release)
        self.assertIn("verify_quantum_witness_inventory_evidence.py", release)
        self.assertIn("--blackcoind \"$bundled_blackcoind\"", release)
        self.assertIn("--blackcoin-cli \"$bundled_cli\"", release)
        self.assertIn('cmp "$authorization" "$recomputed"', release)
        self.assertIn(
            "Blackcoin-$VERSION-quantum-witness-authorization.json",
            release,
        )

    def test_mixed_version_command_runner_executes_all_commands(self):
        builder = load_mixed_version_module("build_previous_releases")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "noncaptured-command-ran"
            self.assertIsNone(
                builder.run(
                    [
                        sys.executable,
                        "-c",
                        "from pathlib import Path; "
                        "Path('noncaptured-command-ran').touch()",
                    ],
                    cwd=root,
                )
            )
            self.assertTrue(marker.is_file())
            self.assertEqual(
                builder.run(
                    [sys.executable, "-c", "print('captured-command-ran')"],
                    cwd=root,
                    capture=True,
                ).strip(),
                "captured-command-ran",
            )
            with self.assertRaises(subprocess.CalledProcessError):
                builder.run(
                    [sys.executable, "-c", "raise SystemExit(9)"],
                    cwd=root,
                )

    def test_mixed_version_check_isolates_datadir_and_home(self):
        builder = load_mixed_version_module("build_previous_releases")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            legacy_home = root / "legacy-home"
            legacy_home.mkdir()
            (legacy_home / ".blackmore").mkdir()
            binary = root / "blackcoind"
            binary.write_text(
                "#!/usr/bin/env python3\n"
                "import os\n"
                "from pathlib import Path\n"
                "import sys\n"
                "datadirs = [a.split('=', 1)[1] for a in sys.argv "
                "if a.startswith('-datadir=')]\n"
                "isolated = (len(datadirs) == 1 "
                "and Path(datadirs[0]).is_dir() "
                "and not (Path(os.environ['HOME']) / '.blackmore').exists())\n"
                "print('Blackcoin version v30.1.0' if isolated "
                "else 'Blackcoin first-run migration: 0%')\n",
                encoding="utf8",
            )
            binary.chmod(0o755)
            with mock.patch.dict(os.environ, {"HOME": str(legacy_home)}):
                self.assertEqual(
                    builder.verified_reported_version(
                        binary,
                        "v30.1.0",
                        expected_product="Blackcoin",
                        scratch_root=root,
                    ),
                    "Blackcoin version v30.1.0",
                )

    def test_mixed_version_check_accepts_historical_product_roles(self):
        builder = load_mixed_version_module("build_previous_releases")
        cases = (
            ("blackcoind", "Blackcoin More version v26.2.0"),
            ("blackcoin-cli", "Blackcoin More RPC client version v26.2.0"),
        )
        for role, banner in cases:
            with self.subTest(role=role):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    binary = root / role
                    binary.write_text(
                        f"#!/bin/sh\nprintf '%s\\n' '{banner}'\n",
                        encoding="utf8",
                    )
                    binary.chmod(0o755)
                    self.assertEqual(
                        builder.verified_reported_version(
                            binary,
                            "v26.2.0",
                            expected_product="Blackcoin More",
                            scratch_root=root,
                        ),
                        banner,
                    )

    def test_mixed_version_check_rejects_wrong_version(self):
        builder = load_mixed_version_module("build_previous_releases")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "blackcoind"
            binary.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'Blackcoin version v29.0.0'\n",
                encoding="utf8",
            )
            binary.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "unexpected version"):
                builder.verified_reported_version(
                    binary,
                    "v30.1.0",
                    expected_product="Blackcoin",
                    scratch_root=root,
                )

    def test_mixed_version_check_rejects_substring_collision(self):
        builder = load_mixed_version_module("build_previous_releases")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "blackcoind"
            binary.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'Blackcoin version v130.1.0'\n",
                encoding="utf8",
            )
            binary.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "unexpected version"):
                builder.verified_reported_version(
                    binary,
                    "v30.1.0",
                    expected_product="Blackcoin",
                    scratch_root=root,
                )

    def test_mixed_version_check_rejects_executable_role_mismatch(self):
        builder = load_mixed_version_module("build_previous_releases")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "blackcoin-cli"
            binary.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'Blackcoin version v30.1.0'\n",
                encoding="utf8",
            )
            binary.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "unexpected version"):
                builder.verified_reported_version(
                    binary,
                    "v30.1.0",
                    expected_product="Blackcoin",
                    scratch_root=root,
                )

    def test_mixed_version_check_rejects_untrusted_or_leading_banner(self):
        builder = load_mixed_version_module("build_previous_releases")
        banners = (
            "Othercoin version v30.1.0",
            "Blackcoin first-run migration: 0%\\nBlackcoin version v30.1.0",
        )
        for banner in banners:
            with self.subTest(banner=banner):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    binary = root / "blackcoind"
                    binary.write_text(
                        "#!/bin/sh\nprintf '%b\\n' " + repr(banner) + "\n",
                        encoding="utf8",
                    )
                    binary.chmod(0o755)
                    with self.assertRaisesRegex(RuntimeError, "unexpected version"):
                        builder.verified_reported_version(
                            binary,
                            "v30.1.0",
                            expected_product="Blackcoin",
                            scratch_root=root,
                        )

    def test_mixed_version_check_rejects_cross_product_banner(self):
        builder = load_mixed_version_module("build_previous_releases")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "blackcoind"
            binary.write_text(
                "#!/bin/sh\nprintf '%s\\n' 'Blackcoin More version v30.1.0'\n",
                encoding="utf8",
            )
            binary.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "unexpected version"):
                builder.verified_reported_version(
                    binary,
                    "v30.1.0",
                    expected_product="Blackcoin",
                    scratch_root=root,
                )

    def test_unsigned_canary_manifest_is_bound_to_label_and_exact_source(self):
        generator = load_module("generate_canary_manifest")
        package_label = "30.1.1-alpha1"
        prefix = f"Blackcoin-{package_label}-{SOURCE_SHA}-"
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            (artifacts / f"{prefix}Linux-x86_64.tar.gz").write_bytes(b"canary")
            (artifacts / f"{prefix}linux-64-bit-SOURCE_COMMIT.txt").write_text(
                SOURCE_SHA + "\n", encoding="utf-8"
            )
            (artifacts / f"{prefix}REPRODUCIBILITY.txt").write_text(
                f"package_label={package_label}\n"
                "prerelease_channel=alpha\n"
                "configured_version=30.1.1rc1\n"
                f"source_commit={SOURCE_SHA}\n",
                encoding="utf-8",
            )
            (artifacts / f"{prefix}UNSIGNED-CANARY.txt").write_text(
                "UNSIGNED CANARY ARTIFACTS - NOT A PRODUCTION RELEASE\n"
                f"package_label={package_label}\n"
                "prerelease_channel=alpha\n"
                "configured_version=30.1.1rc1\n"
                f"source_commit={SOURCE_SHA}\n"
                "workflow_run_id=12345\n"
                "signed=false\n"
                "developer_id_signed=false\n"
                "macos_adhoc_signed=false\n"
                "notarized=false\npublished=false\n",
                encoding="utf-8",
            )
            output = artifacts / f"{prefix}MANIFEST-UNSIGNED.json"

            manifest = generator.generate_manifest(
                artifacts=artifacts,
                package_label=package_label,
                source_version="30.1.1",
                configured_version="30.1.1rc1",
                source_sha=SOURCE_SHA,
                release_candidate="1",
                workflow_run_id="12345",
                output=output,
            )

            self.assertEqual(manifest["classification"], "UNSIGNED_CANARY_NOT_FOR_PRODUCTION")
            self.assertEqual(manifest["package_label"], package_label)
            self.assertEqual(manifest["prerelease_channel"], "alpha")
            self.assertEqual(manifest["source"]["commit"], SOURCE_SHA)
            self.assertFalse(manifest["release"]["signed"])
            self.assertFalse(manifest["release"]["developer_id_signed"])
            self.assertFalse(manifest["release"]["macos_adhoc_signed"])
            self.assertFalse(manifest["release"]["published"])
            self.assertTrue(output.is_file())
            self.assertTrue(
                all(package_label in subject["name"] and SOURCE_SHA in subject["name"]
                    for subject in manifest["artifacts"])
            )

    def test_unsigned_canary_manifest_rejects_unbound_artifact_names(self):
        generator = load_module("generate_canary_manifest")
        package_label = "30.1.1-alpha1"
        prefix = f"Blackcoin-{package_label}-{SOURCE_SHA}-"
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            (artifacts / "Blackcoin-30.1.1-Linux-x86_64.tar.gz").write_bytes(b"ambiguous")
            (artifacts / f"{prefix}REPRODUCIBILITY.txt").write_text(
                f"package_label={package_label}\n"
                "prerelease_channel=alpha\n"
                "configured_version=30.1.1rc1\n"
                f"source_commit={SOURCE_SHA}\n",
                encoding="utf-8",
            )
            (artifacts / f"{prefix}UNSIGNED-CANARY.txt").write_text(
                "UNSIGNED CANARY ARTIFACTS - NOT A PRODUCTION RELEASE\n"
                f"package_label={package_label}\n"
                "prerelease_channel=alpha\n"
                "configured_version=30.1.1rc1\n"
                f"source_commit={SOURCE_SHA}\n"
                "workflow_run_id=12345\n"
                "signed=false\n"
                "developer_id_signed=false\n"
                "macos_adhoc_signed=false\n"
                "notarized=false\npublished=false\n",
                encoding="utf-8",
            )
            output = artifacts / f"{prefix}MANIFEST-UNSIGNED.json"
            with self.assertRaisesRegex(RuntimeError, "package label and exact source SHA"):
                generator.generate_manifest(
                    artifacts=artifacts,
                    package_label=package_label,
                    source_version="30.1.1",
                    configured_version="30.1.1rc1",
                    source_sha=SOURCE_SHA,
                    release_candidate="1",
                    workflow_run_id="12345",
                    output=output,
                )

    def test_unsigned_beta_manifest_is_bound_to_channel_and_exact_source(self):
        generator = load_module("generate_canary_manifest")
        package_label = "30.1.1-beta1"
        prefix = f"Blackcoin-{package_label}-{SOURCE_SHA}-"
        with tempfile.TemporaryDirectory() as temporary:
            artifacts = Path(temporary)
            (artifacts / f"{prefix}Linux-x86_64.tar.gz").write_bytes(b"beta")
            (artifacts / f"{prefix}linux-64-bit-SOURCE_COMMIT.txt").write_text(
                SOURCE_SHA + "\n", encoding="utf-8"
            )
            (artifacts / f"{prefix}REPRODUCIBILITY.txt").write_text(
                f"package_label={package_label}\n"
                "prerelease_channel=beta\n"
                "configured_version=30.1.1rc1\n"
                f"source_commit={SOURCE_SHA}\n",
                encoding="utf-8",
            )
            (artifacts / f"{prefix}UNSIGNED-CANARY.txt").write_text(
                "UNSIGNED CANARY ARTIFACTS - NOT A PRODUCTION RELEASE\n"
                f"package_label={package_label}\n"
                "prerelease_channel=beta\n"
                "configured_version=30.1.1rc1\n"
                f"source_commit={SOURCE_SHA}\n"
                "workflow_run_id=12345\n"
                "signed=false\n"
                "developer_id_signed=false\n"
                "macos_adhoc_signed=true\n"
                "notarized=false\npublished=false\n",
                encoding="utf-8",
            )
            output = artifacts / f"{prefix}MANIFEST-UNSIGNED.json"

            manifest = generator.generate_manifest(
                artifacts=artifacts,
                package_label=package_label,
                source_version="30.1.1",
                configured_version="30.1.1rc1",
                source_sha=SOURCE_SHA,
                release_candidate="1",
                workflow_run_id="12345",
                output=output,
                macos_adhoc_signed=True,
            )

            self.assertEqual(manifest["package_label"], package_label)
            self.assertEqual(manifest["prerelease_channel"], "beta")
            self.assertEqual(manifest["source"]["commit"], SOURCE_SHA)
            self.assertFalse(manifest["release"]["developer_id_signed"])
            self.assertTrue(manifest["release"]["macos_adhoc_signed"])
            self.assertFalse(manifest["release"]["published"])

    def test_prerelease_workflow_keeps_the_signed_production_gate_separate(self):
        workflow = (TOOLS.parent.parent / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("default: 30.1.1-alpha1", workflow)
        self.assertIn("CALLER_WORKFLOW_SHA: ${{ github.workflow_sha }}", workflow)
        self.assertIn('test "$CALLER_WORKFLOW_SHA" = "$TARGET_SHA"', workflow)
        self.assertIn('test "$EVENT_SHA" = "$TARGET_SHA"', workflow)
        self.assertIn("-(alpha|beta)", workflow)
        self.assertIn(
            'test "$REQUESTED_PACKAGE_LABEL" = "$BASE_VERSION-$PRERELEASE_CHANNEL$RC"',
            workflow,
        )
        self.assertIn("prerelease_channel == 'beta'", workflow)
        self.assertIn('test "$IS_RELEASE" = "false"', workflow)
        self.assertIn('test "$RC" = "0"', workflow)
        self.assertIn('test "$IS_RELEASE" = "true"', workflow)
        self.assertIn("- 'v30.1.1'", workflow)
        self.assertNotIn("- 'v30.1.1-alpha", workflow)
        self.assertNotIn("- 'v30.1.1-beta", workflow)
        self.assertIn("UNSIGNED CANARY ARTIFACTS - NOT A PRODUCTION RELEASE", workflow)
        self.assertIn("raw-release-${{ needs.resolve-target.outputs.package_label }}", workflow)
        self.assertIn("macos-15-intel", workflow)
        self.assertIn("codesign --force --deep --sign - --timestamp=none", workflow)
        self.assertIn("macos_adhoc_signed=$MACOS_SELECTED", workflow)
        self.assertIn('metadata["LSArchitecturePriority"] = [os.environ["EXPECTED_ARCH"]]', workflow)
        self.assertIn('verify_plist_architecture "$verified_plist"', workflow)
        self.assertIn("Developer-ID sign and notarize macOS artifacts", workflow)

    def test_reproducibility_requires_identical_bytes(self):
        verifier = load_module("verify_reproducible")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            primary = root / "primary"
            rebuilt = root / "rebuilt"
            primary.mkdir()
            rebuilt.mkdir()
            (primary / "artifact.bin").write_bytes(b"identical")
            (rebuilt / "artifact.bin").write_bytes(b"identical")
            self.assertEqual(verifier.inventory(primary), verifier.inventory(rebuilt))
            (rebuilt / "artifact.bin").write_bytes(b"different")
            self.assertNotEqual(verifier.inventory(primary), verifier.inventory(rebuilt))

    def test_signature_verifier_requires_configured_fingerprint(self):
        identity = load_module("verify_source_identity")
        good = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=f"[GNUPG:] VALIDSIG {FINGERPRINT} 0 0 0 4 0 1 8 00 {FINGERPRINT}\n",
        )
        with mock.patch.object(identity.subprocess, "run", return_value=good):
            identity.verify_openpgp_signature("HEAD", "commit", FINGERPRINT)
            with self.assertRaises(RuntimeError):
                identity.verify_openpgp_signature("HEAD", "commit", "B" * 40)

        bad = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="[GNUPG:] BADSIG 0000000000000000 Blackcoin-Dev\n",
        )
        with mock.patch.object(identity.subprocess, "run", return_value=bad):
            with self.assertRaises(RuntimeError):
                identity.verify_openpgp_signature("HEAD", "commit", FINGERPRINT)

    def test_windows_payload_inventory_is_exact_and_excludes_test_binary(self):
        verifier = load_module("verify_windows_payload")
        self.assertIn("blackcoin-util.exe", verifier.EXPECTED_EXECUTABLES)
        self.assertNotIn("test_blackcoin.exe", verifier.EXPECTED_EXECUTABLES)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            payload.mkdir()
            for name in verifier.EXPECTED_EXECUTABLES:
                (payload / name).write_bytes(name.encode("ascii"))
            self.assertEqual(
                tuple(path.name for path in verifier.verify_directory(payload)),
                verifier.EXPECTED_EXECUTABLES,
            )

            archive = root / "portable.zip"
            with zipfile.ZipFile(archive, "w") as zipped:
                for name in verifier.EXPECTED_EXECUTABLES:
                    zipped.write(payload / name, name)
            self.assertEqual(verifier.verify_archive(archive), verifier.EXPECTED_EXECUTABLES)

            unsafe_archive = root / "unsafe-portable.zip"
            with zipfile.ZipFile(unsafe_archive, "w") as zipped:
                for name in verifier.EXPECTED_EXECUTABLES:
                    archived_name = f"../{name}" if name == "blackcoin-cli.exe" else name
                    zipped.write(payload / name, archived_name)
            with self.assertRaisesRegex(RuntimeError, "flat filename"):
                verifier.verify_archive(unsafe_archive)

            (payload / "test_blackcoin.exe").write_bytes(b"forbidden")
            with self.assertRaisesRegex(RuntimeError, "unexpected entries"):
                verifier.verify_directory(payload)

    def test_windows_installer_must_embed_the_signed_portable_bytes(self):
        verifier = load_module("verify_windows_payload")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload"
            extracted = root / "extracted"
            payload.mkdir()
            extracted.mkdir()
            for name in verifier.EXPECTED_EXECUTABLES:
                content = f"signed:{name}".encode("ascii")
                (payload / name).write_bytes(content)
                destination = extracted / ("root" if name == "blackcoin-qt.exe" else "daemon") / name
                destination.parent.mkdir(exist_ok=True)
                destination.write_bytes(content)

            embedded = verifier.verify_installer_extraction(extracted, payload)
            self.assertEqual(tuple(path.name for path in embedded), verifier.EXPECTED_EXECUTABLES)

            (extracted / "daemon" / "blackcoin-util.exe").write_bytes(b"unsigned-or-different")
            with self.assertRaisesRegex(RuntimeError, "differs from signed portable"):
                verifier.verify_installer_extraction(extracted, payload)

            (extracted / "daemon" / "blackcoin-util.exe").write_bytes(b"signed:blackcoin-util.exe")
            (extracted / "daemon" / "test_blackcoin.exe").write_bytes(b"forbidden")
            with self.assertRaisesRegex(RuntimeError, "forbidden test executable"):
                verifier.verify_installer_extraction(extracted, payload)

    def test_windows_installer_recipe_uses_production_payload_only(self):
        template = (TOOLS.parent.parent / "share" / "setup.nsi.in").read_text(encoding="utf-8")
        self.assertIn("@BITCOIN_UTIL_NAME@@EXEEXT@", template)
        self.assertNotIn("@BITCOIN_TEST_NAME@@EXEEXT@", template)
        self.assertIn("${BLACKCOIN_PAYLOAD_DIR}", template)
        self.assertIn("${BLACKCOIN_OUTPUT_FILE}", template)

    def test_windows_installer_build_uses_absolute_output_and_sequential_goals(self):
        root = TOOLS.parent.parent
        makefile = (root / "Makefile.am").read_text(encoding="utf-8")
        workflow = (root / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            '-DBLACKCOIN_OUTPUT_FILE="$(abspath $@)"',
            makefile,
        )
        self.assertIn(
            'BITCOIN_WIN_INSTALLER=$PWD/blackcoin-$CONFIGURED_VERSION-win64-setup.exe',
            workflow,
        )
        self.assertIn('for goal in ${{ matrix.goal }}; do', workflow)
        self.assertNotIn('make -j "$MAKEJOBS" ${{ matrix.goal }}', workflow)

    def test_sbom_and_provenance_are_bound_to_artifacts_and_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifacts = root / "artifacts"
            packages = root / "packages"
            artifacts.mkdir()
            packages.mkdir()
            (artifacts / "Blackcoin-30.1.1-test.bin").write_bytes(b"release")
            (packages / "example.mk").write_text(
                "package=example\n"
                "$(package)_version=1.2.3\n"
                "$(package)_sha256_hash=" + "1" * 64 + "\n",
                encoding="utf-8",
            )
            dependency_manifest = root / "dependency-security-manifest.json"
            dependency_manifest.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "dependencies": [
                            {
                                "package": "example",
                                "recipe": "depends/packages/example.mk",
                                "recipe_sha256": hashlib.sha256(
                                    (packages / "example.mk").read_bytes()
                                ).hexdigest(),
                                "version": "1.2.3",
                                "sources": [
                                    {
                                        "url": "https://example.test/example-1.2.3.tar.gz",
                                        "sha256": "1" * 64,
                                    },
                                    {
                                        "url": "https://example.test/example-data-1.2.3.tar.gz",
                                        "sha256": "2" * 64,
                                    },
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            sbom = artifacts / "Blackcoin-30.1.1-SBOM.spdx.json"
            provenance = artifacts / "Blackcoin-30.1.1-provenance.intoto.json"
            subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "generate_spdx_sbom.py"),
                    "--artifacts",
                    str(artifacts),
                    "--depends-packages",
                    str(packages),
                    "--dependency-manifest",
                    str(dependency_manifest),
                    "--version",
                    "30.1.1",
                    "--source-sha",
                    SOURCE_SHA,
                    "--source-date-epoch",
                    "1783950000",
                    "--output",
                    str(sbom),
                ],
                check=True,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "generate_provenance.py"),
                    "--artifacts",
                    str(artifacts),
                    "--repository",
                    "Blackcoin-Dev/Blackcoin",
                    "--source-sha",
                    SOURCE_SHA,
                    "--version",
                    "30.1.1",
                    "--tag",
                    "v30.1.1",
                    "--workflow-run-id",
                    "12345",
                    "--output",
                    str(provenance),
                ],
                check=True,
            )

            sbom_document = json.loads(sbom.read_text(encoding="utf-8"))
            provenance_document = json.loads(provenance.read_text(encoding="utf-8"))
            self.assertEqual(sbom_document["spdxVersion"], "SPDX-2.3")
            self.assertTrue(
                any(relationship["relationshipType"] == "DEPENDS_ON" for relationship in sbom_document["relationships"])
            )
            dependency_packages = [
                package for package in sbom_document["packages"]
                if package["name"] == "example"
            ]
            self.assertEqual(len(dependency_packages), 1)
            self.assertEqual(
                dependency_packages[0]["downloadLocation"],
                "https://example.test/example-1.2.3.tar.gz",
            )
            self.assertTrue(
                any(
                    package["downloadLocation"] ==
                    "https://example.test/example-data-1.2.3.tar.gz"
                    for package in sbom_document["packages"]
                )
            )
            self.assertEqual(provenance_document["_type"], "https://in-toto.io/Statement/v1")
            self.assertEqual(
                provenance_document["predicate"]["buildDefinition"]["externalParameters"]["source"]["digest"]["gitCommit"],
                SOURCE_SHA,
            )
            subject_names = {subject["name"] for subject in provenance_document["subject"]}
            self.assertIn("Blackcoin-30.1.1-test.bin", subject_names)
            self.assertIn(sbom.name, subject_names)
            self.assertNotIn(provenance.name, subject_names)

    def test_dependency_security_manifest_is_fail_closed(self):
        verifier = load_module("verify_dependency_security")
        repository = TOOLS.parents[1]
        manifest_path = TOOLS / "dependency-security-manifest.json"
        verifier.verify(repository, manifest_path)

        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["baselines"]["v30_1_0"] = "0" * 40
        with tempfile.TemporaryDirectory() as temporary:
            mutated = Path(temporary) / "dependency-security-manifest.json"
            mutated.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "immutable review revisions"):
                verifier.verify(repository, mutated)

        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["dependencies"][0]["recipe_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as temporary:
            mutated = Path(temporary) / "dependency-security-manifest.json"
            mutated.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "recipe changed without a manifest review"):
                verifier.verify(repository, mutated)

        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["dependency_delta"].pop()
        with tempfile.TemporaryDirectory() as temporary:
            mutated = Path(temporary) / "dependency-security-manifest.json"
            mutated.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "compare every candidate dependency"):
                verifier.verify(repository, mutated)

        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        document["dependency_update_dispositions"].pop()
        with tempfile.TemporaryDirectory() as temporary:
            mutated = Path(temporary) / "dependency-security-manifest.json"
            mutated.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "lack exact dispositions"):
                verifier.verify(repository, mutated)


class SourceBuildIdentityTests(unittest.TestCase):
    def setUp(self):
        self.root = TOOLS.parents[1]
        self.genbuild = self.root / "share" / "genbuild.sh"

    def make_repository(self, directory):
        repository = directory / "source"
        repository.mkdir()
        subprocess.run(["git", "init", "-q", repository], check=True)
        (repository / "tracked.txt").write_text("identity\n", encoding="utf-8")
        subprocess.run(["git", "-C", repository, "add", "tracked.txt"], check=True)
        subprocess.run([
            "git", "-C", repository,
            "-c", "user.name=Blackcoin-Dev",
            "-c", "user.email=298119138+Blackcoin-Dev@users.noreply.github.com",
            "commit", "-q", "-m", "identity fixture",
        ], check=True)
        source_sha = subprocess.check_output(
            ["git", "-C", repository, "rev-parse", "HEAD"], text=True,
        ).strip()
        return repository, source_sha

    def generate_header(self, repository, directory):
        header = directory / "build.h"
        subprocess.run([self.genbuild, header, repository], check=True)
        return header.read_text(encoding="utf-8")

    def test_untagged_beta_embeds_full_source_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repository, source_sha = self.make_repository(directory)
            header = self.generate_header(repository, directory)
            self.assertIn(f'#define BUILD_SOURCE_COMMIT "{source_sha}"', header)
            self.assertIn("#define BUILD_SOURCE_DIRTY 0", header)
            self.assertIn(f'#define BUILD_GIT_COMMIT "{source_sha[:12]}"', header)

    def test_prerelease_and_final_tags_preserve_full_source_identity(self):
        for tag in ("v30.1.1-beta1", "v30.1.1"):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                repository, source_sha = self.make_repository(directory)
                subprocess.run(["git", "-C", repository, "tag", tag], check=True)
                header = self.generate_header(repository, directory)
                self.assertIn(f'#define BUILD_SOURCE_COMMIT "{source_sha}"', header)
                self.assertIn("#define BUILD_SOURCE_DIRTY 0", header)
                self.assertIn(f'#define BUILD_GIT_TAG "{tag}"', header)

    def test_dirty_tree_keeps_commit_but_sets_fail_closed_dirty_bit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repository, source_sha = self.make_repository(directory)
            (repository / "tracked.txt").write_text("changed\n", encoding="utf-8")
            header = self.generate_header(repository, directory)
            self.assertIn(f'#define BUILD_SOURCE_COMMIT "{source_sha}"', header)
            self.assertIn("#define BUILD_SOURCE_DIRTY 1", header)
            self.assertIn(f'#define BUILD_GIT_COMMIT "{source_sha[:12]}-dirty"', header)

    def test_untracked_source_sets_fail_closed_dirty_bit(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repository, source_sha = self.make_repository(directory)
            (repository / "untracked-source.cpp").write_text(
                "// could affect a wildcard build\n", encoding="utf-8",
            )
            header = self.generate_header(repository, directory)
            self.assertIn(f'#define BUILD_SOURCE_COMMIT "{source_sha}"', header)
            self.assertIn("#define BUILD_SOURCE_DIRTY 1", header)
            self.assertIn(f'#define BUILD_GIT_COMMIT "{source_sha[:12]}-dirty"', header)

    def test_git_archive_substitutes_full_commit_and_unsubstituted_source_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repository = directory / "source"
            (repository / "src").mkdir(parents=True)
            (repository / ".gitattributes").write_text(
                "src/clientversion.cpp export-subst\n", encoding="utf-8",
            )
            clientversion = repository / "src" / "clientversion.cpp"
            clientversion.write_text(
                '#define GIT_COMMIT_ID "$Format:%H$"\n', encoding="utf-8",
            )
            subprocess.run(["git", "init", "-q", repository], check=True)
            subprocess.run(["git", "-C", repository, "add", "."], check=True)
            subprocess.run([
                "git", "-C", repository,
                "-c", "user.name=Blackcoin-Dev",
                "-c", "user.email=298119138+Blackcoin-Dev@users.noreply.github.com",
                "commit", "-q", "-m", "archive fixture",
            ], check=True)
            source_sha = subprocess.check_output(
                ["git", "-C", repository, "rev-parse", "HEAD"], text=True,
            ).strip()
            archive = directory / "source.tar"
            subprocess.run([
                "git", "-C", repository, "archive", "--format=tar",
                f"--output={archive}", "HEAD",
            ], check=True)
            with tarfile.open(archive) as source:
                archived = source.extractfile("src/clientversion.cpp").read().decode()
            self.assertIn(f'#define GIT_COMMIT_ID "{source_sha}"', archived)

            no_git = directory / "no-git"
            no_git.mkdir()
            header = directory / "no-git-build.h"
            environment = os.environ.copy()
            environment["BITCOIN_GENBUILD_NO_GIT"] = "1"
            subprocess.run([self.genbuild, header, no_git], check=True, env=environment)
            self.assertNotIn("BUILD_SOURCE_COMMIT", header.read_text(encoding="utf-8"))
            self.assertIn("$Format:%H$", clientversion.read_text(encoding="utf-8"))

    def test_release_verifier_accepts_tagged_display_with_exact_clean_source(self):
        audit = load_path(
            "quantum_witness_inventory_source_identity",
            self.root / "contrib" / "devtools" /
            "quantum_witness_inventory_audit.py",
        )
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "blackcoind"
            binary.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' 'Blackcoin Core version v30.1.1' "
                f"'Source commit: {SOURCE_SHA}'\n",
                encoding="utf-8",
            )
            binary.chmod(0o755)
            identity = audit.verify_binary(binary, SOURCE_SHA, "blackcoind")
            self.assertEqual(identity["source_commit"], SOURCE_SHA)
            self.assertFalse(identity["source_dirty"])
            self.assertIn("version v30.1.1", identity["version"])

    def test_release_verifier_rejects_dirty_or_unavailable_source_identity(self):
        audit = load_path(
            "quantum_witness_inventory_bad_source_identity",
            self.root / "contrib" / "devtools" /
            "quantum_witness_inventory_audit.py",
        )
        identities = (
            f"Source commit: {SOURCE_SHA} (dirty)",
            "Source commit: unavailable",
        )
        for source_identity in identities:
            with self.subTest(source_identity=source_identity), \
                    tempfile.TemporaryDirectory() as temporary:
                binary = Path(temporary) / "blackcoind"
                binary.write_text(
                    "#!/bin/sh\n"
                    "printf '%s\\n' 'Blackcoin Core version v30.1.1' "
                    f"'{source_identity}'\n",
                    encoding="utf-8",
                )
                binary.chmod(0o755)
                with self.assertRaisesRegex(
                    audit.AuditError, "full immutable source identity is absent or dirty"
                ):
                    audit.verify_binary(binary, SOURCE_SHA, "blackcoind")


class WitnessInventoryAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.audit = load_path(
            "quantum_witness_inventory_audit",
            TOOLS.parents[1] / "contrib" / "devtools" /
            "quantum_witness_inventory_audit.py",
        )
        self.verifier = load_module("verify_quantum_witness_inventory_evidence")
        self.runner = load_module("run_quantum_witness_inventory_gate")
        self.contract_path = TOOLS / "shadow_resource_production_contract.json"
        self.contract = json.loads(self.contract_path.read_text(encoding="utf-8"))
        self.contract_sha = hashlib.sha256(
            self.contract_path.read_bytes()
        ).hexdigest()
        self.bestblock = "a" * 64
        self.muhash = "b" * 64

    def record(self, number, version, handling,
               origin_group="pre_migration_window"):
        version_class = {14: "v14", 15: "v15", 16: "v16"}.get(
            version, "unknown"
        )
        return {
            "txid": f"{number:064x}",
            "vout": number,
            "amount": "1.00000000",
            "scriptPubKey": f"{0x50 + version:02x}20" + "11" * 32,
            "witness_version": version,
            "version_class": version_class,
            "bridge_handling": handling,
            "origin_height": 5_950_100,
            "origin_blockhash": "c" * 64,
            "origin_block_time": 2_000_000_000,
            "coin_time": 2_000_000_000,
            "origin_phase": "gold_rush",
            "origin_group": origin_group,
            "coinbase": False,
            "coinstake": False,
        }

    def binary_identities(self):
        version = (
            "Blackcoin Core version v30.1.1rc1-test\n"
            f"Source commit: {SOURCE_SHA}"
        )
        return {
            "blackcoind": {
                "sha256": "1" * 64,
                "version": version,
                "source_commit": SOURCE_SHA,
                "source_dirty": False,
            },
            "blackcoin_cli": {
                "sha256": "2" * 64,
                "version": version,
                "source_commit": SOURCE_SHA,
                "source_dirty": False,
            },
        }

    def server_identity(self):
        return {
            "launched_by_acceptance_verifier": True,
            "non_daemonized_process": True,
            "pid": 123,
            "executable": "/candidate/blackcoind",
            "executable_sha256": "1" * 64,
            "process_image_binding": {
                "mechanism": "linux_proc_pid_exe",
                "observed_path": "/candidate/blackcoind",
                "sha256": "1" * 64,
            },
            "rpc_endpoint": "127.0.0.1:12345",
            "rpc_authentication": {
                "mechanism": "verifier_owned_cookie",
                "private_directory_mode": "0700",
                "cookie_path": "/private/rpc-auth.cookie",
                "secret_recorded": False,
            },
            "rpc_reported_build": "v30.1.1rc1-test",
            "rpc_reported_source_commit": SOURCE_SHA,
            "rpc_reported_source_dirty": False,
            "wallet_disabled": True,
            "staking_disabled": True,
            "pow_mining_disabled": True,
            "network_frozen_during_snapshot": True,
        }

    def capture_manifest(self, *, captured_at=2_000_000_000):
        return {
            "schema": 2,
            "evidence_kind": "current_live_partial_epoch",
            "contract_sha256": self.contract_sha,
            "target_sha": SOURCE_SHA,
            "network": "main",
            "archive_sha256": "d" * 64,
            "archive_size_bytes": 1,
            "archive_root": "mainnet",
            "captured_at_unix": captured_at,
            "capture_attestation": (
                "protected_operator_confirmed_connected_mainnet_tip"
            ),
            "capture_rpc": {
                "chain": "main",
                "blocks": 5_953_262,
                "headers": 5_953_262,
                "bestblockhash": self.bestblock,
                "initialblockdownload": False,
                "connections": 1,
            },
            "end_height": 5_953_262,
            "end_hash": self.bestblock,
            "pre_gold_rush_hash": "c" * 64,
            "first_gold_rush_hash": "d" * 64,
            "issued_claims": 3,
            "spent_claims": 0,
            "unspent_claims": 3,
        }

    def generate_evidence(self, records, *, dispositions=None,
                          dispositions_sha256=None):
        return self.audit.generate_evidence(
            self.rpc(records),
            source={
                "repository": "https://github.com/Blackcoin-Dev/Blackcoin.git",
                "commit": SOURCE_SHA,
                "clean": True,
            },
            binaries=self.binary_identities(),
            source_sha=SOURCE_SHA,
            server=self.server_identity(),
            dispositions=dispositions,
            dispositions_sha256=dispositions_sha256,
            page_size=1,
        )

    def verify_evidence(self, evidence, manifest, *, now=2_000_000_100,
                        actual_binaries=None):
        manifest_sha = hashlib.sha256(
            json.dumps(manifest, sort_keys=True).encode("utf-8")
        ).hexdigest()
        if actual_binaries is None:
            actual_binaries = evidence["binaries"]
        return self.verifier.verify_evidence_document(
            evidence,
            manifest,
            self.contract,
            target_sha=SOURCE_SHA,
            manifest_sha256=manifest_sha,
            contract_sha256=self.contract_sha,
            actual_binaries=actual_binaries,
            now=now,
        )

    def rehash_evidence(self, evidence):
        evidence.pop("evidence_payload_sha256", None)
        evidence["evidence_payload_sha256"] = hashlib.sha256(
            self.audit.canonical_bytes(evidence)
        ).hexdigest()

    def rpc(self, records, *, moving_page=False, truncate=False):
        def bucket(selected):
            return {
                "count": len(selected),
                "amount": f"{len(selected)}.00000000",
                "amount_atomic": str(len(selected) * 100_000_000),
            }

        def partition(field, cross_field=None):
            keys = {
                f"{record[field]}/{record[cross_field]}" if cross_field else record[field]
                for record in records
            }
            return {
                key: bucket([
                    record for record in records
                    if (f"{record[field]}/{record[cross_field]}" if cross_field
                        else record[field]) == key
                ])
                for key in keys
            }

        def call(method, *params):
            if method == "getblockchaininfo":
                return {
                    "chain": "main",
                    "blocks": 5_953_262,
                    "headers": 5_953_262,
                    "bestblockhash": self.bestblock,
                    "initialblockdownload": False,
                    "pruned": False,
                }
            if method == "getnetworkinfo":
                return {
                    "build": "v30.1.1rc1-test",
                    "source_commit": SOURCE_SHA,
                    "source_dirty": False,
                    "protocolversion": 70016,
                    "subversion": "/Blackcoin:30.1.1/",
                    "networkactive": False,
                }
            if method == "getquantumquasarinfo":
                return {
                    "phase": "gold_rush",
                    "phase_context": "next_block",
                    "active_tip_phase": "gold_rush",
                    "next_block_phase": "gold_rush",
                    "active_tip_height": 5_953_262,
                    "next_block_height": 5_953_263,
                    "lifecycle_schedule_valid": True,
                    "v4_activation_height": 5_950_000,
                    "gold_rush_end_height": 6_192_999,
                    "quantum_migration_end_height": 6_921_999,
                    "shadow_reward_start_height": 5_950_000,
                    "shadow_reward_end_height": 6_192_999,
                    "height_boundaries_authoritative": True,
                    "time_boundaries_are_estimates": True,
                    "shadow_merge_mining_active": True,
                    "shadow_reward_height_active": True,
                    "shadow_reward_next_height": 5_953_263,
                    "quantum_spend_enforcement_active": False,
                    "quantum_migration_outputs_fundable": False,
                    "legacy_addresses_accepted": True,
                    "quantum_address_required": False,
                    "qqp4_activation_disabled": True,
                    "qqp4_activation_height": 0,
                    "qqp4_active_at_tip": False,
                    "qqp4_active_next_block": False,
                    "qqp4_exact_input_required_next_block": False,
                }
            if method == "getblockhash":
                return self.audit.MAINNET_GENESIS_HASH
            if method == "getblockheader":
                return {
                    "hash": self.bestblock,
                    "height": 5_953_262,
                    "time": 2_000_000_000,
                    "confirmations": 1,
                }
            if method == "gettxoutsetinfo":
                return {
                    "height": 5_953_262,
                    "bestblock": self.bestblock,
                    "txouts": 50,
                    "muhash": self.muhash,
                    "total_amount": "100.00000000",
                }
            if method == "getcirculatingsupply":
                return {
                    "schema": "blackcoin.supply.lifecycle.v2",
                    "height": 5_953_262,
                    "evaluation_height": 5_953_263,
                    "bestblock": self.bestblock,
                    "height_boundaries_authoritative": True,
                    "nominal_amount": "100.00000000",
                    "synthetic_non_merkle_nominal_amount": "3.00000000",
                    "goldrush_synthetic_immature_amount": "1.00000000",
                    "goldrush_locked_payout_amount": "2.00000000",
                    "txouts": 50,
                    "goldrush_synthetic_immature_txouts": 1,
                    "goldrush_locked_payout_txouts": 2,
                    "shadow": {
                        "synthetic": True,
                        "merkle_included": False,
                        "issued_count": 3,
                        "issued_nominal_amount": "3.00000000",
                        "spent_count": 0,
                        "spent_nominal_amount": "0.00000000",
                        "unspent_count": 3,
                        "unspent_nominal_amount": "3.00000000",
                        "claimable_next_block": True,
                    },
                }
            if method != "getquantumwitnessinventory":
                raise AssertionError(method)
            _, offset, count, _ = params
            page_records = records[offset:offset + count]
            if truncate and offset:
                page_records = []
            page_end = offset + len(page_records)
            next_offset = page_end if page_end < len(records) else None
            page_bestblock = "e" * 64 if moving_page and offset else self.bestblock
            return {
                "schema": "blackcoin.quantum.witness_inventory.v1",
                "height": 5_953_262,
                "bestblock": page_bestblock,
                "view": "utxos",
                "offset": offset,
                "count": len(page_records),
                "total_records": len(records),
                "next_offset": next_offset,
                "classification": self.audit.INVENTORY_CLASSIFICATION,
                "utxo_snapshot": {
                    "algorithm": "muhash3072",
                    "commitment": self.muhash,
                    "txouts": 50,
                    "excludes_authenticated_zero_value_protocol_markers": True,
                },
                "current_utxos": {
                    "total": {
                        "count": len(records),
                        "amount": f"{len(records)}.00000000",
                        "amount_atomic": str(len(records) * 100_000_000),
                    },
                    "by_version": partition("version_class"),
                    "by_origin_group": partition("origin_group"),
                    "by_origin_phase": partition("origin_phase"),
                    "by_version_and_origin": partition(
                        "version_class", "origin_group",
                    ),
                    "by_bridge_handling": partition("bridge_handling"),
                    "excluded_synthetic_shadow": {
                        "count": 3,
                        "amount": "3.00000000",
                        "amount_atomic": "300000000",
                    },
                },
                "coverage": {
                    "snapshot_current_utxos_exact": True,
                    "snapshot_tip_still_active": True,
                    "snapshot_utxo_commitment_exact": True,
                    "snapshot_includes_mempool": False,
                    "snapshot_includes_synthetic_shadow_outputs": False,
                },
                "records": page_records,
            }
        return call

    def test_zero_result_is_explicit_and_source_bound(self):
        records = []
        server = {
            "launched_by_acceptance_verifier": True,
            "executable_sha256": "1" * 64,
            "process_image_binding": {
                "mechanism": "linux_proc_pid_exe",
                "observed_path": "/candidate/blackcoind",
                "sha256": "1" * 64,
            },
            "rpc_authentication": {
                "mechanism": "verifier_owned_cookie",
                "private_directory_mode": "0700",
                "cookie_path": "/private/rpc-auth.cookie",
                "secret_recorded": False,
            },
            "rpc_reported_build": "v30.1.1rc1-test",
            "rpc_reported_source_commit": SOURCE_SHA,
            "rpc_reported_source_dirty": False,
        }
        evidence = self.audit.generate_evidence(
            self.rpc(records),
            source={"repository": "https://github.com/Blackcoin-Dev/Blackcoin.git",
                    "commit": SOURCE_SHA, "clean": True},
            binaries={"blackcoind": {
                          "sha256": "1" * 64,
                          "version": (
                              "Blackcoin Core version v30.1.1rc1-test\n"
                              f"Source commit: {SOURCE_SHA}"
                          ),
                      },
                      "blackcoin_cli": {"sha256": "2" * 64}},
            source_sha=SOURCE_SHA,
            server=server,
            page_size=1,
        )
        self.assertEqual(evidence["source"]["commit"], SOURCE_SHA)
        self.assertEqual(evidence["snapshot"]["utxo_muhash"], self.muhash)
        self.assertEqual(
            evidence["bridge_review"]["result"], "zero_relevant_outpoints"
        )
        self.assertEqual(evidence["native_quantum_formats"]["count"], 0)
        self.assertEqual(
            evidence["live_shadow_reconciliation"]["unspent_count"], 3
        )
        self.assertRegex(evidence["evidence_payload_sha256"], r"^[0-9a-f]{64}$")

    def test_offline_production_verifier_authorizes_zero_review_capture(self):
        evidence = self.generate_evidence([])
        authorization = self.verify_evidence(evidence, self.capture_manifest())
        self.assertTrue(authorization["authorized"])
        self.assertEqual(
            authorization["mode"],
            "exact_final_mainnet_witness_inventory",
        )
        self.assertEqual(authorization["target_sha"], SOURCE_SHA)
        self.assertEqual(
            authorization["bridge_review"],
            {
                "result": "zero_relevant_outpoints",
                "count": 0,
                "dispositions_file_sha256": None,
            },
        )

    def test_offline_production_verifier_rejects_stale_or_tampered_capture(self):
        evidence = self.generate_evidence([])
        manifest = self.capture_manifest()
        with self.assertRaisesRegex(
            self.verifier.VerificationError, "capture is stale"
        ):
            self.verify_evidence(
                evidence,
                manifest,
                now=manifest["captured_at_unix"] + 86_401,
            )

        tampered_evidence = copy.deepcopy(evidence)
        tampered_evidence["snapshot"]["height"] += 1
        with self.assertRaisesRegex(
            self.verifier.VerificationError, "payload SHA256 does not match"
        ):
            self.verify_evidence(tampered_evidence, manifest)

        self.rehash_evidence(tampered_evidence)
        with self.assertRaisesRegex(
            self.verifier.VerificationError, "snapshot differs"
        ):
            self.verify_evidence(tampered_evidence, manifest)

        tampered_manifest = copy.deepcopy(manifest)
        tampered_manifest["capture_rpc"]["connections"] = 0
        with self.assertRaisesRegex(
            self.verifier.VerificationError, "connected synchronized exact tip"
        ):
            self.verify_evidence(evidence, tampered_manifest)

    def test_offline_production_verifier_binds_downloaded_binary_identity(self):
        evidence = self.generate_evidence([])
        manifest = self.capture_manifest()
        substituted = copy.deepcopy(evidence["binaries"])
        substituted["blackcoin_cli"]["sha256"] = "f" * 64
        with self.assertRaisesRegex(
            self.verifier.VerificationError, "bundled witness binaries differ"
        ):
            self.verify_evidence(
                evidence, manifest, actual_binaries=substituted,
            )

        wrong_source = copy.deepcopy(evidence)
        wrong_source["binaries"]["blackcoind"]["version"] = (
            "Blackcoin Core version v30.1.1rc1-test\n"
            f"Source commit: {'0' * 40}"
        )
        self.rehash_evidence(wrong_source)
        with self.assertRaisesRegex(
            self.verifier.VerificationError, "blackcoind is not bound"
        ):
            self.verify_evidence(wrong_source, manifest)

    def test_offline_production_verifier_enforces_disposition_paths(self):
        manifest = self.capture_manifest()
        zero_review = self.generate_evidence([])
        zero_review["acceptance"]["dispositions_file_sha256"] = "4" * 64
        self.rehash_evidence(zero_review)
        with self.assertRaisesRegex(
            self.verifier.VerificationError, "disposition-free"
        ):
            self.verify_evidence(zero_review, manifest)

        record = self.record(1, 16, "recognized_direct_quantum")
        disposition = {
            "schema": self.audit.DISPOSITIONS_SCHEMA,
            "source_commit": SOURCE_SHA,
            "network": "main",
            "snapshot": {
                "height": 5_953_262,
                "bestblock": self.bestblock,
                "utxo_muhash": self.muhash,
            },
            "outpoints": {
                f"{record['txid']}:{record['vout']}": {
                    "action": "preserve_locked_pending_protocol_review",
                    "rationale": "Exact-snapshot production review fixture.",
                    "approval_ref": "release-review-1",
                },
            },
        }
        disposition_sha = hashlib.sha256(
            json.dumps(disposition, sort_keys=True).encode("utf-8")
        ).hexdigest()
        nonzero_review = self.generate_evidence(
            [record], dispositions=disposition,
            dispositions_sha256=disposition_sha,
        )
        authorization = self.verify_evidence(nonzero_review, manifest)
        self.assertEqual(authorization["bridge_review"]["count"], 1)
        self.assertEqual(
            authorization["bridge_review"]["dispositions_file_sha256"],
            disposition_sha,
        )

        incomplete = copy.deepcopy(nonzero_review)
        incomplete["acceptance"]["dispositions_file_sha256"] = None
        self.rehash_evidence(incomplete)
        with self.assertRaisesRegex(
            self.verifier.VerificationError, "dispositions are incomplete"
        ):
            self.verify_evidence(incomplete, manifest)

    def test_protected_runner_binds_optional_dispositions(self):
        self.runner.verify_dispositions_input(None, "")
        with self.assertRaisesRegex(
            RuntimeError, "digest was supplied without"
        ):
            self.runner.verify_dispositions_input(None, "1" * 64)

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "dispositions.json"
            path.write_text('{"schema": 1}\n', encoding="utf-8")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.runner.verify_dispositions_input(path, digest)
            with self.assertRaisesRegex(RuntimeError, "lowercase hexadecimal"):
                self.runner.verify_dispositions_input(path, "")
            with self.assertRaisesRegex(RuntimeError, "immutable requested digest"):
                self.runner.verify_dispositions_input(path, "0" * 64)

    def test_every_relevant_outpoint_requires_snapshot_bound_disposition(self):
        records = [
            self.record(1, 2, "unknown_or_malformed_witness_program_requires_explicit_review"),
            self.record(2, 15, "recognized_eutxo"),
            self.record(3, 14, "unknown_or_malformed_witness_program_requires_explicit_review"),
            self.record(4, 16, "unknown_or_malformed_witness_program_requires_explicit_review"),
        ]
        inventory = self.audit.collect_inventory(self.rpc(records), page_size=2)
        with self.assertRaisesRegex(self.audit.AuditError, "dispositions file is required"):
            self.audit.apply_dispositions(
                inventory["records"], dispositions=None, source_sha=SOURCE_SHA,
                network="regtest", snapshot=inventory["snapshot"],
            )

        dispositions = {
            "schema": "blackcoin.quantum.witness_bridge_dispositions.v1",
            "source_commit": SOURCE_SHA,
            "network": "main",
            "snapshot": {
                "height": 5_953_262,
                "bestblock": self.bestblock,
                "utxo_muhash": self.muhash,
            },
            "outpoints": {
                f"{record['txid']}:{record['vout']}": {
                    "action": "preserve_locked_pending_protocol_review",
                    "rationale": "Fixture disposition for exact-snapshot acceptance coverage.",
                    "approval_ref": "test-review-1",
                }
                for record in records
            },
        }
        review, native = self.audit.apply_dispositions(
            inventory["records"], dispositions=dispositions,
            source_sha=SOURCE_SHA, network="main",
            snapshot=inventory["snapshot"],
        )
        self.assertEqual(review["result"], "explicit_per_outpoint_dispositions")
        self.assertEqual(review["count"], 4)
        self.assertEqual(native, [])

        dispositions["snapshot"]["bestblock"] = "f" * 64
        with self.assertRaisesRegex(self.audit.AuditError, "stale"):
            self.audit.apply_dispositions(
                inventory["records"], dispositions=dispositions,
                source_sha=SOURCE_SHA, network="main",
                snapshot=inventory["snapshot"],
            )

    def test_pre_migration_native_outputs_require_disposition(self):
        pre_migration = self.record(
            1, 16, "recognized_direct_quantum",
            origin_group="pre_migration_window",
        )
        self.assertEqual(self.audit.review_class(pre_migration), "pre_migration_v16")
        after_migration = self.record(
            2, 16, "recognized_direct_quantum",
            origin_group="migration_or_later",
        )
        self.assertIsNone(self.audit.review_class(after_migration))

    def test_release_evidence_rejects_non_mainnet_identity(self):
        with self.assertRaisesRegex(self.audit.AuditError, "must be generated on mainnet"):
            self.audit.validate_mainnet_identity(
                "regtest",
                {
                    "build": "v30.1.1rc1-test",
                    "source_commit": SOURCE_SHA,
                    "source_dirty": False,
                    "networkactive": False,
                },
                {},
                self.audit.MAINNET_GENESIS_HASH,
                {"height": 5_953_262},
                SOURCE_SHA,
            )

    def test_verifier_rejects_direct_and_negated_identity_overrides(self):
        controlled = self.audit.VerifierOwnedDaemon.CONTROLLED_ARGUMENTS
        for argument in (
            "-chain=regtest", "-regtest=1", "-noregtest=0",
            "-networkactive=1", "-nonetworkactive=0", "-wallet=test.dat",
            "-rpcuser=other", "-rpcpassword=other", "-rpcauth=other",
            "-rpccookiefile=/other/cookie",
        ):
            with self.subTest(argument=argument):
                self.assertIn(self.audit._argument_name(argument), controlled)

    def test_verifier_daemon_and_cli_share_private_cookie(self):
        with tempfile.TemporaryDirectory() as temporary:
            datadir = Path(temporary) / "datadir"
            datadir.mkdir()
            daemon = self.audit.VerifierOwnedDaemon(
                "/candidate/blackcoind", "/candidate/blackcoin-cli",
                datadir, [], startup_timeout=1,
            )
            process = mock.Mock()
            process.poll.return_value = None
            with mock.patch.object(
                self.audit.subprocess, "Popen", return_value=process,
            ) as popen, mock.patch.object(
                self.audit, "_run", return_value="{}",
            ):
                daemon.__enter__()
                command = popen.call_args.args[0]
                daemon_cookie = next(
                    item for item in command if item.startswith("-rpccookiefile=")
                )
                cli_cookie = next(
                    item for item in daemon.cli_options
                    if item.startswith("-rpccookiefile=")
                )
                self.assertEqual(daemon_cookie, cli_cookie)
                cookie_path = Path(daemon_cookie.split("=", 1)[1])
                self.assertEqual(cookie_path.parent, Path(daemon.temporary.name))
                self.assertEqual(cookie_path.parent.stat().st_mode & 0o777, 0o700)
                process.poll.return_value = 0
                daemon.__exit__(None, None, None)

    def test_linux_process_image_binding_hashes_the_running_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "blackcoind"
            binary.write_bytes(b"exact candidate image")
            process = root / "123"
            process.mkdir()
            (process / "exe").symlink_to(binary)
            expected = hashlib.sha256(binary.read_bytes()).hexdigest()
            identity = self.audit._proc_process_image_identity(
                123, expected, proc_root=root,
            )
            self.assertEqual(identity["mechanism"], "linux_proc_pid_exe")
            self.assertEqual(identity["sha256"], expected)
            with self.assertRaisesRegex(
                self.audit.AuditError, "process image differs"
            ):
                self.audit._proc_process_image_identity(
                    123, "0" * 64, proc_root=root,
                )

    def test_inventory_record_and_aggregate_mismatches_fail_closed(self):
        record = self.record(1, 16, "recognized_direct_quantum")
        malformed = dict(record)
        malformed["scriptPubKey"] = "5f20" + "11" * 32
        with self.assertRaisesRegex(
            self.audit.AuditError, "declared witness version"
        ):
            self.audit.collect_inventory(self.rpc([malformed]), page_size=1)

        original = self.rpc([record])

        def inconsistent(method, *params):
            response = original(method, *params)
            if method == "getquantumwitnessinventory":
                response["current_utxos"]["total"]["amount_atomic"] = "2"
            return response

        with self.assertRaisesRegex(
            self.audit.AuditError, "display and atomic amounts disagree"
        ):
            self.audit.collect_inventory(inconsistent, page_size=1)

    def test_moving_tip_and_incomplete_pagination_fail_closed(self):
        records = [
            self.record(1, 16, "recognized_direct_quantum"),
            self.record(2, 14, "recognized_quantum_cold_stake"),
        ]
        with self.assertRaisesRegex(self.audit.AuditError, "snapshot changed"):
            self.audit.collect_inventory(
                self.rpc(records, moving_page=True), page_size=1
            )
        with self.assertRaisesRegex(self.audit.AuditError, "non-contiguous|non-progressing"):
            self.audit.collect_inventory(
                self.rpc(records, truncate=True), page_size=1
            )


if __name__ == "__main__":
    unittest.main()
