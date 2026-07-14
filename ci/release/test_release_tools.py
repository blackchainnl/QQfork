#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regression tests for fail-closed release metadata and identity tooling."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
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


class ReleaseToolTests(unittest.TestCase):
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
            self.assertEqual(provenance_document["_type"], "https://in-toto.io/Statement/v1")
            self.assertEqual(
                provenance_document["predicate"]["buildDefinition"]["externalParameters"]["source"]["digest"]["gitCommit"],
                SOURCE_SHA,
            )
            subject_names = {subject["name"] for subject in provenance_document["subject"]}
            self.assertIn("Blackcoin-30.1.1-test.bin", subject_names)
            self.assertIn(sbom.name, subject_names)
            self.assertNotIn(provenance.name, subject_names)


if __name__ == "__main__":
    unittest.main()
