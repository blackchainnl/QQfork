#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Regression tests for fail-closed release metadata and identity tooling."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
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


def load_path(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseToolTests(unittest.TestCase):
    def test_resource_benchmark_evidence_is_source_bound_and_fail_closed(self):
        generator = load_module("generate_resource_benchmark_evidence")
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
            binary.write_bytes(b"exact-benchmark-binary")
            evidence = generator.generate_evidence(
                nanobench_json=raw,
                binary=binary,
                source_sha=source_sha,
                repo_root=repository,
                repository="Blackcoin-Dev/Blackcoin",
                platform="linux",
                architecture="x86_64",
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

            synthetic_result = document["results"].pop()
            raw.write_text(json.dumps(document), encoding="utf-8")
            partial_evidence = generator.generate_evidence(
                nanobench_json=raw,
                binary=binary,
                source_sha=source_sha,
                repo_root=repository,
                repository="Blackcoin-Dev/Blackcoin",
                platform="linux",
                architecture="x86_64",
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
                    platform="linux",
                    architecture="x86_64",
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
                    platform="linux",
                    architecture="x86_64",
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
                    platform="linux",
                    architecture="x86_64",
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
        self.assertIn("test \"${#resource_evidence[@]}\" -eq 3", release)

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
                "signed=false\nnotarized=false\npublished=false\n",
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
                "signed=false\nnotarized=false\npublished=false\n",
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
                "signed=false\nnotarized=false\npublished=false\n",
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

            self.assertEqual(manifest["package_label"], package_label)
            self.assertEqual(manifest["prerelease_channel"], "beta")
            self.assertEqual(manifest["source"]["commit"], SOURCE_SHA)
            self.assertFalse(manifest["release"]["published"])

    def test_prerelease_workflow_keeps_the_signed_production_gate_separate(self):
        workflow = (TOOLS.parent.parent / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("default: 30.1.1-alpha1", workflow)
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


class WitnessInventoryAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.audit = load_path(
            "quantum_witness_inventory_audit",
            TOOLS.parents[1] / "contrib" / "devtools" /
            "quantum_witness_inventory_audit.py",
        )
        self.bestblock = "a" * 64
        self.muhash = "b" * 64

    def record(self, number, version, handling):
        version_class = {14: "v14", 15: "v15", 16: "v16"}.get(
            version, "unknown"
        )
        return {
            "txid": f"{number:064x}",
            "vout": number,
            "amount": "1.00000000",
            "scriptPubKey": "5120" + "11" * 32,
            "witness_version": version,
            "version_class": version_class,
            "bridge_handling": handling,
            "origin_height": 100,
            "origin_blockhash": "c" * 64,
            "origin_phase": "gold_rush",
            "origin_group": "pre_migration_window",
        }

    def rpc(self, records, *, moving_page=False, truncate=False):
        def call(method, *params):
            if method == "getblockchaininfo":
                return {
                    "chain": "regtest",
                    "blocks": 120,
                    "bestblockhash": self.bestblock,
                    "initialblockdownload": False,
                }
            if method == "getnetworkinfo":
                return {"protocolversion": 70016, "subversion": "/Blackcoin:30.1.1/"}
            if method == "getquantumquasarinfo":
                return {
                    "phase": "migration",
                    "active_tip_phase": "gold_rush",
                    "next_block_phase": "migration",
                    "active_tip_height": 120,
                    "next_block_height": 121,
                    "gold_rush_end_height": 120,
                    "quantum_migration_end_height": 220,
                    "height_boundaries_authoritative": True,
                    "quantum_spend_enforcement_active": True,
                    "legacy_addresses_accepted": True,
                    "quantum_address_required": False,
                }
            if method == "getblockhash":
                return "d" * 64
            if method == "getblockheader":
                return {
                    "hash": self.bestblock,
                    "height": 120,
                    "time": 2_000_000_000,
                    "confirmations": 1,
                }
            if method == "gettxoutsetinfo":
                return {
                    "height": 120,
                    "bestblock": self.bestblock,
                    "txouts": 50,
                    "muhash": self.muhash,
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
                "height": 120,
                "bestblock": page_bestblock,
                "view": "utxos",
                "offset": offset,
                "count": len(page_records),
                "total_records": len(records),
                "next_offset": next_offset,
                "classification": "native value-bearing witness versions >1",
                "utxo_snapshot": {
                    "algorithm": "muhash3072",
                    "commitment": self.muhash,
                    "txouts": 50,
                    "excludes_authenticated_zero_value_protocol_markers": True,
                },
                "current_utxos": {
                    "total": {"count": len(records), "amount": "1.00000000", "amount_atomic": "100000000"},
                },
                "coverage": {
                    "snapshot_current_utxos_exact": True,
                    "snapshot_tip_still_active": True,
                    "snapshot_utxo_commitment_exact": True,
                    "snapshot_includes_mempool": False,
                },
                "records": page_records,
            }
        return call

    def test_zero_result_is_explicit_and_source_bound(self):
        records = [self.record(1, 16, "recognized_direct_quantum")]
        evidence = self.audit.generate_evidence(
            self.rpc(records),
            source={"repository": "https://github.com/Blackcoin-Dev/Blackcoin.git",
                    "commit": SOURCE_SHA, "clean": True},
            binaries={"blackcoind": {"sha256": "1" * 64},
                      "blackcoin_cli": {"sha256": "2" * 64}},
            source_sha=SOURCE_SHA,
            page_size=1,
        )
        self.assertEqual(evidence["source"]["commit"], SOURCE_SHA)
        self.assertEqual(evidence["snapshot"]["utxo_muhash"], self.muhash)
        self.assertEqual(
            evidence["bridge_review"]["result"], "zero_relevant_outpoints"
        )
        self.assertEqual(evidence["native_quantum_formats"]["count"], 1)
        self.assertRegex(evidence["evidence_payload_sha256"], r"^[0-9a-f]{64}$")

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
            "network": "regtest",
            "snapshot": {
                "height": 120,
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
            source_sha=SOURCE_SHA, network="regtest",
            snapshot=inventory["snapshot"],
        )
        self.assertEqual(review["result"], "explicit_per_outpoint_dispositions")
        self.assertEqual(review["count"], 4)
        self.assertEqual(native, [])

        dispositions["snapshot"]["bestblock"] = "f" * 64
        with self.assertRaisesRegex(self.audit.AuditError, "stale"):
            self.audit.apply_dispositions(
                inventory["records"], dispositions=dispositions,
                source_sha=SOURCE_SHA, network="regtest",
                snapshot=inventory["snapshot"],
            )

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
