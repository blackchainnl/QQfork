# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fail-closed tests for release-CI source identity freezing."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
GENBUILD = ROOT / "share" / "genbuild.sh"


class FrozenSourceIdentityTests(unittest.TestCase):
    def make_repository(self, directory, tag=None):
        repository = directory / "source"
        repository.mkdir()
        subprocess.run(["git", "init", "-q", repository], check=True)
        (repository / "tracked.txt").write_text("identity\n", encoding="utf-8")
        subprocess.run(["git", "-C", repository, "add", "tracked.txt"], check=True)
        subprocess.run(
            [
                "git", "-C", repository,
                "-c", "user.name=Blackcoin-Dev",
                "-c", "user.email=298119138+Blackcoin-Dev@users.noreply.github.com",
                "commit", "-q", "-m", "identity fixture",
            ],
            check=True,
        )
        source_sha = subprocess.check_output(
            ["git", "-C", repository, "rev-parse", "HEAD"], text=True,
        ).strip()
        if tag:
            subprocess.run(["git", "-C", repository, "tag", tag], check=True)
        return repository, source_sha

    def generate(self, repository, header):
        subprocess.run([GENBUILD, header, repository], check=True)
        return header.read_text(encoding="utf-8")

    def freeze(self, repository, header, source_sha, check=True, extra_env=None):
        environment = os.environ.copy()
        environment["BITCOIN_GENBUILD_FROZEN_SOURCE_COMMIT"] = source_sha
        environment.update(extra_env or {})
        return subprocess.run(
            [GENBUILD, header, repository],
            check=check,
            capture_output=True,
            text=True,
            env=environment,
        )

    def test_clean_snapshot_survives_later_untracked_build_output(self):
        for tag in (None, "v30.1.1-test"):
            with self.subTest(tag=tag), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                repository, source_sha = self.make_repository(directory, tag=tag)
                header = directory / "build.h"
                original = self.generate(repository, header)
                (repository / "parallel-build-output").write_text(
                    "generated after the clean snapshot\n", encoding="utf-8",
                )
                self.freeze(repository, header, source_sha)
                self.assertEqual(header.read_text(encoding="utf-8"), original)
                self.assertIn("#define BUILD_SOURCE_DIRTY 0", original)

    def test_invalid_empty_or_mismatched_commit_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repository, source_sha = self.make_repository(directory)
            header = directory / "build.h"
            self.generate(repository, header)
            for candidate, message in (
                ("", "full lowercase SHA-1"),
                (source_sha[:12], "full lowercase SHA-1"),
                ("0" * 40, "does not match the current HEAD"),
            ):
                with self.subTest(candidate=candidate):
                    result = self.freeze(
                        repository, header, candidate, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(message, result.stderr)

    def test_tracked_and_staged_changes_fail(self):
        for staged, message in (
            (False, "tracked source changed"),
            (True, "staged source changed"),
        ):
            with self.subTest(staged=staged), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                repository, source_sha = self.make_repository(directory)
                header = directory / "build.h"
                self.generate(repository, header)
                (repository / "tracked.txt").write_text("changed\n", encoding="utf-8")
                if staged:
                    subprocess.run(
                        ["git", "-C", repository, "add", "tracked.txt"], check=True,
                    )
                result = self.freeze(repository, header, source_sha, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_missing_or_tampered_header_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repository, source_sha = self.make_repository(directory)
            header = directory / "build.h"
            missing = self.freeze(repository, header, source_sha, check=False)
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("does not exist", missing.stderr)

            original = self.generate(repository, header)
            for tampered in (
                original.replace(source_sha, "f" * 40),
                original.replace(source_sha[:12], "f" * 12),
                original.replace("BUILD_SOURCE_DIRTY 0", "BUILD_SOURCE_DIRTY 1"),
                original + "#define INJECTED_IDENTITY 1\n",
                original + f'#define BUILD_GIT_COMMIT "{source_sha[:12]}"\n',
            ):
                with self.subTest(tampered=tampered):
                    header.write_text(tampered, encoding="utf-8")
                    result = self.freeze(repository, header, source_sha, check=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("does not exactly match", result.stderr)

    def test_frozen_identity_cannot_disable_git(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            repository, source_sha = self.make_repository(directory)
            header = directory / "build.h"
            self.generate(repository, header)
            result = self.freeze(
                repository,
                header,
                source_sha,
                check=False,
                extra_env={"BITCOIN_GENBUILD_NO_GIT": "1"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot disable git verification", result.stderr)

    def test_workflow_freezes_only_macos_between_exhaustive_clean_gates(self):
        workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(
            encoding="utf-8"
        )
        before = workflow.index(
            'source_status=$(git status --porcelain=v1 --untracked-files=all)'
        )
        scoped = workflow.index('case "${{ matrix.name }}" in', before)
        self.assertIn("macos-*)", workflow[scoped:])
        generate = workflow.index('./share/genbuild.sh "$PWD/src/obj/build.h" "$PWD"', scoped)
        freeze = workflow.index(
            'export BITCOIN_GENBUILD_FROZEN_SOURCE_COMMIT="$TARGET_SHA"', generate
        )
        build = workflow.index('for goal in ${{ matrix.goal }}; do', freeze)
        post = workflow.index(
            "- name: Verify generated source identity and clean checkout", build
        )
        final_head = workflow.index(
            'test "$(git rev-parse --verify HEAD)" = "$TARGET_SHA"', post
        )
        final_freeze = workflow.index(
            'BITCOIN_GENBUILD_FROZEN_SOURCE_COMMIT="$TARGET_SHA"', final_head
        )
        final_generate = workflow.index(
            './share/genbuild.sh "$PWD/src/obj/build.h" "$PWD"', final_freeze
        )
        after = workflow.index(
            'source_status=$(git status --porcelain=v1 --untracked-files=all)',
            final_generate,
        )
        self.assertLess(before, scoped)
        self.assertLess(scoped, generate)
        self.assertLess(generate, freeze)
        self.assertLess(freeze, build)
        self.assertLess(build, post)
        self.assertLess(post, final_head)
        self.assertLess(final_head, final_freeze)
        self.assertLess(final_freeze, final_generate)
        self.assertLess(final_generate, after)
        self.assertLess(build, after)
        self.assertIn(
            './share/genbuild.sh "$PWD/src/obj/build.h" "$PWD"',
            workflow[freeze:build],
        )
        self.assertIn("git diff --quiet --exit-code --", workflow[build:after])
        self.assertIn("git diff --cached --quiet --exit-code --", workflow[build:after])
        self.assertNotIn("GITHUB_ENV", workflow[scoped:build])
        self.assertIn('expected_source_line="Source commit: $TARGET_SHA"', workflow)
        self.assertGreaterEqual(
            workflow.count(
                'sed -n \'2p\')" = "$expected_source_line"'
            ),
            2,
        )
        self.assertGreaterEqual(
            workflow.count('if [[ "$PUBLISH" == true ]]; then'), 2
        )
        self.assertGreaterEqual(
            workflow.count('expected_line="Blackcoin version v$VERSION"'), 2
        )
        self.assertGreaterEqual(
            workflow.count(
                'expected_line="Blackcoin version v$CONFIGURED_VERSION-${TARGET_SHA:0:12}"'
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main()
