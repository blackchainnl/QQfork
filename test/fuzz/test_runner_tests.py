#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for source-pinned fuzz regression inputs."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import test_runner

from test_runner import (
    decode_pinned_regression,
    missing_pinned_regression_targets,
    PINNED_REGRESSION_INPUTS,
)


FAKE_CONFIG = """\
[components]
ENABLE_FUZZ_BINARY = true
[environment]
BUILDDIR = /tmp/blackcoin-fuzz-build
SRCDIR = /tmp/blackcoin-fuzz-source
"""


class PinnedFuzzRegressionTests(unittest.TestCase):
    def test_block_chainstate_regression_is_exact(self):
        regression = PINNED_REGRESSION_INPUTS['block'][0]
        data = decode_pinned_regression(regression)
        self.assertEqual(regression['name'], 'initialized-chainstate')
        self.assertEqual(len(data), 89)
        self.assertEqual(data[:4], bytes.fromhex('01800000'))

    def test_corrupt_regression_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            decode_pinned_regression({
                'name': 'corrupt',
                'base64': 'AA==',
                'sha256': '0' * 64,
            })

    def test_malformed_base64_fails_closed(self):
        with self.assertRaisesRegex(ValueError, 'invalid pinned'):
            decode_pinned_regression({
                'name': 'malformed',
                'base64': '*',
                'sha256': '0' * 64,
            })

    def test_required_block_regression_cannot_be_omitted(self):
        self.assertEqual(missing_pinned_regression_targets([]), ['block'])
        self.assertEqual(missing_pinned_regression_targets(['transaction']), ['block'])
        self.assertEqual(missing_pinned_regression_targets(['block']), [])

    def test_ordinary_targeted_run_may_omit_pinned_block(self):
        help_result = subprocess.CompletedProcess([], 0, stderr='standalone fuzz driver')
        with tempfile.TemporaryDirectory() as corpus_dir:
            (Path(corpus_dir) / 'transaction').mkdir()
            with mock.patch.object(sys, 'argv', ['test_runner.py', corpus_dir, 'transaction']), \
                    mock.patch('builtins.open', mock.mock_open(read_data=FAKE_CONFIG)), \
                    mock.patch.object(test_runner, 'parse_test_list', return_value=['block', 'transaction']), \
                    mock.patch.object(test_runner.subprocess, 'run', return_value=help_result) as subprocess_run, \
                    mock.patch.object(test_runner, 'run_once') as run_once:
                test_runner.main()

        subprocess_run.assert_called_once()
        run_once.assert_called_once()
        self.assertEqual(run_once.call_args.kwargs['test_list'], ['transaction'])

    def test_required_run_rejects_absent_or_excluded_block(self):
        cases = (
            ('absent', ['test_runner.py', '--require-pinned-regressions', 'corpus', 'transaction']),
            ('excluded', ['test_runner.py', '--require-pinned-regressions', '--exclude', 'block', 'corpus']),
        )
        for name, argv in cases:
            with self.subTest(name=name):
                with mock.patch.object(sys, 'argv', argv), \
                        mock.patch('builtins.open', mock.mock_open(read_data=FAKE_CONFIG)), \
                        mock.patch.object(test_runner, 'parse_test_list', return_value=['block', 'transaction']), \
                        mock.patch.object(test_runner.subprocess, 'run') as subprocess_run, \
                        mock.patch.object(test_runner, 'run_pinned_regressions') as pinned, \
                        self.assertLogs(level='ERROR'):
                    with self.assertRaises(SystemExit) as error:
                        test_runner.main()
                self.assertEqual(error.exception.code, 1)
                subprocess_run.assert_not_called()
                pinned.assert_not_called()

    def test_nonzero_pinned_regression_is_fatal(self):
        expected = decode_pinned_regression(PINNED_REGRESSION_INPUTS['block'][0])

        def fail_regression(args, **kwargs):
            self.assertEqual(args[1], '-runs=1')
            self.assertEqual(Path(args[-1]).read_bytes(), expected)
            return subprocess.CompletedProcess(args, 9, stderr='pinned regression failure')

        with mock.patch.object(test_runner.subprocess, 'run', side_effect=fail_regression) as run:
            with self.assertRaises(SystemExit) as error:
                test_runner.run_pinned_regressions(
                    targets=['block'],
                    src_dir='/tmp/blackcoin-source',
                    build_dir='/tmp/blackcoin-build',
                    using_libfuzzer=True,
                    use_valgrind=False,
                )

        self.assertEqual(error.exception.code, 1)
        run.assert_called_once()

    def test_required_generate_and_merge_run_regression_first(self):
        help_result = subprocess.CompletedProcess([], 0, stderr='libFuzzer')
        with tempfile.TemporaryDirectory() as temporary:
            corpus_dir = str(Path(temporary) / 'corpus')
            merge_dir = str(Path(temporary) / 'merge')
            Path(corpus_dir).mkdir()
            Path(merge_dir).mkdir()
            cases = (
                ('generate', ['test_runner.py', '--require-pinned-regressions', '--generate', corpus_dir, 'block'], 'generate_corpus'),
                ('merge', ['test_runner.py', '--require-pinned-regressions', '--m_dir', merge_dir, corpus_dir, 'block'], 'merge_inputs'),
            )
            for name, argv, mode_function in cases:
                with self.subTest(name=name):
                    calls = []

                    def record_pinned(**kwargs):
                        self.assertEqual(kwargs['targets'], ['block'])
                        self.assertTrue(kwargs['using_libfuzzer'])
                        calls.append('pinned')

                    def record_mode(**kwargs):
                        calls.append(name)

                    with mock.patch.object(sys, 'argv', argv), \
                            mock.patch('builtins.open', mock.mock_open(read_data=FAKE_CONFIG)), \
                            mock.patch.object(test_runner, 'parse_test_list', return_value=['block']), \
                            mock.patch.object(test_runner.subprocess, 'run', return_value=help_result), \
                            mock.patch.object(test_runner, 'run_pinned_regressions', side_effect=record_pinned), \
                            mock.patch.object(test_runner, mode_function, side_effect=record_mode), \
                            mock.patch.object(test_runner, 'run_once') as run_once:
                        test_runner.main()

                    self.assertEqual(calls, ['pinned', name])
                    run_once.assert_not_called()

    def test_release_fuzz_environment_retains_required_flag(self):
        repository = Path(__file__).resolve().parents[2]
        fuzz_environment = (repository / 'ci/test/00_setup_env_native_fuzz.sh').read_text(encoding='utf-8')
        fuzz_driver = (repository / 'ci/test/06_script_b.sh').read_text(encoding='utf-8')
        workflow = (repository / '.github/workflows/pr-gate.yml').read_text(encoding='utf-8')

        self.assertIn('export FUZZ_TESTS_CONFIG="--require-pinned-regressions"', fuzz_environment)
        self.assertIn('test/fuzz/test_runner.py ${FUZZ_TESTS_CONFIG}', fuzz_driver)
        self.assertIn('FILE_ENV: ci/test/00_setup_env_native_fuzz.sh', workflow)


if __name__ == '__main__':
    unittest.main()
