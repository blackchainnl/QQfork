#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for source-pinned fuzz regression inputs."""

import unittest

from test_runner import decode_pinned_regression, PINNED_REGRESSION_INPUTS


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


if __name__ == '__main__':
    unittest.main()
