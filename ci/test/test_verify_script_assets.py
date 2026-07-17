#!/usr/bin/env python3
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests for the fail-closed script-assets corpus preflight."""

import unittest

from verify_script_assets import CorpusError, transaction_version, verify_vectors


class ScriptAssetsPreflightTests(unittest.TestCase):
    def test_signed_little_endian_version(self):
        self.assertEqual(transaction_version("01000000", 0), 1)
        self.assertEqual(transaction_version("02000000", 0), 2)
        self.assertEqual(transaction_version("ffffff7f", 0), 2_147_483_647)
        self.assertEqual(transaction_version("00000080", 0), -2_147_483_648)
        self.assertEqual(transaction_version("ffffffff", 0), -1)

    def test_only_version_two_or_greater_is_compatible(self):
        vectors = [
            {"tx": "ffffffff"},
            {"tx": "01000000"},
            {"tx": "02000000"},
            {"tx": "ffffff7f"},
        ]
        counts = verify_vectors(
            vectors,
            expected_total=4,
            expected_incompatible=2,
            expected_compatible=2,
        )
        self.assertEqual(counts.incompatible, 2)
        self.assertEqual(counts.compatible, 2)

    def test_malformed_or_missing_transactions_fail(self):
        bad_vectors = [
            [{}],
            [{"tx": 2}],
            [{"tx": "0200000"}],
            [{"tx": "0200000z"}],
            ["02000000"],
        ]
        for vectors in bad_vectors:
            with self.subTest(vectors=vectors):
                with self.assertRaises(CorpusError):
                    verify_vectors(
                        vectors,
                        expected_total=1,
                        expected_incompatible=0,
                        expected_compatible=1,
                    )

    def test_changed_counts_fail_closed(self):
        with self.assertRaisesRegex(CorpusError, "classification changed"):
            verify_vectors(
                [{"tx": "02000000"}],
                expected_total=1,
                expected_incompatible=1,
                expected_compatible=0,
            )


if __name__ == "__main__":
    unittest.main()
