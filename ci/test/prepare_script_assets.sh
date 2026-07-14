#!/usr/bin/env bash
# Copyright (c) 2026 The Blackcoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8
set -euo pipefail

readonly QA_ASSETS_COMMIT=0772287676fdf3fcf87631b383b12442ab48ce75
readonly SCRIPT_ASSETS_SHA256=cd789a58ec45916e1721cdd14e82ca4c93100959f1cef4e229b22e3bf539f095
readonly SCRIPT_ASSETS_NAME=script_assets_test.json
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd)"
readonly SCRIPT_ROOT

: "${DIR_UNIT_TEST_DATA:?DIR_UNIT_TEST_DATA must name the script corpus directory}"
mkdir -p "${DIR_UNIT_TEST_DATA}"
readonly corpus_path="${DIR_UNIT_TEST_DATA%/}/${SCRIPT_ASSETS_NAME}"

if [[ ! -f "${corpus_path}" ]]; then
  readonly temporary_path="${corpus_path}.download.$$"
  trap 'rm -f "${temporary_path}"' EXIT
  curl --location --fail --silent --show-error --retry 3 --retry-delay 1 --retry-all-errors \
    "https://raw.githubusercontent.com/bitcoin-core/qa-assets/${QA_ASSETS_COMMIT}/unit_test_data/${SCRIPT_ASSETS_NAME}" \
    --output "${temporary_path}"
  mv "${temporary_path}" "${corpus_path}"
  trap - EXIT
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_hash="$(sha256sum "${corpus_path}" | awk '{print $1}')"
else
  actual_hash="$(shasum -a 256 "${corpus_path}" | awk '{print $1}')"
fi
test "${actual_hash}" = "${SCRIPT_ASSETS_SHA256}"
echo "${corpus_path}: OK"

test -r "${corpus_path}"
python3 "${SCRIPT_ROOT}/ci/test/verify_script_assets.py" "${corpus_path}"
