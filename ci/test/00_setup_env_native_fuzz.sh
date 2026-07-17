#!/usr/bin/env bash
#
# Copyright (c) 2019-present Blackcoin Core Developers
# Copyright (c) 2019-present Blackcoin More Developers
# Copyright (c) 2019-present Blackcoin Developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CI_IMAGE_NAME_TAG="docker.io/ubuntu:24.04"
export CONTAINER_NAME=ci_native_fuzz
export PACKAGES="cmake clang-17 llvm-17 libclang-rt-17-dev libevent-dev libboost-dev libsqlite3-dev"
# Build the consensus-critical pinned liboqs dependency.  Fuzzing against an
# arbitrary host library would not exercise the release implementation.
export DEP_OPTS="NO_QT=1 NO_UPNP=1 NO_NATPMP=1 CC=clang-17 CXX=clang++-17"
export RUN_UNIT_TESTS=false
export RUN_FUNCTIONAL_TESTS=false
export RUN_FUZZ_TESTS=true
export FUZZ_TESTS_CONFIG="--require-pinned-regressions --pinned-regressions-only"
export GOAL="install"
export CI_CONTAINER_CAP="--cap-add SYS_PTRACE"  # If run with (ASan + LSan), the container needs access to ptrace (https://github.com/google/sanitizers/issues/764)
export BITCOIN_CONFIG="--enable-fuzz --with-sanitizers=fuzzer,address,undefined,float-divide-by-zero,integer \
CC='clang-17 -ftrivial-auto-var-init=pattern' CXX='clang++-17 -ftrivial-auto-var-init=pattern'"
export CCACHE_MAXSIZE=200M
