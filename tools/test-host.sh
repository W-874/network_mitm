#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
test_bin=$(mktemp /tmp/nextendo-pki-test.XXXXXX)
trap 'rm -f "$test_bin"' EXIT
"${CXX:-g++}" -std=c++17 -Wall -Wextra -Werror -O2 \
    ${SANITIZER_FLAGS:-} -Inetwork_mitm/source tests/test_pki.cpp -o "$test_bin"
"$test_bin"
