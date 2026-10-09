#!/bin/sh
# Builds and runs the portable device identity tests with whatever C++20 compiler is available.
set -e
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
out=${TMPDIR:-/tmp}/device_identity_tests
cxx=${CXX:-}
if [ -z "$cxx" ]; then
  for candidate in clang++ g++ c++; do
    if command -v "$candidate" >/dev/null 2>&1; then cxx=$candidate; break; fi
  done
fi
"$cxx" -std=c++20 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined \
  -I"$root/common/device_identity" "$here/device_identity_tests.cpp" -o "$out"
"$out"

snap=${TMPDIR:-/tmp}/other_env_snapshot_tests
"$cxx" -std=c++20 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -pthread \
  -I"$root/MemoryDll/rpc" "$here/other_env_snapshot_tests.cpp" -o "$snap"
"$snap"
