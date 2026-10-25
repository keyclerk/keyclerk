#!/bin/bash -eu
# SPDX-License-Identifier: EUPL-1.2
# Every tools/fuzz_*.py becomes a fuzz target, with the keyclerk package on its path (compile_python_fuzzer is
# OSS-Fuzz's, from the base image; extra arguments go to PyInstaller).
cd "$SRC/keyclerk"
for fuzzer in tools/fuzz_*.py; do
  compile_python_fuzzer "$fuzzer" --paths "$SRC/keyclerk"
done
