#!/bin/sh
# Build and test Loki. Usage: ./scripts/build.sh [preset] [--no-test]
set -e
preset="default"
run_tests=1
for arg in "$@"; do
  case "$arg" in
    --no-test) run_tests=0 ;;
    *) preset="$arg" ;;
  esac
done
cmake --preset "$preset"
cmake --build --preset "$preset" -j "$(sysctl -n hw.ncpu 2>/dev/null || nproc)"
if [ "$run_tests" -eq 1 ]; then
  ctest --preset "$preset"
fi
