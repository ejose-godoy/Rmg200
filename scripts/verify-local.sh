#!/usr/bin/env bash
# Testes puramente estaticos; nao compila nem executa kernel no dispositivo.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
printf "=== LOCAL SAFE VALIDATION ===\n"
bash -n scripts/preflight.sh scripts/run-lab.sh scripts/verify-local.sh
bash scripts/preflight.sh
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
if command -v cc >/dev/null 2>&1; then
  cc -std=gnu11 -Wall -Wextra -Werror -fsyntax-only initramfs/init.c
  echo "PASS: initramfs/init.c syntax (no executable produced)"
else
  echo "INFO: cc ausente, verificacao sintatica C adiada"
fi
echo "PASS: local static validation"
