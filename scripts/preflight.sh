#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# Protecao preventiva: nao enviar binarios, partições ou artefatos privados no repositorio.
mapfile -d '' suspicious < <(find . -type f \
  \( -iname '*.img' -o -iname '*.elf' -o -iname '*.dtb' -o -iname '*.bin' \
     -o -iname '*.cpio' -o -iname '*.cpio.gz' -o -iname '*magisk*' \
     -o -iname '*boot_a*' -o -iname '*userdata*' -o -iname '*sepolicy*' \
     -o -iname '*.key' -o -iname '*.pem' \) -print0)
if ((${#suspicious[@]})); then
  printf 'BLOQUEADO: possiveis arquivos privados encontrados:\n' >&2
  printf '  %s\n' "${suspicious[@]}" >&2
  exit 21
fi
for file in scripts/run-lab.sh scripts/preflight.sh initramfs/init.c \
            .github/workflows/arm64-kasan-lab.yml; do
  test -s "$file" || { echo "FALHA: ausente $file" >&2; exit 22; }
done
printf 'PASS: sem imagens de boot, chaves, binarios ou dados privados no repositorio\n'
