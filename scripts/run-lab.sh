#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p reports work
STATE="iniciado"
finish() {
  status=$?
  if ((status == 0)); then
    printf 'STATUS=PASS\nFASE=%s\n' "$STATE" > reports/status.txt
  else
    printf 'STATUS=FAIL\nFASE=%s\nCODIGO=%s\n' "$STATE" "$status" > reports/status.txt
  fi
}
trap finish EXIT

# IMPORTANTE: base AOSP publica, ainda NAO corresponde necessariamente ao kernel da Motorola.
SOURCE_URL="https://android.googlesource.com/kernel/common"
SOURCE_TAG="android12-5.4.147_r00"
SOURCE_COMMIT="34b5f809f17e66d5011086a3d90802989e667f75"
SRC="$ROOT/work/linux-public"
OUT="$ROOT/work/kernel-out"
ROOTFS="$ROOT/work/rootfs"
INITRD="$ROOT/work/initramfs.cpio.gz"
CC="gcc-12"
export ARCH=arm64

STATE="preflight"
bash scripts/preflight.sh | tee reports/preflight.txt
{
  printf 'kernel_source_url=%s\n' "$SOURCE_URL"
  printf 'kernel_source_tag=%s\n' "$SOURCE_TAG"
  printf 'kernel_source_commit_expected=%s\n' "$SOURCE_COMMIT"
  printf 'motorola_kernel_equivalence=NOT_VERIFIED\n'
  printf 'motorola_boot_image_in_ci=NO\n'
  uname -a
  "$CC" --version | head -n 1
  qemu-system-aarch64 --version | head -n 1
  df -h .
} > reports/toolchain-and-source.txt

STATE="obter fontes publicas"
if [[ ! -d "$SRC/.git" ]]; then
  git clone --depth 1 --single-branch --branch "$SOURCE_TAG" "$SOURCE_URL" "$SRC"
fi
actual="$(git -C "$SRC" rev-parse HEAD)"
[[ "$actual" == "$SOURCE_COMMIT" ]] || { printf 'FALHA: commit nao coincide: %s\n' "$actual" >&2; exit 31; }
printf 'source_commit_verified=%s\n' "$actual" >> reports/toolchain-and-source.txt
sha256sum "$SRC/kernel/locking/rtmutex.c" "$SRC/kernel/futex.c" > reports/source-files-sha256.txt

STATE="configurar KASAN"
mkdir -p "$OUT"
make -C "$SRC" O="$OUT" ARCH=arm64 CC="$CC" defconfig
cfg="$OUT/.config"
# O defconfig da plataforma virt difere do firmware Qualcomm do Moto G200.
"$SRC/scripts/config" --file "$cfg" \
  -e MODULES -m TEST_KASAN -e KASAN -e KASAN_GENERIC -e KASAN_OUTLINE -d KASAN_INLINE \
  -e DEBUG_KERNEL -e STACKTRACE -e KALLSYMS -e KALLSYMS_ALL \
  -e BLK_DEV_INITRD -e RD_GZIP -e DEVTMPFS -e DEVTMPFS_MOUNT \
  -e SERIAL_AMBA_PL011 -e SERIAL_AMBA_PL011_CONSOLE \
  -d KASAN_SW_TAGS -d RANDOMIZE_BASE \
  -d CFI_CLANG -d LTO_CLANG -d LTO_CLANG_THIN -d DEBUG_INFO
make -C "$SRC" O="$OUT" ARCH=arm64 CC="$CC" olddefconfig
for wanted in CONFIG_KASAN=y CONFIG_KASAN_GENERIC=y CONFIG_KASAN_OUTLINE=y \
              CONFIG_BLK_DEV_INITRD=y CONFIG_SERIAL_AMBA_PL011_CONSOLE=y CONFIG_MODULES=y CONFIG_TEST_KASAN=m; do
  grep -qx "$wanted" "$cfg" || { echo "FALHA: configuracao ausente $wanted" >&2; exit 32; }
done
grep -E '^(CONFIG_KASAN|CONFIG_KASAN_GENERIC|CONFIG_KASAN_OUTLINE|CONFIG_STACKTRACE|CONFIG_DEBUG_INFO|CONFIG_BLK_DEV_INITRD|CONFIG_SERIAL_AMBA_PL011_CONSOLE)=' "$cfg" > reports/kasan-config.txt

STATE="compilar kernel"
# Limitar paralelismo e nao criar imagem de boot Motorola; apenas Image QEMU generico.
make -C "$SRC" O="$OUT" ARCH=arm64 CC="$CC" -j2 Image 2>&1 | tee reports/kernel-build.log
KERNEL="$OUT/arch/arm64/boot/Image"
test -s "$KERNEL"
# Verificar simbolos da instrumentacao, alem do bit de configuracao.
if ! nm "$OUT/vmlinux" | grep -E ' __asan_(load|store)' >/dev/null; then
  echo 'FALHA: simbolos KASAN nao identificados no vmlinux' >&2
  exit 33
fi
{
  echo 'KASAN_COMPILADO=SIM'
  sha256sum "$KERNEL" "$OUT/vmlinux"
  grep -E '^Linux version ' "$SRC/Makefile" 2>/dev/null || true
} > reports/kernel-build.txt

STATE="compilar modulo oficial de autoverificacao KASAN"
# Teste oficial da revisao Android 5.4, em modulo (CONFIG_TEST_KASAN=m).
# Compilacao por alvo unico: nao compilar todos os modulos da defconfig.
make -C "$SRC" O="$OUT" ARCH=arm64 CC="$CC" -j2 lib/test_kasan.ko 2>&1 | tee reports/kasan-module-build.log
test -s "$OUT/lib/test_kasan.ko" || { echo "FALHA: test_kasan.ko ausente" >&2; exit 34; }
printf 'OFFICIAL_TEST_MODULE=lib/test_kasan.ko\n' > reports/kasan-module.txt
sha256sum "$OUT/lib/test_kasan.ko" >> reports/kasan-module.txt

STATE="criar initramfs"
mkdir -p "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev"
cp "$OUT/lib/test_kasan.ko" "$ROOTFS/test_kasan.ko"
"$CC" -O2 -static -Wall -Wextra -Werror -o "$ROOTFS/init" initramfs/init.c
chmod 755 "$ROOTFS/init"
( cd "$ROOTFS" && find . -print0 | cpio --null -o -H newc --quiet | gzip -9 ) > "$INITRD"

STATE="iniciar QEMU e coletar log"
# TCG evita depender de nested virtualization / KVM dentro do runner GitHub.
set +e
timeout -k 5s 240s qemu-system-aarch64 \
  -M virt -cpu cortex-a57 -accel tcg -smp 2 -m 2048 \
  -nodefaults -display none -serial stdio -nic none \
  -no-reboot -monitor none \
  -kernel "$KERNEL" -initrd "$INITRD" \
  -append 'console=ttyAMA0 earlycon=pl011,0x09000000 rdinit=/init loglevel=7 panic=-1 panic_on_warn=0 kasan_multi_shot' \
  > reports/qemu-serial.log 2>&1
qemu_status=$?
set -e
printf 'qemu_exit_status=%s\n' "$qemu_status" > reports/qemu-result.txt
if [[ "$qemu_status" -eq 124 || "$qemu_status" -eq 137 ]]; then
  echo 'FALHA: QEMU excedeu limite de tempo' >&2
  exit 41
fi
if [[ "$qemu_status" -ne 0 ]]; then
  printf 'FALHA: QEMU encerrou com codigo %s\n' "$qemu_status" >&2
  sed -n '1,50p' reports/qemu-serial.log >&2
  exit 44
fi
if ! grep -q 'KASAN_LAB_INIT_OK' reports/qemu-serial.log; then
  echo 'FALHA: nao apareceu marcador de inicializacao no console serial' >&2
  exit 42
fi
# Os relatos KASAN sao esperados no modulo oficial de testes (VM descartavel).
if grep -q 'Kernel panic - not syncing' reports/qemu-serial.log; then
  echo 'FALHA: kernel experimental sofreu panic antes de encerrar' >&2
  exit 43
fi
count="$(grep -c 'BUG: KASAN:' reports/qemu-serial.log || true)"
printf 'KASAN_REPORT_COUNT=%s\n' "$count" >> reports/qemu-result.txt
if [[ "$count" -lt 2 ]]; then
  echo "FALHA: detector nao produziu dois relatos KASAN (total=$count)" >&2
  exit 45
fi
for marker in 'KASAN_SELFTEST_MODULE_BEGIN' 'KASAN_SELFTEST_MODULE_RETURN_EXPECTED' 'KASAN_SELFTEST_DONE' 'kasan test:'; do
  grep -q "$marker" reports/qemu-serial.log || { echo "FALHA: marcador KASAN nao encontrado: $marker" >&2; exit 46; }
done
printf 'BOOT_VM=PASS\nKASAN_COMPILED=PASS\nKASAN_RUNTIME_SELFTEST=PASS\nGHOSTLOCK_TRIGGER=NOT_PERFORMED\n' >> reports/qemu-result.txt
STATE="laboratorio completo (sem teste de vulnerabilidade)"
