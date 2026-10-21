#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
REACH11_VARIANT="${REACH11_VARIANT:-}"
case "$REACH11_VARIANT" in
  unpatched|corrected) ;;
  *) echo "REACH11_INVALID_VARIANT=$REACH11_VARIANT" >&2; exit 60 ;;
esac
mkdir -p reports work
echo "REACH11_VARIANT=$REACH11_VARIANT"
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

STATE="instrumentar APENAS fonte publica QEMU"
python3 scripts/instrument-reach08.py "$SRC/kernel/locking/rtmutex.c" "$SRC/kernel/futex.c" "$REACH11_VARIANT" | tee reports/reach11-instrumentation.txt

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

STATE="criar initramfs"
mkdir -p "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/dev"
"$CC" -O2 -static -pthread -Wall -Wextra -Werror -o "$ROOTFS/init" initramfs/reach11_init.c
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
  -append 'console=ttyAMA0 earlycon=pl011,0x09000000 rdinit=/init loglevel=7 panic=-1 panic_on_warn=0 kasan_multi_shot reach01_vm=1 reach11_stage=1' \
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
# Os marcadores sao provas independentes da VM e da fonte instrumentada.
for marker in   'REACH01_VM_ONLY=1'   'REACH01_NO_ROOT_NO_UAF_PROBE=1'   'REACH01_GUEST_UID=10000 EUID=10000' \
  'REACH01_GUEST_EDEADLK=1'   'REACH01_KERNEL_ROLLBACK_EDEADLK=1'   'REACH01_RESULT=PASS'   'REACH01_GUEST_DONE=1'; do
  if ! grep -q "$marker" reports/qemu-serial.log; then
    printf 'FALHA: marcador REACH-01 ausente: %s\n' "$marker" >&2
    exit 42
  fi
done
# Demarcacao rigorosa: PID1 ja e root no initramfs, nao houve root por exploit.
# O processo filho UID10000 deve ter setresuid(0) rejeitado por EPERM.
for marker in \
    'REACH06_VM_ONLY=1' \
    'REACH06_INIT_PID1_UID=0 EUID=0' \
    'REACH06_PID1_ROOT_IS_NOT_AN_EXPLOIT=1' \
    'REACH06_EXPLOIT_NOT_ATTEMPTED=1' \
    'REACH06_PRECHECK_UID_BOUNDARY=PASS' \
    'REACH06_POSTCHECK_UID_BOUNDARY=PASS' \
    'REACH06_NO_PRIVILEGE_ESCALATION_OBSERVED=1' \
    'REACH06_BEFORE_UIDS=10000,10000,10000' \
    'REACH06_AFTER_UIDS=10000,10000,10000' \
    'REACH06_BEFORE_SETRESUID0_RET=-1 ERRNO=1' \
    'REACH06_AFTER_SETRESUID0_RET=-1 ERRNO=1'; do
  grep -q "$marker" reports/qemu-serial.log || { echo "REACH06_FAIL_MISSING=$marker" >&2; exit 61; }
done
# A new independent KASAN report is a possible detection signal, not
# a reason to claim root. Patched kernels must have zero KASAN alerts.
if grep -q 'BUG: KASAN:' reports/qemu-serial.log; then
  if [[ "$REACH11_VARIANT" == "corrected" ]]; then
    echo "REACH11_CORRECTED_UNEXPECTED_KASAN=1" >&2
    exit 63
  fi
  echo "REACH11_UNPATCHED_KASAN_OBSERVED=1" >> reports/qemu-result.txt
  echo "KASAN_DETECTION=OBSERVED_IN_UNPATCHED" >> reports/qemu-result.txt
else
  echo "REACH11_KASAN_OBSERVED=0" >> reports/qemu-result.txt
  echo "KASAN_DETECTION=NOT_OBSERVED" >> reports/qemu-result.txt
fi
for marker in \
    'REACH07_VM_ONLY=1' \
    'REACH07_NO_ARTIFICIAL_DEREFERENCE=1' \
    'REACH07_NO_MOTOROLA_EXECUTION=1' \
    'REACH07_SCHED_TARGET_TID_VALID=1' \
    'REACH07_SCHED_SET_BATCH_RET=0 ERRNO=0' \
    'REACH07_SCHED_SYSCALL_COMPLETED=1'; do
  if ! grep -q "$marker" reports/qemu-serial.log; then
    echo "REACH07_MISSING_MARKER=$marker" >&2
    exit 62
  fi
done
if [[ "$REACH11_VARIANT" == "unpatched" ]]; then
  if grep -q 'REACH07_ADJUST_PI_WAITING_FIELD_NON_NULL=1' reports/qemu-serial.log; then
    echo "REACH07_UNPATCHED_NATURAL_SCHED_SINK=OBSERVED" >> reports/qemu-result.txt
  else
    echo "REACH07_UNPATCHED_NATURAL_SCHED_SINK=NOT_OBSERVED" >> reports/qemu-result.txt
  fi
fi
# Lifetime probe is read-only: compare the task pointer with the address
# of an automatic rt_mutex_waiter just before its function returns.
case "$REACH11_VARIANT" in
 unpatched) eq=1; nil=0 ;;
 corrected) eq=0; nil=1 ;;
esac
for marker in \
  'REACH08_VM_ONLY=1' \
  'REACH08_NO_FORCED_UAF=1' \
  'REACH08_WAITER_STACK_OBJECT_INITIALIZED=1' \
  'REACH08_WAITER_STACK_SCOPE_ABOUT_TO_END=1' \
  'REACH08_GUEST_SYSCALL_RETURNED=1' \
  "REACH08_RETURN_FIELD_EQ_LOCAL_WAITER=$eq" \
  "REACH08_RETURN_FIELD_NULL=$nil"; do
 grep -q "$marker" reports/qemu-serial.log || {
   echo "REACH08_FAIL_LIFETIME_MARKER=$marker" >&2
   exit 64
 }
done
# Event order proves a non-NULL pointer was recorded before the
# automatic stack object's scope ended, and the guest syscall then returned.
python3 - <<'PY_ORDER'
from pathlib import Path
log=Path('reports/qemu-serial.log').read_text()
markers=[
 'REACH08_WAITER_STACK_OBJECT_INITIALIZED=1',
 'REACH01_KERNEL_ROLLBACK_EDEADLK=1',
 'REACH08_WAITER_STACK_SCOPE_ABOUT_TO_END=1',
 'REACH08_GUEST_SYSCALL_RETURNED=1',
 'REACH07_SCHED_SYSCALL_COMPLETED=1']
indices=[log.index(x) for x in markers]
assert indices==sorted(indices),(indices,markers)
print('REACH08_SERIAL_ORDER=PASS')
PY_ORDER
{
 echo "REACH11_VARIANT=$REACH11_VARIANT"
 echo "REACH08_RETURN_FIELD_EQ_LOCAL_WAITER=$eq"
 echo "REACH08_RETURN_FIELD_NULL=$nil"
 echo "REACH08_SYSCALL_RETURN_OBSERVED=YES"
 echo "REACH08_STACK_OBJECT_OUT_OF_SCOPE_AFTER_RETURN=YES"
 echo "REACH08_UAF_KASAN_PROOF=NOT_YET_DEMONSTRATED"
} >> reports/qemu-result.txt
# Root is proven as a native virtual kernel privilege (mounting a tmpfs),
# not a local privilege escalation. The unprivileged process remains UID10000.
for marker in \
 'REACH11_VM_ONLY=1' \
 'REACH11_BOOTSTRAP_ROOT_IS_NOT_AN_EXPLOIT=1' \
 'REACH11_BOOT_STAGE=1' \
 'REACH11_STAGE1_PID1_UIDS=0,0,0' \
 'REACH11_STAGE1_ROOTFS_STARTS_CLEAN=PASS' \
 'REACH11_STAGE1_ROOT_TMPFS_MOUNT_RET=0 ERRNO=0' \
 'REACH11_STAGE1_PRIVILEGED_TMPFS_IO=PASS' \
 'REACH11_STAGE1_ROOT_TMPFS_UMOUNT_RET=0' \
 'REACH11_FIRSTBOOT_MARKER_IN_RAM=1' \
 'REACH11_STAGE1_ROOT_CONTROL=PASS' \
 'REACH11_FIRST_BOOT_ROOT=PASS' \
 'REACH11_ROOT_ORIGIN=PROVISIONED_PID1_NOT_EXPLOIT' \
 'REACH11_UID10000_TO_UID0_BY_EXPLOIT=NOT_OBTAINED'; do
 grep -Fq "$marker" reports/qemu-serial.log || { echo "REACH11_BOOT1_MISSING=$marker" >&2; exit 81; }
done
if grep -q 'Kernel panic - not syncing' reports/qemu-serial.log; then
  echo 'FALHA: QEMU sofreu panic' >&2
  exit 43
fi

{
  echo 'REACH01_RESULT=PASS'
  echo 'VM_PLATFORM=AOSP_ARM64_REFERENCE'
  echo 'SOURCE_COMMIT_VERIFIED=34b5f809f17e66d5011086a3d90802989e667f75'
  echo 'PROXY_DEADLOCK_ROLLBACK=CONFIRMED_IN_INSTRUMENTED_VM'
  echo 'KASAN_ENABLED=1'
  echo 'REACH11_ROOT_FROM_EXPLOIT=NOT_OBTAINED'
  echo 'MOTOROLA_EQUIVALENCE=NOT_VERIFIED'
  echo 'MOTOROLA_REACHABILITY=NOT_PERFORMED'
  echo 'ROOT_ESCALATION=NOT_PERFORMED'
} >> reports/qemu-result.txt
case "$REACH11_VARIANT" in
  unpatched)
    expected="REACH05_CLEARED_TARGET=CURRENT"
    expected_remaining=1
    expected_null=0
    unexpected="REACH05_CLEARED_TARGET=WAITER_TASK"
    ;;
  corrected)
    expected="REACH05_CLEARED_TARGET=WAITER_TASK"
    expected_remaining=0
    expected_null=1
    unexpected="REACH05_CLEARED_TARGET=CURRENT"
    ;;
esac
if ! grep -q "REACH05_TASKS_DIFFER=1" reports/qemu-serial.log; then
  echo "REACH05_FAIL_NO_DISTINCT_TASK_PROOF" >&2
  exit 51
fi
if ! grep -q "$expected" reports/qemu-serial.log; then
  echo "REACH05_FAIL_WRONG_CLEANUP_TARGET=$REACH11_VARIANT" >&2
  exit 52
fi
if grep -q "$unexpected" reports/qemu-serial.log; then
  echo "REACH05_FAIL_UNEXPECTED_CLEANUP_TARGET=$REACH11_VARIANT" >&2
  exit 53
fi
if ! grep -q "REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER=$expected_remaining" reports/qemu-serial.log; then
  echo "REACH05_FAIL_RESIDUAL_POINTER_MISMATCH=$REACH11_VARIANT" >&2
  exit 54
fi
if ! grep -q "REACH05_WAITER_PI_BLOCKED_ON_NULL=$expected_null" reports/qemu-serial.log; then
  echo "REACH05_FAIL_RESIDUAL_NULL_MISMATCH=$REACH11_VARIANT" >&2
  exit 55
fi
{
  echo "REACH11_VARIANT=$REACH11_VARIANT"
  echo "REACH05_TASKS_DIFFER=1"
  echo "REACH05_CLEARED_TARGET_EXPECTED=$expected"
  echo "REACH05_WAITER_PI_BLOCKED_ON_EQ_WAITER=$expected_remaining"
  echo "REACH05_WAITER_PI_BLOCKED_ON_NULL=$expected_null"
  echo "REACH05_CONTROL=PASS"
  echo "MOTOROLA_REAL_DEVICE_TEST=NOT_PERFORMED"
} >> reports/qemu-result.txt
{
  echo "REACH11_VARIANT=$REACH11_VARIANT"
  echo "REACH06_UID10000_TO_ROOT=NOT_OBSERVED"
  echo "REACH06_INITIAL_ROOT_PID1=BASELINE_ONLY"
  echo "REACH06_ROOT_EXPLOIT=NOT_ATTEMPTED"
  echo "REACH11_COMPARATIVE_UID_BOUNDARY=PASS"
} >> reports/qemu-result.txt
# Fresh VM with the exact same guest initramfs bytes. The RAM marker from
# stage 1 must be absent, proving no persistent rootfs write across VM boots.
STATE="segundo boot QEMU sem disco"
set +e
timeout -k 5s 120s qemu-system-aarch64 \
  -M virt -cpu cortex-a57 -accel tcg -smp 2 -m 2048 \
  -nodefaults -display none -serial stdio -nic none \
  -no-reboot -monitor none \
  -kernel "$KERNEL" -initrd "$INITRD" \
  -append 'console=ttyAMA0 earlycon=pl011,0x09000000 rdinit=/init loglevel=7 panic=-1 panic_on_warn=0 reach01_vm=1 reach11_stage=2' \
  > reports/qemu-second-boot.log 2>&1
second_status=$?
set -e
echo "REACH11_SECOND_BOOT_QEMU_EXIT=$second_status" >> reports/qemu-result.txt
[[ "$second_status" -eq 0 ]] || { echo "REACH11_SECOND_BOOT_QEMU_FAILED=$second_status" >&2; exit 82; }
for marker in \
 'REACH11_VM_ONLY=1' \
 'REACH11_BOOT_STAGE=2' \
 'REACH11_STAGE2_PID1_UIDS=0,0,0' \
 'REACH11_STAGE2_ROOTFS_STARTS_CLEAN=PASS' \
 'REACH11_STAGE2_ROOT_TMPFS_MOUNT_RET=0 ERRNO=0' \
 'REACH11_STAGE2_PRIVILEGED_TMPFS_IO=PASS' \
 'REACH11_STAGE2_ROOT_TMPFS_UMOUNT_RET=0' \
 'REACH11_STAGE2_ROOT_CONTROL=PASS' \
 'REACH11_SECOND_BOOT=PASS' \
 'REACH11_ROOT_ORIGIN=PROVISIONED_PID1_NOT_EXPLOIT' \
 'REACH11_UID10000_TO_UID0_BY_EXPLOIT=NOT_OBTAINED';do
 grep -Fq "$marker" reports/qemu-second-boot.log || { echo "REACH11_BOOT2_MISSING=$marker" >&2; exit 83; }
done
if grep -Fq 'REACH11_FIRSTBOOT_MARKER_IN_RAM=1' reports/qemu-second-boot.log; then
 echo 'REACH11_MARKER_WRITTEN_IN_SECOND_BOOT_UNEXPECTED=1' >&2
 exit 84
fi
{
 echo "REACH11_VARIANT=$REACH11_VARIANT"
 echo "REACH11_QEMU_VIRTUAL_KERNEL_ROOT=PASS"
 echo "REACH11_ROOT_ORIGIN=PREEXISTING_VM_PID1"
 echo "REACH11_PREBOOT_UNPRIVILEGED_UID=10000"
 echo "REACH11_UNPRIVILEGED_TO_ROOT_ESCALATION=NOT_OBTAINED"
 echo "REACH11_ROOT_VIA_GHOSTLOCK=NOT_DEMONSTRATED"
 echo "REACH11_TMPFS_PRIVILEGED_CONTROL=PASS"
 echo "REACH11_FRESH_BOOT_MARKER_ABSENT=PASS"
 echo "REACH11_NO_PERSISTENT_VM_DISK=1"
 echo "REACH11_MOTOROLA_ROOT=NOT_OBTAINED"
} >> reports/qemu-result.txt
STATE="REACH-11 QEMU root provisionado e reboot duplo: $REACH11_VARIANT COMPLETE"
