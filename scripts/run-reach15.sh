#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
cd "$(dirname "$0")/.."
case "${REACH15_VARIANT:-}" in unpatched|corrected);; *) exit 61;; esac
mkdir -p work reports
state=started
finish(){ status=$?; if ((status==0));then printf 'STATUS=PASS\nSTAGE=%s\n' "$state" > reports/status.txt; else printf 'STATUS=FAIL\nEXIT=%s\nSTAGE=%s\n' "$status" "$state" > reports/status.txt; fi; }
trap finish EXIT
state=clone
src="$PWD/work/linux-public"
out="$PWD/work/kernel-out"
rootfs="$PWD/work/rootfs"
git clone --depth 1 --single-branch --branch android12-5.4.147_r00 https://android.googlesource.com/kernel/common "$src"
test "$(git -C "$src" rev-parse HEAD)" = 34b5f809f17e66d5011086a3d90802989e667f75
python3 scripts/reach15_binder_instrument.py "$src/drivers/android/binder.c" "$REACH15_VARIANT" | tee reports/reach15-binder-patch.txt
state=config
export ARCH=arm64
make -C "$src" O="$out" ARCH=arm64 CC=gcc-12 defconfig
cfg="$out/.config"
"$src/scripts/config" --file "$cfg" -e ANDROID -e ANDROID_BINDER_IPC --set-str ANDROID_BINDER_DEVICES binder -d ANDROID_BINDERFS -e KASAN -e KASAN_GENERIC -e KASAN_OUTLINE -d KASAN_SW_TAGS -d KASAN_INLINE -e DEBUG_KERNEL -e KALLSYMS -e KALLSYMS_ALL -e DEVTMPFS -e DEVTMPFS_MOUNT -e BLK_DEV_INITRD -e RD_GZIP -e SERIAL_AMBA_PL011 -e SERIAL_AMBA_PL011_CONSOLE -d RANDOMIZE_BASE -d CFI_CLANG -d LTO_CLANG -d LTO_CLANG_THIN -d DEBUG_INFO
make -C "$src" O="$out" ARCH=arm64 CC=gcc-12 olddefconfig
for opt in 'CONFIG_ANDROID_BINDER_IPC=y' 'CONFIG_ANDROID_BINDER_DEVICES="binder"' 'CONFIG_DEVTMPFS=y' 'CONFIG_KASAN=y' 'CONFIG_KASAN_GENERIC=y';do grep -Fxq "$opt" "$cfg" || { echo "MISSING_$opt";exit 62;};done
grep -E '^(CONFIG_ANDROID_BINDER|CONFIG_KASAN|CONFIG_DEVTMPFS)=' "$cfg" > reports/binder-kasan-config.txt || :
state=build
make -C "$src" O="$out" ARCH=arm64 CC=gcc-12 -j2 Image > reports/kernel-build.log 2>&1 || { tail -65 reports/kernel-build.log;exit 63;}
test -s "$out/arch/arm64/boot/Image"
nm "$out/vmlinux" | grep ' binder_inc_ref_for_node' > /dev/null || { echo BINDER_FUNCTION_MISSING;exit 64; }
nm "$out/vmlinux" | grep ' __asan_load' > /dev/null || { echo KASAN_RUNTIME_MISSING;exit 65; }
sha256sum "$out/arch/arm64/boot/Image" "$out/vmlinux" > reports/kernel-sha256.txt
state=guest
mkdir -p "$rootfs/dev" "$rootfs/proc"
# umask 077 makes the initramfs top-level directory 0700 unless fixed.
chmod 0755 "$rootfs" "$rootfs/dev" "$rootfs/proc"
for dir in "$rootfs" "$rootfs/dev" "$rootfs/proc";do
  test "$(stat -c %a "$dir")" = 755 || { echo "ROOTFS_PERMISSION_FAIL=$dir" >&2;exit 69;}
done
echo 'REACH15_ROOTFS_TRAVERSAL_MODE=0755' > reports/initramfs-permissions.txt
gcc-12 -O2 -static -Wall -Wextra -Werror -o "$rootfs/init" initramfs/reach15_init.c
( cd "$rootfs"; find . -print0 | cpio --null -o -H newc --quiet | gzip -9 ) > work/reach15-initramfs.cpio.gz
state=qemu
set +e
timeout -k 5s 180s qemu-system-aarch64 -M virt -cpu cortex-a57 -accel tcg -smp 2 -m 2048 -nodefaults -display none -serial stdio -nic none -no-reboot -monitor none -kernel "$out/arch/arm64/boot/Image" -initrd work/reach15-initramfs.cpio.gz -append 'console=ttyAMA0 earlycon=pl011,0x09000000 rdinit=/init loglevel=7 panic=-1 panic_on_warn=0 kasan_multi_shot' > reports/qemu-serial.log 2>&1
rc=$?
set -e
echo "QEMU_EXIT=$rc" > reports/qemu-result.txt
if (( rc!=0 ));then tail -55 reports/qemu-serial.log;exit 66;fi
for marker in 'REACH15_QEMU_ONLY=1' 'REACH15_VM_LOCAL_DAC_NOT_ANDROID_SELINUX=1' 'REACH15_CONTEXT_MANAGER_RET=0 ERRNO=0' 'REACH15_CONTEXT_MANAGER_UID=10000' 'REACH15_CLIENT_UID=10000' 'REACH15_INCREFS_RET=0 ERRNO=0 CONSUMED=8' 'REACH15_ACQUIRE_RET=0 ERRNO=0 CONSUMED=8' 'REACH15_RELEASE_RET=0 ERRNO=0 CONSUMED=8' 'REACH15_DECREFS_RET=0 ERRNO=0 CONSUMED=8' 'REACH15_CLIENT_COMPLETED_NORMAL_REF_CYCLE=1' 'REACH15_CLIENT_EXIT=0' 'REACH15_MANAGER_EXIT=0' 'REACH15_NO_RACE=1' 'REACH15_NO_EXPLOIT=1' 'REACH15_NO_PRIVILEGE_CHANGE=1' 'REACH15_REF_CREATED_NORMAL=1' 'REACH15_REF_CLEANUP_NORMAL=1' 'REACH15_RESULT=PASS';do
 grep -Fq "$marker" reports/qemu-serial.log || { echo "MISSING_MARKER=$marker";exit 67;}
done
if grep -Fq 'BUG: KASAN:' reports/qemu-serial.log || grep -Fq 'Kernel panic' reports/qemu-serial.log; then echo 'REACH15_KERNEL_SAFETY_FAIL';exit 68;fi
{
 echo 'REACH15_STATUS=PASS'
 echo "REACH15_VARIANT=$REACH15_VARIANT"
 echo 'REACH15_BINDER_KASAN=ENABLED'
 echo 'REACH15_VM_UID10000_NORMAL_REF_LIFECYCLE=PASS'
 echo 'REACH15_REAL_ERROR_RACE=NOT_EXECUTED'
 echo 'REACH15_ROOT=NOT_OBTAINED'
 echo 'REACH15_PHYSICAL_MOTOROLA=NOT_TOUCHED'
} >> reports/qemu-result.txt
state="complete $REACH15_VARIANT"
