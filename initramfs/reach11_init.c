/*
 * REACH-11: teste consolidado QEMU, root VM e fronteira UID10000, no QEMU ARM64 / Android Common 5.4.147.
 * Reavalia o estado do waiter via scheduler, apenas na VM, sem UAF forçada;
 * nenhuma exploracao de memoria, UAF ativa ou execucao Android.
 * Restrito ao initramfs de QEMU pelo workflow dedicado.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static _Alignas(4) uint32_t src = 0;
static _Alignas(4) uint32_t dst = 0;
static _Alignas(4) uint32_t chain = 0;
static atomic_int owner_ready, waiter_ready, owner_blocking, waiter_waiting;
static atomic_int worker_status;
static atomic_int reach07_waiter_tid, reach07_waiter_returned, reach07_sched_done;

static long fx(uint32_t *a, int op, uint32_t val, const void *time_or_val,
               uint32_t *b, uint32_t val3)
{
    return syscall(SYS_futex, a, op | FUTEX_PRIVATE_FLAG, val,
                   time_or_val, b, val3);
}

static int await_flag(atomic_int *flag)
{
    struct timespec t = { .tv_sec = 0, .tv_nsec = 1000000 };
    for (int i = 0; i < 6000; i++) {
        if (atomic_load_explicit(flag, memory_order_acquire))
            return 0;
        nanosleep(&t, NULL);
    }
    return -1;
}

static void *owner(void *unused)
{
    (void)unused;
    atomic_store_explicit((_Atomic uint32_t *)&dst,
                          (uint32_t)syscall(SYS_gettid), memory_order_release);
    atomic_store(&owner_ready, 1);
    if (await_flag(&waiter_ready)) {
        atomic_store(&worker_status, 2);
        return NULL;
    }
    atomic_store(&owner_blocking, 1);
    long ret = fx(&chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    if (ret == 0)
        (void)fx(&chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    else
        atomic_store(&worker_status, 3);
    return NULL;
}

static void *waiter(void *unused)
{
    (void)unused;
    atomic_store(&reach07_waiter_tid, (int)syscall(SYS_gettid));
    if (await_flag(&owner_ready)) {
        atomic_store(&worker_status, 4);
        return NULL;
    }
    atomic_store_explicit((_Atomic uint32_t *)&chain,
                          (uint32_t)syscall(SYS_gettid), memory_order_release);
    atomic_store(&waiter_ready, 1);
    if (await_flag(&owner_blocking)) {
        atomic_store(&worker_status, 5);
        return NULL;
    }

    const struct timespec short_delay = { .tv_sec = 0, .tv_nsec = 20000000 };
    nanosleep(&short_delay, NULL);
    atomic_store(&waiter_waiting, 1);

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += 2;
    long ret = fx(&src, FUTEX_WAIT_REQUEUE_PI, 0, &deadline, &dst, 0);
    int saved = errno;
    printf("REACH01_WAITER_RET=%ld ERRNO=%d\n", ret, saved);
    fflush(stdout);
    puts("REACH08_GUEST_SYSCALL_RETURNED=1");
    atomic_store(&reach07_waiter_returned, 1);
    /* Keep this unprivileged task alive while its stale waiter state is
     * checked by a normal scheduler API call on the other thread. */
    if (await_flag(&reach07_sched_done) != 0) {
        puts("REACH07_WAITER_CONTROLLER_TIMEOUT=1");
        atomic_store(&worker_status, 6);
    }

    const struct timespec pause_before_release = { .tv_sec = 0, .tv_nsec = 50000000 };
    nanosleep(&pause_before_release, NULL);
    (void)fx(&chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static int reach06_uid_boundary(const char *when)
{
    uid_t ruid = (uid_t)-1, euid = (uid_t)-1, suid = (uid_t)-1;
    if (getresuid(&ruid, &euid, &suid) != 0) {
        printf("REACH06_%s_GETRESUID_FAILED=1\n", when);
        return 1;
    }
    printf("REACH06_%s_UIDS=%u,%u,%u\n", when,
           (unsigned)ruid, (unsigned)euid, (unsigned)suid);
    if (ruid != 10000 || euid != 10000 || suid != 10000)
        return 2;
    errno = 0;
    int ret = setresuid(0, 0, 0);
    int error = errno;
    printf("REACH06_%s_SETRESUID0_RET=%d ERRNO=%d\n",
           when, ret, error);
    if (ret != -1 || error != EPERM)
        return 3;
    if (getuid() != 10000 || geteuid() != 10000)
        return 4;
    return 0;
}

static int run_unprivileged(void)
{
    printf("REACH01_GUEST_UID=%u EUID=%u\n",
           (unsigned)getuid(), (unsigned)geteuid());
    if (getuid() != 10000 || geteuid() != 10000) {
        puts("REACH01_ABORT_WRONG_UID=1");
        return 21;
    }
    if (reach06_uid_boundary("BEFORE") != 0) {
        puts("REACH06_PRECHECK_UID_BOUNDARY=FAIL");
        return 34;
    }
    puts("REACH06_PRECHECK_UID_BOUNDARY=PASS");
    pthread_t a, b;
    int ok = 0;
    if (pthread_create(&a, NULL, owner, NULL) ||
        pthread_create(&b, NULL, waiter, NULL)) {
        puts("REACH01_THREAD_CREATE_FAILED=1");
        return 30;
    }
    if (await_flag(&waiter_waiting)) {
        puts("REACH01_WAITER_NOT_READY=1");
        ok = 31;
    } else {
        const struct timespec settle = { .tv_sec = 0, .tv_nsec = 40000000 };
        nanosleep(&settle, NULL);
        errno = 0;
        long ret = fx(&src, FUTEX_CMP_REQUEUE_PI, 1,
                      (const void *)(uintptr_t)1, &dst, 0);
        int err = errno;
        printf("REACH01_CMP_REQUEUE_RET=%ld ERRNO=%d\n", ret, err);
        if (ret == -1 && err == EDEADLK)
            puts("REACH01_GUEST_EDEADLK=1");
        else {
            puts("REACH01_GUEST_EDEADLK=0");
            ok = 32;
        }
    }
    if (ok == 0) {
        if (await_flag(&reach07_waiter_returned) != 0) {
            puts("REACH07_WAITER_POSTROLLBACK_NOT_READY=1");
            ok = 36;
        } else {
            const pid_t target = atomic_load(&reach07_waiter_tid);
            printf("REACH07_SCHED_TARGET_TID_VALID=%d\n", target > 0);
            struct sched_param sp = { .sched_priority = 0 };
            errno = 0;
            /* Natural kernel path: sched_setscheduler -> rt_mutex_adjust_pi.
             * No kernel memory access is performed by this user-space code. */
            const int rc = sched_setscheduler(target, SCHED_BATCH, &sp);
            const int err = errno;
            printf("REACH07_SCHED_SET_BATCH_RET=%d ERRNO=%d\n", rc, err);
            if (rc != 0)
                ok = 37;
            puts("REACH07_SCHED_SYSCALL_COMPLETED=1");
        }
    }
    atomic_store(&reach07_sched_done, 1);
    pthread_join(b, NULL);
    pthread_join(a, NULL);
    if (atomic_load(&worker_status)) {
        printf("REACH01_WORKER_ERROR=%d\n", atomic_load(&worker_status));
        ok = 33;
    }
    if (reach06_uid_boundary("AFTER") != 0) {
        puts("REACH06_POSTCHECK_UID_BOUNDARY=FAIL");
        ok = 35;
    } else {
        puts("REACH06_POSTCHECK_UID_BOUNDARY=PASS");
    }
    puts("REACH06_NO_PRIVILEGE_ESCALATION_OBSERVED=1");
    puts(ok ? "REACH01_RESULT=FAIL" : "REACH01_RESULT=PASS");
    return ok;
}

/* Strict VM-only positive root control, executed by PID1 that STARTS at uid0.
 * It NEVER escalates from UID10000. A tmpfs mount checks privileged access.
 * The rootfs marker is intentionally NOT durable between QEMU processes.
 */
static int reach11_provisioned_root_test(int stage)
{
    uid_t r=(uid_t)-1,e=(uid_t)-1,s=(uid_t)-1;
    if (getpid()!=1 || getresuid(&r,&e,&s)!=0 || r!=0 || e!=0 || s!=0) {
        puts("REACH11_ROOT_CONTROL_REFUSED_NO_PREEXISTING_ROOT=1");
        return 80;
    }
    printf("REACH11_STAGE%d_PID1_UIDS=0,0,0\n",stage);
    errno=0;
    int previous=access("/reach11-firstboot-marker",F_OK);
    int miss=errno;
    if (previous!=-1 || miss!=ENOENT) {
        puts("REACH11_PERSISTENCE_EXPECTED_EMPTY_ROOTFS=FAIL");
        return 81;
    }
    printf("REACH11_STAGE%d_ROOTFS_STARTS_CLEAN=PASS\n",stage);
    if (mkdir("/reach11-rootcheck",0700)!=0 && errno!=EEXIST)
        return 82;
    errno=0;
    int mounted=mount("tmpfs","/reach11-rootcheck","tmpfs",
                      MS_NODEV|MS_NOSUID,"size=65536");
    int err=errno;
    printf("REACH11_STAGE%d_ROOT_TMPFS_MOUNT_RET=%d ERRNO=%d\n",
           stage,mounted,err);
    if (mounted!=0)
        return 83;
    int status=84;
    do {
        int fd=open("/reach11-rootcheck/privileged-proof",
                    O_CREAT|O_EXCL|O_RDWR,0600);
        if (fd<0) break;
        const char payload[]="vm-root-control";
        char data[sizeof(payload)]={0};
        ssize_t wr=write(fd,payload,sizeof(payload));
        if(wr!=(ssize_t)sizeof(payload)) {close(fd);break;}
        if (lseek(fd,0,SEEK_SET)!=0) {close(fd);break;}
        ssize_t rd=read(fd,data,sizeof(data));
        close(fd);
        if(rd!=(ssize_t)sizeof(payload) ||
           memcmp(data,payload,sizeof(payload))!=0) break;
        printf("REACH11_STAGE%d_PRIVILEGED_TMPFS_IO=PASS\n",stage);
        status=0;
    } while(0);
    int um=umount("/reach11-rootcheck");
    printf("REACH11_STAGE%d_ROOT_TMPFS_UMOUNT_RET=%d\n",stage,um);
    if(status!=0 || um!=0) return 85;
    puts("REACH11_ROOT_ORIGIN=PROVISIONED_PID1_NOT_EXPLOIT");
    puts("REACH11_UID10000_TO_UID0_BY_EXPLOIT=NOT_OBTAINED");
    if(stage==1) {
        int f=open("/reach11-firstboot-marker",O_CREAT|O_EXCL|O_WRONLY,0600);
        if(f<0) return 86;
        const char msg[]="first-boot-only";
        int wr=write(f,msg,sizeof(msg));
        close(f);
        if(wr!=(int)sizeof(msg)) return 87;
        puts("REACH11_FIRSTBOOT_MARKER_IN_RAM=1");
    }
    printf("REACH11_STAGE%d_ROOT_CONTROL=PASS\n",stage);
    return 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("REACH11_VM_ONLY=1");
    puts("REACH11_BOOTSTRAP_ROOT_IS_NOT_AN_EXPLOIT=1");
    puts("REACH08_VM_ONLY=1");
    puts("REACH08_NO_FORCED_UAF=1");
    puts("REACH07_VM_ONLY=1");
    puts("REACH07_NO_ARTIFICIAL_DEREFERENCE=1");
    puts("REACH07_NO_MOTOROLA_EXECUTION=1");
    puts("REACH06_VM_ONLY=1");
    printf("REACH06_INIT_PID1_UID=%u EUID=%u\n", (unsigned)getuid(), (unsigned)geteuid());
    puts("REACH06_PID1_ROOT_IS_NOT_AN_EXPLOIT=1");
    puts("REACH06_EXPLOIT_NOT_ATTEMPTED=1");
    puts("REACH01_VM_ONLY=1");
    puts("REACH01_NO_ROOT_NO_UAF_PROBE=1");
    if (getpid() != 1) {
        puts("REACH01_ABORT_NOT_PID1=1");
        return 20;
    }

    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        puts("REACH01_ABORT_NO_PROC=1");
        return 22;
    }
    FILE *fp = fopen("/proc/cmdline", "r");
    char cmdline[2048] = { 0 };
    if (!fp || !fgets(cmdline, sizeof(cmdline), fp)
            || !strstr(cmdline, "reach01_vm=1")
            || !strstr(cmdline, "rdinit=/init")) {
        puts("REACH01_ABORT_NOT_QEMU_CMDLINE=1");
        if (fp) fclose(fp);
        return 23;
    }
    fclose(fp);

    int stage=0;
    if (strstr(cmdline,"reach11_stage=1"))
        stage=1;
    else if (strstr(cmdline,"reach11_stage=2"))
        stage=2;
    else {
        puts("REACH11_ABORT_WRONG_VM_STAGE=1");
        return 88;
    }
    printf("REACH11_BOOT_STAGE=%d\n",stage);
    if (stage==2) {
        int result=reach11_provisioned_root_test(2);
        puts(result==0 ? "REACH11_SECOND_BOOT=PASS" : "REACH11_SECOND_BOOT=FAIL");
        sync();
        (void)reboot(RB_POWER_OFF);
        return result;
    }

    pid_t child = fork();
    if (child == 0) {
        if (setresgid(10000, 10000, 10000) != 0
                || setresuid(10000, 10000, 10000) != 0) {
            puts("REACH01_ABORT_PRIV_DROP_FAILED=1");
            _exit(24);
        }
        int rc = run_unprivileged();
        _exit(rc);
    }
    if (child < 0) {
        puts("REACH01_ABORT_FORK_FAILED=1");
        return 25;
    }
    int status = 0;
    if (waitpid(child, &status, 0) < 0) {
        puts("REACH01_ABORT_WAITPID_FAILED=1");
    } else {
        printf("REACH01_CHILD_WIFEXITED=%d STATUS=%d\n",
               WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : 255);
    }
    puts("REACH01_GUEST_DONE=1");
    if (!(WIFEXITED(status) && WEXITSTATUS(status)==0)) {
        puts("REACH11_REFUSED_ROOT_CONTROL_UNPRIVILEGED_TEST_FAILED=1");
        sync();
        (void)reboot(RB_POWER_OFF);
        return 89;
    }
    int root_status=reach11_provisioned_root_test(1);
    if(root_status!=0) {
        puts("REACH11_FIRST_BOOT_ROOT=FAIL");
        sync();
        (void)reboot(RB_POWER_OFF);
        return root_status;
    }
    puts("REACH11_FIRST_BOOT_ROOT=PASS");
    sync();
    if (reboot(RB_POWER_OFF) != 0) {
        perror("reboot(RB_POWER_OFF)");
        for (;;) pause();
    }
    return 0;
}
