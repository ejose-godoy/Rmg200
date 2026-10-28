/*
 * REACH-01: descartavel, somente QEMU ARM64 / Android Common 5.4.147.
 * Prova apenas caminho de retorno EDEADLK de Futex PI; nenhuma tentativa
 * de corrupcao, sondagem de UAF, ganho de privilegios ou execucao Android.
 * Restrito ao initramfs de QEMU pelo workflow dedicado.
 */
#define _GNU_SOURCE
#include <errno.h>
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
    const struct timespec pause_before_release = { .tv_sec = 0, .tv_nsec = 50000000 };
    nanosleep(&pause_before_release, NULL);
    (void)fx(&chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}

static int run_unprivileged(void)
{
    printf("REACH01_GUEST_UID=%u EUID=%u\n",
           (unsigned)getuid(), (unsigned)geteuid());
    if (getuid() != 10000 || geteuid() != 10000) {
        puts("REACH01_ABORT_WRONG_UID=1");
        return 21;
    }
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
    pthread_join(b, NULL);
    pthread_join(a, NULL);
    if (atomic_load(&worker_status)) {
        printf("REACH01_WORKER_ERROR=%d\n", atomic_load(&worker_status));
        ok = 33;
    }
    puts(ok ? "REACH01_RESULT=FAIL" : "REACH01_RESULT=PASS");
    return ok;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
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
    sync();
    if (reboot(RB_POWER_OFF) != 0) {
        perror("reboot(RB_POWER_OFF)");
        for (;;) pause();
    }
    return 0;
}
