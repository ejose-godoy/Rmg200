/* Linux 5.4 TEST_KASAN=m: load official module in disposable QEMU guest only. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int run_official_kasan_module(void)
{
    const char *path = "/test_kasan.ko";
    FILE *fp = fopen(path, "rb");
    struct stat st;
    void *image;
    size_t bytes;
    int rc, saved;
    if (!fp || stat(path, &st) != 0 || st.st_size <= 0 || st.st_size > 8000000) {
        printf("KASAN_SELFTEST_LOAD_FAILED: module unavailable\n");
        if (fp) fclose(fp);
        return 1;
    }
    bytes = (size_t)st.st_size;
    image = malloc(bytes);
    if (!image || fread(image, 1, bytes, fp) != bytes) {
        printf("KASAN_SELFTEST_LOAD_FAILED: read failure\n");
        fclose(fp);
        free(image);
        return 1;
    }
    fclose(fp);
    puts("KASAN_SELFTEST_MODULE_BEGIN");
    fflush(stdout);
    errno = 0;
    rc = (int)syscall(SYS_init_module, image, bytes, "");
    saved = errno;
    printf("KASAN_SELFTEST_MODULE_RETURN rc=%d errno=%d\n", rc, saved);
    if (rc == -1 && saved == EAGAIN) {
        puts("KASAN_SELFTEST_MODULE_RETURN_EXPECTED");
    } else {
        puts("KASAN_SELFTEST_MODULE_RETURN_UNEXPECTED");
    }
    fflush(stdout);
    free(image);
    return rc == -1 && saved == EAGAIN ? 0 : 1;
}

int main(void)
{
    int status;
    (void)mount("proc", "/proc", "proc", 0, NULL);
    (void)mount("sysfs", "/sys", "sysfs", 0, NULL);
    puts("KASAN_LAB_INIT_OK: kernel ARM64 iniciou na maquina virtual");
    fflush(stdout);
    status = run_official_kasan_module();
    puts(status == 0 ? "KASAN_SELFTEST_DONE" : "KASAN_SELFTEST_FAILED");
    fflush(stdout);
    sync();
    if (reboot(RB_POWER_OFF) != 0) {
        perror("reboot(RB_POWER_OFF)");
        for (;;) pause();
    }
    return status;
}
