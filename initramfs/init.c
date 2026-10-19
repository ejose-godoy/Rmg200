/* PID 1 minimo: teste seguro de inicializacao, sem reproduzir qualquer exploit. */
#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <unistd.h>
int main(void) {
    (void)mount("proc", "/proc", "proc", 0, NULL);
    (void)mount("sysfs", "/sys", "sysfs", 0, NULL);
    puts("KASAN_LAB_INIT_OK: kernel ARM64 iniciou na maquina virtual");
    fflush(stdout);
    sync();
    if (reboot(RB_POWER_OFF) != 0) {
        perror("reboot(RB_POWER_OFF)");
        for (;;) pause();
    }
    return 0;
}
