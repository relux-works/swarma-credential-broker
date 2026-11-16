#define _GNU_SOURCE
#include <pthread.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int process;

/* Only inherited fixture pipes are used. No files, accounts or network. */
static void *newborn(void *unused) {
    (void)unused;
    for (;;) pause();
    return 0;
}

static void *creator(void *unused) {
    (void)unused;
    char gate;
    pthread_t thread;
    if (read(3, &gate, 1) != 1)
        syscall(SYS_exit_group, 125);
    if (process) {
        /* No CLONE_THREAD and no SIGCHLD: a distinct process reported as CLONE. */
        pid_t child = process == 3 ? syscall(SYS_clone, 0, 0, 0, 0, 0)
                                  : (process == 2 ? vfork() : fork());
        if (child < 0) syscall(SYS_exit_group, 125);
        if (child == 0) newborn(0);
    } else if (pthread_create(&thread, 0, newborn, 0)) {
        syscall(SYS_exit_group, 125);
    }
    for (;;) pause();
    return 0;
}

int main(int argc, char **argv) {
    process = argc == 2 ? (strcmp(argv[1], "raw-clone") == 0 ? 3 :
                          (strcmp(argv[1], "vfork") == 0 ? 2 : 1)) : 0;
    pthread_t thread;
    char gate;
    if (pthread_create(&thread, 0, creator, 0) || write(5, "r", 1) != 1 ||
        read(4, &gate, 1) != 1)
        syscall(SYS_exit_group, 125);
    syscall(SYS_exit_group, 0);
    return 125;
}
