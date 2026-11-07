#define _GNU_SOURCE
#include <pthread.h>
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
        pid_t child = fork();
        if (child < 0) syscall(SYS_exit_group, 125);
        if (child == 0) newborn(0);
    } else if (pthread_create(&thread, 0, newborn, 0)) {
        syscall(SYS_exit_group, 125);
    }
    for (;;) pause();
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    process = argc == 2;
    pthread_t thread;
    char gate;
    if (pthread_create(&thread, 0, creator, 0) || write(5, "r", 1) != 1 ||
        read(4, &gate, 1) != 1)
        syscall(SYS_exit_group, 125);
    syscall(SYS_exit_group, 0);
    return 125;
}
