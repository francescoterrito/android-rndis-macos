/* Reproduce an inherited blocked SIGTERM from a privileged launcher. */
#define main daemon_main
#include "../src/main.c"
#undef main
#include <assert.h>
int main(void) {
    sigset_t set;
    sigemptyset(&set); sigaddset(&set, SIGTERM); sigaddset(&set, SIGINT);
    assert(pthread_sigmask(SIG_BLOCK, &set, NULL) == 0);
    assert(install_stop_handlers() == 0);
    assert(raise(SIGTERM) == 0);
    assert(g_stop == 1 && atomic_load(&g_running) == 0);
    puts("ok stop handlers unblock inherited SIGTERM and stop the bridge");
    return 0;
}
