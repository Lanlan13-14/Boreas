/* GitHub Actions fixture only; never a release or daemon implementation.
 * Self-check exits successfully, but the supervised service process exits
 * before readiness. A liveness-only or self-check-only gate would be wrong. */
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "self-check") == 0) {
        return 0;
    }
#ifdef WAIT_FOR_SUPERVISOR_KILL
    /* A process that hangs before readiness. The VM test kills the
     * supervisor, not this child, and expects it to be reaped and rolled back. */
    sleep(120);
#endif
    return 42;
}
