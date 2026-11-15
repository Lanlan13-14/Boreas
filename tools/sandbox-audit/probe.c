/*
 * Boreas sandbox-audit probe fixture.
 *
 * Scope (master plan v1.11.0, section 9.5 / Phase 3 G-SANDBOX):
 * This program is an audit *fixture*. It installs a reference classic-BPF
 * seccomp filter in its own process and then exercises socket / io_uring
 * attempts, printing one machine-parseable result line per attempt.
 *
 * It proves (at most) that the reference filter and the audit harness work
 * on the host that ran it. It does NOT prove that any Boreas daemon/worker
 * installs this filter, nor that G-SANDBOX passes. There is currently no
 * accepted production daemon/worker to audit.
 *
 * Reference policy implemented here (fail-closed):
 *   - PR_SET_NO_NEW_PRIVS=1 before installing the filter.
 *   - Reject any AUDIT_ARCH other than the native build arch
 *     (x86-64: AUDIT_ARCH_X86_64 only; AArch64: AUDIT_ARCH_AARCH64 only).
 *   - Deny io_uring_setup / io_uring_enter / io_uring_register.
 *   - Deny socketcall where the ABI has it (classic BPF cannot dereference
 *     its argument pointer, so it is rejected wholesale, per plan 9.5).
 *   - Deny socket() when (type & 0xf) is SOCK_DGRAM or SOCK_RAW, for every
 *     address family. This intentionally also denies AF_UNIX SOCK_DGRAM:
 *     classic BPF sees only the low 32 bits of each argument and this
 *     fixture chooses the stricter, family-independent rule. The plan only
 *     requires denying INET/INET6 DGRAM/RAW; AF_UNIX needs (management and
 *     notify) use SOCK_STREAM / SOCK_SEQPACKET in this fixture. A future
 *     daemon that needs AF_UNIX DGRAM must use a reviewed two-argument
 *     filter and separate evidence; see README.md.
 *
 * Exit codes: 0 = probe ran to completion (verdicts are in stdout lines,
 * the harness judges them); 3 = environment unsupported / filter could
 * not be installed (harness must report UNPROVEN, never PASS).
 *
 * Build (no libseccomp dependency): cc -O2 -Wall -Wextra -o probe probe.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static void report_socket(const char *name, int domain, int type, int protocol,
                          int expect_allowed)
{
    errno = 0;
    int fd = socket(domain, type, protocol);
    int saved_errno = errno;
    const char *verdict;
    if (fd >= 0) {
        verdict = expect_allowed ? "OK_ALLOWED" : "FAIL_ALLOWED_UNEXPECTEDLY";
        close(fd);
    } else if (expect_allowed) {
        verdict = "FAIL_DENIED_UNEXPECTEDLY";
    } else if (saved_errno == EPERM) {
        verdict = "OK_DENIED_EPERM";
    } else {
        /* Denied, but not by our EPERM rule (e.g. EACCES from another LSM,
         * EAFNOSUPPORT, ENOSYS from an outer sandbox). The harness must
         * treat this as INCONCLUSIVE for this case, not as proof. */
        verdict = "INCONCLUSIVE_DENIED_OTHER_ERRNO";
    }
    printf("CASE %s result=%s errno=%d\n", name, verdict, saved_errno);
    fflush(stdout);
}

static void report_raw_syscall(const char *name, long nr, long a1)
{
    errno = 0;
    long ret = syscall(nr, a1, 0L, 0L, 0L, 0L, 0L);
    int saved_errno = errno;
    const char *verdict;
    if (ret >= 0) {
        verdict = "FAIL_ALLOWED_UNEXPECTEDLY";
        if (nr == __NR_io_uring_setup)
            close((int)ret);
    } else if (saved_errno == EPERM) {
        verdict = "OK_DENIED_EPERM";
    } else {
        /* ENOSYS here usually means an outer sandbox (e.g. Android/PRoot)
         * intercepted the syscall before our filter could be observed.
         * That is not evidence that this filter denies io_uring. */
        verdict = "INCONCLUSIVE_DENIED_OTHER_ERRNO";
    }
    printf("CASE %s result=%s errno=%d\n", name, verdict, saved_errno);
    fflush(stdout);
}

int main(void)
{
#if defined(__aarch64__)
    const unsigned expected_arch = AUDIT_ARCH_AARCH64;
    const char *arch_name = "aarch64";
#elif defined(__x86_64__)
    const unsigned expected_arch = AUDIT_ARCH_X86_64;
    const char *arch_name = "x86_64";
#else
    puts("PROBE_UNSUPPORTED_ARCH");
    return 3;
#endif

    /* Classic-BPF reference filter. Jump offsets are relative; keep the
     * layout linear and auditable. SECCOMP_RET_ERRNO|EPERM is the deny
     * action so callers see a deterministic errno. */
    struct sock_filter filter[] = {
        /* arch check first (plan 9.5: verify AUDIT_ARCH before anything) */
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, expected_arch, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        /* syscall number dispatch */
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_io_uring_setup, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_io_uring_enter, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_io_uring_register, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
#ifdef __NR_socketcall
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_socketcall, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
#endif
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_socket, 1, 0),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
        /* socket(): inspect (type & 0xf); low word of args[1] */
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS,
                 offsetof(struct seccomp_data, args) + sizeof(__u64)),
        BPF_STMT(BPF_ALU + BPF_AND + BPF_K, 0xf),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SOCK_DGRAM, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SOCK_RAW, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    printf("PROBE_START arch=%s\n", arch_name);
    fflush(stdout);

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        printf("PROBE_ENV_ERROR step=no_new_privs errno=%d\n", errno);
        return 3;
    }
    /* Single-threaded at this point, so plain filter install is atomic for
     * this process. SECCOMP_FILTER_FLAG_TSYNC is required for a real
     * multi-threaded daemon (plan 9.5) and is deliberately NOT claimed
     * here; the harness reports tsync=not_applicable_single_thread. */
    if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0UL, &prog) != 0) {
        printf("PROBE_ENV_ERROR step=seccomp_install errno=%d\n", errno);
        return 3;
    }
    printf("FILTER_INSTALLED arch=%s tsync=not_applicable_single_thread\n", arch_name);
    fflush(stdout);

    /* Positive cases: management-plane transports must keep working. */
    report_socket("unix_stream", AF_UNIX, SOCK_STREAM, 0, 1);
    report_socket("unix_seqpacket", AF_UNIX, SOCK_SEQPACKET, 0, 1);
    report_socket("tcp_stream_v4", AF_INET, SOCK_STREAM, 0, 1);
    report_socket("tcp_stream_v6", AF_INET6, SOCK_STREAM, 0, 1);

    /* Negative cases required by G-SANDBOX (plus cloexec flag bypass try). */
    report_socket("inet_udp_v4", AF_INET, SOCK_DGRAM, 0, 0);
    report_socket("inet_udp_v6", AF_INET6, SOCK_DGRAM, 0, 0);
    report_socket("inet_udp_cloexec", AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0, 0);
    report_socket("inet_udp_nonblock", AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0, 0);
    report_socket("inet_raw_v4", AF_INET, SOCK_RAW, IPPROTO_TCP, 0);
    report_socket("inet_raw_v6", AF_INET6, SOCK_RAW, IPPROTO_TCP, 0);
    report_socket("unix_dgram_strict", AF_UNIX, SOCK_DGRAM, 0, 0);
    report_raw_syscall("io_uring_setup", __NR_io_uring_setup, 8);

    /* Surface kernel-reported sandbox state for the evidence bundle. */
    FILE *status = fopen("/proc/self/status", "r");
    if (status != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), status) != NULL) {
            if (strncmp(line, "NoNewPrivs:", 11) == 0 ||
                strncmp(line, "Seccomp:", 8) == 0 ||
                strncmp(line, "Seccomp_filters:", 16) == 0) {
                printf("PROC_STATUS %s", line);
            }
        }
        fclose(status);
    } else {
        puts("PROC_STATUS unavailable");
    }
    puts("PROBE_DONE");
    fflush(stdout);
    return 0;
}
