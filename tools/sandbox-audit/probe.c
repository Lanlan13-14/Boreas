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
 *   - Deny socketcall where the build ABI defines it (the supported
 *     x86-64/AArch64 builds do not define __NR_socketcall, so this probe
 *     never claims a native socketcall case).
 *   - Deny socket() when (type & 0xf) is SOCK_DGRAM or SOCK_RAW, for every
 *     address family. This intentionally also denies AF_UNIX SOCK_DGRAM:
 *     classic BPF sees only the low 32 bits of each argument and this
 *     fixture chooses the stricter, family-independent rule. The plan only
 *     requires denying INET/INET6 DGRAM/RAW; AF_UNIX needs (management and
 *     notify) use SOCK_STREAM / SOCK_SEQPACKET in this fixture. A future
 *     daemon that needs AF_UNIX DGRAM must use a reviewed two-argument
 *     filter and separate evidence; see README.md.
 *
 * Inherited-fd audit: before installing the filter the probe creates a
 * connected loopback UDP socket, an AF_UNIX SOCK_DGRAM pair and (when the
 * kernel permits it) an io_uring ring. After installation it reports whether
 * those already-open fds still work and whether further io_uring_enter calls
 * on the pre-existing ring are blocked. This demonstrates that the filter
 * cannot revoke inherited descriptors; it is NOT a daemon fd-cleanup audit and
 * does not prove that a Boreas daemon inherits no network fds or rings.
 *
 * Exit codes: 0 = probe ran to completion (verdicts are in stdout lines,
 * the harness judges them); 3 = environment unsupported / filter could
 * not be installed (harness must report UNPROVEN, never PASS).
 *
 * Build (no libseccomp dependency): cc -O2 -Wall -Wextra -o probe probe.c
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/io_uring.h>
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
        /* Not compiled on the supported x86-64/AArch64 probes. */
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

    /* --- Inherited-fd audit setup, before the filter exists. --------------
     * These descriptors are deliberately created first. After the filter is
     * installed the probe reports whether they still work: a seccomp filter
     * cannot revoke an fd the process already holds. This audits THIS PROBE
     * only; it does not audit any daemon's inherited-fd cleanup and does not
     * claim that fd inheritance is safe in production. */
    int udp_recv = -1;
    int udp_send = -1;
    struct sockaddr_in udp_addr;
    socklen_t udp_addr_len = (socklen_t)sizeof(udp_addr);
    memset(&udp_addr, 0, sizeof(udp_addr));
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    udp_addr.sin_port = 0;
    udp_recv = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_recv >= 0
        && bind(udp_recv, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) == 0
        && getsockname(udp_recv, (struct sockaddr *)&udp_addr, &udp_addr_len) == 0) {
        udp_send = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_send < 0
            || connect(udp_send, (struct sockaddr *)&udp_addr, udp_addr_len) != 0) {
            if (udp_send >= 0) {
                close(udp_send);
                udp_send = -1;
            }
        }
    } else {
        if (udp_recv >= 0) {
            close(udp_recv);
            udp_recv = -1;
        }
    }
    if (udp_recv < 0 || udp_send < 0) {
        if (udp_recv >= 0) {
            close(udp_recv);
            udp_recv = -1;
        }
        if (udp_send >= 0) {
            close(udp_send);
            udp_send = -1;
        }
    }
    int unix_pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, unix_pair) != 0) {
        unix_pair[0] = -1;
        unix_pair[1] = -1;
    }
    int ring_fd = -1;
    int ring_setup_errno = 0;
    struct io_uring_params ring_params;
    memset(&ring_params, 0, sizeof(ring_params));
    errno = 0;
    ring_fd = (int)syscall(__NR_io_uring_setup, 2U, &ring_params);
    if (ring_fd < 0) {
        ring_setup_errno = errno;
    } else if (fcntl(ring_fd, F_GETFD) < 0) {
        /* Some outer ptrace sandboxes fabricate a success return for
         * io_uring_setup. An fd that fcntl cannot see is not a ring we can
         * honestly audit, so record the setup as failed instead. */
        ring_setup_errno = EBADF;
        close(ring_fd);
        ring_fd = -1;
    }

    /* Prove the pre-filter fds work BEFORE attributing anything to the
     * filter. A failed setup must be INCONCLUSIVE, never evidence. */
    if (udp_recv >= 0 && udp_send >= 0) {
        char sent = 'P';
        char received = 0;
        if (send(udp_send, &sent, 1, 0) != 1
            || recv(udp_recv, &received, 1, 0) != 1
            || received != sent) {
            close(udp_send);
            close(udp_recv);
            udp_send = -1;
            udp_recv = -1;
        }
    }
    if (unix_pair[0] >= 0) {
        char sent = 'P';
        char received = 0;
        if (write(unix_pair[0], &sent, 1) != 1
            || read(unix_pair[1], &received, 1) != 1
            || received != sent) {
            close(unix_pair[0]);
            close(unix_pair[1]);
            unix_pair[0] = -1;
            unix_pair[1] = -1;
        }
    }

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
    /* enter/register take different arguments; the reference filter denies by
     * syscall number before looking at them, so an invalid fd is sufficient. */
    report_raw_syscall("io_uring_enter", __NR_io_uring_enter, -1);
    report_raw_syscall("io_uring_register", __NR_io_uring_register, -1);

    /* --- Inherited-fd audit (fds created before the filter). --------------- */
    if (udp_recv >= 0 && udp_send >= 0) {
        char sent = 'I';
        char received = 0;
        errno = 0;
        ssize_t send_ret = send(udp_send, &sent, 1, 0);
        int send_errno = errno;
        errno = 0;
        ssize_t recv_ret = recv(udp_recv, &received, 1, 0);
        int recv_errno = errno;
        if (send_ret == 1 && recv_ret == 1 && received == sent) {
            printf("CASE inherited_udp_fd result=OK_INHERITED_FD_STILL_USABLE\n");
        } else {
            printf("CASE inherited_udp_fd result=FAIL_INHERITED_FD_BROKEN"
                   " send_ret=%zd send_errno=%d recv_ret=%zd recv_errno=%d\n",
                   send_ret, send_errno, recv_ret, recv_errno);
        }
    } else {
        printf("CASE inherited_udp_fd result=INCONCLUSIVE_SETUP_FAILED\n");
    }
    if (unix_pair[0] >= 0) {
        char sent = 'U';
        char received = 0;
        errno = 0;
        ssize_t write_ret = write(unix_pair[0], &sent, 1);
        int write_errno = errno;
        errno = 0;
        ssize_t read_ret = read(unix_pair[1], &received, 1);
        int read_errno = errno;
        if (write_ret == 1 && read_ret == 1 && received == sent) {
            printf("CASE inherited_unix_dgram_fd result=OK_INHERITED_FD_STILL_USABLE\n");
        } else {
            printf("CASE inherited_unix_dgram_fd result=FAIL_INHERITED_FD_BROKEN"
                   " write_ret=%zd write_errno=%d read_ret=%zd read_errno=%d\n",
                   write_ret, write_errno, read_ret, read_errno);
        }
    } else {
        printf("CASE inherited_unix_dgram_fd result=INCONCLUSIVE_SETUP_FAILED\n");
    }
    if (ring_fd >= 0) {
        /* The ring and its fd predate the filter. The filter cannot revoke
         * them; it only stops further io_uring_enter calls. That is why
         * inherited io_uring cleanup must be a separate daemon-side step. */
        errno = 0;
        long enter_ret = syscall(__NR_io_uring_enter, (unsigned int)ring_fd,
                                 0U, 0U, 0U, NULL, (size_t)0);
        int enter_errno = errno;
        if (enter_ret < 0 && enter_errno == EPERM) {
            printf("CASE inherited_io_uring_ring"
                   " result=OK_INHERITED_RING_FD_BLOCKED_EPERM\n");
        } else if (enter_ret < 0) {
            printf("CASE inherited_io_uring_ring"
                   " result=INCONCLUSIVE_DENIED_OTHER_ERRNO errno=%d\n",
                   enter_errno);
        } else {
            printf("CASE inherited_io_uring_ring result=FAIL_ENTER_ALLOWED\n");
        }
        close(ring_fd);
    } else {
        printf("CASE inherited_io_uring_ring result=INCONCLUSIVE_SETUP_FAILED"
               " errno=%d\n", ring_setup_errno);
    }
    if (udp_send >= 0) {
        close(udp_send);
    }
    if (udp_recv >= 0) {
        close(udp_recv);
    }
    if (unix_pair[0] >= 0) {
        close(unix_pair[0]);
        close(unix_pair[1]);
    }


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
