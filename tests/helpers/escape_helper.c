/*
 * Sandbox escape test helper.
 *
 * Compiled OUTSIDE the sandbox by the integration tests, then
 * executed INSIDE ai-jail to verify that restricted operations
 * are properly blocked.
 *
 * Each subcommand attempts one restricted syscall and prints:
 *   BLOCKED  (exit 0)  — sandbox correctly denied the operation
 *   ALLOWED  (exit 1)  — operation succeeded, sandbox is broken
 *
 * The choice of syscalls is deliberate: each one normally
 * succeeds for unprivileged processes, so EPERM can only come
 * from seccomp (not from missing capabilities).
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BLOCKED() \
    do { puts("BLOCKED"); exit(0); } while (0)
#define ALLOWED(fmt, ...) \
    do { printf("ALLOWED " fmt "\n", ##__VA_ARGS__); \
         exit(1); } while (0)

/*
 * ptrace(PTRACE_TRACEME) marks the calling process as traceable
 * by its parent. Normally succeeds for any unprivileged process.
 * EPERM here can only come from seccomp.
 */
static void test_ptrace(void)
{
    errno = 0;
    long r = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=%ld, errno=%d)", r, errno);
}

/*
 * personality(0xffffffff) reads the current execution domain
 * without changing it. Normally succeeds for any process.
 * EPERM here can only come from seccomp.
 */
static void test_personality(void)
{
    errno = 0;
    int r = personality(0xffffffff);
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=0x%x, errno=%d)", r, errno);
}

/*
 * io_uring_setup() has no glibc wrapper; called via syscall().
 * With invalid args it normally returns EFAULT or EINVAL.
 * EPERM means seccomp blocked it before argument validation,
 * which is the desired behavior (io_uring can bypass seccomp
 * filters on inner syscalls).
 */
static void test_io_uring(void)
{
#ifdef SYS_io_uring_setup
    errno = 0;
    long r = syscall(SYS_io_uring_setup, 1, NULL);
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=%ld, errno=%d)", r, errno);
#else
    fprintf(stderr, "SYS_io_uring_setup not defined\n");
    exit(2);
#endif
}

/*
 * bpf(BPF_MAP_CREATE, NULL, 0) — with NULL attr it normally
 * returns EFAULT. EPERM means seccomp blocked it. eBPF can
 * load programs into the kernel to read arbitrary memory.
 */
static void test_bpf(void)
{
#ifdef SYS_bpf
    errno = 0;
    long r = syscall(SYS_bpf, 0 /* BPF_MAP_CREATE */, NULL, 0);
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=%ld, errno=%d)", r, errno);
#else
    fprintf(stderr, "SYS_bpf not defined\n");
    exit(2);
#endif
}

/*
 * clone3(NULL, 0) — with NULL args it normally returns EFAULT.
 * EPERM means seccomp blocked it. clone3's extensible struct
 * interface makes argument-level seccomp filtering unreliable.
 */
static void test_clone3(void)
{
#ifdef SYS_clone3
    errno = 0;
    long r = syscall(SYS_clone3, NULL, (size_t)0);
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=%ld, errno=%d)", r, errno);
#else
    fprintf(stderr, "SYS_clone3 not defined\n");
    exit(2);
#endif
}

/*
 * unshare(CLONE_NEWUSER) is normally available to unprivileged
 * processes (it creates a new user namespace). EPERM here means
 * seccomp blocked it — the sandbox prevents namespace escapes.
 */
static void test_unshare(void)
{
    errno = 0;
    int r = unshare(CLONE_NEWUSER);
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=%d, errno=%d)", r, errno);
}

/*
 * mount("none", "/tmp", "tmpfs", 0, NULL) — inside a user
 * namespace the process has CAP_SYS_ADMIN (within the ns),
 * so without seccomp this could succeed. EPERM means seccomp
 * blocked it, preventing filesystem rearrangement.
 */
static void test_mount(void)
{
    errno = 0;
    int r = mount("none", "/tmp", "tmpfs", 0, NULL);
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=%d, errno=%d)", r, errno);
}

/*
 * init_module(NULL, 0, "") — with NULL image it normally
 * returns EFAULT (or EPERM without CAP_SYS_MODULE). Since
 * bwrap doesn't grant CAP_SYS_MODULE, EPERM could come from
 * either capabilities or seccomp. We test it anyway as
 * defense-in-depth verification.
 */
static void test_init_module(void)
{
    errno = 0;
    long r = syscall(SYS_init_module, NULL, (unsigned long)0, "");
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=%ld, errno=%d)", r, errno);
}

/*
 * Attempt a TCP connection to an external IP. In lockdown mode:
 *  - --unshare-net removes all network interfaces except lo
 *  - Landlock V4 blocks TCP connect
 * Either ENETUNREACH (no route) or EACCES/EPERM (Landlock)
 * indicates the network is properly isolated.
 */
static void test_network(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        if (errno == EPERM || errno == EACCES)
            BLOCKED();
        ALLOWED("(socket errno=%d)", errno);
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    inet_pton(AF_INET, "1.1.1.1", &addr.sin_addr);

    errno = 0;
    int r = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    int err = errno;
    close(fd);

    if (r == -1) {
        switch (err) {
        case ENETUNREACH: /* no route — network ns isolation */
        case ENETDOWN:    /* interface down                  */
        case EACCES:      /* Landlock V4 TCP deny            */
        case EPERM:       /* seccomp or Landlock              */
            BLOCKED();
        }
    }
    ALLOWED("(connect ret=%d, errno=%d)", r, err);
}

/*
 * Try to create a file in /usr (read-only system directory).
 * Blocked by bwrap ro-bind mount + Landlock ro rules.
 */
static void test_write_sys(void)
{
    errno = 0;
    FILE *f = fopen("/usr/.sandbox_test", "w");
    if (f == NULL) {
        if (errno == EPERM || errno == EACCES || errno == EROFS)
            BLOCKED();
        ALLOWED("(fopen errno=%d)", errno);
    }
    fclose(f);
    unlink("/usr/.sandbox_test");
    ALLOWED("(file created in /usr!)");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <test>\n"
            "Tests: ptrace personality io_uring bpf clone3\n"
            "       unshare mount init_module network\n"
            "       write_sys\n",
            argv[0]);
        return 2;
    }

    const char *t = argv[1];
    if (strcmp(t, "ptrace") == 0)       test_ptrace();
    if (strcmp(t, "personality") == 0)   test_personality();
    if (strcmp(t, "io_uring") == 0)      test_io_uring();
    if (strcmp(t, "bpf") == 0)           test_bpf();
    if (strcmp(t, "clone3") == 0)        test_clone3();
    if (strcmp(t, "unshare") == 0)       test_unshare();
    if (strcmp(t, "mount") == 0)         test_mount();
    if (strcmp(t, "init_module") == 0)   test_init_module();
    if (strcmp(t, "network") == 0)       test_network();
    if (strcmp(t, "write_sys") == 0)     test_write_sys();

    fprintf(stderr, "Unknown test: %s\n", t);
    return 2;
}
