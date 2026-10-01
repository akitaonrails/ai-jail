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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sched.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int is_directory(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

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
static void test_tiocsti_highbits(void)
{
    /* Advisory GHSA-w976-gw52-hvx2 #2: the kernel reads the ioctl request as
     * 32 bits, so TIOCSTI with any upper-32 bits set is the same request. A
     * 64-bit seccomp compare missed it. Use an invalid fd: EPERM means the
     * seccomp rule fired (blocked); EBADF means the call reached the kernel
     * (the filter was bypassed). */
    errno = 0;
    unsigned long req = (unsigned long)TIOCSTI | (1UL << 32);
    long r = syscall(SYS_ioctl, -1, req, 0);
    if (r == -1 && errno == EPERM)
        BLOCKED();
    ALLOWED("(ret=%ld, errno=%d)", r, errno);
}

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
/*
 * Open the netlink route socket getifaddrs() uses to enumerate interfaces.
 * Permitted only when the sandbox already has unrestricted network and is
 * not in lockdown; the seccomp filter denies every other SOCK_RAW domain
 * and every other netlink protocol.
 */
static void test_netlink_route(void)
{
    errno = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW, 0 /* NETLINK_ROUTE */);
    if (fd == -1) {
        if (errno == EPERM || errno == EACCES)
            BLOCKED();
        ALLOWED("(socket errno=%d)", errno);
    }
    close(fd);
    ALLOWED("(netlink route socket opened)");
}

/*
 * A different netlink protocol must stay denied even when the route socket
 * is permitted, so the carve-out cannot become "all of netlink".
 */
static void test_netlink_audit(void)
{
    errno = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW, 9 /* NETLINK_AUDIT */);
    if (fd == -1) {
        if (errno == EPERM || errno == EACCES)
            BLOCKED();
        ALLOWED("(socket errno=%d)", errno);
    }
    close(fd);
    ALLOWED("(netlink audit socket opened)");
}

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
 * Attempt to create a file in a read-only system directory (/usr, /nix, or /etc).
 * Blocked by bwrap ro-bind mount and Landlock ro rules.
 */
static void test_write_sys(void)
{
    errno = 0;
    const char *target = NULL;
    if (is_directory("/usr"))
        target = "/usr/.sandbox_test";
    else if (is_directory("/nix"))
        target = "/nix/.sandbox_test";
    else if (is_directory("/etc"))
        target = "/etc/.sandbox_test";

    if (target == NULL) {
        fprintf(stderr, "SKIPPED: no system directory (/usr, /nix, /etc) available to test\n");
        exit(2);
    }

    FILE *f = fopen(target, "w");
    if (f == NULL) {
        if (errno == EPERM || errno == EACCES || errno == EROFS)
            BLOCKED();
        ALLOWED("(fopen errno=%d)", errno);
    }
    fclose(f);
    unlink(target);
    ALLOWED("(file created in %s!)", target);
}

/*
 * Cross-directory rename(2) within a writable tree (/tmp). rustc stages
 * each output in a temp dir and renames it into deps/; rustup stages then
 * renames into toolchains/. A stacked Landlock layer that does not handle
 * LANDLOCK_ACCESS_FS_REFER makes every such reparent fail with EXDEV, which
 * silently breaks all Rust compilation in the jail. This MUST succeed; it
 * prints REFER_OK (exit 0) on success, REFER_FAIL (exit 1) on EXDEV.
 */
static void test_refer_rename(void)
{
    mkdir("/tmp/.aijail_refer", 0700);
    mkdir("/tmp/.aijail_refer/a", 0700);
    mkdir("/tmp/.aijail_refer/b", 0700);
    int fd = open("/tmp/.aijail_refer/a/f", O_CREAT | O_WRONLY, 0600);
    if (fd >= 0)
        close(fd);
    errno = 0;
    if (rename("/tmp/.aijail_refer/a/f", "/tmp/.aijail_refer/b/f") == 0) {
        puts("REFER_OK");
        exit(0);
    }
    printf("REFER_FAIL (errno=%d)\n", errno);
    exit(1);
}

/*
 * Adversarial: reparent a file OUT of a read-only mapped tree into a
 * writable one. REFER is granted only on read-write paths, never read-only
 * ones, so the source directory has no REFER right and this must stay denied
 * even though /tmp is writable. Expected BLOCKED (EXDEV/EACCES/EPERM).
 */
static void test_refer_escape(void)
{
    errno = 0;
    if (rename("/tmp/aijail_rosrc/f", "/tmp/escaped") == 0)
        ALLOWED("reparent out of read-only map succeeded");
    BLOCKED();
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
    if (strcmp(t, "tiocsti_highbits") == 0) test_tiocsti_highbits();
    if (strcmp(t, "clone3") == 0)        test_clone3();
    if (strcmp(t, "unshare") == 0)       test_unshare();
    if (strcmp(t, "mount") == 0)         test_mount();
    if (strcmp(t, "init_module") == 0)   test_init_module();
    if (strcmp(t, "network") == 0)       test_network();
    if (strcmp(t, "netlink_route") == 0) test_netlink_route();
    if (strcmp(t, "netlink_audit") == 0) test_netlink_audit();
    if (strcmp(t, "write_sys") == 0)     test_write_sys();
    if (strcmp(t, "refer_rename") == 0)  test_refer_rename();
    if (strcmp(t, "refer_escape") == 0)  test_refer_escape();

    fprintf(stderr, "Unknown test: %s\n", t);
    return 2;
}
