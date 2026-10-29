/*
 * duckadbd — KPM: hide adbd's presence from ordinary apps.
 *
 * Targets the Duck Detector ADB Runtime card's socket observations:
 *   - fstatat/statx("/dev/socket/adbd") -> ENOENT (uid >= 10000)
 *   - connect(AF_UNIX, "\0jdwp-control") -> ECONNREFUSED via LSM hook
 *     security_socket_connect (kernel sockaddr, no uaccess needed).
 *     The detector reads EACCES/EPERM as "listener exists", so it must
 *     see ECONNREFUSED, which it reads as absence.
 *
 * getdents64 is not touched: with stat()=ENOENT and "adbd" left listed,
 * the detector's resolver yields UNKNOWN at worst, never PRESENT.
 *
 * Property spoofing (init.svc.adbd=stopped, persist.sys.usb.config=mtp) is
 * done in userspace (resetprop -n); this module only removes the
 * kernel-visible sockets that would otherwise contradict the stopped story.
 */

#include <compiler.h>
#include <kpmodule.h>
#include <ksyms.h>
#include <hook.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include <uapi/asm-generic/unistd.h>

#define offsetof_local(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

static bool app_uid(void)
{
    return current_uid() >= 10000;
}

static bool path_is_adbd_socket(const char *p)
{
    static const char target[] = "/dev/socket/adbd";
    size_t i;

    if (!p)
        return false;
    for (i = 0; i + 1 < sizeof(target); i++) {
        if (p[i] != target[i])
            return false;
    }
    return p[i] == '\0';
}

/* Copy a user pathname; returns true when a NUL-terminated copy landed in dst. */
static bool read_user_path(char *dst, size_t dstlen, uint64_t upath)
{
    long n;

    if ((long)upath <= 0)
        return false;
    n = compat_strncpy_from_user(dst, (const char __user *)(uintptr_t)upath,
                                 (long)dstlen);
    if (n <= 0)
        return false;
    if (n >= (long)dstlen)
        n = (long)dstlen - 1; /* truncated: still comparable, worst case a miss */
    dst[n] = '\0';
    return true;
}

/*
 * Hook bodies. With has_syscall_wrapper the syscall args live in pt_regs;
 * syscall_argn() resolves that for us regardless of kernel config.
 */

static u32 g_stat_hits;
static u32 g_stat_path_fail;
static u32 g_fstatat_calls;

static void before_newfstatat(hook_fargs4_t *a, void *u)
{
    char path[96];
    uint64_t arg1;

    if (++g_fstatat_calls == 1)
        pr_info("[duckadbd] fstatat callback first call uid=%d\n", current_uid());
    if (!app_uid() || !a)
        return;
    arg1 = syscall_argn(a, 1); /* filename */
    if (!read_user_path(path, sizeof(path), arg1)) {
        if (++g_stat_path_fail == 1)
            pr_info("[duckadbd] fstatat: path read failed arg1=%llx\n", arg1);
        return;
    }
    if (!path_is_adbd_socket(path))
        return;

    if (++g_stat_hits == 1)
        pr_info("[duckadbd] fstatat: masking /dev/socket/adbd for uid %d\n", current_uid());
    a->ret = (uint64_t)(-(uint64_t)ENOENT);
    a->skip_origin = 1;
}

static void before_statx(hook_fargs4_t *a, void *u)
{
    char path[96];
    uint64_t arg1;
    static u32 statx_calls;

    if (++statx_calls == 1)
        pr_info("[duckadbd] statx callback first call uid=%d\n", current_uid());
    if (!app_uid() || !a)
        return;
    arg1 = syscall_argn(a, 1); /* filename */
    if (!read_user_path(path, sizeof(path), arg1))
        return;
    if (!path_is_adbd_socket(path))
        return;

    a->ret = (uint64_t)(-(uint64_t)ENOENT);
    a->skip_origin = 1;
}

/* getdents64 filtering is intentionally omitted: the detector only treats a
 * listed "adbd" as corroborating evidence. With stat() returning ENOENT and
 * "adbd" left in the listing, resolveInitSocketPresence() yields UNKNOWN
 * at worst — never PRESENT/PRESENT_DENIED. */

struct sockaddr_un_min {
    uint16_t sun_family;
    char sun_path[108];
};

/*
 * security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
 * LSM hook: `address` is already a KERNEL pointer here — no user copy needed.
 */
static void before_security_socket_connect(hook_fargs4_t *a, void *u)
{
    struct sockaddr_un_min *sa = (struct sockaddr_un_min *)(uintptr_t)a->arg1;
    static const char name[] = "jdwp-control";
    size_t i;

    if (!app_uid() || !a)
        return;
    if ((uintptr_t)sa <= 0)
        return;
    if ((int)a->arg2 < (int)(offsetof_local(struct sockaddr_un_min, sun_path) + 2))
        return;
    if (sa->sun_family != 1) /* AF_UNIX */
        return;
    if (sa->sun_path[0] != '\0') /* abstract only */
        return;
    for (i = 0; i + 1 < sizeof(name); i++) {
        if (sa->sun_path[1 + i] != name[i])
            return;
    }
    if (sa->sun_path[1 + sizeof(name) - 1] != '\0')
        return;

    a->ret = (uint64_t)(-(uint64_t)ECONNREFUSED);
    a->skip_origin = 1;
}

static long duckadbd_init(const char *args, const char *event, void *reserved)
{
    hook_err_t err;
    int installed = 0;

    /* syscall hooks by number: survives unregistered-symbols and wrappers.
     * arm64: fstatat is exposed as __NR3264_fstatat in the KP table. */
    err = inline_hook_syscalln(__NR3264_fstatat, 4, before_newfstatat, NULL, NULL);
    if (err == HOOK_NO_ERR) installed++;
    else pr_err("[duckadbd] fstatat hook err %d\n", err);

    err = inline_hook_syscalln(__NR_statx, 5, before_statx, NULL, NULL);
    if (err == HOOK_NO_ERR) installed++;
    else pr_err("[duckadbd] statx hook err %d\n", err);

    /* jdwp-control: LSM hook gets a kernel sockaddr pointer — no uaccess dance */
    {
        unsigned long saddr = kallsyms_lookup_name("security_socket_connect");
        if (saddr && hook_wrap((void *)saddr, 3, before_security_socket_connect, NULL, NULL) == HOOK_NO_ERR)
            installed++;
        else
            pr_err("[duckadbd] security_socket_connect hook failed\n");
    }

    pr_info("[duckadbd] installed %d hooks (wrapper=%d)\n", installed, has_syscall_wrapper);
    return installed > 0 ? 0 : -1;
}

static long duckadbd_exit(void *reserved)
{
    inline_unhook_syscalln(__NR3264_fstatat, before_newfstatat, NULL);
    inline_unhook_syscalln(__NR_statx, before_statx, NULL);
    pr_info("[duckadbd] exit\n");
    return 0;
}

KPM_NAME("duckadbd");
KPM_VERSION("1.2.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("payebal");
KPM_DESCRIPTION("Hide adbd init socket and jdwp-control from apps uid>=10000");
KPM_INIT(duckadbd_init);
KPM_EXIT(duckadbd_exit);
