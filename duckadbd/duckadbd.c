/*
 * duckadbd — KPM: hide adbd's presence from ordinary apps.
 *
 * Targets the Duck Detector ADB Runtime card's socket observations:
 *   - stat/statx("/dev/socket/adbd")     -> ENOENT  (uid >= 10000)
 *   - getdents64 listing of /dev/socket  -> "adbd" entries dropped
 *   - connect(AF_UNIX, "\0jdwp-control") -> ECONNREFUSED (never EACCES:
 *     the detector reads EACCES/EPERM as "listener exists")
 *
 * Property spoofing (init.svc.adbd=stopped, persist.sys.usb.config=mtp) is
 * done in userspace (resetprop -n + watchdog); this module only removes the
 * kernel-visible sockets that would otherwise contradict the stopped story.
 */

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/err.h>
#include <asm/current.h>
#include <uapi/asm-generic/errno.h>
#include <ksyms.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>

#define offsetof_local(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

typedef unsigned long (*copy_from_user_fn_t)(void *to, const void *from, unsigned long n);
static copy_from_user_fn_t copy_from_user_fn;

/* returns true when the whole chunk was copied */
static bool copy_from_user_helper(void *dst, const void *src, size_t n)
{
    if (!copy_from_user_fn)
        return false;
    return copy_from_user_fn(dst, src, (unsigned long)n) == 0;
}

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
        n = (long)dstlen - 1; /* truncated source: still comparable, worst case a miss */
    dst[n] = '\0';
    return true;
}

/*
 * sys_newfstatat(int dfd, const char __user *filename,
 *                struct stat __user *statbuf, int flag)
 */
static void before_sys_newfstatat(hook_fargs4_t *a, void *u)
{
    char path[96];

    if (!app_uid() || !a)
        return;
    if (!read_user_path(path, sizeof(path), a->arg1))
        return;
    if (!path_is_adbd_socket(path))
        return;

    a->ret = (uint64_t)(-(uint64_t)ENOENT);
    a->skip_origin = 1;
}

/*
 * sys_statx(int dfd, const char __user *filename, unsigned int flags,
 *           unsigned int mask, struct statx __user *buffer)
 */
static void before_sys_statx(hook_fargs8_t *a, void *u)
{
    char path[96];

    if (!app_uid() || !a)
        return;
    if (!read_user_path(path, sizeof(path), a->arg1))
        return;
    if (!path_is_adbd_socket(path))
        return;

    a->ret = (uint64_t)(-(uint64_t)ENOENT);
    a->skip_origin = 1;
}

struct dents64_min {
    uint64_t d_ino;
    int64_t d_off;
    uint16_t d_reclen;
    uint8_t d_type;
    char d_name[];
};

static bool name_is_adbd(const char *name)
{
    return name[0] == 'a' && name[1] == 'd' && name[2] == 'b' &&
           name[3] == 'd' && name[4] == '\0';
}

/*
 * sys_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
 *                unsigned int count) — drop "adbd" entries for app uids.
 */
static void after_sys_getdents64(hook_fargs4_t *a, void *u)
{
    char kbuf[2048];
    struct dents64_min *de;
    long ret, total, kept;
    size_t chunk, off, out, i;
    unsigned long user_buf;

    if (!app_uid() || !a)
        return;
    ret = (long)a->ret;
    if (ret <= 0)
        return;
    user_buf = (unsigned long)a->arg1;
    if (!user_buf)
        return;

    total = 0;
    kept = 0;
    while (total < ret) {
        chunk = (size_t)(ret - total);
        if (chunk > sizeof(kbuf))
            chunk = sizeof(kbuf);
        if (!copy_from_user_helper(kbuf, (void *)(user_buf + total), chunk))
            return; /* fault: leave the listing untouched */

        off = 0;
        out = 0;
        while (off < chunk) {
            de = (struct dents64_min *)(kbuf + off);
            if (de->d_reclen == 0 || off + de->d_reclen > chunk)
                break;
            if (!name_is_adbd(de->d_name)) {
                if (out != off) {
                    for (i = 0; i < de->d_reclen; i++)
                        kbuf[out + i] = kbuf[off + i];
                }
                out += de->d_reclen;
            }
            off += de->d_reclen;
        }
        if (out != chunk) {
            for (i = out; i < chunk; i++)
                kbuf[i] = 0;
            if (!copy_to_user_helper((void *)(user_buf + total), kbuf, chunk))
                return;
        }
        kept += (long)out;
        total += (long)chunk;
    }

    if (kept != ret)
        a->ret = (uint64_t)kept;
}

struct sockaddr_un_min {
    uint16_t sun_family;
    char sun_path[108];
};

static bool uaddr_is_jdwp(uint64_t arg1, uint64_t arg2)
{
    struct sockaddr_un_min kaddr;
    static const char name[] = "jdwp-control";
    size_t i;

    if ((long)arg1 <= 0)
        return false;
    if ((long)arg2 < (long)(offsetof_local(struct sockaddr_un_min, sun_path) + 2))
        return false;
    if (!copy_from_user_helper(&kaddr, (void *)(uintptr_t)arg1, sizeof(kaddr)))
        return false;
    if (kaddr.sun_family != 1) /* AF_UNIX */
        return false;
    if (kaddr.sun_path[0] != '\0')
        return false;
    for (i = 0; i + 1 < sizeof(name); i++) {
        if (kaddr.sun_path[1 + i] != name[i])
            return false;
    }
    return kaddr.sun_path[1 + sizeof(name) - 1] == '\0';
}

static void before_unix_stream_connect(hook_fargs4_t *a, void *u)
{
    if (!app_uid() || !a)
        return;
    if (!uaddr_is_jdwp(a->arg1, a->arg2))
        return;

    a->ret = (uint64_t)(-(uint64_t)ECONNREFUSED);
    a->skip_origin = 1;
}

static bool copy_to_user_helper(void *dst, const void *src, size_t n)
{
    int rc = compat_copy_to_user(dst, src, (int)n);
    return rc != 0;
}

static long duckadbd_init(const char *args, const char *event, void *reserved)
{
    unsigned long addr;
    int installed = 0;

    copy_from_user_fn = (copy_from_user_fn_t)kallsyms_lookup_name("_copy_from_user");
    if (!copy_from_user_fn)
        copy_from_user_fn = (copy_from_user_fn_t)kallsyms_lookup_name("copy_from_user");

    addr = kallsyms_lookup_name("sys_newfstatat");
    if (addr && hook_wrap((void *)addr, 4, before_sys_newfstatat, NULL, NULL) == HOOK_NO_ERR)
        installed++;

    addr = kallsyms_lookup_name("sys_statx");
    if (addr && hook_wrap((void *)addr, 5, before_sys_statx, NULL, NULL) == HOOK_NO_ERR)
        installed++;

    addr = kallsyms_lookup_name("sys_getdents64");
    if (addr && hook_wrap((void *)addr, 3, NULL, after_sys_getdents64, NULL) == HOOK_NO_ERR)
        installed++;

    addr = kallsyms_lookup_name("unix_stream_connect");
    if (addr && hook_wrap((void *)addr, 4, before_unix_stream_connect, NULL, NULL) == HOOK_NO_ERR)
        installed++;

    pr_info("[duckadbd] installed %d hooks\n", installed);
    return installed > 0 ? 0 : -1;
}

static long duckadbd_exit(void *reserved)
{
    pr_info("[duckadbd] exit\n");
    return 0;
}

KPM_NAME("duckadbd");
KPM_VERSION(1, 0, 0);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("payebal");
KPM_DESCRIPTION("Hide adbd init socket and jdwp-control from apps uid>=10000");
KPM_INIT(duckadbd_init);
KPM_EXIT(duckadbd_exit);
