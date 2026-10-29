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

#include "kpmodule.h"
#include "kpmalloc.h"
#include <hook.h>
#include <ksyms.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/un.h>
#include <linux/time.h>
#include <asm/posix_types.h>
#include <linux/uio.h>

#define offsetof_macro(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

#define ENOENT_K 2
#define ECONNREFUSED_K 111

typedef long (*strncpy_from_user_fn_t)(char *dst, const char *src, long count);
typedef unsigned long (*copy_from_user_fn_t)(void *to, const void *from, unsigned long n);
typedef unsigned long (*copy_to_user_fn_t)(void *to, const void *from, unsigned long n);

static strncpy_from_user_fn_t strncpy_from_user_fn;
static copy_from_user_fn_t copy_from_user_fn;
static copy_to_user_fn_t copy_to_user_fn;

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

static void before_sys_newfstatat(hook_fargs4_t *a, void *u)
{
    char path[96];
    long n;

    if (!app_uid() || !a)
        return;
    if ((long)a->arg1 <= 0)
        return;
    if (!strncpy_from_user_fn)
        return;
    n = strncpy_from_user_fn(path, (const char *)(uintptr_t)a->arg1, sizeof(path) - 1);
    if (n <= 0)
        return;
    path[n] = '\0';
    /* ENAMETOOLONG-class truncation: if the source was longer, bail */
    if (n == (long)sizeof(path) - 1 && path[n - 1] != '\0')
        return;
    if (!path_is_adbd_socket(path))
        return;

    a->ret = (uint64_t)(-(uint64_t)ENOENT_K);
    a->skip_origin = 1;
}

static void before_sys_statx(hook_fargs8_t *a, void *u)
{
    char path[96];
    long n;

    if (!app_uid() || !a)
        return;
    if ((long)a->arg1 <= 0)
        return;
    if (!strncpy_from_user_fn)
        return;
    n = strncpy_from_user_fn(path, (const char *)(uintptr_t)a->arg1, sizeof(path) - 1);
    if (n <= 0)
        return;
    path[n] = '\0';
    if (n == (long)sizeof(path) - 1 && path[n - 1] != '\0')
        return;
    if (!path_is_adbd_socket(path))
        return;

    a->ret = (uint64_t)(-(uint64_t)ENOENT_K);
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
    return name[0] == 'a' && name[1] == 'd' && name[2] == 'b' && name[3] == 'd' && name[4] == '\0';
}

static void after_sys_getdents64(hook_fargs4_t *a, void *u)
{
    char kbuf[2048];
    struct dents64_min *de;
    long ret, total, kept;
    size_t chunk, off, out;
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
        if (copy_from_user_fn(kbuf, (void *)(user_buf + total), chunk) != 0)
            return; /* fault: leave the listing untouched */

        off = 0;
        out = 0;
        while (off < chunk) {
            de = (struct dents64_min *)(kbuf + off);
            if (de->d_reclen == 0 || off + de->d_reclen > chunk)
                break;
            if (!name_is_adbd(de->d_name)) {
                if (out != off) {
                    for (size_t i = 0; i < de->d_reclen; i++)
                        kbuf[out + i] = kbuf[off + i];
                }
                out += de->d_reclen;
            }
            off += de->d_reclen;
        }
        if (out != chunk) {
            for (size_t i = out; i < chunk; i++)
                kbuf[i] = 0;
            if (copy_to_user_fn((void *)(user_buf + total), kbuf, chunk) != 0)
                return;
        }
        kept += (long)out;
        total += (long)chunk;
    }

    if (kept != ret)
        a->ret = (uint64_t)kept;
}

static bool uaddr_is_jdwp(uint64_t arg1, uint64_t arg2)
{
    struct sockaddr_un kaddr;

    if ((long)arg1 <= 0)
        return false;
    if ((long)arg2 < (long)(offsetof_macro(struct sockaddr_un, sun_path) + 2))
        return false;
    if (!copy_from_user_fn)
        return false;
    if (copy_from_user_fn(&kaddr, (void *)(uintptr_t)arg1, sizeof(kaddr)) != 0)
        return false;
    if (kaddr.sun_family != 1 /* AF_UNIX */)
        return false;
    if (kaddr.sun_path[0] != '\0')
        return false;
    /* abstract: "\0jdwp-control" */
    {
        static const char name[] = "jdwp-control";
        for (size_t i = 0; i + 1 < sizeof(name); i++) {
            if (kaddr.sun_path[1 + i] != name[i])
                return false;
        }
        return kaddr.sun_path[1 + sizeof(name) - 1] == '\0';
    }
}

static void before_unix_stream_connect(hook_fargs4_t *a, void *u)
{
    if (!app_uid() || !a)
        return;
    if (!uaddr_is_jdwp(a->arg1, a->arg2))
        return;

    a->ret = (uint64_t)(-(uint64_t)ECONNREFUSED_K);
    a->skip_origin = 1;
}

static long duckadbd_init(const char *args, const char *event, void *reserved)
{
    unsigned long addr;
    int installed = 0;

    strncpy_from_user_fn = (strncpy_from_user_fn_t)kallsyms_lookup_name("strncpy_from_user");
    copy_from_user_fn = (copy_from_user_fn_t)kallsyms_lookup_name("_copy_from_user");
    copy_to_user_fn = (copy_to_user_fn_t)kallsyms_lookup_name("_copy_to_user");
    if (!strncpy_from_user_fn || !copy_from_user_fn || !copy_to_user_fn) {
        pr_info("[duckadbd] usercopy helpers missing %d %d %d\n",
                !!strncpy_from_user_fn, !!copy_from_user_fn, !!copy_to_user_fn);
        return -1;
    }

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

#define offsetof_macro(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)

KPM_NAME("duckadbd");
KPM_VERSION(1, 0, 0);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("payebal");
KPM_DESCRIPTION("Hide adbd init socket and jdwp-control from apps uid>=10000");
KPM_INIT(duckadbd_init);
KPM_EXIT(duckadbd_exit);
