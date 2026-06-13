#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* ============================================================
 * Feature flags — all enabled by default.
 * Disable at compile time: clang ... -UMONITOR_EXEC
 * ============================================================ */
#ifndef MONITOR_EXEC
#define MONITOR_EXEC
#endif
#ifndef MONITOR_SUDO
#define MONITOR_SUDO
#endif
#ifndef MONITOR_PASSWD
#define MONITOR_PASSWD
#endif
#ifndef MONITOR_CONNECT
#define MONITOR_CONNECT
#endif
#ifndef MONITOR_PTRACE
#define MONITOR_PTRACE
#endif
#ifndef MONITOR_OPENAT
#define MONITOR_OPENAT
#endif
#ifndef MONITOR_SETUID
#define MONITOR_SETUID
#endif
#ifndef MONITOR_FORK
#define MONITOR_FORK
#endif
#ifndef MONITOR_EXIT
#define MONITOR_EXIT
#endif
#ifndef MONITOR_BIND
#define MONITOR_BIND
#endif
#ifndef MONITOR_DNS
#define MONITOR_DNS
#endif
#ifndef MONITOR_CAPSET
#define MONITOR_CAPSET
#endif
#ifndef MONITOR_WRITE
#define MONITOR_WRITE
#endif
#ifndef MONITOR_OPEN
#define MONITOR_OPEN
#endif
#ifndef MONITOR_OPENAT2
#define MONITOR_OPENAT2
#endif
#ifndef MONITOR_OOM
#define MONITOR_OOM
#endif

/* ============================================================
 * Event types for ringbuf
 * ============================================================ */
#define EVENT_EXEC      1
#define EVENT_CONNECT   2
#define EVENT_PTRACE    3
#define EVENT_OPENAT    4
#define EVENT_SETUID    5
#define EVENT_SETGID    6
#define EVENT_FORK      7
#define EVENT_EXIT      8
#define EVENT_BIND      9
#define EVENT_DNS       10
#define EVENT_CAPSET    11
#define EVENT_WRITE     12
#define EVENT_OOM_KILL  13

#define EVENT_HEADER_SIZE 72
#define MAX_EXEC_PATH     128

/* Event flags */
#define FLAG_SUDO              (1 << 0)
#define FLAG_SUSPICIOUS_PORT   (1 << 1)
#define FLAG_SENSITIVE_FILE    (1 << 2)
#define FLAG_PASSWD_READ       (1 << 3)
#define FLAG_TMP_FILE          (1 << 4)

/* ============================================================
 * Fixed event header for ringbuf (72 bytes); exec may append path tail
 * ============================================================ */
struct ebpf_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  event_type;
    __u8  flags;
    __u16 dest_port;
    __u8  ip_version; /* 0=none, 4=IPv4, 6=IPv6 */
    __u8  path_len;
    __u16 _pad;
    __u64 cgroup_id;
    __u8  dest_ip[16];
    char  comm[16];
    __u32 _tail_pad;
};

/* ============================================================
 * RingBuf for rich events to userspace
 * ============================================================ */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ringbuf_drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u32);
} pid_parents SEC(".maps");

#ifdef MONITOR_CONNECT
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u16);
    __type(value, __u8);
} suspicious_ports SEC(".maps");
#endif

#ifdef MONITOR_OPENAT
struct openat_rl {
    __u64 window_ns;
    __u32 count;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct openat_rl);
} openat_rate_limit SEC(".maps");
#endif

#ifdef MONITOR_WRITE
struct write_rl {
    __u64 window_ns;
    __u32 count;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct write_rl);
} write_rate_limit SEC(".maps");
#endif

static __always_inline void inc_ringbuf_drop(void)
{
    __u32 drop_key = 0;
    __u64 *drops = bpf_map_lookup_elem(&ringbuf_drops, &drop_key);
    if (drops)
        __sync_fetch_and_add(drops, 1);
}

static __always_inline __u32 lookup_ppid(__u32 pid)
{
    __u32 *pp = bpf_map_lookup_elem(&pid_parents, &pid);
    if (pp)
        return *pp;
    return 0;
}

/* ============================================================
 * Helper: zero destination IP bytes
 * ============================================================ */
static __always_inline void zero_dest_ip(__u8 *dest_ip)
{
    dest_ip[0] = 0;
    dest_ip[1] = 0;
    dest_ip[2] = 0;
    dest_ip[3] = 0;
    dest_ip[4] = 0;
    dest_ip[5] = 0;
    dest_ip[6] = 0;
    dest_ip[7] = 0;
    dest_ip[8] = 0;
    dest_ip[9] = 0;
    dest_ip[10] = 0;
    dest_ip[11] = 0;
    dest_ip[12] = 0;
    dest_ip[13] = 0;
    dest_ip[14] = 0;
    dest_ip[15] = 0;
}

static __always_inline void fill_event_header(struct ebpf_event *e, __u8 event_type,
                                              __u8 flags, __u16 dest_port, __u8 ip_version,
                                              __u8 path_len, __u32 ip4, const void *ip6_src)
{
    e->timestamp_ns = bpf_ktime_get_ns();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    e->pid = pid;
    e->ppid = lookup_ppid(pid);
    __u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid & 0xFFFFFFFF;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->event_type = event_type;
    e->flags = flags;
    e->dest_port = dest_port;
    e->ip_version = ip_version;
    e->path_len = path_len;
    e->_pad = 0;

    zero_dest_ip(e->dest_ip);

    if (ip_version == 4) {
        *(__u32 *)e->dest_ip = ip4;
    } else if (ip_version == 6 && ip6_src) {
        __builtin_memcpy(e->dest_ip, ip6_src, 16);
    }

    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

/* ============================================================
 * Helper: emit a fixed-size header to the ringbuf
 * ============================================================ */
static __always_inline void emit_event(__u8 event_type, __u8 flags,
                                       __u16 dest_port, __u8 ip_version,
                                       __u32 ip4, const void *ip6_src)
{
    struct ebpf_event *e = bpf_ringbuf_reserve(&events, EVENT_HEADER_SIZE, 0);
    if (!e) {
        inc_ringbuf_drop();
        return;
    }

    fill_event_header(e, event_type, flags, dest_port, ip_version, 0, ip4, ip6_src);
    bpf_ringbuf_submit(e, 0);
}

static __always_inline void emit_exec_event(__u8 flags, const char *filename, __u32 path_len)
{
    if (path_len > MAX_EXEC_PATH)
        path_len = MAX_EXEC_PATH;

    __u32 total = EVENT_HEADER_SIZE + path_len;
    char buf[EVENT_HEADER_SIZE + MAX_EXEC_PATH] = {};

    struct ebpf_event *e = (struct ebpf_event *)buf;
    fill_event_header(e, EVENT_EXEC, flags, 0, 0, (__u8)path_len, 0, NULL);
    if (path_len > 0 && filename) {
        #pragma unroll
        for (__u32 i = 0; i < MAX_EXEC_PATH; i++) {
            if (i >= path_len)
                break;
            buf[EVENT_HEADER_SIZE + i] = filename[i];
        }
    }

    long ret = bpf_ringbuf_output(&events, buf, total, 0);
    if (ret < 0)
        inc_ringbuf_drop();
}

/* ============================================================
 * Helper: check if path ends with a given suffix
 * ============================================================ */
static __always_inline int ends_with(char *path, long len, int buf_len,
                                     const char *suffix, int suffix_len)
{
    long idx = len - suffix_len - 1;
    if (idx < 0 || idx >= buf_len)
        return 0;
    for (int i = 0; i < suffix_len; i++) {
        if (path[idx + i] != suffix[i])
            return 0;
    }
    return 1;
}

/* ============================================================
 * Helper: exact string match
 * ============================================================ */
static __always_inline int str_eq(char *buf, const char *target, int target_len)
{
    for (int i = 0; i < target_len; i++) {
        if (buf[i] != target[i])
            return 0;
    }
    return 1;
}

/* ============================================================
 * Helper: check if port is suspicious (map lookup + compile-time defaults)
 * ============================================================ */
#ifdef MONITOR_CONNECT
static __always_inline int is_suspicious_port(__u16 port)
{
    __u8 *found = bpf_map_lookup_elem(&suspicious_ports, &port);
    return found != NULL;
}
#endif

/* ============================================================
 * TRACEPOINT: sys_enter_execve
 * ============================================================ */
#ifdef MONITOR_EXEC
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_exec(struct trace_event_raw_sys_enter *ctx)
{
    char filename[128] = {0};
    char arg_buf[16] = {0};
    __u8 flags = 0;

    long ret = bpf_probe_read_user_str(filename, sizeof(filename) - 1, (void *)ctx->args[0]);
    if (ret <= 0) {
        emit_exec_event(0, NULL, 0);
        return 0;
    }

    if (ret >= (long)sizeof(filename))
        filename[sizeof(filename) - 1] = '\0';
    else
        filename[ret] = '\0';

    int is_sudo = ends_with(filename, ret, sizeof(filename), "/sudo", 5);
    if (is_sudo)
        flags |= FLAG_SUDO;

    int is_cat = ends_with(filename, ret, sizeof(filename), "/cat", 4);

#ifdef MONITOR_PASSWD
    if (is_cat || is_sudo) {
        char **argv_array = (char **)ctx->args[1];
        char *arg_ptr = NULL;

        if (is_cat) {
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_array[1]) == 0 && arg_ptr) {
                long arg_ret = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf) - 1, arg_ptr);
                if (arg_ret == 12 && str_eq(arg_buf, "/etc/passwd", 11))
                    flags |= FLAG_PASSWD_READ;
            }
        } else if (is_sudo) {
            char *arg1_ptr = NULL, *arg2_ptr = NULL;
            if (bpf_probe_read_user(&arg1_ptr, sizeof(arg1_ptr), &argv_array[1]) != 0)
                goto done;
            if (bpf_probe_read_user(&arg2_ptr, sizeof(arg2_ptr), &argv_array[2]) != 0)
                goto done;
            if (arg1_ptr && arg2_ptr) {
                long a1 = bpf_probe_read_user_str(arg_buf, 5, arg1_ptr);
                if (a1 == 5 && arg_buf[0] == 'c' && arg_buf[1] == 'a' && arg_buf[2] == 't' && arg_buf[3] == '\0') {
                    long a2 = bpf_probe_read_user_str(arg_buf, sizeof(arg_buf) - 1, arg2_ptr);
                    if (a2 == 12 && str_eq(arg_buf, "/etc/passwd", 11))
                        flags |= FLAG_PASSWD_READ;
                }
            }
        }
    }
#endif /* MONITOR_PASSWD */

done:
    {
    __u32 path_len = (__u32)(ret - 1);
    if (path_len > MAX_EXEC_PATH)
        path_len = MAX_EXEC_PATH;
    emit_exec_event(flags, filename, path_len);
    }
    return 0;
}
#endif /* MONITOR_EXEC */

/* ============================================================
 * TRACEPOINT: sys_enter_connect
 * ============================================================ */
#ifdef MONITOR_CONNECT
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr = {0};
    struct sockaddr_in6 addr6 = {0};
    __u8 flags = 0;
    __u16 port = 0;
    __u32 ip = 0;
    __u16 family = 0;

    int addrlen = (int)ctx->args[2];
    void *uaddr = (void *)ctx->args[1];

    if (bpf_probe_read_user(&family, sizeof(family), uaddr) != 0)
        goto done;

    if (family == 2 && addrlen >= (int)sizeof(struct sockaddr_in)) {
        if (bpf_probe_read_user(&addr, sizeof(addr), uaddr) != 0)
            goto done;
        port = __builtin_bswap16(addr.sin_port);
        ip = addr.sin_addr.s_addr;
        if (is_suspicious_port(port))
            flags |= FLAG_SUSPICIOUS_PORT;
        emit_event(EVENT_CONNECT, flags, port, 4, ip, NULL);
        return 0;
    }

    if (family == 10 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
        if (bpf_probe_read_user(&addr6, sizeof(addr6), uaddr) != 0)
            goto done;
        port = __builtin_bswap16(addr6.sin6_port);
        if (is_suspicious_port(port))
            flags |= FLAG_SUSPICIOUS_PORT;
        emit_event(EVENT_CONNECT, flags, port, 6, 0, &addr6.sin6_addr);
        return 0;
    }

done:
    emit_event(EVENT_CONNECT, flags, port, 0, 0, NULL);
    return 0;
}
#endif /* MONITOR_CONNECT */

/* ============================================================
 * TRACEPOINT: sys_enter_ptrace
 * ============================================================ */
#ifdef MONITOR_PTRACE
SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    emit_event(EVENT_PTRACE, 0, 0, 0, 0, NULL);
    return 0;
}
#endif /* MONITOR_PTRACE */

/* ============================================================
 * TRACEPOINT: sys_enter_openat
 * ============================================================ */
#ifdef MONITOR_OPENAT
static __always_inline __u8 classify_path_flags(char *path, long ret, int buf_len)
{
    __u8 flags = 0;

    if (ret == 12 && str_eq(path, "/etc/shadow", 11)) {
        flags |= FLAG_SENSITIVE_FILE;
    } else if (ret == 13 && str_eq(path, "/etc/sudoers", 12)) {
        flags |= FLAG_SENSITIVE_FILE;
    } else if (ret >= 17 && ends_with(path, ret, buf_len, "/authorized_keys", 16)) {
        flags |= FLAG_SENSITIVE_FILE;
    } else if (ret >= 12 && str_eq(path, "/etc/passwd", 11)) {
        flags |= FLAG_PASSWD_READ;
    } else if (ret >= 5 && path[0] == '/' && path[1] == 't' && path[2] == 'm' && path[3] == 'p' &&
               (path[4] == '/' || ret == 5)) {
        flags |= FLAG_TMP_FILE;
    }
    return flags;
}

static __always_inline void try_emit_file_open_sampled(void)
{
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    const __u64 win_ns = 1000000000ULL;
    const __u32 max_per_sec = 100;

    struct openat_rl *v = bpf_map_lookup_elem(&openat_rate_limit, &key);
    if (!v)
        return;
    if (v->window_ns == 0 || now - v->window_ns > win_ns) {
        v->window_ns = now;
        v->count = 0;
    }
    if (v->count >= max_per_sec)
        return;
    v->count++;
    emit_event(EVENT_OPENAT, 0, 0, 0, 0, NULL);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    char path[64] = {0};

    long ret = bpf_probe_read_user_str(path, sizeof(path) - 1, (void *)ctx->args[1]);
    if (ret <= 0)
        return 0;

    __u8 flags = classify_path_flags(path, ret, sizeof(path));

    if (flags)
        emit_event(EVENT_OPENAT, flags, 0, 0, 0, NULL);
    else
        try_emit_file_open_sampled();

    return 0;
}
#endif /* MONITOR_OPENAT */

#ifdef MONITOR_OPEN
SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    char path[64] = {0};

    long ret = bpf_probe_read_user_str(path, sizeof(path) - 1, (void *)ctx->args[0]);
    if (ret <= 0)
        return 0;

    __u8 flags = classify_path_flags(path, ret, sizeof(path));
    if (flags)
        emit_event(EVENT_OPENAT, flags, 0, 0, 0, NULL);
    else
        try_emit_file_open_sampled();

    return 0;
}
#endif /* MONITOR_OPEN */

#ifdef MONITOR_OPENAT2
SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
    char path[64] = {0};

    long ret = bpf_probe_read_user_str(path, sizeof(path) - 1, (void *)ctx->args[1]);
    if (ret <= 0)
        return 0;

    __u8 flags = classify_path_flags(path, ret, sizeof(path));
    if (flags)
        emit_event(EVENT_OPENAT, flags, 0, 0, 0, NULL);
    else
        try_emit_file_open_sampled();

    return 0;
}
#endif /* MONITOR_OPENAT2 */

/* ============================================================
 * TRACEPOINT: sys_enter_setuid / sys_enter_setgid
 * ============================================================ */
#ifdef MONITOR_SETUID
SEC("tracepoint/syscalls/sys_enter_setuid")
int trace_setuid(struct trace_event_raw_sys_enter *ctx)
{
    emit_event(EVENT_SETUID, 0, 0, 0, 0, NULL);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_setgid")
int trace_setgid(struct trace_event_raw_sys_enter *ctx)
{
    emit_event(EVENT_SETGID, 0, 0, 0, 0, NULL);
    return 0;
}
#endif /* MONITOR_SETUID */

/* ============================================================
 * TRACEPOINT: sched_process_fork
 * ============================================================ */
#ifdef MONITOR_FORK
SEC("tracepoint/sched/sched_process_fork")
int trace_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    __u32 child = (__u32)ctx->child_pid;
    __u32 parent = (__u32)ctx->parent_pid;
    bpf_map_update_elem(&pid_parents, &child, &parent, BPF_ANY);
    emit_event(EVENT_FORK, 0, 0, 0, 0, NULL);
    return 0;
}
#endif /* MONITOR_FORK */

/* ============================================================
 * TRACEPOINT: sched_process_exit
 * ============================================================ */
#ifdef MONITOR_EXIT
SEC("tracepoint/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
    emit_event(EVENT_EXIT, 0, 0, 0, 0, NULL);
    return 0;
}
#endif /* MONITOR_EXIT */

/* ============================================================
 * TRACEPOINT: sys_enter_bind
 * ============================================================ */
#ifdef MONITOR_BIND
SEC("tracepoint/syscalls/sys_enter_bind")
int trace_bind(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr = {0};
    struct sockaddr_in6 addr6 = {0};
    __u16 port = 0;
    __u16 family = 0;
    void *uaddr = (void *)ctx->args[1];

    int addrlen = (int)ctx->args[2];
    if (bpf_probe_read_user(&family, sizeof(family), uaddr) != 0)
        goto done;

    if (family == 2 && addrlen >= (int)sizeof(struct sockaddr_in)) {
        if (bpf_probe_read_user(&addr, sizeof(addr), uaddr) != 0)
            goto done;
        port = __builtin_bswap16(addr.sin_port);
        emit_event(EVENT_BIND, 0, port, 4, addr.sin_addr.s_addr, NULL);
        return 0;
    }
    if (family == 10 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
        if (bpf_probe_read_user(&addr6, sizeof(addr6), uaddr) != 0)
            goto done;
        port = __builtin_bswap16(addr6.sin6_port);
        emit_event(EVENT_BIND, 0, port, 6, 0, &addr6.sin6_addr);
        return 0;
    }

done:
    emit_event(EVENT_BIND, 0, port, 0, 0, NULL);
    return 0;
}
#endif /* MONITOR_BIND */

/* ============================================================
 * TRACEPOINT: sys_enter_sendto (DNS on port 53)
 * ============================================================ */
#ifdef MONITOR_DNS
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr = {0};
    struct sockaddr_in6 addr6 = {0};
    __u16 family = 0;

    void *addr_ptr = (void *)ctx->args[4];
    if (!addr_ptr)
        return 0;

    int addrlen = (int)ctx->args[5];
    if (bpf_probe_read_user(&family, sizeof(family), addr_ptr) != 0)
        return 0;

    if (family == 2 && addrlen >= (int)sizeof(struct sockaddr_in)) {
        if (bpf_probe_read_user(&addr, sizeof(addr), addr_ptr) != 0)
            return 0;
        __u16 port = __builtin_bswap16(addr.sin_port);
        if (port == 53)
            emit_event(EVENT_DNS, 0, 53, 4, addr.sin_addr.s_addr, NULL);
        return 0;
    }

    if (family == 10 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
        if (bpf_probe_read_user(&addr6, sizeof(addr6), addr_ptr) != 0)
            return 0;
        __u16 port = __builtin_bswap16(addr6.sin6_port);
        if (port == 53)
            emit_event(EVENT_DNS, 0, 53, 6, 0, &addr6.sin6_addr);
    }

    return 0;
}
#endif /* MONITOR_DNS */

/* ============================================================
 * TRACEPOINT: sys_enter_capset
 * ============================================================ */
#ifdef MONITOR_CAPSET
SEC("tracepoint/syscalls/sys_enter_capset")
int trace_capset(struct trace_event_raw_sys_enter *ctx)
{
    emit_event(EVENT_CAPSET, 0, 0, 0, 0, NULL);
    return 0;
}
#endif /* MONITOR_CAPSET */

#ifdef MONITOR_WRITE
static __always_inline void try_emit_write_sampled(void)
{
    __u32 key = 0;
    __u64 now = bpf_ktime_get_ns();
    const __u64 win_ns = 1000000000ULL;
    const __u32 max_per_sec = 50;

    struct write_rl *v = bpf_map_lookup_elem(&write_rate_limit, &key);
    if (!v)
        return;
    if (v->window_ns == 0 || now - v->window_ns > win_ns) {
        v->window_ns = now;
        v->count = 0;
    }
    if (v->count >= max_per_sec)
        return;
    v->count++;
    emit_event(EVENT_WRITE, 0, 0, 0, 0, NULL);
}

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write(struct trace_event_raw_sys_enter *ctx)
{
    try_emit_write_sampled();
    return 0;
}
#endif /* MONITOR_WRITE */

#ifdef MONITOR_OOM
SEC("tracepoint/oom/mark_victim")
int trace_oom_kill(void *ctx)
{
    emit_event(EVENT_OOM_KILL, 0, 0, 0, 0, NULL);
    return 0;
}
#endif /* MONITOR_OOM */
