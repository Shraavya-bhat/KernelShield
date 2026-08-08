// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "process_exec.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ---------------------------------------------------------- */
/* Maps */
/* ---------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
} exec_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

/* ---------------------------------------------------------- */
/* EXEC */
/* ---------------------------------------------------------- */

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    struct task_struct *task;
    struct ks_event *e;

    u64 ts;
    u64 id;
    u64 uid_gid;

    pid_t pid;
    unsigned fname_off;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

    if (min_duration_ns)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = ts;
    e->duration_ns = 0;

    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->exit_code = 0;

    e->type = KS_EVENT_EXEC;
    e->exit_event = false;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    fname_off = ctx->__data_loc_filename & 0xFFFF;

    bpf_probe_read_str(
        e->filename,
        sizeof(e->filename),
        (void *)ctx + fname_off
    );

    bpf_ringbuf_submit(e, 0);

    return 0;
}

/* ---------------------------------------------------------- */
/* NETWORK CONNECT */
/* ---------------------------------------------------------- */

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct sockaddr_in addr;
    struct ks_event *e;

    u64 id;
    u64 uid_gid;

    pid_t pid;

    const struct sockaddr *user_addr;

    id = bpf_get_current_pid_tgid();
    pid = id >> 32;

    user_addr = (const struct sockaddr *)ctx->args[1];

    if (!user_addr)
        return 0;

    if (bpf_probe_read_user(
            &addr,
            sizeof(addr),
            user_addr) != 0)
        return 0;

    if (addr.sin_family != 2)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    uid_gid = bpf_get_current_uid_gid();

    e->timestamp_ns = bpf_ktime_get_ns();
    e->duration_ns = 0;

    e->pid = pid;

    {
        struct task_struct *task;

        task = (struct task_struct *)bpf_get_current_task();

        e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    }

    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->exit_code = 0;

    e->type = KS_EVENT_NETWORK;
    e->exit_event = false;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    e->filename[0] = '\0';

    e->src_ipv4 = 0;
    e->dst_ipv4 = addr.sin_addr.s_addr;
    e->src_port = 0;
    e->dst_port = addr.sin_port;

    bpf_ringbuf_submit(e, 0);

    return 0;
}


/* ---------------------------------------------------------- */
/* EXIT */
/* ---------------------------------------------------------- */

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct task_struct *task;
    struct ks_event *e;

    u64 id;
    u64 ts;
    u64 uid_gid;

    u64 *start_ts;
    u64 duration_ns = 0;

    pid_t pid;
    pid_t tid;

    id = bpf_get_current_pid_tgid();

    pid = id >> 32;
    tid = (u32)id;

    if (pid != tid)
        return 0;

    start_ts = bpf_map_lookup_elem(&exec_start, &pid);

    if (start_ts)
        duration_ns = bpf_ktime_get_ns() - *start_ts;
    else if (min_duration_ns)
        return 0;

    bpf_map_delete_elem(&exec_start, &pid);

    if (min_duration_ns && duration_ns < min_duration_ns)
        return 0;

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

    if (!e)
        return 0;

    task = (struct task_struct *)bpf_get_current_task();

    uid_gid = bpf_get_current_uid_gid();
    ts = bpf_ktime_get_ns();

    e->timestamp_ns = ts;
    e->duration_ns = duration_ns;

    e->pid = pid;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    e->uid = (u32)uid_gid;
    e->gid = (u32)(uid_gid >> 32);

    e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;

    e->type = KS_EVENT_EXIT;
    e->exit_event = true;

    bpf_get_current_comm(e->comm, sizeof(e->comm));

    e->filename[0] = '\0';

    bpf_ringbuf_submit(e, 0);

    return 0;
}
