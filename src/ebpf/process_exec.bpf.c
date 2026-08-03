// SPDX-License-Identifier: GPL-2.0
/*
 * KernelShield
 * Process Execution Sensor
 *
 * Stage 1:
 * Attach to the sched_process_exec tracepoint.
 * Event collection will be added in the next stage.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../../include/event.h"

/*
 * Ring buffer map.
 * The collector will read events from this map.
 * We will start using it in Stage 2.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   /* 16 MB */
} events SEC(".maps");

/*
 * Process execution tracepoint.
 *
 * Runs every time a process successfully executes
 * a new executable.
 */
SEC("tracepoint/sched/sched_process_exec")
int handle_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    /*
     * Stage 1:
     * Successfully attach.
     *
     * Stage 2:
     * Reserve ring buffer event.
     *
     * Stage 3:
     * Populate ks_event.
     *
     * Stage 4:
     * Submit event.
     */

    return 0;
}

/* Required license for eBPF programs */
char LICENSE[] SEC("license") = "GPL";
