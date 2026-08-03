#ifndef KERNELSHIELD_EVENT_H
#define KERNELSHIELD_EVENT_H

#include <linux/types.h>

#define KS_COMM_LEN      16
#define KS_FILENAME_LEN  256

/* Event types */
enum ks_event_type {
    KS_EVENT_PROCESS_EXEC = 1,
    KS_EVENT_PROCESS_EXIT,
    KS_EVENT_NETWORK_CONNECT,
    KS_EVENT_PRIVILEGE_CHANGE
};

/* Shared event structure between kernel and userspace */
struct ks_event {

    /* Timestamp */
    __u64 timestamp_ns;

    /* Process lifetime (used for EXIT events) */
    __u64 duration_ns;

    /* Process identifiers */
    __u32 pid;
    __u32 ppid;

    /* User information */
    __u32 uid;
    __u32 gid;

    /* Exit status */
    __u32 exit_code;

    /* Event type */
    __u32 type;

    /* 0 = EXEC, 1 = EXIT */
    __u8 exit_event;

    /* Padding for alignment */
    __u8 reserved[3];

    /* Process name */
    char comm[KS_COMM_LEN];

    /* Executable filename */
    char filename[KS_FILENAME_LEN];
};

#endif
