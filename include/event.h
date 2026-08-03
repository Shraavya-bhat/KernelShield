#ifndef KERNELSHIELD_EVENT_H
#define KERNELSHIELD_EVENT_H

#include <linux/types.h>

#define KS_COMM_LEN 16
#define KS_FILENAME_LEN 256

enum ks_event_type {
    KS_EVENT_PROCESS_EXEC = 1,
    KS_EVENT_PROCESS_EXIT,
    KS_EVENT_NETWORK_CONNECT,
    KS_EVENT_PRIVILEGE_CHANGE
};

struct ks_event {

    __u64 timestamp_ns;

    __u64 duration_ns;

    __u32 pid;
    __u32 ppid;

    __u32 uid;
    __u32 gid;

    __u32 exit_code;

    __u32 type;

    bool exit_event;

    char comm[KS_COMM_LEN];

    char filename[KS_FILENAME_LEN];
};

#endif
