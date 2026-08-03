#ifndef __KS_EVENT_H
#define __KS_EVENT_H

#include <stdint.h>
#include <stdbool.h>

#define TASK_COMM_LEN       16
#define KS_MAX_FILENAME_LEN 256

enum ks_event_type {
    KS_EVENT_EXEC = 1,
    KS_EVENT_EXIT = 2,
    KS_EVENT_NETWORK = 3,
    KS_EVENT_PRIVILEGE = 4,
    KS_EVENT_ALERT = 5,
};

struct ks_event {
    uint64_t timestamp_ns;
    uint64_t duration_ns;

    uint32_t pid;
    uint32_t ppid;

    uint32_t uid;
    uint32_t gid;

    int32_t exit_code;

    uint16_t type;

    bool exit_event;

    char comm[TASK_COMM_LEN];
    char filename[KS_MAX_FILENAME_LEN];
};

#endif
