#ifndef __KS_EVENT_H
#define __KS_EVENT_H

#ifdef __BPF__

typedef unsigned long long uint64_t;
typedef unsigned int       uint32_t;
typedef int                int32_t;
typedef unsigned short     uint16_t;
typedef unsigned char      uint8_t;
typedef _Bool              bool;

#else

#include <stdint.h>
#include <stdbool.h>

#endif

#define TASK_COMM_LEN       16
#define KS_MAX_FILENAME_LEN 256
#define KS_MAX_PATH_LEN     256

enum ks_event_type {
    KS_EVENT_EXEC      = 1,
    KS_EVENT_EXIT      = 2,
    KS_EVENT_NETWORK   = 3,
    KS_EVENT_PRIVILEGE = 4,
    KS_EVENT_FILE      = 5,
    KS_EVENT_ALERT     = 6,
};

enum ks_file_operation {
    KS_FILE_UNKNOWN = 0,
    KS_FILE_OPEN    = 1,
    KS_FILE_WRITE   = 2,
    KS_FILE_CREATE  = 3,
    KS_FILE_RENAME  = 4,
    KS_FILE_DELETE  = 5,
    KS_FILE_EXECUTE = 6,
};

enum ks_privilege_operation {
    KS_PRIV_UNKNOWN         = 0,
    KS_PRIV_UID_CHANGE      = 1,
    KS_PRIV_GID_CHANGE      = 2,
    KS_PRIV_EXEC_PRIVILEGED = 3,
};

struct ks_event {

    /* Common event metadata */
    uint64_t timestamp_ns;
    uint64_t duration_ns;

    uint32_t pid;
    uint32_t ppid;

    uint32_t uid;
    uint32_t gid;

    int32_t exit_code;

    uint16_t type;
    uint16_t reserved;

    bool exit_event;
    uint8_t reserved2[3];

    char comm[TASK_COMM_LEN];

    /* Executable associated with EXEC events */
    char filename[KS_MAX_FILENAME_LEN];

    /* Network telemetry */
    uint32_t src_ipv4;
    uint32_t dst_ipv4;

    uint16_t src_port;
    uint16_t dst_port;

    uint8_t protocol;
    uint8_t address_family;

    uint16_t network_flags;

    /* File telemetry */
    uint32_t file_operation;
    uint32_t file_mode;

    uint64_t file_size;

    char file_path[KS_MAX_PATH_LEN];

    /* Privilege telemetry */
    uint32_t old_uid;
    uint32_t new_uid;

    uint32_t old_gid;
    uint32_t new_gid;

    uint32_t privilege_operation;
};

#endif
