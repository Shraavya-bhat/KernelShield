#ifndef KS_PROCESS_TABLE_H
#define KS_PROCESS_TABLE_H

#include <stdbool.h>
#include <stdint.h>

#include "../../include/ks_event.h"

#define KS_MAX_PROCESSES 8192

typedef struct {
    bool active;

    uint32_t pid;
    uint32_t ppid;

    uint32_t uid;
    uint32_t gid;

    uint64_t start_time_ns;
    uint64_t end_time_ns;
    /* Behaviour state */
    uint64_t last_activity_ns;
    uint32_t network_count;

    bool spawned_shell;
    bool made_network_connection;

    /* Multi-stage attack correlation */
    bool attack_chain_detected;

    int risk_score;

    /* Execution transition history */
    char previous_comm[TASK_COMM_LEN];
    char previous_filename[KS_MAX_FILENAME_LEN];
    uint32_t exec_count;

    char comm[TASK_COMM_LEN];
    char filename[KS_MAX_FILENAME_LEN];

} ks_process;

void ks_process_table_init(void);

void ks_process_add(const struct ks_event *event);

void ks_process_remove(const struct ks_event *event);

ks_process *ks_process_find(uint32_t pid);

void ks_process_table_print(void);

#endif
