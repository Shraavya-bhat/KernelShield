#ifndef KS_PROCESS_TABLE_H
#define KS_PROCESS_TABLE_H

#include <stdbool.h>
#include <stdint.h>

#include "../../include/ks_event.h"

#define KS_MAX_PROCESSES 8192

/*
 * Behavioral evidence maintained for every active process.
 *
 * This is deliberately independent of the final alert schema.
 * The detector can evolve internally without changing ks_alert.
 */
typedef struct {

    bool active;

    uint32_t pid;
    uint32_t ppid;

    uint32_t uid;
    uint32_t gid;

    uint64_t start_time_ns;
    uint64_t end_time_ns;
    uint64_t last_activity_ns;

    /*
     * Behavioral counters.
     */
    uint32_t exec_count;
    uint32_t network_count;
    uint32_t file_open_count;
    uint32_t file_write_count;
    uint32_t file_create_count;
    uint32_t privilege_event_count;

    /*
     * Temporal evidence.
     */
    uint64_t last_exec_ns;
    uint64_t last_network_ns;
    uint64_t last_file_write_ns;
    uint64_t last_privilege_ns;

    /*
     * Behavioral transitions.
     */
    bool spawned_shell;
    bool made_network_connection;
    bool wrote_file;
    bool created_file;
    bool privilege_transition;

    /*
     * Correlation state.
     */
    bool attack_chain_detected;
    bool alert_emitted;

    /*
     * Internal behavioral score.
     *
     * This is NOT exported as a formal risk score in ks_alert.
     * It is an internal decision signal.
     */
    int behavioral_score;

    /*
     * Execution transition history.
     */
    char previous_comm[TASK_COMM_LEN];
    char previous_filename[KS_MAX_FILENAME_LEN];

    char comm[TASK_COMM_LEN];
    char filename[KS_MAX_FILENAME_LEN];

} ks_process;

void ks_process_table_init(void);

void ks_process_add(const struct ks_event *event);

void ks_process_remove(const struct ks_event *event);

ks_process *ks_process_find(uint32_t pid);

void ks_process_table_print(void);

#endif
