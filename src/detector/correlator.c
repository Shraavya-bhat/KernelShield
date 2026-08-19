#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "detector.h"
#include "rules.h"
#include "state.h"
#include "process_table.h"
#include "ks_alert.h"

/*
 * Temporal correlation window.
 *
 * Events occurring within this window are considered part
 * of the same behavioral episode.
 *
 * 30 seconds gives enough room for multi-stage activity
 * without correlating unrelated activity indefinitely.
 */
#define KS_BEHAVIOR_WINDOW_NS 30000000000ULL

/*
 * Add behavioral evidence.
 */
static void add_behavior_score(
    ks_process *process,
    int points)
{
    if (!process)
        return;

    process->behavioral_score += points;

    if (process->behavioral_score > 100)
        process->behavioral_score = 100;
}

/*
 * Check whether two timestamps belong to the same
 * behavioral episode.
 */
static bool within_window(
    uint64_t current,
    uint64_t previous)
{
    if (previous == 0)
        return false;

    if (current < previous)
        return false;

    return (current - previous) <=
           KS_BEHAVIOR_WINDOW_NS;
}

/*
 * Convert behavioral evidence into a severity.
 */
static const char *severity_for_score(int score)
{
    if (score >= 80)
        return "critical";

    if (score >= 50)
        return "high";

    if (score >= 30)
        return "medium";

    return "low";
}

/*
 * Generate standardized ks_alert.
 */
static void emit_detection_alert(
    const struct ks_event *event,
    const char *attack_type,
    const char *alert_type,
    const char *severity,
    const char *reason,
    const char *mitre,
    uint8_t has_network,
    const char *destination_ip,
    uint16_t destination_port,
    uint32_t event_count)
{
    if (!event)
        return;

    ks_alert alert;

    memset(&alert, 0, sizeof(alert));

    alert.schema_version =
        KS_ALERT_SCHEMA_VERSION;

    alert.timestamp_ns =
        event->timestamp_ns;

    alert.pid =
        event->pid;

    alert.ppid =
        event->ppid;

    alert.uid =
        event->uid;

    alert.gid =
        event->gid;

    strncpy(
        alert.process_name,
        event->comm,
        sizeof(alert.process_name) - 1
    );

    ks_process *parent =
        ks_process_find(event->ppid);

    if (parent) {

        strncpy(
            alert.parent_name,
            parent->comm,
            sizeof(alert.parent_name) - 1
        );

    } else {

        strncpy(
            alert.parent_name,
            "unknown",
            sizeof(alert.parent_name) - 1
        );
    }

    strncpy(
        alert.attack_type,
        attack_type,
        sizeof(alert.attack_type) - 1
    );

    strncpy(
        alert.alert_type,
        alert_type,
        sizeof(alert.alert_type) - 1
    );

    strncpy(
        alert.severity,
        severity,
        sizeof(alert.severity) - 1
    );

    strncpy(
        alert.reason,
        reason,
        sizeof(alert.reason) - 1
    );

    strncpy(
        alert.mitre_technique,
        mitre,
        sizeof(alert.mitre_technique) - 1
    );

    alert.has_network = has_network;

    if (has_network && destination_ip) {

        strncpy(
            alert.destination_ip,
            destination_ip,
            sizeof(alert.destination_ip) - 1
        );

        alert.destination_port =
            destination_port;
    }

    alert.event_count =
        event_count;

    if (ks_alert_write(&alert) != 0) {

        fprintf(
            stderr,
            "[KernelShield] Failed to write ks_alert\n"
        );
    }
}

void ks_detector_init(void)
{
    ks_state_init();
    ks_process_table_init();

    if (ks_alert_init() != 0) {

        fprintf(
            stderr,
            "[KernelShield] WARNING: "
            "ks_alert initialization failed\n"
        );
    }
}

void ks_detector_process_event(
    const struct ks_event *event)
{
    if (!event)
        return;

    /*
     * ======================================================
     * EXECUTION
     * ======================================================
     */
    if (event->type == KS_EVENT_EXEC) {

        ks_process_add(event);

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        process->last_activity_ns =
            event->timestamp_ns;

        /*
         * Existing process transition is itself evidence.
         *
         * Example:
         *
         * application -> interpreter
         * interpreter -> network utility
         */
        if (process->exec_count > 1) {

            add_behavior_score(process, 5);

            printf(
                "[BEHAVIOR] PID=%u transition %s -> %s\n",
                process->pid,
                process->previous_comm,
                process->comm
            );
        }

        /*
         * Server -> shell remains a useful semantic signal,
         * but it is now only ONE component of the behavioral
         * score rather than the entire detection mechanism.
         */
        if (ks_rule_shell_from_server(event)) {

            process->spawned_shell = true;

            add_behavior_score(process, 25);

            /*
             * Do not immediately terminate anything here.
             *
             * Response Engine owns mitigation.
             */
            emit_detection_alert(
                event,
                "server_to_shell",
                "behavioral",
                "high",
                "Server process spawned a shell",
                "T1059",
                0,
                NULL,
                0,
                process->exec_count
            );
        }

        return;
    }

    /*
     * ======================================================
     * NETWORK
     * ======================================================
     */
    if (event->type == KS_EVENT_NETWORK) {

        ks_state_add_network(event);

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        process->last_activity_ns =
            event->timestamp_ns;

        process->network_count++;
        process->made_network_connection = true;
        process->last_network_ns =
            event->timestamp_ns;

        /*
         * Network activity immediately after an execution
         * transition is stronger evidence than an isolated
         * connection.
         */
        if (within_window(
                event->timestamp_ns,
                process->last_exec_ns)) {

            add_behavior_score(process, 15);
        }

        /*
         * Repeated network activity increases evidence.
         */
        if (process->network_count >= 3) {

            add_behavior_score(process, 10);
        }

        char ip[INET_ADDRSTRLEN] = "unknown";

        inet_ntop(
            AF_INET,
            &event->dst_ipv4,
            ip,
            sizeof(ip)
        );

        /*
         * Multi-stage correlation:
         *
         * process
         *    ↓
         * shell ancestor
         *    ↓
         * network
         */
        if (!process->attack_chain_detected &&
            ks_rule_attack_chain(process->pid)) {

            process->attack_chain_detected = true;

            add_behavior_score(process, 40);

            emit_detection_alert(
                event,
                "multi_stage_attack",
                "correlation",
                "critical",
                "Execution and network behavior formed a correlated multi-stage process chain",
                "T1059",
                1,
                ip,
                ntohs(event->dst_port),
                process->exec_count +
                process->network_count
            );

            return;
        }

        /*
         * Shell network activity is another behavioral signal.
         */
        if (ks_rule_network_from_shell(event)) {

            add_behavior_score(process, 20);

            emit_detection_alert(
                event,
                "shell_network_activity",
                "network",
                severity_for_score(
                    process->behavioral_score
                ),
                "Shell process generated outbound network activity",
                "T1059",
                1,
                ip,
                ntohs(event->dst_port),
                process->network_count
            );
        }

        return;
    }

    /*
     * ======================================================
     * FILE ACTIVITY
     * ======================================================
     */
    if (event->type == KS_EVENT_FILE) {

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        process->last_activity_ns =
            event->timestamp_ns;

        switch (event->file_operation) {

        case KS_FILE_OPEN:

            process->file_open_count++;
            break;

        case KS_FILE_WRITE:

            process->file_write_count++;
            process->wrote_file = true;
            process->last_file_write_ns =
                event->timestamp_ns;

            /*
             * File modification following execution/network
             * behavior is stronger than an isolated write.
             */
            if (within_window(
                    event->timestamp_ns,
                    process->last_exec_ns) ||
                within_window(
                    event->timestamp_ns,
                    process->last_network_ns)) {

                add_behavior_score(process, 10);
            }

            break;

        case KS_FILE_CREATE:

            process->file_create_count++;
            process->created_file = true;

            if (within_window(
                    event->timestamp_ns,
                    process->last_network_ns)) {

                add_behavior_score(process, 15);
            }

            break;

        default:
            break;
        }

        return;
    }

    /*
     * ======================================================
     * PRIVILEGE
     * ======================================================
     */
    if (event->type == KS_EVENT_PRIVILEGE) {

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        process->privilege_event_count++;
        process->privilege_transition = true;
        process->last_privilege_ns =
            event->timestamp_ns;

        /*
         * Privilege transitions are significant evidence,
         * particularly when close to execution/network activity.
         */
        add_behavior_score(process, 20);

        if (within_window(
                event->timestamp_ns,
                process->last_exec_ns) ||
            within_window(
                event->timestamp_ns,
                process->last_network_ns)) {

            add_behavior_score(process, 15);
        }

        emit_detection_alert(
            event,
            "privilege_transition",
            "behavioral",
            severity_for_score(
                process->behavioral_score
            ),
            "Process performed a privilege transition",
            "T1548",
            0,
            NULL,
            0,
            process->privilege_event_count
        );

        return;
    }

    /*
     * ======================================================
     * EXIT
     * ======================================================
     */
    if (event->type == KS_EVENT_EXIT) {

        ks_process *process =
            ks_process_find(event->pid);

        if (process) {

            process->last_activity_ns =
                event->timestamp_ns;

            ks_process_remove(event);
        }

        return;
    }
}

void ks_detector_shutdown(void)
{
    ks_alert_close();
}
