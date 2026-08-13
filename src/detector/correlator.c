#include <stdio.h>
#include <arpa/inet.h>

#include "detector.h"
#include "rules.h"
#include "state.h"
#include "process_table.h"

static void add_risk(ks_process *process, int points)
{
    if (!process)
        return;

    process->risk_score += points;

    if (process->risk_score > 100)
        process->risk_score = 100;
}

void ks_detector_init(void)
{
    ks_state_init();
}

void ks_detector_process_event(const struct ks_event *event)
{
    /*
     * ------------------------------------------------------
     * EXEC EVENT
     * ------------------------------------------------------
     */
    if (event->type == KS_EVENT_EXEC) {

        /*
         * Add/update the process before evaluating it.
         */
        ks_process_add(event);

        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        process->last_activity_ns =
            event->timestamp_ns;

        /*
         * Execution transition:
         *
         * Example:
         *   bash -> curl
         *
         * Keep the transition as behavioural context.
         */
        if (process->exec_count > 1 &&
            process->previous_comm[0] != '\0') {

            printf("\n");
            printf("============================================\n");
            printf("[INFO] Process Execution Transition\n");
            printf("PID      : %u\n", process->pid);
            printf("Previous : %s\n", process->previous_comm);
            printf("Current  : %s\n", process->comm);
            printf("Execs    : %u\n", process->exec_count);
            printf("============================================\n\n");
        }

        /*
         * Check whether this process was created by
         * a server process and is now a shell.
         */
        if (ks_rule_shell_from_server(event)) {

            process->spawned_shell = true;

            /*
             * Server -> shell is a strong behavioural signal.
             */
            add_risk(process, 40);

            printf("\n");
            printf("============================================\n");
            printf("[HIGH] Suspicious Server-to-Shell Execution\n");
            printf("Process : %s (%u)\n",
                   process->comm,
                   process->pid);
            printf("Parent  : %u\n",
                   process->ppid);
            printf("Risk    : %d/100\n",
                   process->risk_score);
            printf("Reason  : Server process spawned a shell\n");
            printf("MITRE   : T1059 Command and Scripting Interpreter\n");
            printf("============================================\n\n");
        }

        return;
    }

    /*
     * ------------------------------------------------------
     * NETWORK EVENT
     * ------------------------------------------------------
     */
    if (event->type == KS_EVENT_NETWORK) {

        /*
         * Store network history.
         */
        ks_state_add_network(event);

        /*
         * Find the process responsible for the connection.
         */
        ks_process *process =
            ks_process_find(event->pid);

        if (!process)
            return;

        process->last_activity_ns =
            event->timestamp_ns;

        process->made_network_connection = true;
        process->network_count++;

        /*
         * --------------------------------------------------
         * MULTI-STAGE ATTACK CHAIN
         * --------------------------------------------------
         *
         * This check MUST happen for ANY network process,
         * not only shells.
         *
         * Example:
         *
         *     python3 -> bash -> curl -> network
         *
         * curl itself is not a shell, but its ancestor
         * bash was spawned by a server process.
         */
        if (!process->attack_chain_detected &&
            ks_rule_attack_chain(process->pid)) {

            process->attack_chain_detected = true;

            /*
             * Strong correlation signal.
             */
            add_risk(process, 40);

            printf("\n");
            printf("============================================\n");
            printf("[CRITICAL] Multi-Stage Attack Chain Detected\n");
            printf("Process : %s (%u)\n",
                   process->comm,
                   process->pid);
            printf("Parent  : %u\n",
                   process->ppid);
            printf("Risk    : %d/100\n",
                   process->risk_score);
            printf("Chain   : server -> shell -> network process\n");
            printf("Signals : server-to-shell + network activity\n");
            printf("MITRE   : T1059 Command and Scripting Interpreter\n");
            printf("============================================\n\n");
        }

        /*
         * --------------------------------------------------
         * SHELL NETWORK ACTIVITY
         * --------------------------------------------------
         *
         * This is a separate signal.
         */
        if (ks_rule_network_from_shell(event)) {

            add_risk(process, 20);

            char ip[INET_ADDRSTRLEN];

            inet_ntop(AF_INET,
                      &event->dst_ipv4,
                      ip,
                      sizeof(ip));

            printf("\n");
            printf("============================================\n");
            printf("[INFO] Shell Network Activity\n");
            printf("Process : %s (%u)\n",
                   process->comm,
                   process->pid);
            printf("Target  : %s:%u\n",
                   ip,
                   ntohs(event->dst_port));
            printf("Network : %u connections\n",
                   process->network_count);
            printf("Risk    : %d/100\n",
                   process->risk_score);
            printf("============================================\n\n");
        }

        /*
         * Multiple connections from the same process
         * add another behavioural signal.
         */
        if (process->network_count == 3) {
            add_risk(process, 10);
        }

        return;
    }

    /*
     * ------------------------------------------------------
     * EXIT EVENT
     * ------------------------------------------------------
     */
    if (event->type == KS_EVENT_EXIT) {

        ks_process *process =
            ks_process_find(event->pid);

        if (process) {

            process->last_activity_ns =
                event->timestamp_ns;

            /*
             * Only remove the process after we have
             * finished using its state.
             */
            ks_process_remove(event);
        }

        return;
    }
}
