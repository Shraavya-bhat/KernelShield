#include <stdio.h>
#include <arpa/inet.h>

#include "detector.h"
#include "rules.h"
#include "state.h"
#include "process_table.h"

void ks_detector_init(void)
{
    ks_state_init();
}

void ks_detector_process_event(const struct ks_event *event)
{
    /*
     * Track network behaviour first.
     */
    if (event->type == KS_EVENT_NETWORK) {

        ks_state_add_network(event);

        /*
         * A shell making a network connection is not
         * automatically malicious.
         *
         * We only raise an alert when combined with
         * suspicious process ancestry.
         */
        if (ks_rule_network_from_shell(event)) {

            ks_process *process =
                ks_process_find(event->pid);

            if (process) {

                char ip[INET_ADDRSTRLEN];

                inet_ntop(AF_INET,
                          &event->dst_ipv4,
                          ip,
                          sizeof(ip));

                printf("\n");
                printf("============================================\n");
                printf("[HIGH] Suspicious Shell Network Activity\n");
                printf("Process : %s (%u)\n",
                       process->comm,
                       process->pid);
                printf("Parent  : %u\n",
                       process->ppid);
                printf("Target  : %s:%u\n",
                       ip,
                       ntohs(event->dst_port));
                printf("Reason  : Shell process initiated network connection\n");
                printf("============================================\n\n");
            }
        }

        return;
    }

    /*
     * Detect a server -> shell transition.
     */
    if (event->type == KS_EVENT_EXEC) {

        if (ks_rule_shell_from_server(event)) {

            ks_process *parent =
                ks_process_find(event->ppid);

            printf("\n");
            printf("============================================\n");
            printf("[HIGH] Suspicious Server-to-Shell Execution\n");

            if (parent) {
                printf("Parent  : %s (%u)\n",
                       parent->comm,
                       parent->pid);
            }

            printf("Child   : %s (%u)\n",
                   event->comm,
                   event->pid);

            printf("Reason  : Server process spawned a shell\n");
            printf("MITRE   : T1059 Command and Scripting Interpreter\n");
            printf("============================================\n\n");
        }
    }
}
