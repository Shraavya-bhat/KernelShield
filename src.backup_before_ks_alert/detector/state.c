#include <string.h>

#include "state.h"

static ks_network_state network_table[KS_MAX_TRACKED_NETWORK];

void ks_state_init(void)
{
    memset(network_table, 0, sizeof(network_table));
}

void ks_state_add_network(const struct ks_event *event)
{
    ks_network_state *state = ks_state_find_network(event->pid);

    /*
     * Process already has network activity.
     * Update its existing state instead of creating
     * another record.
     */
    if (state) {
        state->dst_ipv4 = event->dst_ipv4;
        state->dst_port = event->dst_port;
        state->last_seen_ns = event->timestamp_ns;
        state->network_count++;

        return;
    }

    /*
     * First network event for this process.
     */
    for (int i = 0; i < KS_MAX_TRACKED_NETWORK; i++) {

        if (!network_table[i].active) {

            network_table[i].active = true;

            network_table[i].pid = event->pid;
            network_table[i].ppid = event->ppid;

            strncpy(network_table[i].comm,
                    event->comm,
                    sizeof(network_table[i].comm) - 1);

            network_table[i].comm[
                sizeof(network_table[i].comm) - 1
            ] = '\0';

            network_table[i].dst_ipv4 = event->dst_ipv4;
            network_table[i].dst_port = event->dst_port;

            network_table[i].first_seen_ns = event->timestamp_ns;
            network_table[i].last_seen_ns = event->timestamp_ns;

            network_table[i].network_count = 1;

            return;
        }
    }
}

ks_network_state *ks_state_find_network(uint32_t pid)
{
    for (int i = 0; i < KS_MAX_TRACKED_NETWORK; i++) {

        if (network_table[i].active &&
            network_table[i].pid == pid) {

            return &network_table[i];
        }
    }

    return NULL;
}

void ks_state_remove_network(uint32_t pid)
{
    for (int i = 0; i < KS_MAX_TRACKED_NETWORK; i++) {

        if (network_table[i].active &&
            network_table[i].pid == pid) {

            network_table[i].active = false;
            return;
        }
    }
}
