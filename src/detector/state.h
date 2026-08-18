#ifndef KS_DETECTOR_STATE_H
#define KS_DETECTOR_STATE_H

#include <stdbool.h>
#include <stdint.h>
#include "../../include/ks_event.h"

#define KS_MAX_TRACKED_NETWORK 8192

typedef struct {
    bool active;

    uint32_t pid;
    uint32_t ppid;

    char comm[16];

    uint32_t dst_ipv4;
    uint16_t dst_port;

    uint64_t first_seen_ns;
    uint64_t last_seen_ns;

    uint32_t network_count;
} ks_network_state;

void ks_state_init(void);

void ks_state_add_network(const struct ks_event *event);

ks_network_state *ks_state_find_network(uint32_t pid);

void ks_state_remove_network(uint32_t pid);

#endif
