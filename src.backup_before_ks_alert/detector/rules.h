#ifndef KS_DETECTOR_RULES_H
#define KS_DETECTOR_RULES_H

#include "../../include/ks_event.h"

int ks_rule_shell_from_server(const struct ks_event *event);

int ks_rule_network_from_shell(const struct ks_event *event);

int ks_rule_correlated_behavior(uint32_t pid);

/* Detect a multi-stage process -> shell -> network-tool chain. */
int ks_rule_attack_chain(uint32_t pid);

#endif
