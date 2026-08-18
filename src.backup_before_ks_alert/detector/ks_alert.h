#ifndef KS_ALERT_H
#define KS_ALERT_H

#include <stdint.h>

#define KS_ALERT_SCHEMA_VERSION 1

#define KS_ALERT_PROCESS_LEN 64
#define KS_ALERT_ATTACK_TYPE_LEN 64
#define KS_ALERT_ALERT_TYPE_LEN 32
#define KS_ALERT_SEVERITY_LEN 16
#define KS_ALERT_REASON_LEN 256
#define KS_ALERT_MITRE_LEN 32
#define KS_ALERT_IP_LEN 46

/*
 * KernelShield Detection Alert Contract
 *
 * This is the canonical interface between:
 *
 *     Detection Engine
 *          |
 *          v
 *       ks_alert
 *        /   \
 *       v     v
 * Response   ELK
 *
 * IMPORTANT:
 * This structure is a USERSPACE interface.
 * It is not passed directly through the eBPF ring buffer.
 */

typedef struct ks_alert {

    /* Schema */
    uint32_t schema_version;

    /* Detection time */
    uint64_t timestamp_ns;

    /* Process identity */
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;

    /* Process context */
    char process_name[KS_ALERT_PROCESS_LEN];
    char parent_name[KS_ALERT_PROCESS_LEN];

    /* Detection classification */
    char attack_type[KS_ALERT_ATTACK_TYPE_LEN];
    char alert_type[KS_ALERT_ALERT_TYPE_LEN];
    char severity[KS_ALERT_SEVERITY_LEN];

    /* Human-readable explanation */
    char reason[KS_ALERT_REASON_LEN];

    /* MITRE ATT&CK technique */
    char mitre_technique[KS_ALERT_MITRE_LEN];

    /*
     * Network context.
     *
     * has_network == 0:
     *     destination_ip and destination_port are not meaningful.
     *
     * has_network == 1:
     *     destination_ip and destination_port contain the
     *     destination associated with the detection.
     */
    uint8_t has_network;

    char destination_ip[KS_ALERT_IP_LEN];

    uint16_t destination_port;

    /*
     * Number of behavioral events/signals that contributed
     * to this alert.
     *
     * This is NOT network_count.
     */
    uint32_t event_count;

} ks_alert;
int ks_alert_init(void);

void ks_alert_close(void);

int ks_alert_write(const ks_alert *alert);
#endif
