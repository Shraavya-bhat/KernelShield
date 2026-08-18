#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "ks_alert.h"

/*
 * Canonical KernelShield alert output.
 *
 * One JSON object per line.
 *
 * Consumers:
 *
 *   /tmp/kernelshield-alerts.jsonl
 *          |
 *          +---- Response Engine
 *          |
 *          +---- ELK
 */

#define KS_ALERT_JSONL_PATH "/tmp/kernelshield-alerts.jsonl"

static FILE *alert_fp = NULL;


/* ============================================================
 * Initialization
 * ============================================================ */

int ks_alert_init(void)
{
    if (alert_fp)
        return 0;

    alert_fp = fopen(KS_ALERT_JSONL_PATH, "a");

    if (!alert_fp)
        return -1;

    /*
     * Line-buffered output means every alert becomes visible
     * immediately to downstream consumers.
     */
    setvbuf(
        alert_fp,
        NULL,
        _IOLBF,
        0
    );

    return 0;
}


/* ============================================================
 * Shutdown
 * ============================================================ */

void ks_alert_close(void)
{
    if (!alert_fp)
        return;

    fflush(alert_fp);
    fclose(alert_fp);

    alert_fp = NULL;
}


/* ============================================================
 * JSON escaping
 * ============================================================ */

static void json_escape(
    const char *src,
    char *dst,
    size_t dst_size)
{
    size_t j = 0;

    if (!src || !dst || dst_size == 0)
        return;

    for (size_t i = 0;
         src[i] != '\0' && j + 2 < dst_size;
         i++) {

        unsigned char c =
            (unsigned char)src[i];

        switch (c) {

        case '\"':
            if (j + 2 >= dst_size)
                goto done;

            dst[j++] = '\\';
            dst[j++] = '\"';
            break;

        case '\\':
            if (j + 2 >= dst_size)
                goto done;

            dst[j++] = '\\';
            dst[j++] = '\\';
            break;

        case '\n':
            if (j + 2 >= dst_size)
                goto done;

            dst[j++] = '\\';
            dst[j++] = 'n';
            break;

        case '\r':
            if (j + 2 >= dst_size)
                goto done;

            dst[j++] = '\\';
            dst[j++] = 'r';
            break;

        case '\t':
            if (j + 2 >= dst_size)
                goto done;

            dst[j++] = '\\';
            dst[j++] = 't';
            break;

        default:
            /*
             * Avoid emitting raw control characters.
             */
            if (c < 0x20)
                break;

            dst[j++] = c;
            break;
        }
    }

done:
    dst[j] = '\0';
}


/* ============================================================
 * Serialization
 * ============================================================ */

int ks_alert_write(const ks_alert *alert)
{
    if (!alert)
        return -1;

    if (!alert_fp) {

        if (ks_alert_init() != 0)
            return -1;
    }

    char process_name[KS_ALERT_PROCESS_LEN * 2];
    char parent_name[KS_ALERT_PROCESS_LEN * 2];
    char attack_type[KS_ALERT_ATTACK_TYPE_LEN * 2];
    char alert_type[KS_ALERT_ALERT_TYPE_LEN * 2];
    char severity[KS_ALERT_SEVERITY_LEN * 2];
    char reason[KS_ALERT_REASON_LEN * 2];
    char mitre[KS_ALERT_MITRE_LEN * 2];
    char destination_ip[KS_ALERT_IP_LEN * 2];

    json_escape(
        alert->process_name,
        process_name,
        sizeof(process_name)
    );

    json_escape(
        alert->parent_name,
        parent_name,
        sizeof(parent_name)
    );

    json_escape(
        alert->attack_type,
        attack_type,
        sizeof(attack_type)
    );

    json_escape(
        alert->alert_type,
        alert_type,
        sizeof(alert_type)
    );

    json_escape(
        alert->severity,
        severity,
        sizeof(severity)
    );

    json_escape(
        alert->reason,
        reason,
        sizeof(reason)
    );

    json_escape(
        alert->mitre_technique,
        mitre,
        sizeof(mitre)
    );

    json_escape(
        alert->destination_ip,
        destination_ip,
        sizeof(destination_ip)
    );

    /*
     * Keep network fields explicit.
     *
     * This makes downstream parsing deterministic.
     */
    fprintf(
        alert_fp,
        "{"
        "\"schema_version\":%u,"
        "\"timestamp_ns\":%llu,"
        "\"pid\":%u,"
        "\"ppid\":%u,"
        "\"uid\":%u,"
        "\"gid\":%u,"
        "\"process_name\":\"%s\","
        "\"parent_name\":\"%s\","
        "\"attack_type\":\"%s\","
        "\"alert_type\":\"%s\","
        "\"severity\":\"%s\","
        "\"reason\":\"%s\","
        "\"mitre_technique\":\"%s\","
        "\"has_network\":%u,"
        "\"destination_ip\":\"%s\","
        "\"destination_port\":%u,"
        "\"event_count\":%u"
        "}\n",

        alert->schema_version,

        (unsigned long long)
            alert->timestamp_ns,

        alert->pid,
        alert->ppid,
        alert->uid,
        alert->gid,

        process_name,
        parent_name,

        attack_type,
        alert_type,
        severity,

        reason,

        mitre,

        alert->has_network,
        destination_ip,
        alert->destination_port,

        alert->event_count
    );

    fflush(alert_fp);

    return ferror(alert_fp) ? -1 : 0;
}
