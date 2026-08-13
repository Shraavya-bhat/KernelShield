#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "logger.h"

#define KS_LOG_SCHEMA "1.0"

static FILE *log_file = NULL;

static const char *event_type_name(uint16_t type)
{
    switch (type) {
    case KS_EVENT_EXEC:
        return "exec";
    case KS_EVENT_EXIT:
        return "exit";
    case KS_EVENT_NETWORK:
        return "network";
    case KS_EVENT_PRIVILEGE:
        return "privilege";
    case KS_EVENT_ALERT:
        return "alert";
    default:
        return "unknown";
    }
}

static void json_escape(
    FILE *fp,
    const char *str)
{
    if (!str) {
        fputs("", fp);
        return;
    }

    for (const unsigned char *p =
             (const unsigned char *)str;
         *p;
         p++) {

        switch (*p) {
        case '\"':
            fputs("\\\"", fp);
            break;

        case '\\':
            fputs("\\\\", fp);
            break;

        case '\n':
            fputs("\\n", fp);
            break;

        case '\r':
            fputs("\\r", fp);
            break;

        case '\t':
            fputs("\\t", fp);
            break;

        default:
            if (*p < 32)
                fprintf(fp, "\\u%04x", *p);
            else
                fputc(*p, fp);
        }
    }
}

static void write_timestamp(FILE *fp)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        fputs("1970-01-01T00:00:00.000Z", fp);
        return;
    }

    struct tm tm_value;

    if (gmtime_r(&ts.tv_sec, &tm_value) == NULL) {
        fputs("1970-01-01T00:00:00.000Z", fp);
        return;
    }

    long milliseconds = ts.tv_nsec / 1000000L;

    fprintf(fp,
            "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
            tm_value.tm_year + 1900,
            tm_value.tm_mon + 1,
            tm_value.tm_mday,
            tm_value.tm_hour,
            tm_value.tm_min,
            tm_value.tm_sec,
            milliseconds);
}

static void write_common_fields(
    FILE *fp,
    const struct ks_event *event)
{
    char hostname[256] = "unknown";

    if (gethostname(hostname, sizeof(hostname) - 1) != 0)
        strcpy(hostname, "unknown");

    hostname[sizeof(hostname) - 1] = '\0';

    fprintf(fp, "\"schema_version\":\"%s\",", KS_LOG_SCHEMA);

    fprintf(fp, "\"sensor\":\"kernelshield\",");

    fprintf(fp, "\"host\":\"");
    json_escape(fp, hostname);
    fprintf(fp, "\",");

    fprintf(fp, "\"timestamp\":\"");
    write_timestamp(fp);
    fprintf(fp, "\",");

    fprintf(fp,
            "\"timestamp_ns\":%llu,",
            (unsigned long long)event->timestamp_ns);

    fprintf(fp,
            "\"event_type\":\"%s\",",
            event_type_name(event->type));

    fprintf(fp,
            "\"pid\":%u,"
            "\"ppid\":%u,"
            "\"uid\":%u,"
            "\"gid\":%u,",
            event->pid,
            event->ppid,
            event->uid,
            event->gid);

    fprintf(fp, "\"comm\":\"");
    json_escape(fp, event->comm);
    fprintf(fp, "\",");

    fprintf(fp, "\"filename\":\"");
    json_escape(fp, event->filename);
    fprintf(fp, "\"");
}

int ks_logger_init(const char *path)
{
    if (!path)
        return -1;

    log_file = fopen(path, "a");

    if (!log_file)
        return -1;

    setvbuf(log_file,
            NULL,
            _IOLBF,
            0);

    return 0;
}

void ks_logger_close(void)
{
    if (log_file) {
        fflush(log_file);
        fclose(log_file);
        log_file = NULL;
    }
}

void ks_logger_event(const struct ks_event *event)
{
    if (!log_file || !event)
        return;

    fprintf(log_file, "{");

    write_common_fields(log_file, event);

    if (event->type == KS_EVENT_EXIT) {

        fprintf(log_file,
                ",\"exit_code\":%d,"
                "\"duration_ms\":%llu",
                event->exit_code,
                (unsigned long long)
                    (event->duration_ns / 1000000ULL));
    }

    else if (event->type == KS_EVENT_NETWORK) {

        char dst_ip[INET_ADDRSTRLEN] =
            "unknown";

        inet_ntop(AF_INET,
                  &event->dst_ipv4,
                  dst_ip,
                  sizeof(dst_ip));

        fprintf(log_file,
                ",\"network\":{"
                "\"src_ipv4\":%u,"
                "\"dst_ipv4\":\"%s\","
                "\"src_port\":%u,"
                "\"dst_port\":%u"
                "}",
                event->src_ipv4,
                dst_ip,
                ntohs(event->src_port),
                ntohs(event->dst_port));
    }

    fprintf(log_file, "}\n");

    fflush(log_file);
}

void ks_logger_alert(
    const char *severity,
    const char *alert_type,
    const struct ks_event *event,
    int risk_score,
    const char *reason,
    const char *mitre)
{
    if (!log_file || !event)
        return;

    fprintf(log_file, "{");

    write_common_fields(log_file, event);

    fprintf(log_file,
            ",\"event_type\":\"alert\","
            "\"severity\":\"");

    json_escape(log_file, severity);

    fprintf(log_file,
            "\",\"alert_type\":\"");

    json_escape(log_file, alert_type);

    fprintf(log_file,
            "\",\"risk_score\":%d,"
            "\"reason\":\"",
            risk_score);

    json_escape(log_file, reason);

    fprintf(log_file,
            "\",\"mitre_technique\":\"");

    json_escape(log_file, mitre);

    fprintf(log_file, "\"}\n");

    fflush(log_file);
}
