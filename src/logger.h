#ifndef KS_LOGGER_H
#define KS_LOGGER_H

#include <stddef.h>

#include "../include/ks_event.h"

int ks_logger_init(const char *path);

void ks_logger_close(void);

void ks_logger_event(const struct ks_event *event);

void ks_logger_alert(
    const char *severity,
    const char *alert_type,
    const struct ks_event *event,
    int risk_score,
    const char *reason,
    const char *mitre
);

#endif
