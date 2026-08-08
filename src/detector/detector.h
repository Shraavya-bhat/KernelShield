#ifndef KS_DETECTOR_H
#define KS_DETECTOR_H

#include "../../include/ks_event.h"

void ks_detector_init(void);

void ks_detector_process_event(const struct ks_event *event);

#endif
