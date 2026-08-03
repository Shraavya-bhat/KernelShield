#ifndef __PROCESS_EXEC_H
#define __PROCESS_EXEC_H

#include "vmlinux.h"

/* BPF-compatible integer aliases */
typedef __u64 uint64_t;
typedef __u32 uint32_t;
typedef __s32 int32_t;

#ifndef __cplusplus
typedef _Bool bool;
#endif

#include "../../include/ks_event.h"

#endif
