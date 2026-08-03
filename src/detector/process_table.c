#include <stdio.h>
#include <string.h>

#include "process_table.h"

static ks_process process_table[KS_MAX_PROCESSES];

static int find_slot(uint32_t pid)
{
    for (int i = 0; i < KS_MAX_PROCESSES; i++) {
        if (process_table[i].active && process_table[i].pid == pid)
            return i;
    }

    return -1;
}

static int find_free_slot(void)
{
    for (int i = 0; i < KS_MAX_PROCESSES; i++) {
        if (!process_table[i].active)
            return i;
    }

    return -1;
}

void ks_process_table_init(void)
{
    memset(process_table, 0, sizeof(process_table));
}

void ks_process_add(const struct ks_event *event)
{
    int slot = find_slot(event->pid);

    if (slot == -1)
        slot = find_free_slot();

    if (slot == -1)
        return;

    process_table[slot].active = true;

    process_table[slot].pid = event->pid;
    process_table[slot].ppid = event->ppid;

    process_table[slot].uid = event->uid;
    process_table[slot].gid = event->gid;

    process_table[slot].start_time_ns = event->timestamp_ns;
    process_table[slot].end_time_ns = 0;

    strncpy(process_table[slot].comm,
            event->comm,
            TASK_COMM_LEN - 1);

    process_table[slot].comm[TASK_COMM_LEN - 1] = '\0';

    strncpy(process_table[slot].filename,
            event->filename,
            KS_MAX_FILENAME_LEN - 1);

    process_table[slot].filename[KS_MAX_FILENAME_LEN - 1] = '\0';
}

void ks_process_remove(const struct ks_event *event)
{
    int slot = find_slot(event->pid);

    if (slot == -1)
        return;

    process_table[slot].end_time_ns = event->timestamp_ns;
    process_table[slot].active = false;
}

ks_process *ks_process_find(uint32_t pid)
{
    int slot = find_slot(pid);

    if (slot == -1)
        return NULL;

    return &process_table[slot];
}

void ks_process_table_print(void)
{
    printf("\n");
    printf("========== KernelShield Process Table ==========\n");

    for (int i = 0; i < KS_MAX_PROCESSES; i++) {

        if (!process_table[i].active)
            continue;

        printf("PID=%u PPID=%u UID=%u GID=%u COMM=%s FILE=%s\n",
               process_table[i].pid,
               process_table[i].ppid,
               process_table[i].uid,
               process_table[i].gid,
               process_table[i].comm,
               process_table[i].filename);
    }

    printf("===============================================\n");
}
