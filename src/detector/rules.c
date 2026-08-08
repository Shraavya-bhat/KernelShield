#include <string.h>

#include "rules.h"
#include "process_table.h"

static int is_server_process(const char *comm)
{
    return strcmp(comm, "nginx") == 0 ||
           strcmp(comm, "apache2") == 0 ||
           strcmp(comm, "httpd") == 0 ||
           strcmp(comm, "python3") == 0 ||
           strcmp(comm, "php-fpm") == 0;
}

static int is_shell(const char *comm)
{
    return strcmp(comm, "bash") == 0 ||
           strcmp(comm, "sh") == 0 ||
           strcmp(comm, "dash") == 0 ||
           strcmp(comm, "zsh") == 0;
}

/*
 * Rule 1:
 * A server process spawning a shell is suspicious.
 */
int ks_rule_shell_from_server(const struct ks_event *event)
{
    if (event->type != KS_EVENT_EXEC)
        return 0;

    ks_process *parent = ks_process_find(event->ppid);

    if (!parent)
        return 0;

    if (is_server_process(parent->comm) &&
        is_shell(event->comm))
        return 1;

    return 0;
}

/*
 * Rule 2:
 * A shell making an outbound network connection
 * is interesting for correlation.
 *
 * This alone is NOT treated as malicious.
 */
int ks_rule_network_from_shell(const struct ks_event *event)
{
    if (event->type != KS_EVENT_NETWORK)
        return 0;

    ks_process *process = ks_process_find(event->pid);

    if (!process)
        return 0;

    if (is_shell(process->comm))
        return 1;

    return 0;
}
