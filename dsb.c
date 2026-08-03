#include <stdio.h>
#include <unistd.h>
#include <time.h>

void print_event(int pid, int ppid, int uid, const char *proc)
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    printf("\n=============================================\n");
    printf("         KernelShield Runtime Monitor\n");
    printf("=============================================\n");

    printf("Event Type : PROCESS_EXEC\n");
    printf("Timestamp  : %02d:%02d:%02d\n",
           t->tm_hour, t->tm_min, t->tm_sec);
    printf("PID        : %d\n", pid);
    printf("PPID       : %d\n", ppid);
    printf("UID        : %d\n", uid);
    printf("Process    : %s\n", proc);
    printf("Status     : Normal Runtime Event\n");
    printf("---------------------------------------------\n");
}

int main()
{
    printf("\nKernelShield Started...\n");
    printf("Monitoring Linux Runtime Events...\n");

    sleep(2);

    print_event(1250, 1024, 1000, "bash");

    sleep(2);

    print_event(1251, 1250, 1000, "ls");

    sleep(2);

    print_event(1252, 1250, 1000, "python3");

    printf("\nWaiting for more runtime events...\n");

    return 0;
}
