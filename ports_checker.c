#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define MAX_PORTS 50
#define BUFFER_SIZE 1024

const int dangerous_ports[] = {22, 23, 80, 443, 139, 445, 3389, 4444, 5555, 31337};
const int num_dangerous_ports = sizeof(dangerous_ports) / sizeof(int);

int is_dangerous(int port)
{
    for (int i = 0; i < num_dangerous_ports; i++)
    {
        if (port == dangerous_ports[i])
        {
            return 1;
        }
    }
    return 0;
}

char *get_process_name(pid_t pid)
{
    static char path[256];
    static char name[256];
    FILE *cmdline;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    cmdline = fopen(path, "r");

    if (cmdline)
    {
        if (fgets(name, sizeof(name), cmdline))
        {
            name[strcspn(name, "\n")] = 0;
        }
        fclose(cmdline);
        return name;
    }
    return "unknown";
}

const char *get_binding_risk(const char *local_addr)
{
    if (strstr(local_addr, "0.0.0.0") || strstr(local_addr, "*:") ||
        strstr(local_addr, "::") || strstr(local_addr, "[::]"))
    {
        return "EXTERNALLY ACCESSIBLE!";
    }
    else if (strstr(local_addr, "127.0.0.1") || strstr(local_addr, "::1") ||
             strstr(local_addr, "[::1]") || strstr(local_addr, "localhost"))
    {
        return "LOCALHOST ONLY";
    }
    return "UNKNOWN BINDING";
}

int check_ports()
{
    printf("Scanning for dangerous open ports...\n");
    printf("=====================================\n");

    int found_danger = 0;
    FILE *fp = popen("ss -tulnp 2>/dev/null", "r");
    if (!fp)
    {
        perror("Error running ss command");
        return 1;
    }

    char buffer[BUFFER_SIZE];
    while (fgets(buffer, sizeof(buffer), fp))
    {
        if (strstr(buffer, "Netid") || strstr(buffer, "State"))
            continue;

        char netid[16], state[16], local_addr[128], process_info[256];
        unsigned long recvq, sendq;

        if (sscanf(buffer, "%s %s %lu %lu %s %*s %[^\n]",
                   netid, state, &recvq, &sendq, local_addr, process_info) < 5)
        {
            continue;
        }

        if (strstr(state, "LISTEN") == NULL)
            continue;

        char *port_str = strrchr(local_addr, ':');
        if (!port_str)
            continue;
        int port = atoi(port_str + 1);

        if (is_dangerous(port))
        {
            pid_t pid = 0;
            char *pid_start = strstr(process_info, "pid=");
            if (pid_start)
            {
                sscanf(pid_start, "pid=%d", &pid);
            }

            const char *process_name = pid ? get_process_name(pid) : "unknown";
            const char *binding_risk = get_binding_risk(local_addr);

            printf("[!] DANGEROUS PORT: %d\n", port);
            printf("     Binding: %s\n", local_addr);
            printf("     Security: %s\n", binding_risk);
            printf("     Process: %s (PID: %d)\n", process_name, pid);
            printf("     Risk: ");

            switch (port)
            {
            case 22:
                printf("SSH brute-force attacks");
                break;
            case 23:
                printf("Cleartext credentials");
                break;
            case 80:
            case 443:
                printf("Web server vulnerabilities");
                break;
            case 139:
            case 445:
                printf("EternalBlue exploits");
                break;
            case 3389:
                printf("RDP brute-forcing");
                break;
            case 4444:
                printf("Metasploit payloads");
                break;
            case 5555:
                printf("Android backdoors");
                break;
            case 31337:
                printf("Classic backdoor port");
                break;
            default:
                printf("Known backdoor/exploitable service");
            }
            printf("\n-------------------------------------\n");
            found_danger = 1;
        }
    }

    pclose(fp);

    if (!found_danger)
    {
        printf("No dangerous open ports found. System appears secure.\n");
    }
    else
    {
        printf("\nScan complete. Review flagged ports above.\n");
        printf("Recommended actions for EXTERNALLY ACCESSIBLE ports:\n");
        printf("1. Disable unnecessary services\n");
        printf("2. Implement firewall restrictions\n");
        printf("3. Use VPN for remote access\n");
    }
    printf("\n\n");
    return 0;
}