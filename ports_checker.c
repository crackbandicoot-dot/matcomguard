#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "common.h"

#define BUFFER_SIZE 1024

const int dangerous_ports[] = {
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    80,    // HTTP
    110,   // POP3
    111,   // RPC
    135,   // MSRPC
    139,   // NetBIOS
    143,   // IMAP
    161,   // SNMP
    389,   // LDAP
    443,   // HTTPS
    445,   // SMB
    465,   // SMTP SSL
    587,   // SMTP Submission
    993,   // IMAP SSL
    995,   // POP3 SSL
    1433,  // MSSQL
    1521,  // Oracle DB
    2049,  // NFS
    3306,  // MySQL
    3389,  // RDP
    4444,  // Metasploit
    5000,  // UPnP
    5432,  // PostgreSQL
    5555,  // Android ADB
    5900,  // VNC
    6379,  // Redis
    8080,  // HTTP Proxy
    8443,  // HTTPS Alt
    8888,  // HTTP Alt
    9000,  // PHP-FPM
    9090,  // WebSphere
    11211, // Memcached
    27017, // MongoDB
    31337, // Backdoor
    49152  // Windows RPC
};
const int num_dangerous_ports = sizeof(dangerous_ports) / sizeof(int);

int is_dangerous(int port) {
    for (int i = 0; i < num_dangerous_ports; i++) {
        if (port == dangerous_ports[i]) {
            return 1;
        }
    }
    return 0;
}

char *get_process_name(pid_t pid) {
    static char path[256];
    static char name[256];
    FILE *cmdline;

    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    cmdline = fopen(path, "r");

    if (cmdline) {
        if (fgets(name, sizeof(name), cmdline)) {
            name[strcspn(name, "\n")] = 0;
        }
        fclose(cmdline);
        return name;
    }
    return "unknown";
}

const char *get_binding_risk(const char *local_addr) {
    if (strstr(local_addr, "0.0.0.0") || strstr(local_addr, "*:") ||
        strstr(local_addr, "::") || strstr(local_addr, "[::]")) {
        return "EXTERNALLY ACCESSIBLE! ⚠️";
    }
    else if (strstr(local_addr, "127.0.0.1") || strstr(local_addr, "::1") ||
             strstr(local_addr, "[::1]") || strstr(local_addr, "localhost")) {
        return "LOCALHOST ONLY 🏠";
    }
    return "UNKNOWN BINDING ❓";
}

int check_ports() {
    printf(PORT_GUARD "Scanning castle walls for dangerous open ports...\n");
    printf(PORT_GUARD "=====================================\n");

    int found_danger = 0;
    FILE *fp = popen("ss -tulnp 2>/dev/null", "r");
    if (!fp) {
        perror("Error running ss command");
        return 1;
    }

    char buffer[BUFFER_SIZE];
    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "Netid") || strstr(buffer, "State"))
            continue;

        char netid[16], state[16], local_addr[128], process_info[256];
        unsigned long recvq, sendq;

        if (sscanf(buffer, "%s %s %lu %lu %s %*s %[^\n]",
                   netid, state, &recvq, &sendq, local_addr, process_info) < 5) {
            continue;
        }

        if (strstr(state, "LISTEN") == NULL)
            continue;

        char *port_str = strrchr(local_addr, ':');
        if (!port_str)
            continue;
        int port = atoi(port_str + 1);

        if (is_dangerous(port)) {
            pid_t pid = 0;
            char *pid_start = strstr(process_info, "pid=");
            if (pid_start) {
                sscanf(pid_start, "pid=%d", &pid);
            }

            const char *process_name = pid ? get_process_name(pid) : "unknown";
            const char *binding_risk = get_binding_risk(local_addr);

            printf(PORT_GUARD ALERT "Breach in castle wall! Port: %d\n", port);
            printf(PORT_GUARD "Location: %s\n", local_addr);
            printf(PORT_GUARD "Security: %s\n", binding_risk);
            printf(PORT_GUARD "Guard: %s (PID: %d)\n", process_name, pid);
            printf(PORT_GUARD "Threat: ");

            switch (port) {
            case 21:
                printf("FTP brute-force/anonymous login 📂");
                break;
            case 22:
                printf("SSH brute-force attacks 🪓");
                break;
            case 23:
                printf("Cleartext credentials (Telnet) 📜");
                break;
            case 25:
                printf("SMTP open relay/spam abuse 📧");
                break;
            case 80:
                printf("Web server vulnerabilities (HTTP) 🕸️");
                break;
            case 110:
                printf("POP3 cleartext credentials 💌");
                break;
            case 111:
                printf("RPC service vulnerabilities 🌀");
                break;
            case 135:
                printf("Windows RPC exploits 🪟");
                break;
            case 139:
            case 445:
                printf("EternalBlue/SMB exploits 💣");
                break;
            case 143:
                printf("IMAP cleartext credentials 📨");
                break;
            case 161:
                printf("SNMP default community strings 📡");
                break;
            case 389:
                printf("LDAP injection/brute-force attacks 🔓");
                break;
            case 443:
                printf("HTTPS vulnerabilities/SSL stripping 🔒");
                break;
            case 465:
            case 587:
                printf("SMTP auth brute-force attacks 📤");
                break;
            case 993:
            case 995:
                printf("Email service brute-force attacks 📭");
                break;
            case 1433:
                printf("SQL Server brute-force attacks 🗄️");
                break;
            case 1521:
                printf("Oracle DB TNS poison attacks 🐉");
                break;
            case 2049:
                printf("NFS unauthorized access 🗂️");
                break;
            case 3306:
                printf("MySQL brute-force attacks 🐬");
                break;
            case 3389:
                printf("RDP brute-forcing 💻");
                break;
            case 4444:
                printf("Metasploit payloads 🧨");
                break;
            case 5000:
                printf("UPnP control abuse 🎛️");
                break;
            case 5432:
                printf("PostgreSQL exploits 🐘");
                break;
            case 5555:
                printf("Android backdoors 📱");
                break;
            case 5900:
                printf("VNC screen capture/control 👁️");
                break;
            case 6379:
                printf("Redis unauthorized access 🧠");
                break;
            case 8080:
            case 8888:
                printf("Proxy abuse/web attacks 🕸️");
                break;
            case 8443:
                printf("HTTPS MITM attacks 🎭");
                break;
            case 9000:
                printf("PHP-FPM remote code execution 🐘");
                break;
            case 9090:
                printf("WebSphere administrative access ⚙️");
                break;
            case 11211:
                printf("Memcached amplification attacks 📦");
                break;
            case 27017:
                printf("MongoDB unauthorized access 🍃");
                break;
            case 31337:
                printf("Classic backdoor port 🕵️");
                break;
            case 49152:
                printf("Windows RPC dynamic ports exploit 🪟");
                break;
            default:
                printf("Known backdoor/exploitable service ⚠️");
            }
            printf("\n-------------------------------------\n");
            found_danger = 1;
        }
    }

    pclose(fp);

    if (!found_danger) {
        printf(PORT_GUARD "Castle walls are secure! No dangerous open ports found 🛡️\n");
    } else {
        printf(PORT_GUARD "\nScan complete. Review flagged ports above.\n");
        printf(PORT_GUARD "Recommended actions for EXTERNALLY ACCESSIBLE ports:\n");
        printf(PORT_GUARD "1. Disable unnecessary services\n");
        printf(PORT_GUARD "2. Implement firewall restrictions\n");
        printf(PORT_GUARD "3. Use VPN for remote access\n");
    }
    printf("\n\n");
    return 0;
}