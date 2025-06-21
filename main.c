#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include "procces_checker.h"
#include "ports_checker.h"
#include "discovery.h"
#include "scanner.h"
#include <string.h>
#include <ctype.h>
#include <limits.h>

// Global variables for USB patrol
pthread_t usb_patrol_thread;
atomic_int usb_patrol_active = 0;
USBMonitor *global_monitor = NULL;
Scanner *global_scanner = NULL;
pthread_mutex_t cleanup_mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct
{
    float size_change_threshold;
    int max_file_copies;
    float change_percentage_threshold;
    int scan_interval;
} USB_Thresholds;
USB_Thresholds *Thresholds;

// Callback for USB events
void usb_event_callback(const char *action, const char *devnode, const char *mount_point, Baseline *baseline)
{
    if (strcmp(action, "add") == 0)
    {
        printf(ROYAL_GUARD "USB device connected: %s at %s\n", devnode, mount_point);
        if (baseline)
        {
            printf(ROYAL_GUARD "Royal baseline established for %s\n", mount_point);
        }
    }
    else
    {
        printf(ROYAL_GUARD "USB device disconnected: %s from %s\n", devnode, mount_point);
    }
}

// Signal handler
void handle_signal(int sig)
{
    if (sig == SIGUSR1)
    {
        printf(CASTLE "Royal command received to stop patrol\n");
    }
    else
    {
        printf(CASTLE "Signal %d received. Stopping...\n", sig);
    }

    atomic_store(&usb_patrol_active, 0);
}

void *usb_patrol_thread_function(void *arg)
{
    // Signal handling setup
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    // Register signal handlers
    if (sigaction(SIGINT, &sa, NULL) == -1)
        perror("sigaction(SIGINT)");
    if (sigaction(SIGTERM, &sa, NULL) == -1)
        perror("sigaction(SIGTERM)");
    if (sigaction(SIGUSR1, &sa, NULL) == -1)
        perror("sigaction(SIGUSR1)");

    // Start USB monitoring
    USBMonitor *monitor = usb_monitor_start(usb_event_callback);
    if (!monitor)
    {
        fprintf(stderr, ROYAL_GUARD ALERT "Error starting USB monitor\n");
        return NULL;
    }
    global_monitor = monitor;

    // Scanner configuration
    ScannerConfig config = {
        .size_change_threshold = 500.0,
        .max_file_copies = 5,
        .change_percentage_threshold = 0.05,
        .scan_interval = 60};

    Scanner *scanner = malloc(sizeof(Scanner));
    if (!scanner)
    {
        fprintf(stderr, ROYAL_GUARD ALERT "Error creating scanner\n");
        usb_monitor_stop(monitor);
        return NULL;
    }

    scanner_init(scanner, monitor, &config, Thresholds->size_change_threshold, Thresholds->max_file_copies, Thresholds->change_percentage_threshold, Thresholds->scan_interval);
    scanner_start(scanner);
    global_scanner = scanner;

    // Main patrol loop
    while (atomic_load(&usb_patrol_active))
    {
        sleep(1);
    }

    // Cleanup
    scanner_stop(scanner);
    free(scanner);
    usb_monitor_stop(monitor);

    return NULL;
}

void start_usb_patrol()
{
    if (atomic_load(&usb_patrol_active))
    {
        printf(CASTLE "USB patrol is already active!\n");
        return;
    }
    atomic_store(&usb_patrol_active, 1);
    if (pthread_create(&usb_patrol_thread, NULL, usb_patrol_thread_function, NULL) != 0)
    {
        perror("Failed to start USB patrol");
        atomic_store(&usb_patrol_active, 0);
    }
    else
    {
        printf(CASTLE "Royal guards dispatched to patrol the files!\n");
    }
}

void stop_usb_patrol()
{
    if (!atomic_load(&usb_patrol_active))
    {
        printf(CASTLE "No active USB patrol to stop!\n");
        return;
    }

    atomic_store(&usb_patrol_active, 0);
    pthread_kill(usb_patrol_thread, SIGUSR1);
    pthread_join(usb_patrol_thread, NULL);
    printf(CASTLE "USB patrol recalled to the castle.\n");
}

int main()
{
    // Welcome banner
    int porcentaje_ram = 0;
    int porcentaje_cpu = 0;
    int change_percentage_threshold = 0;
    int max_file_copies = 0;
    int scan_interval = 0;
    int size_change_threshold = 0;
    FILE *file = fopen("config.config", "r");
    if (file == NULL)
    {
        perror("fopen");
        return 1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file) != NULL)
    {
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n')
        {
            line[len - 1] = '\0';
        }
        char *current = line;
        while (isspace((unsigned char)*current))
        {
            current++;
        }

        if (*current == '\0')
        {
            continue;
        }

        char *colon = strchr(current, ':');
        if (colon == NULL)
        {
            fprintf(stderr, "Skipping invalid line (no colon): %s\n", line);
            continue;
        }

        char *key_start = current;
        char *key_end = colon - 1;
        while (key_end >= key_start && isspace((unsigned char)*key_end))
        {
            key_end--;
        }

        if (key_end < key_start)
        {
            fprintf(stderr, "Skipping line with empty key: %s\n", line);
            continue;
        }

        size_t key_len = key_end - key_start + 1;
        char key[100];
        if (key_len >= sizeof(key))
        {
            key_len = sizeof(key) - 1;
        }
        strncpy(key, key_start, key_len);
        key[key_len] = '\0';

        char *value_start = colon + 1;
        while (isspace((unsigned char)*value_start))
        {
            value_start++;
        }

        if (*value_start == '\0')
        {
            fprintf(stderr, "Skipping line with empty value: %s\n", line);
            continue;
        }

        char *endptr;
        int value = strtol(value_start, &endptr, 10);

        if (endptr == value_start)
        {
            fprintf(stderr, "No digits found in value for key '%s'. Line: %s\n", key, line);
            continue;
        }

        char *p = endptr;
        while (*p != '\0' && isspace((unsigned char)*p))
        {
            p++;
        }
        if (*p != '\0')
        {
            fprintf(stderr, "Invalid trailing characters in value for key '%s'. Line: %s\n", key, line);
            continue;
        }

        if (value < 0)
        {
            printf(stderr, "Value out of range for key '%s'. Line: %s\n", key, line);
            return -1;
        }
        if (strcmp(key, "porcentaje_ram") == 0)
        {
            if (value > 100)
            {
                printf(stderr, "Value out of range for key '%s'. Line: %s\n", key, line);
                return -1;
            }

            porcentaje_ram = value;
        }
        else if (strcmp(key, "porcentaje_cpu") == 0)
        {
            if (value > 100)
            {
                printf(stderr, "Value out of range for key '%s'. Line: %s\n", key, line);
                return -1;
            }
            porcentaje_cpu = value;
        }
        else if (strcmp(key, "change_percentage_threshold") == 0)
        {
            if (value > 100)
            {
                printf(stderr, "Value out of range for key '%s'. Line: %s\n", key, line);
                return -1;
            }
            change_percentage_threshold = value;
        }
        else if (strcmp(key, "max_file_copies") == 0)
        {
            max_file_copies = value;
        }
        else if (strcmp(key, "scan_interval") == 0)
        {
            scan_interval = value;
        }
        else if (strcmp(key, "size_change_threshold") == 0)
        {
            size_change_threshold = value;
        }
        else
        {
            printf("Invalid key %s", key);
            return -1;
        }
    }
    fclose(file);

    if (porcentaje_cpu == 0)
    {
        porcentaje_cpu = 70;
    }
    if (porcentaje_ram == 0)
    {
        porcentaje_ram = 50;
    }
    if (change_percentage_threshold == 0)
    {
        change_percentage_threshold = 10;
    }
    if (max_file_copies == 0)
    {
        max_file_copies = 3;
    }
    if (scan_interval == 0)
    {
        scan_interval = 30;
    }
    if (size_change_threshold == 0)
    {
        size_change_threshold = 2;
    }

    Thresholds = malloc(sizeof(USB_Thresholds));
    Thresholds->max_file_copies = max_file_copies;
    Thresholds->scan_interval = scan_interval;
    Thresholds->size_change_threshold = size_change_threshold;
    Thresholds->change_percentage_threshold = change_percentage_threshold;
    
    //-----------------------------------------------------------------
    printf("\n");
    printf(COLOR_BLUE BOLD "╔══════════════════════════════════════════╗\n");
    printf(COLOR_BLUE BOLD "║                                          ║\n");
    printf(COLOR_BLUE BOLD "║ " COLOR_RESET "  Welcome to the Kingdom of FileGuard  " COLOR_BLUE BOLD "  ║\n");
    printf(COLOR_BLUE BOLD "║                                          ║\n");
    printf(COLOR_BLUE BOLD "╚══════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");

    while (1)
    {
        printf(CASTLE "\n=== " UNDERLINE "Royal Command Menu" COLOR_RESET " ===\n");
        printf("1 - 🛡️  Patrol Kingdom's Files (USB devices)\n");
        printf("2 - ⚔️  Inspect Kingdom's Processes\n");
        printf("3 - 🏰  Guard Castle Walls (Open ports)\n");
        printf("4 - 🚨 General Mobilization! (Full inspection)\n");
        printf("5 - 🏳️  Recall USB Patrol (Stop scanning)\n");
        printf("6 - 👑 Leave the Kingdom (Exit)\n");
        printf("\nEnter your command: ");

        int option;
        if (scanf("%d", &option) != 1)
        {
            printf(CASTLE ALERT "Invalid input!\n");
            while (getchar() != '\n')
                ; // Clear input buffer
            continue;
        }

        switch (option)
        {
        case 1:
            start_usb_patrol(change_percentage_threshold, scan_interval, max_file_copies, size_change_threshold);
            break;
        case 2:
            printf(PROCESS_WATCH "\nInspecting kingdom's processes...\n");
            process_check(porcentaje_cpu, porcentaje_ram);
            break;
        case 3:
            printf(PORT_GUARD "\nGuarding castle walls...\n");
            check_ports();
            break;
        case 4:
            printf(CASTLE "\nSound the alarm! General Mobilization!\n");
            if (atomic_load(&usb_patrol_active))
            {
                printf(CASTLE "USB patrol already active\n");
            }
            else
            {
                start_usb_patrol();
            }
            process_check();
            check_ports();
            break;
        case 5:
            stop_usb_patrol();
            break;
        case 6:
            if (atomic_load(&usb_patrol_active))
            {
                stop_usb_patrol();
            }
            // Goodbye banner
            printf(CASTLE "Farewell, noble guardian!\n");
            printf(COLOR_GREEN BOLD "╔══════════════════════════════════════════╗\n");
            printf(COLOR_GREEN BOLD "║                                          ║\n");
            printf(COLOR_GREEN BOLD "║  " COLOR_RESET " May your kingdom remain ever secure! " COLOR_GREEN BOLD "  ║\n");
            printf(COLOR_GREEN BOLD "║                                          ║\n");
            printf(COLOR_GREEN BOLD "╚══════════════════════════════════════════╝\n" COLOR_RESET);
            printf("\n");
            return 0;
        default:
            printf(CASTLE ALERT "Invalid command! Choose 1-6\n");
            while (getchar() != '\n')
                ; // Clear input buffer
            break;
        }
    }
    return 0;
}