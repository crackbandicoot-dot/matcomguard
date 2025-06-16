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

// Global variables for USB patrol
pthread_t usb_patrol_thread;
atomic_int usb_patrol_active = 0;
USBMonitor *global_monitor = NULL;
Scanner *global_scanner = NULL;
pthread_mutex_t cleanup_mutex = PTHREAD_MUTEX_INITIALIZER;

// Callback for USB events
void usb_event_callback(const char *action, const char *devnode, const char *mount_point, Baseline *baseline) {
    if (strcmp(action, "add") == 0) {
        printf(ROYAL_GUARD "USB device connected: %s at %s\n", devnode, mount_point);
        if (baseline) {
            printf(ROYAL_GUARD "Royal baseline established for %s\n", mount_point);
        }
    } else {
        printf(ROYAL_GUARD "USB device disconnected: %s from %s\n", devnode, mount_point);
    }
}

// Signal handler
void handle_signal(int sig) {
    if (sig == SIGUSR1) {
        printf(CASTLE "Royal command received to stop patrol\n");
    } else {
        printf(CASTLE "Signal %d received. Stopping...\n", sig);
    }
    
    atomic_store(&usb_patrol_active, 0);
}

void *usb_patrol_thread_function(void *arg) {
    // Signal handling setup
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    // Register signal handlers
    if (sigaction(SIGINT, &sa, NULL) == -1) perror("sigaction(SIGINT)");
    if (sigaction(SIGTERM, &sa, NULL) == -1) perror("sigaction(SIGTERM)");
    if (sigaction(SIGUSR1, &sa, NULL) == -1) perror("sigaction(SIGUSR1)");

    // Start USB monitoring
    USBMonitor *monitor = usb_monitor_start(usb_event_callback);
    if (!monitor) {
        fprintf(stderr, ROYAL_GUARD ALERT "Error starting USB monitor\n");
        return NULL;
    }
    global_monitor = monitor;

    // Scanner configuration
    ScannerConfig config = {
        .size_change_threshold = 500.0,
        .max_file_copies = 5,
        .change_percentage_threshold = 0.05,
        .scan_interval = 60
    };
    
    Scanner *scanner = malloc(sizeof(Scanner));
    if (!scanner) {
        fprintf(stderr, ROYAL_GUARD ALERT "Error creating scanner\n");
        usb_monitor_stop(monitor);
        return NULL;
    }
    
    scanner_init(scanner, monitor, &config);
    scanner_start(scanner);
    global_scanner = scanner;

    // Main patrol loop
    while (atomic_load(&usb_patrol_active)) {
        sleep(1);
    }

    // Cleanup
    scanner_stop(scanner);
    free(scanner);
    usb_monitor_stop(monitor);
    
    return NULL;
}

void start_usb_patrol() {
    if (atomic_load(&usb_patrol_active)) {
        printf(CASTLE "USB patrol is already active!\n");
        return;
    }
    
    atomic_store(&usb_patrol_active, 1);
    if (pthread_create(&usb_patrol_thread, NULL, usb_patrol_thread_function, NULL) != 0) {
        perror("Failed to start USB patrol");
        atomic_store(&usb_patrol_active, 0);
    } else {
        printf(CASTLE "Royal guards dispatched to patrol the files!\n");
    }
}

void stop_usb_patrol() {
    if (!atomic_load(&usb_patrol_active)) {
        printf(CASTLE "No active USB patrol to stop!\n");
        return;
    }
    
    atomic_store(&usb_patrol_active, 0);
    pthread_kill(usb_patrol_thread, SIGUSR1);
    pthread_join(usb_patrol_thread, NULL);
    printf(CASTLE "USB patrol recalled to the castle.\n");
}

int main() {
    // Welcome banner
    printf("\n");
    printf(COLOR_BLUE BOLD "╔══════════════════════════════════════════╗\n");
    printf(COLOR_BLUE BOLD "║                                          ║\n");
    printf(COLOR_BLUE BOLD "║ " COLOR_RESET "  Welcome to the Kingdom of FileGuard  " COLOR_BLUE BOLD "  ║\n");
    printf(COLOR_BLUE BOLD "║                                          ║\n");
    printf(COLOR_BLUE BOLD "╚══════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
    
    while (1) {
        printf(CASTLE "\n=== " UNDERLINE "Royal Command Menu" COLOR_RESET " ===\n");
        printf("1 - 🛡️  Patrol Kingdom's Files (USB devices)\n");
        printf("2 - ⚔️  Inspect Kingdom's Processes\n");
        printf("3 - 🏰  Guard Castle Walls (Open ports)\n");
        printf("4 - 🚨 General Mobilization! (Full inspection)\n");
        printf("5 - 🏳️  Recall USB Patrol (Stop scanning)\n");
        printf("6 - 👑 Leave the Kingdom (Exit)\n");
        printf("\nEnter your command: ");
        
        int option;
        if (scanf("%d", &option) != 1) {
            printf(CASTLE ALERT "Invalid input!\n");
            while (getchar() != '\n'); // Clear input buffer
            continue;
        }
        
        switch (option) {
        case 1:
            start_usb_patrol();
            break;
        case 2:
            printf(PROCESS_WATCH "\nInspecting kingdom's processes...\n");
            process_check();
            break;
        case 3:
            printf(PORT_GUARD "\nGuarding castle walls...\n");
            check_ports();
            break;
        case 4:
            printf(CASTLE "\nSound the alarm! General Mobilization!\n");
            if (atomic_load(&usb_patrol_active)) {
                printf(CASTLE "USB patrol already active\n");
            } else {
                start_usb_patrol();
            }
            process_check();
            check_ports();
            break;
        case 5:
            stop_usb_patrol();
            break;
        case 6:
            if (atomic_load(&usb_patrol_active)) {
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
            while (getchar() != '\n'); // Clear input buffer
            break;
        }
    }
    return 0;
}