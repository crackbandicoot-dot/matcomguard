#ifndef SCANNER_H
#define SCANNER_H

#include "common.h"
#include "baseline.h"
#include "discovery.h"

// Scanner configuration
typedef struct {
    double size_change_threshold;   // Suspicious growth threshold (e.g. 1000.0)
    int max_file_copies;            // Maximum allowed file copies
    double change_percentage_threshold; // Changed files percentage threshold (e.g. 0.1 = 10%)
    int scan_interval;              // Seconds between scans
} ScannerConfig;

// Scanner state
typedef struct {
    pthread_t thread_id;
    bool running;
    USBMonitor *monitor;
    ScannerConfig config;
} Scanner;

// Initialization and control
void scanner_init(Scanner *scanner, USBMonitor *monitor, ScannerConfig *config, float size_change_threshold, int max_file_copies, float change_percentage_threshold, int scan_interval);
void scanner_start(Scanner *scanner);
void scanner_stop(Scanner *scanner);

// Internal functions (declared for testing)
void scan_device(DeviceList *device, ScannerConfig *config);
int compare_with_baseline(Baseline *baseline, const char *mount_point, ScannerConfig *config);

#endif