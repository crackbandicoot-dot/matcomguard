#ifndef COMMON_H
#define COMMON_H

#include <libudev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <sys/select.h>

// Forward declaration for Baseline
struct Baseline;

// Connected devices structure
typedef struct DeviceList {
    char *devnode;
    char *mount_point;
    struct Baseline *baseline;
    struct DeviceList *next;
} DeviceList;

// ============ CONSOLE STYLES ============
#define COLOR_RESET   "\x1B[0m"
#define COLOR_RED     "\x1B[31m"
#define COLOR_GREEN   "\x1B[32m"
#define COLOR_YELLOW  "\x1B[33m"
#define COLOR_BLUE    "\x1B[34m"
#define COLOR_MAGENTA "\x1B[35m"
#define COLOR_CYAN    "\x1B[36m"
#define COLOR_WHITE   "\x1B[37m"
#define BOLD          "\x1B[1m"
#define UNDERLINE     "\x1B[4m"

// Module prefixes
#define ROYAL_GUARD   "🛡️ " COLOR_CYAN "[Royal Guard] " COLOR_RESET
#define PROCESS_WATCH "⚔️ " COLOR_MAGENTA "[Process Watch] " COLOR_RESET
#define PORT_GUARD    "🏰 " COLOR_YELLOW "[Port Guard] " COLOR_RESET
#define CASTLE        "🏯 " COLOR_GREEN "[Castle] " COLOR_RESET

// Status indicators
#define ALERT         COLOR_RED "⚠️ ALERT! " COLOR_RESET
#define SUSPICIOUS    COLOR_YELLOW "🔍 SUSPICIOUS! " COLOR_RESET
#define INFO          COLOR_BLUE "ℹ️  " COLOR_RESET
#define DELETED       COLOR_MAGENTA "🗑️ DELETED! " COLOR_RESET
#define MODIFIED      COLOR_YELLOW "✏️ MODIFIED! " COLOR_RESET
#define NEW_FILE      COLOR_GREEN "📄 NEW! " COLOR_RESET

#endif