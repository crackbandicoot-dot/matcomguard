#ifndef MONITOR_H
#define MONITOR_H

#include "common.h"
#include "discovery.h"
#include "scanner.h"

// Custom signal to stop USB patrol
#define USB_PATROL_STOP_SIGNAL SIGUSR1

// Function declarations
void usb_event_callback(const char *action, const char *devnode, const char *mount_point, Baseline *baseline);
void handle_signal(int sig);

#endif