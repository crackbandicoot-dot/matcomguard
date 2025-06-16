#ifndef DISCOVERY_H
#define DISCOVERY_H

#include "common.h"
#include "baseline.h"

// Monitor structure
typedef struct USBMonitor {
    pthread_t thread_id;
    bool running;
    struct udev *udev;
    struct udev_monitor *mon;
    int stop_fd[2];  // Stop control pipe
    pthread_mutex_t mutex;
    DeviceList *device_list;
    void (*event_callback)(const char *action, const char *devnode, const char *mount_point, Baseline *baseline);
} USBMonitor;

void* usb_monitor_thread(void *arg);
USBMonitor* usb_monitor_start(void (*callback)(const char *, const char *, const char *, Baseline *));
void usb_monitor_stop(USBMonitor *monitor);

#endif