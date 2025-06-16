#include "discovery.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <openssl/sha.h>

// Function to start USB monitoring
USBMonitor *usb_monitor_start(void (*callback)(const char *, const char *, const char *, Baseline *)) {
    USBMonitor *monitor = malloc(sizeof(USBMonitor));
    if (!monitor)
        return NULL;

    memset(monitor, 0, sizeof(USBMonitor));

    // Create stop control pipe
    if (pipe(monitor->stop_fd) == -1) {
        perror("pipe");
        free(monitor);
        return NULL;
    }

    // Initialize udev
    monitor->udev = udev_new();
    if (!monitor->udev) {
        fprintf(stderr, ROYAL_GUARD ALERT "Failed to create udev context\n");
        close(monitor->stop_fd[0]);
        close(monitor->stop_fd[1]);
        free(monitor);
        return NULL;
    }

    // Create monitor
    monitor->mon = udev_monitor_new_from_netlink(monitor->udev, "udev");
    if (!monitor->mon) {
        fprintf(stderr, ROYAL_GUARD ALERT "Failed to create monitor\n");
        udev_unref(monitor->udev);
        close(monitor->stop_fd[0]);
        close(monitor->stop_fd[1]);
        free(monitor);
        return NULL;
    }

    // Configure filters
    udev_monitor_filter_add_match_subsystem_devtype(monitor->mon, "block", NULL);
    udev_monitor_enable_receiving(monitor->mon);

    // Initialize mutex
    pthread_mutex_init(&monitor->mutex, NULL);

    // Configure callback
    monitor->event_callback = callback;

    // Start thread
    monitor->running = true;
    if (pthread_create(&monitor->thread_id, NULL, usb_monitor_thread, monitor) != 0) {
        perror("pthread_create");
        usb_monitor_stop(monitor);
        return NULL;
    }

    return monitor;
}

// Stop USB monitoring
void usb_monitor_stop(USBMonitor *monitor) {
    if (!monitor)
        return;

    if (monitor->running) {
        // Signal thread to stop
        monitor->running = false;
        char stop_signal = 's';
        write(monitor->stop_fd[1], &stop_signal, 1);

        // Wait for thread to finish
        pthread_join(monitor->thread_id, NULL);
    }

    // Free resources
    if (monitor->mon)
        udev_monitor_unref(monitor->mon);
    if (monitor->udev)
        udev_unref(monitor->udev);

    close(monitor->stop_fd[0]);
    close(monitor->stop_fd[1]);

    // Free device list
    DeviceList *cur = monitor->device_list;
    while (cur) {
        DeviceList *next = cur->next;
        free(cur->devnode);
        if (cur->mount_point)
            free(cur->mount_point);
        if (cur->baseline)
            baseline_free(cur->baseline);
        free(cur);
        cur = next;
    }

    pthread_mutex_destroy(&monitor->mutex);
    free(monitor);
}

// Find mount point
char *find_mount_point(const char *device_path) {
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp)
        return NULL;

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char device[256], mount_point[256];
        if (sscanf(line, "%255s %255s", device, mount_point) == 2) {
            if (strcmp(device, device_path) == 0) {
                fclose(fp);
                return strdup(mount_point);
            }
        }
    }
    fclose(fp);
    return NULL;
}

// Decode octal escape sequences
char *decode_mount_point(const char *input) {
    if (!input)
        return NULL;

    size_t len = strlen(input);
    char *output = malloc(len + 1);
    if (!output)
        return NULL;

    char *dest = output;
    const char *src = input;

    while (*src) {
        if (*src == '\\' && src[1] == '0' && isdigit(src[2]) &&
            isdigit(src[3]) && isdigit(src[4])) {
            // Decode octal sequence (3 digits)
            int octal = (src[2] - '0') * 64 + (src[3] - '0') * 8 + (src[4] - '0');
            *dest++ = (char)octal;
            src += 5;
        } else {
            *dest++ = *src++;
        }
    }
    *dest = '\0';

    return output;
}

// Check if device is USB
bool is_usb_device(struct udev_device *dev) {
    const char *id_bus = udev_device_get_property_value(dev, "ID_BUS");
    return id_bus && strcmp(id_bus, "usb") == 0;
}

// Check if partition is mountable
bool is_mountable_partition(struct udev_device *dev) {
    // Check if partition
    const char *devtype = udev_device_get_devtype(dev);
    if (!devtype || strcmp(devtype, "partition") != 0) {
        return false;
    }

    // Check filesystem type
    const char *fs_type = udev_device_get_property_value(dev, "ID_FS_TYPE");
    if (!fs_type || fs_type[0] == '\0') {
        return false;
    }

    // Ignore special devices
    if (strcmp(fs_type, "swap") == 0 || strcmp(fs_type, "LVM2_member") == 0) {
        return false;
    }

    return true;
}

// Main monitor thread
void *usb_monitor_thread(void *arg) {
    USBMonitor *monitor = (USBMonitor *)arg;

    int udev_fd = udev_monitor_get_fd(monitor->mon);

    while (monitor->running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(udev_fd, &fds);
        FD_SET(monitor->stop_fd[0], &fds); // Control pipe

        int max_fd = (udev_fd > monitor->stop_fd[0]) ? udev_fd : monitor->stop_fd[0];

        // Wait for events with timeout
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        if (select(max_fd + 1, &fds, NULL, NULL, &tv) < 0) {
            perror("select");
            break;
        }

        // Check stop signal
        if (FD_ISSET(monitor->stop_fd[0], &fds)) {
            char buf;
            read(monitor->stop_fd[0], &buf, 1);
            break;
        }

        // Process udev events
        if (FD_ISSET(udev_fd, &fds)) {
            struct udev_device *dev = udev_monitor_receive_device(monitor->mon);
            if (!dev)
                continue;

            const char *action = udev_device_get_action(dev);
            const char *devnode = udev_device_get_devnode(dev);

            if (!action || !devnode) {
                udev_device_unref(dev);
                continue;
            }

            // Filter only mountable USB partitions
            if (is_usb_device(dev) && is_mountable_partition(dev)) {
                if (strcmp(action, "add") == 0) {
                    // Wait for mounting
                    char *mount_point = NULL;
                    int attempts = 0;
                    const int max_attempts = 5;

                    while (monitor->running && attempts < max_attempts && !mount_point) {
                        sleep(1);
                        mount_point = find_mount_point(devnode);
                        attempts++;
                    }

                    char *decoded_mount = NULL;
                    if (mount_point) {
                        decoded_mount = decode_mount_point(mount_point);
                        free(mount_point);
                    }

                    // Create baseline
                    Baseline *baseline = NULL;
                    if (decoded_mount) {
                        baseline = baseline_create(decoded_mount);
                        if (!baseline) {
                            fprintf(stderr, ROYAL_GUARD ALERT "Error creating baseline for %s\n", decoded_mount);
                        }
                    }

                    // Add to list (with mutex)
                    pthread_mutex_lock(&monitor->mutex);

                    DeviceList *new_dev = malloc(sizeof(DeviceList));
                    if (new_dev) {
                        new_dev->devnode = strdup(devnode);
                        new_dev->mount_point = decoded_mount ? strdup(decoded_mount) : NULL;
                        new_dev->baseline = baseline;
                        new_dev->next = monitor->device_list;
                        monitor->device_list = new_dev;
                    } else {
                        if (baseline) baseline_free(baseline);
                        if (decoded_mount) free(decoded_mount);
                    }

                    pthread_mutex_unlock(&monitor->mutex);

                    // Call callback if configured
                    if (monitor->event_callback) {
                        monitor->event_callback("add", devnode,
                                               decoded_mount ? decoded_mount : "UNKNOWN",
                                               baseline);
                    }
                    
                    if (decoded_mount) free(decoded_mount);
                } else if (strcmp(action, "remove") == 0) {
                    char *saved_mount = NULL;
                    Baseline *baseline_to_free = NULL;

                    // Search list (with mutex)
                    pthread_mutex_lock(&monitor->mutex);

                    DeviceList **cur = &monitor->device_list;
                    while (*cur) {
                        DeviceList *entry = *cur;
                        if (strcmp(entry->devnode, devnode) == 0) {
                            *cur = entry->next;
                            saved_mount = entry->mount_point ? strdup(entry->mount_point) : NULL;
                            baseline_to_free = entry->baseline;

                            free(entry->devnode);
                            if (entry->mount_point)
                                free(entry->mount_point);
                            free(entry);
                            break;
                        }
                        cur = &(*cur)->next;
                    }

                    pthread_mutex_unlock(&monitor->mutex);

                    // Call callback if configured
                    if (monitor->event_callback) {
                        monitor->event_callback("remove", devnode,
                                               saved_mount ? saved_mount : "UNKNOWN",
                                               NULL);
                    }

                    // Free resources outside mutex
                    if (saved_mount)
                        free(saved_mount);
                    if (baseline_to_free)
                        baseline_free(baseline_to_free);
                }
            }
            udev_device_unref(dev);
        }
    }
    return NULL;
}