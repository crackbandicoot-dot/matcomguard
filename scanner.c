#include "scanner.h"
#include "discovery.h"
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <math.h>
#include <pthread.h>
#include <fnmatch.h>

// Exclusion list (system files/dirs)
static const char *excluded_patterns[] = {
    "System Volume Information/*",
    ".*",  // Hidden files
    "*.tmp",
    "*.temp",
    "*.swp",
    "*~",
    NULL
};

// Check if path should be excluded
static int is_excluded(const char *path) {
    for (int i = 0; excluded_patterns[i] != NULL; i++) {
        if (fnmatch(excluded_patterns[i], path, FNM_PATHNAME) == 0) {
            return 1;
        }
    }
    return 0;
}

// Check if path exists
static int path_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

// Optimized hash calculation
static int compute_sha256(const char *file_path, 
                         unsigned char *output) {
    FILE *file = fopen(file_path, "rb");
    if (!file) return -1;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char buffer[65536];  // Large buffer for better performance
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file))) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }

    SHA256_Final(output, &sha256);
    fclose(file);
    return 0;
}

// Detect suspicious file changes
static void check_suspicious_changes(const BaselineEntry *baseline_entry, 
                                    const FileMetadata *current_meta, 
                                    const char *full_path,
                                    ScannerConfig *config) {
    // 1. Unusual size growth
    if (baseline_entry->metadata.size > 0) {
        double growth_ratio = (double)current_meta->size / baseline_entry->metadata.size;
        if (growth_ratio > config->size_change_threshold) {
            printf(ROYAL_GUARD SUSPICIOUS "%s bloated from %ld bytes to %ld bytes (%.1fx)\n",
                   full_path, baseline_entry->metadata.size, current_meta->size, growth_ratio);
        }
    }

    // 2. Permissions changed to 777
    if ((current_meta->permissions & 0777) == 0777) {
        printf(ROYAL_GUARD SUSPICIOUS "%s has dangerous 777 permissions (anyone can modify!)\n", full_path);
    }

    // 3. Ownership changed
    if (baseline_entry->metadata.uid != current_meta->uid ||
        baseline_entry->metadata.gid != current_meta->gid) {
        printf(ROYAL_GUARD SUSPICIOUS "%s changed ownership from %d:%d to %d:%d\n",
               full_path, baseline_entry->metadata.uid, baseline_entry->metadata.gid,
               current_meta->uid, current_meta->gid);
    }
}

// Compare current file with baseline entry
static void compare_file(const BaselineEntry *entry, 
                         const char *mount_point, 
                         ScannerConfig *config,
                         int *changed_count) {
    char full_path[4096];
    snprintf(full_path, sizeof(full_path), "%s/%s", mount_point, entry->path);
    
    // Check if excluded
    if (is_excluded(entry->path)) {
        return;
    }

    struct stat stat_buf;
    if (lstat(full_path, &stat_buf) != 0) {
        // File deleted
        printf(ROYAL_GUARD DELETED "%s\n", entry->path);
        (*changed_count)++;
        return;
    }

    // Get current metadata
    FileMetadata current_meta = {
        .size = stat_buf.st_size,
        .permissions = stat_buf.st_mode,
        .last_access = stat_buf.st_atime,
        .last_modification = stat_buf.st_mtime,
        .last_status_change = stat_buf.st_ctime,
        .uid = stat_buf.st_uid,
        .gid = stat_buf.st_gid
    };

    int content_changed = 0;
    int metadata_changed = 0;

    // Check metadata changes (ignore access timestamps)
    if (entry->metadata.size != current_meta.size) metadata_changed = 1;
    if (entry->metadata.permissions != current_meta.permissions) metadata_changed = 1;
    if (entry->metadata.uid != current_meta.uid) metadata_changed = 1;
    if (entry->metadata.gid != current_meta.gid) metadata_changed = 1;
    
    // Ignore access timestamp-only changes
    if (metadata_changed && 
        entry->metadata.size == current_meta.size &&
        entry->metadata.permissions == current_meta.permissions &&
        entry->metadata.uid == current_meta.uid &&
        entry->metadata.gid == current_meta.gid) {
        metadata_changed = 0;
    }

    // Check content changes (regular files only)
    if (S_ISREG(stat_buf.st_mode) && 
        entry->metadata.size != current_meta.size) {
        unsigned char current_hash[SHA256_DIGEST_LENGTH];
        if (compute_sha256(full_path, current_hash) == 0) {
            if (memcmp(entry->metadata.sha256, current_hash, SHA256_DIGEST_LENGTH) != 0) {
                content_changed = 1;
            }
        }
    } else if (S_ISREG(stat_buf.st_mode) && 
               entry->metadata.size == current_meta.size) {
        // If size is same, assume content unchanged
        content_changed = 0;
    }

    // Report changes
    if (metadata_changed || content_changed) {
        if (metadata_changed) {
            printf(ROYAL_GUARD MODIFIED "%s\n", entry->path);
            
            // Report specific permission and ownership changes
            if (entry->metadata.permissions != current_meta.permissions) {
                printf(ROYAL_GUARD INFO "Permission change: %04o → %04o\n", 
                       entry->metadata.permissions & 07777,
                       current_meta.permissions & 07777);
            }
            
            if (entry->metadata.uid != current_meta.uid) {
                printf(ROYAL_GUARD INFO "UID change: %d → %d\n",
                       entry->metadata.uid, current_meta.uid);
            }
            
            if (entry->metadata.gid != current_meta.gid) {
                printf(ROYAL_GUARD INFO "GID change: %d → %d\n",
                       entry->metadata.gid, current_meta.gid);
            }
            
            check_suspicious_changes(entry, &current_meta, full_path, config);
        }
        if (content_changed) {
            printf(ROYAL_GUARD ALERT "Content changed: %s\n", entry->path);
        }
        (*changed_count)++;
    }
}

// Recursive function to detect new files
static void detect_new_files_recursive(const char *base_path, 
                                      const char *current_path,
                                      Baseline *baseline, 
                                      ScannerConfig *config,
                                      int *changed_count) {
    char full_dir_path[4096];
    snprintf(full_dir_path, sizeof(full_dir_path), "%s/%s", base_path, current_path);
    
    DIR *dir = opendir(full_dir_path);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) 
            continue;

        char relative_path[4096];
        if (strlen(current_path) == 0) {
            snprintf(relative_path, sizeof(relative_path), "%s", entry->d_name);
        } else {
            snprintf(relative_path, sizeof(relative_path), "%s/%s", current_path, entry->d_name);
        }
        
        // Check if excluded
        if (is_excluded(relative_path)) {
            continue;
        }

        char full_entry_path[4096];
        snprintf(full_entry_path, sizeof(full_entry_path), "%s/%s", base_path, relative_path);
        
        struct stat stat_buf;
        if (lstat(full_entry_path, &stat_buf) != 0) continue;

        // Search in baseline
        int found = 0;
        BaselineEntry *bl_entry = baseline->entries;
        while (bl_entry) {
            if (strcmp(bl_entry->path, relative_path) == 0) {
                found = 1;
                break;
            }
            bl_entry = bl_entry->next;
        }

        // If not in baseline, it's new
        if (!found) {
            printf(ROYAL_GUARD NEW_FILE "%s\n", relative_path);
            (*changed_count)++;
        }

        // Recursion for directories
        if (S_ISDIR(stat_buf.st_mode)) {
            detect_new_files_recursive(base_path, relative_path, baseline, config, changed_count);
        }
    }
    closedir(dir);
}

// Scan a specific device
void scan_device(DeviceList *device, ScannerConfig *config) {
    if (!device || !device->mount_point || !device->baseline) return;
    
    // Check if device is still mounted
    if (!path_exists(device->mount_point)) {
        printf(ROYAL_GUARD ALERT "Device not found: %s\n", device->mount_point);
        return;
    }

    int changed_files = 0;
    int total_files = device->baseline->file_count;

    // 1. Detect deleted and modified files
    BaselineEntry *entry = device->baseline->entries;
    while (entry) {
        compare_file(entry, device->mount_point, config, &changed_files);
        entry = entry->next;
    }

    // 2. Detect new files (recursively)
    detect_new_files_recursive(device->mount_point, "", device->baseline, config, &changed_files);

    // Check change threshold
    if (total_files > 0) {
        double change_percentage = (double)changed_files / total_files;
        if (change_percentage > config->change_percentage_threshold) {
            printf(ROYAL_GUARD ALERT "Treachery in %s! %.0f%% of files altered 🔥\n", 
                   device->mount_point, change_percentage * 100);
        }
    }
}

// Main scanner thread function
static void *scanner_thread(void *arg) {
    Scanner *scanner = (Scanner *)arg;
    const int scan_interval = scanner->config.scan_interval;
    int time_waited = 0;
    
    while (scanner->running) {
        // Sleep in short intervals for quick shutdown
        while (time_waited < scan_interval && scanner->running) {
            sleep(1);
            time_waited++;
        }
        
        if (!scanner->running) {
            break;
        }
        
        // Reset counter
        time_waited = 0;
        
        // Lock access to device list
        pthread_mutex_lock(&scanner->monitor->mutex);
        
        DeviceList *current = scanner->monitor->device_list;
        while (current) {
            scan_device(current, &scanner->config);
            current = current->next;
        }
        
        pthread_mutex_unlock(&scanner->monitor->mutex);
    }
    return NULL;
}

void scanner_init(Scanner *scanner, USBMonitor *monitor, ScannerConfig *config) {
    memset(scanner, 0, sizeof(Scanner));
    scanner->monitor = monitor;
    if (config) {
        scanner->config = *config;
    } else {
        // Default values
        scanner->config.size_change_threshold = 1000.0;  // 1000x growth
        scanner->config.max_file_copies = 3;             // Max 3 copies
        scanner->config.change_percentage_threshold = 0.1; // 10% changes
        scanner->config.scan_interval = 30;              // 30 seconds
    }
}

void scanner_start(Scanner *scanner) {
    if (scanner->running) return;
    
    scanner->running = true;
    pthread_create(&scanner->thread_id, NULL, scanner_thread, scanner);
}

void scanner_stop(Scanner *scanner) {
    if (!scanner->running) return;
    
    scanner->running = false;
    pthread_join(scanner->thread_id, NULL);
}