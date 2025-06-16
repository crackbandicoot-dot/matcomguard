#ifndef BASELINE_H
#define BASELINE_H

#include <openssl/sha.h>
#include <sys/stat.h>

// File metadata
typedef struct {
    unsigned char sha256[SHA256_DIGEST_LENGTH];
    off_t size;
    mode_t permissions;
    time_t last_access;
    time_t last_modification;
    time_t last_status_change;
    uid_t uid;
    gid_t gid;
} FileMetadata;

// Baseline entry (individual file)
typedef struct BaselineEntry {
    char *path;
    FileMetadata metadata;
    struct BaselineEntry *next;
} BaselineEntry;

// Complete device baseline
typedef struct Baseline {
    char *mount_point;
    BaselineEntry *entries;
    int file_count;
} Baseline;

Baseline *baseline_create(const char *mount_point);
void baseline_free(Baseline *baseline);
void baseline_print(Baseline *baseline);

#endif