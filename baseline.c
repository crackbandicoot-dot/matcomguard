#include "baseline.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <openssl/sha.h>

// SHA-256 calculation
static int compute_sha256(const char *file_path, unsigned char *output)
{
    FILE *file = fopen(file_path, "rb");
    if (!file)
        return -1;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char buffer[65536];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)))
    {
        SHA256_Update(&sha256, buffer, bytes_read);
    }

    SHA256_Final(output, &sha256);
    fclose(file);
    return 0;
}

// Recursive directory scanning
static void scan_directory(const char *base_path, const char *current_path,
                           BaselineEntry **entries, int *file_count)
{
    char full_path[4096];
    if (snprintf(full_path, sizeof(full_path), "%s/%s", base_path, current_path) >= (int)sizeof(full_path))
    {
        return;
    }

    DIR *dir = opendir(full_path);
    if (!dir)
        return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char new_path[4096];
        const char *separator = (current_path[0] == '\0') ? "" : "/";
        if (snprintf(new_path, sizeof(new_path), "%s%s%s",
                     current_path, separator, entry->d_name) >= (int)sizeof(new_path))
            continue;

        char entry_full_path[4096];
        if (snprintf(entry_full_path, sizeof(entry_full_path), "%s/%s", base_path, new_path) >= (int)sizeof(entry_full_path))
            continue;

        struct stat stat_buf;
        if (lstat(entry_full_path, &stat_buf) != 0)
            continue;

        // Process file/directory
        BaselineEntry *new_entry = malloc(sizeof(BaselineEntry));
        if (!new_entry)
            continue;

        new_entry->path = strdup(new_path);
        if (!new_entry->path)
        {
            free(new_entry);
            continue;
        }

        char *ext = strrchr(entry->d_name, '.');
        if (ext)
        {
            new_entry->basename = strndup(entry->d_name, ext - entry->d_name);
        }
        else
        {
            new_entry->basename = strdup(entry->d_name);
        }

        // Fill metadata
        FileMetadata *meta = &new_entry->metadata;
        meta->size = stat_buf.st_size;
        meta->permissions = stat_buf.st_mode;
        meta->last_access = stat_buf.st_atime;
        meta->last_modification = stat_buf.st_mtime;
        meta->last_status_change = stat_buf.st_ctime;
        meta->uid = stat_buf.st_uid;
        meta->gid = stat_buf.st_gid;

        // Calculate hash for regular files
        if (S_ISREG(stat_buf.st_mode))
        {
            if (compute_sha256(entry_full_path, meta->sha256) != 0)
            {
                memset(meta->sha256, 0, SHA256_DIGEST_LENGTH);
            }
            // Increment file count
            (*file_count)++;
        }
        else
        {
            memset(meta->sha256, 0, SHA256_DIGEST_LENGTH);
        }

        // Add to list
        new_entry->next = *entries;
        *entries = new_entry;

        // Recursion for directories
        if (S_ISDIR(stat_buf.st_mode))
        {
            scan_directory(base_path, new_path, entries, file_count);
        }
    }
    closedir(dir);
}

Baseline *baseline_create(const char *mount_point)
{
    Baseline *baseline = malloc(sizeof(Baseline));
    if (!baseline)
        return NULL;

    baseline->mount_point = strdup(mount_point);
    if (!baseline->mount_point)
    {
        free(baseline);
        return NULL;
    }

    baseline->entries = NULL;
    baseline->file_count = 0;

    // Start scan with file count reference
    scan_directory(mount_point, "", &baseline->entries, &baseline->file_count);

    return baseline;
}

void baseline_free(Baseline *baseline)
{
    if (!baseline)
        return;

    BaselineEntry *entry = baseline->entries;
    while (entry)
    {
        BaselineEntry *next = entry->next;
        free(entry->path);
        free(entry);
        entry = next;
    }

    free(baseline->mount_point);
    free(baseline);
}

void baseline_print(Baseline *baseline)
{
    if (!baseline)
    {
        printf("Baseline: NULL\n");
        return;
    }

    printf("\n=== Baseline for %s ===\n", baseline->mount_point);
    printf("Total files: %d\n", baseline->file_count);
    printf("%-50s %-10s %-10s %-10s %-16s %s\n",
           "Path", "Size", "Perms", "UID", "GID", "Hash (SHA-256)");
    printf("---------------------------------------------------------------------------------------------------\n");

    BaselineEntry *entry = baseline->entries;
    int count = 0;

    while (entry)
    {
        char perms[11];
        snprintf(perms, sizeof(perms), "%04o", entry->metadata.permissions & 07777);

        char hash_preview[9];
        if (entry->metadata.sha256[0] == 0)
        {
            strcpy(hash_preview, "N/A");
        }
        else
        {
            for (int i = 0; i < 8; i++)
            {
                snprintf(hash_preview + i * 2, 3, "%02x", entry->metadata.sha256[i]);
            }
            hash_preview[8] = '\0';
        }

        printf("%-50s %-10ld %-10s %-10d %-10d %s\n",
               entry->path,
               entry->metadata.size,
               perms,
               entry->metadata.uid,
               entry->metadata.gid,
               hash_preview);

        entry = entry->next;
        count++;
    }

    printf("---------------------------------------------------------------------------------------------------\n");
    printf("Total entries: %d\n\n", count);
}