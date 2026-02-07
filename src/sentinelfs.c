/*
 * SentinelFS - Phase III/IV Implementation
 *
 * FUSE-based ransomware detection system using Shannon entropy analysis
 * and LibMagic deep content inspection.
 *
 * Research paper: "An Iterative Design Study in the Performance, Security,
 * and Efficiency of User-Space Ransomware Detection"
 *
 * Author: Sameer Ahmed
 * Institution: National University of Sciences and Technology (NUST)
 * Department of Computer Science, Islamabad, Pakistan
 *
 * Compile: gcc -Wall -O2 sentinelfs.c `pkg-config fuse3 --cflags --libs` -lmagic -lm -o sentinelfs
 * Usage: ./sentinelfs <storage_path> <mount_point>
 */

#define FUSE_USE_VERSION 31

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <dirent.h>
#include <limits.h>
#include <math.h>
#include <magic.h>
#include <stddef.h>

// Config
#define ENTROPY_THRESHOLD 7.5     // Anything above this is probably encrypted
#define JIT_BACKUP_MAX_SIZE (50 * 1024 * 1024)  // 50MB limit to avoid latency spikes
#define MAX_PATH 4096
#define BACKUP_DIR ".sentinelfs_backups"

// Global context
typedef struct {
    char *storage_path;
    char *backup_path;
    magic_t magic_cookie;  // LibMagic handle for deep file inspection
} sentinelfs_context_t;

static sentinelfs_context_t *global_ctx = NULL;

// Stats for debugging
struct {
    unsigned long total_writes;
    unsigned long blocked_writes;
    unsigned long backups_created;
} stats = {0, 0, 0};

// Translate FUSE path to actual storage path
static void translate_path(const char *path, char *full_path) {
    snprintf(full_path, MAX_PATH, "%s%s", global_ctx->storage_path, path);
}

// Generate backup filename with timestamp
static void get_backup_path(const char *original_path, char *backup_path) {
    char filename[256];
    const char *basename = strrchr(original_path, '/');
    basename = basename ? basename + 1 : original_path;

    struct timeval tv;
    gettimeofday(&tv, NULL);

    snprintf(backup_path, MAX_PATH, "%s/%s.%ld.backup",
             global_ctx->backup_path, basename, tv.tv_sec);
}

// Shannon entropy: H(X) = -Σ P(x) * log₂(P(x))
// Returns 0-8, encrypted data is usually ~7.9-8.0
static double calculate_entropy(const unsigned char *buffer, size_t len) {
    if (len == 0) return 0.0;

    unsigned long counts[256] = {0};  // Stack allocated for speed

    // Count byte frequencies
    for (size_t i = 0; i < len; i++) {
        counts[buffer[i]]++;
    }

    // Calculate entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] > 0) {
            double probability = (double)counts[i] / len;
            entropy -= probability * log2(probability);
        }
    }

    return entropy;
}

// LibMagic deep file inspection - checks actual file structure, not just header bytes
// Fixes the Phase I/II vulnerability where ransomware could fake headers
static int is_whitelisted_file(const unsigned char *buffer, size_t len) {
    const char *mime = magic_buffer(global_ctx->magic_cookie, buffer, len);

    if (!mime) {
        fprintf(stderr, "[SentinelFS] LibMagic error: %s\n",
                magic_error(global_ctx->magic_cookie));
        return 0;
    }

    // Whitelist known safe types
    const char *safe_types[] = {
        "text/",
        "application/pdf",
        "application/x-executable",
        "application/x-sharedlib",
        "application/x-shellscript",
        NULL
    };

    for (int i = 0; safe_types[i] != NULL; i++) {
        if (strstr(mime, safe_types[i]) == mime) {
            return 1;  // Whitelisted
        }
    }

    // Also check for shebang (fixes false positives on shell wrappers like snap/snapctl)
    if (len >= 2 && buffer[0] == '#' && buffer[1] == '!') {
        return 1;
    }

    return 0;
}

// JIT backup - only backs up on first write, not on open
// Saves 90% storage on read-heavy workloads
static int create_jit_backup(const char *source_path) {
    struct stat st;
    if (stat(source_path, &st) == -1) {
        return -1;
    }

    // 50MB limit to avoid noticeable latency
    if (st.st_size > JIT_BACKUP_MAX_SIZE) {
        fprintf(stderr, "[SentinelFS] Skipping backup (file >50MB): %s\n", source_path);
        return 0;
    }

    // Generate backup filename
    char backup_path[MAX_PATH];
    get_backup_path(source_path, backup_path);

    // Copy file
    FILE *src = fopen(source_path, "rb");
    if (!src) return -1;

    FILE *dst = fopen(backup_path, "wb");
    if (!dst) {
        fclose(src);
        return -1;
    }

    char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        fwrite(buffer, 1, bytes, dst);
    }

    fclose(src);
    fclose(dst);

    stats.backups_created++;
    fprintf(stderr, "[SentinelFS] JIT Backup created: %s -> %s\n", source_path, backup_path);

    return 0;
}

// Main detection logic: LibMagic first, then entropy check
static int detect_ransomware(const unsigned char *buffer, size_t len) {
    stats.total_writes++;

    // Step 1: Deep file inspection
    if (is_whitelisted_file(buffer, len)) {
        return 0;  // Safe, allowed
    }

    // Step 2: Entropy check
    double entropy = calculate_entropy(buffer, len);

    if (entropy > ENTROPY_THRESHOLD) {
        stats.blocked_writes++;
        fprintf(stderr, "[SentinelFS] ⚠️  RANSOMWARE DETECTED! Entropy: %.2f (threshold: %.1f)\n",
                entropy, ENTROPY_THRESHOLD);
        return -EIO;  // Block the write
    }

    return 0;  // Allowed
}

// FUSE operations

static int sentinelfs_getattr(const char *path, struct stat *stbuf,
                              struct fuse_file_info *fi) {
    (void) fi;
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    if (lstat(full_path, stbuf) == -1) {
        return -errno;
    }

    return 0;
}

static int sentinelfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                              off_t offset, struct fuse_file_info *fi,
                              enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;
    (void) flags;

    char full_path[MAX_PATH];
    translate_path(path, full_path);

    DIR *dp = opendir(full_path);
    if (!dp) {
        return -errno;
    }

    struct dirent *de;
    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        if (filler(buf, de->d_name, &st, 0, 0)) {
            break;
        }
    }

    closedir(dp);
    return 0;
}

static int sentinelfs_open(const char *path, struct fuse_file_info *fi) {
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    int fd = open(full_path, fi->flags);
    if (fd == -1) {
        return -errno;
    }

    close(fd);
    return 0;
}

static int sentinelfs_read(const char *path, char *buf, size_t size, off_t offset,
                           struct fuse_file_info *fi) {
    (void) fi;
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    int fd = open(full_path, O_RDONLY);
    if (fd == -1) {
        return -errno;
    }

    int res = pread(fd, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }

    close(fd);
    return res;
}

/**
 * Critical Write Interception (The Detection Point)
 *
 * This is where SentinelFS enforces protection. Every write() syscall
 * passes through this function, creating the "Context Switch Barrier"
 * that causes the 11.4x performance overhead quantified in the paper.
 */
static int sentinelfs_write(const char *path, const char *buf, size_t size,
                            off_t offset, struct fuse_file_info *fi) {
    (void) fi;
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    /* Phase IV: JIT Backup (only on first write, offset == 0 heuristic) */
    if (offset == 0) {
        struct stat st;
        if (stat(full_path, &st) == 0 && st.st_size > 0) {
            /* File exists and has content, backup before overwriting */
            create_jit_backup(full_path);
        }
    }

    /* Phase III/IV: Ransomware Detection */
    int detection_result = detect_ransomware((const unsigned char *)buf, size);
    if (detection_result != 0) {
        return detection_result;  /* BLOCK write, return -EIO to application */
    }

    /* Write is ALLOWED, pass through to underlying filesystem */
    int fd = open(full_path, O_WRONLY);
    if (fd == -1) {
        return -errno;
    }

    int res = pwrite(fd, buf, size, offset);
    if (res == -1) {
        res = -errno;
    }

    close(fd);
    return res;
}

static int sentinelfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) fi;
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    int fd = creat(full_path, mode);
    if (fd == -1) {
        return -errno;
    }

    close(fd);
    return 0;
}

static int sentinelfs_mkdir(const char *path, mode_t mode) {
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    if (mkdir(full_path, mode) == -1) {
        return -errno;
    }

    return 0;
}

static int sentinelfs_unlink(const char *path) {
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    if (unlink(full_path) == -1) {
        return -errno;
    }

    return 0;
}

static int sentinelfs_rmdir(const char *path) {
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    if (rmdir(full_path) == -1) {
        return -errno;
    }

    return 0;
}

static int sentinelfs_rename(const char *from, const char *to, unsigned int flags) {
    (void) flags;
    char full_from[MAX_PATH];
    char full_to[MAX_PATH];

    translate_path(from, full_from);
    translate_path(to, full_to);

    if (rename(full_from, full_to) == -1) {
        return -errno;
    }

    return 0;
}

static int sentinelfs_chmod(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) fi;
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    if (chmod(full_path, mode) == -1) {
        return -errno;
    }

    return 0;
}

static int sentinelfs_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi) {
    (void) fi;
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    if (chown(full_path, uid, gid) == -1) {
        return -errno;
    }

    return 0;
}

static int sentinelfs_truncate(const char *path, off_t size, struct fuse_file_info *fi) {
    (void) fi;
    char full_path[MAX_PATH];
    translate_path(path, full_path);

    if (truncate(full_path, size) == -1) {
        return -errno;
    }

    return 0;
}

// Init: setup LibMagic
static void *sentinelfs_init(struct fuse_conn_info *conn, struct fuse_config *cfg) {
    (void) conn;
    cfg->kernel_cache = 0;  // No caching for security

    global_ctx->magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (!global_ctx->magic_cookie) {
        fprintf(stderr, "[SentinelFS] Failed to initialize LibMagic\n");
        exit(1);
    }

    if (magic_load(global_ctx->magic_cookie, NULL) != 0) {
        fprintf(stderr, "[SentinelFS] LibMagic error: %s\n",
                magic_error(global_ctx->magic_cookie));
        exit(1);
    }

    mkdir(global_ctx->backup_path, 0700);  // Create backup dir

    return global_ctx;
}

// Cleanup and print stats
static void sentinelfs_destroy(void *private_data) {
    (void) private_data;

    fprintf(stderr, "\n[SentinelFS] Shutdown Statistics:\n");
    fprintf(stderr, "  Total writes: %lu\n", stats.total_writes);
    fprintf(stderr, "  Blocked writes: %lu (%.2f%%)\n", stats.blocked_writes,
            stats.total_writes > 0 ? (100.0 * stats.blocked_writes / stats.total_writes) : 0.0);
    fprintf(stderr, "  Backups created: %lu\n", stats.backups_created);

    if (global_ctx->magic_cookie) {
        magic_close(global_ctx->magic_cookie);
    }
}

// FUSE operations table
static struct fuse_operations sentinelfs_oper = {
    .init       = sentinelfs_init,
    .destroy    = sentinelfs_destroy,
    .getattr    = sentinelfs_getattr,
    .readdir    = sentinelfs_readdir,
    .open       = sentinelfs_open,
    .read       = sentinelfs_read,
    .write      = sentinelfs_write,
    .create     = sentinelfs_create,
    .mkdir      = sentinelfs_mkdir,
    .unlink     = sentinelfs_unlink,
    .rmdir      = sentinelfs_rmdir,
    .rename     = sentinelfs_rename,
    .chmod      = sentinelfs_chmod,
    .chown      = sentinelfs_chown,
    .truncate   = sentinelfs_truncate,
};

// Main
int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <storage_path> <mount_point>\n", argv[0]);
        fprintf(stderr, "Example: %s /tmp/storage /tmp/mount\n", argv[0]);
        return 1;
    }

    // Initialize context
    global_ctx = calloc(1, sizeof(sentinelfs_context_t));
    if (!global_ctx) {
        fprintf(stderr, "Failed to allocate context\n");
        return 1;
    }

    global_ctx->storage_path = realpath(argv[1], NULL);
    if (!global_ctx->storage_path) {
        fprintf(stderr, "Invalid storage path: %s\n", argv[1]);
        free(global_ctx);
        return 1;
    }

    /* Setup backup directory */
    global_ctx->backup_path = malloc(MAX_PATH);
    snprintf(global_ctx->backup_path, MAX_PATH, "%s/%s",
             global_ctx->storage_path, BACKUP_DIR);

    printf("SentinelFS - Phase III/IV Implementation\n");
    printf("Real-time ransomware detection via FUSE\n");
    printf("Author: Sameer Ahmed (NUST)\n\n");
    printf("Storage:           %s\n", global_ctx->storage_path);
    printf("Mount point:       %s\n", argv[2]);
    printf("Backup directory:  %s\n", global_ctx->backup_path);
    printf("Entropy threshold: %.1f\n", ENTROPY_THRESHOLD);
    printf("Backup size limit: %dMB\n\n", (int)(JIT_BACKUP_MAX_SIZE / 1024 / 1024));

    // Prepare FUSE arguments
    int fuse_argc = argc - 1;
    char **fuse_argv = malloc(sizeof(char *) * (fuse_argc + 1));
    fuse_argv[0] = argv[0];
    for (int i = 2; i < argc; i++) {
        fuse_argv[i - 1] = argv[i];
    }
    fuse_argv[fuse_argc] = NULL;

    // Run FUSE
    int ret = fuse_main(fuse_argc, fuse_argv, &sentinelfs_oper, NULL);

    // Cleanup
    free(fuse_argv);
    free(global_ctx->backup_path);
    free(global_ctx->storage_path);
    free(global_ctx);

    return ret;
}
