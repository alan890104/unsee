/* SECURITY: _GNU_SOURCE must be defined before ANY system headers.
 * On Linux, dlsym(RTLD_NEXT, ...) requires _GNU_SOURCE. If defined
 * after headers are included, RTLD_NEXT may not be declared, causing
 * a compilation error or undefined behavior. */
#ifdef __linux__
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>

#ifdef __linux__
#include <dlfcn.h>
#endif

#ifdef __APPLE__
#define DYLD_INTERPOSE(_replacement, _original) \
    __attribute__((used)) static struct { \
        const void* replacement; \
        const void* original; \
    } _interpose_##_original \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_original \
    };
#endif

#define MAX_FDS 4096
#define MAX_MAPPINGS 256
#define MAX_BUF (1024 * 1024)

/* Track which fds point to .env* files opened for writing.
 * SECURITY: Uses atomic_int to prevent data races when multiple threads
 * call open()/write()/close() concurrently. All accesses go through
 * atomic_store_explicit / atomic_load_explicit with relaxed ordering
 * (sufficient for flag tracking — no cross-variable ordering needed). */
static atomic_int env_fds[MAX_FDS];

/* Reverse mapping: placeholder → real value */
static struct {
    char placeholder[256];
    char real_value[1024];
    size_t ph_len;
    size_t rv_len;
} mappings[MAX_MAPPINGS];
static int num_mappings = 0;
static pthread_once_t mappings_once = PTHREAD_ONCE_INIT;

/* SECURITY: Thread-safe initialization via pthread_once.
 * Without this, concurrent threads calling load_mappings() could race on
 * num_mappings and mappings[], producing corrupt entries. */
static void load_mappings_impl(void) {
    const char *map_file = getenv("UNSEE_MAP_FILE");
    if (!map_file) return;

    FILE *f = fopen(map_file, "r");
    if (!f) return;

    char line[2048];
    while (fgets(line, sizeof(line), f) && num_mappings < MAX_MAPPINGS) {
        /* Format: placeholder\treal_value */
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        char *val = tab + 1;
        char *nl = strchr(val, '\n');
        if (nl) *nl = '\0';

        /* SECURITY: snprintf guarantees null-termination.
         * strncpy does NOT null-terminate if source >= N bytes,
         * leaving the buffer without a terminator → strlen() overread. */
        snprintf(mappings[num_mappings].placeholder,
                 sizeof(mappings[num_mappings].placeholder), "%s", line);
        snprintf(mappings[num_mappings].real_value,
                 sizeof(mappings[num_mappings].real_value), "%s", val);
        mappings[num_mappings].ph_len = strlen(mappings[num_mappings].placeholder);
        mappings[num_mappings].rv_len = strlen(mappings[num_mappings].real_value);
        num_mappings++;
    }
    fclose(f);

    /* Sort mappings by real_value length descending.
     * SECURITY: For read redaction (real→placeholder), longer real values
     * must be matched first to prevent shorter substrings from matching
     * prematurely. E.g., "secret123" must match before "secret". */
    for (int i = 0; i < num_mappings - 1; i++) {
        for (int j = i + 1; j < num_mappings; j++) {
            if (mappings[j].rv_len > mappings[i].rv_len) {
                char tmp_ph[256], tmp_rv[1024];
                size_t tmp_ph_len, tmp_rv_len;
                memcpy(tmp_ph, mappings[i].placeholder, sizeof(tmp_ph));
                memcpy(tmp_rv, mappings[i].real_value, sizeof(tmp_rv));
                tmp_ph_len = mappings[i].ph_len;
                tmp_rv_len = mappings[i].rv_len;
                memcpy(mappings[i].placeholder, mappings[j].placeholder, sizeof(tmp_ph));
                memcpy(mappings[i].real_value, mappings[j].real_value, sizeof(tmp_rv));
                mappings[i].ph_len = mappings[j].ph_len;
                mappings[i].rv_len = mappings[j].rv_len;
                memcpy(mappings[j].placeholder, tmp_ph, sizeof(tmp_ph));
                memcpy(mappings[j].real_value, tmp_rv, sizeof(tmp_rv));
                mappings[j].ph_len = tmp_ph_len;
                mappings[j].rv_len = tmp_rv_len;
            }
        }
    }
}

static void load_mappings(void) {
    pthread_once(&mappings_once, load_mappings_impl);
}

/* SECURITY: Load mappings eagerly during library init (part of exec()),
 * before any user code runs. After loading, delete the map file and clear
 * the env var so the agent cannot read the secret-to-placeholder mapping.
 * The parent also attempts deletion as a backup. */
__attribute__((constructor))
static void interpose_init(void) {
    load_mappings();
    /* Do NOT delete the map file or clear UNSEE_MAP_FILE here.
     * Wrapper binaries (e.g., Homebrew Python) may re-exec the real binary,
     * triggering a second constructor that needs the file path from the env
     * var and the file on disk. The parent's NamedTempFile handles cleanup
     * when the session ends. The StreamRedactor provides defense-in-depth:
     * even if the agent reads the map file, real values in output are
     * replaced with placeholders. */
}

static int is_env_file(const char *path) {
    if (!path) return 0;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strncmp(base, ".env", 4) != 0) return 0;
    char next = base[4];
    if (next == '\0') return 1;
    if (next != '.') return 0;
    /* Exclude template files */
    const char *suffix = base + 4;
    if (strcmp(suffix, ".example") == 0) return 0;
    if (strcmp(suffix, ".sample") == 0) return 0;
    if (strcmp(suffix, ".template") == 0) return 0;
    return 1;
}

/* Replace all placeholder occurrences in buf. Returns malloc'd buffer. */
static char *fix_buffer(const void *buf, size_t count, size_t *out_count) {
    load_mappings();

    char *str = malloc(count + 1);
    memcpy(str, buf, count);
    str[count] = '\0';

    if (num_mappings == 0) {
        *out_count = count;
        return str;
    }

    /* Check if any placeholder present */
    int found = 0;
    for (int i = 0; i < num_mappings; i++) {
        if (strstr(str, mappings[i].placeholder)) { found = 1; break; }
    }
    if (!found) {
        *out_count = count;
        return str;
    }

    /* Do replacements iteratively.
     * SECURITY: Each iteration replaces one placeholder type across the
     * entire buffer. We allocate a new result buffer per iteration and
     * free the previous one. The final result is returned to the caller
     * (caller must free). */
    char *current = str;
    for (int i = 0; i < num_mappings; i++) {
        size_t cur_len = strlen(current);
        /* Allocate enough for worst case: every byte is the start of a
         * placeholder replaced by a longer real value.
         * Upper bound: cur_len / ph_len * rv_len + cur_len + 1 */
        size_t max_replacements = (mappings[i].ph_len > 0)
            ? (cur_len / mappings[i].ph_len + 1) : 1;
        /* SECURITY: Check for integer overflow before allocating.
         * Without this, a large rv_len * max_replacements could wrap size_t,
         * producing a small malloc → heap buffer overflow during memcpy. */
        size_t per_replacement = mappings[i].rv_len + 1;
        if (per_replacement > 0 && max_replacements > SIZE_MAX / per_replacement) {
            /* Overflow detected — return what we have */
            *out_count = strlen(current);
            return current;
        }
        size_t expansion = max_replacements * per_replacement;
        if (expansion > SIZE_MAX - cur_len - 1) {
            *out_count = strlen(current);
            return current;
        }
        size_t alloc = cur_len + expansion + 1;
        /* Cap at MAX_BUF to prevent memory exhaustion from pathological input.
         * SECURITY: Skip this mapping rather than returning early. Returning
         * early would leave subsequent mappings' placeholders unprocessed,
         * leaking placeholder strings into the file on disk. Skipping one
         * oversized mapping is safer — the remaining mappings still get applied. */
        if (alloc > MAX_BUF) {
            continue;
        }
        if (alloc < 256) alloc = 256;
        char *result = malloc(alloc);
        if (!result) {
            /* OOM: return what we have so far rather than crash */
            *out_count = strlen(current);
            return current;
        }
        char *dst = result;
        char *src = current;
        char *pos;

        while ((pos = strstr(src, mappings[i].placeholder)) != NULL) {
            size_t prefix_len = (size_t)(pos - src);
            memcpy(dst, src, prefix_len);
            dst += prefix_len;
            memcpy(dst, mappings[i].real_value, mappings[i].rv_len);
            dst += mappings[i].rv_len;
            src = pos + mappings[i].ph_len;
        }
        /* SECURITY: Copy remainder with explicit length instead of strcpy.
         * strcpy has no bounds check — if the result buffer were miscalculated,
         * it would overflow. strlen+memcpy is bounded. */
        size_t remainder = strlen(src);
        memcpy(dst, src, remainder);
        dst[remainder] = '\0';

        /* Free previous buffer. On first iteration current == str (the
         * original malloc). On subsequent iterations it's the previous
         * iteration's result. Either way, exactly one free per iteration. */
        free(current);
        current = result;
    }

    *out_count = strlen(current);
    return current;
}

/* Replace all real_value occurrences with placeholder in buf (reverse of fix_buffer).
 * Used for read interception: the agent reads .env → sees placeholders.
 * Returns malloc'd buffer; caller must free. */
static char *redact_buffer(const void *buf, size_t count, size_t *out_count) {
    load_mappings();

    char *str = malloc(count + 1);
    if (!str) { *out_count = 0; return NULL; }
    memcpy(str, buf, count);
    str[count] = '\0';

    if (num_mappings == 0) {
        *out_count = count;
        return str;
    }

    int found = 0;
    for (int i = 0; i < num_mappings; i++) {
        if (mappings[i].rv_len > 0 && strstr(str, mappings[i].real_value)) {
            found = 1; break;
        }
    }
    if (!found) {
        *out_count = count;
        return str;
    }

    /* Mappings are sorted by rv_len descending (done in load_mappings_impl),
     * so longer real values are replaced before shorter substrings. */
    char *current = str;
    for (int i = 0; i < num_mappings; i++) {
        if (mappings[i].rv_len == 0) continue;
        size_t cur_len = strlen(current);
        size_t max_replacements = cur_len / mappings[i].rv_len + 1;
        size_t per_replacement = mappings[i].ph_len + 1;
        if (per_replacement > 0 && max_replacements > SIZE_MAX / per_replacement) {
            *out_count = strlen(current);
            return current;
        }
        size_t expansion = max_replacements * per_replacement;
        if (expansion > SIZE_MAX - cur_len - 1) {
            *out_count = strlen(current);
            return current;
        }
        size_t alloc = cur_len + expansion + 1;
        if (alloc > MAX_BUF) continue;
        if (alloc < 256) alloc = 256;
        char *result = malloc(alloc);
        if (!result) {
            *out_count = strlen(current);
            return current;
        }
        char *dst = result;
        char *src = current;
        char *pos;

        while ((pos = strstr(src, mappings[i].real_value)) != NULL) {
            size_t prefix_len = (size_t)(pos - src);
            memcpy(dst, src, prefix_len);
            dst += prefix_len;
            memcpy(dst, mappings[i].placeholder, mappings[i].ph_len);
            dst += mappings[i].ph_len;
            src = pos + mappings[i].rv_len;
        }
        size_t remainder = strlen(src);
        memcpy(dst, src, remainder);
        dst[remainder] = '\0';

        free(current);
        current = result;
    }

    *out_count = strlen(current);
    return current;
}

/* Create a redacted shadow fd from a real .env fd.
 * Reads the file, replaces real values with placeholders, writes to
 * an anonymous temp file (mkstemp + unlink), returns the new fd.
 * The original fd is closed. On failure, returns -1 with errno set. */
static int create_redacted_fd(int real_fd) {
    load_mappings();
    if (num_mappings == 0) return real_fd;

    off_t size = lseek(real_fd, 0, SEEK_END);
    if (size <= 0) return real_fd;
    lseek(real_fd, 0, SEEK_SET);

    char *content = malloc((size_t)size + 1);
    if (!content) return real_fd;

    ssize_t total = 0;
    while (total < size) {
        ssize_t n = read(real_fd, content + total, (size_t)(size - total));
        if (n <= 0) break;
        total += n;
    }
    content[total] = '\0';
    close(real_fd);

    size_t redacted_size;
    char *redacted = redact_buffer(content, (size_t)total, &redacted_size);
    free(content);
    if (!redacted) return -1;

    /* Create anonymous temp file: mkstemp in CWD + immediate unlink.
     * SECURITY: The file is deleted from the filesystem immediately,
     * so the agent cannot discover it by path. The fd remains valid
     * until close(). Uses CWD (not /tmp) because the macOS Seatbelt
     * sandbox may block /tmp but always allows the project directory. */
    char tmpl[] = ".unsee-rd-XXXXXX";
    int tmp_fd = mkstemp(tmpl);
    if (tmp_fd < 0) {
        free(redacted);
        errno = EIO;
        return -1;
    }
    unlink(tmpl);

    ssize_t written = 0;
    while ((size_t)written < redacted_size) {
        ssize_t n = write(tmp_fd, redacted + written, redacted_size - (size_t)written);
        if (n <= 0) break;
        written += n;
    }
    free(redacted);
    lseek(tmp_fd, 0, SEEK_SET);

    return tmp_fd;
}

/* ================================================================
 * macOS: DYLD_INSERT_LIBRARIES + __DATA,__interpose
 * ================================================================ */
#ifdef __APPLE__

int my_open(const char *path, int oflag, ...) {
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    int fd = open(path, oflag, mode);

    if (fd >= 0 && is_env_file(path)) {
        if ((oflag & O_WRONLY) || (oflag & O_RDWR)) {
            if (fd < MAX_FDS)
                atomic_store_explicit(&env_fds[fd], 1, memory_order_relaxed);
        } else {
            /* Read-only open: return a shadow fd with redacted content.
             * SECURITY: The agent (LLM) sees placeholders; the real .env
             * on disk is never modified. Apps get real values via env vars. */
            fd = create_redacted_fd(fd);
        }
    }
    return fd;
}

ssize_t my_write(int fd, const void *buf, size_t count) {
    if (fd >= 0 && fd < MAX_FDS && atomic_load_explicit(&env_fds[fd], memory_order_relaxed)) {
        size_t new_count;
        char *fixed = fix_buffer(buf, count, &new_count);
        ssize_t ret = write(fd, fixed, new_count);
        free(fixed);
        if (ret >= 0) return (ssize_t)count;
        return ret;
    }
    return write(fd, buf, count);
}

int my_close(int fd) {
    if (fd >= 0 && fd < MAX_FDS) {
        atomic_store_explicit(&env_fds[fd], 0, memory_order_relaxed);
    }
    return close(fd);
}

int my_openat(int dirfd, const char *path, int oflag, ...) {
    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    int fd = openat(dirfd, path, oflag, mode);

    if (fd >= 0 && is_env_file(path)) {
        if ((oflag & O_WRONLY) || (oflag & O_RDWR)) {
            if (fd < MAX_FDS)
                atomic_store_explicit(&env_fds[fd], 1, memory_order_relaxed);
        } else {
            fd = create_redacted_fd(fd);
        }
    }
    return fd;
}

DYLD_INTERPOSE(my_open, open)
DYLD_INTERPOSE(my_openat, openat)
DYLD_INTERPOSE(my_write, write)
DYLD_INTERPOSE(my_close, close)

#endif /* __APPLE__ */

/* ================================================================
 * Linux: LD_PRELOAD + dlsym(RTLD_NEXT)
 * ================================================================ */
#ifdef __linux__

typedef int (*orig_open_t)(const char *path, int oflag, ...);
typedef int (*orig_openat_t)(int dirfd, const char *path, int oflag, ...);
typedef ssize_t (*orig_write_t)(int fd, const void *buf, size_t count);
typedef int (*orig_close_t)(int fd);

/* Returns the (possibly replaced) fd. On Linux, read()/write()/close()
 * inside this function resolve to our overrides, but that's safe:
 * - write() passes through because the temp fd is not in env_fds
 * - close() just clears env_fds (already 0) and calls original
 * - read() is not overridden */
static int track_open_fd(int fd, const char *path, int oflag) {
    if (fd >= 0 && is_env_file(path)) {
        if ((oflag & O_WRONLY) || (oflag & O_RDWR)) {
            if (fd < MAX_FDS)
                atomic_store_explicit(&env_fds[fd], 1, memory_order_relaxed);
        } else {
            fd = create_redacted_fd(fd);
        }
    }
    return fd;
}

/* SECURITY: All dlsym() calls check for NULL. If the real symbol cannot
 * be resolved (shouldn't happen in practice, but possible with unusual
 * linker setups), we set errno=ENOSYS and return error rather than
 * calling a NULL function pointer (immediate SIGSEGV). */

int open(const char *path, int oflag, ...) {
    orig_open_t orig = (orig_open_t)dlsym(RTLD_NEXT, "open");
    if (!orig) { errno = ENOSYS; return -1; }

    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    int fd = orig(path, oflag, mode);
    return track_open_fd(fd, path, oflag);
}

int open64(const char *path, int oflag, ...) {
    orig_open_t orig = (orig_open_t)dlsym(RTLD_NEXT, "open64");
    if (!orig) { errno = ENOSYS; return -1; }

    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    int fd = orig(path, oflag, mode);
    return track_open_fd(fd, path, oflag);
}

int openat(int dirfd, const char *path, int oflag, ...) {
    orig_openat_t orig = (orig_openat_t)dlsym(RTLD_NEXT, "openat");
    if (!orig) { errno = ENOSYS; return -1; }

    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    int fd = orig(dirfd, path, oflag, mode);
    return track_open_fd(fd, path, oflag);
}

int openat64(int dirfd, const char *path, int oflag, ...) {
    orig_openat_t orig = (orig_openat_t)dlsym(RTLD_NEXT, "openat64");
    if (!orig) { errno = ENOSYS; return -1; }

    mode_t mode = 0;
    if (oflag & O_CREAT) {
        va_list args;
        va_start(args, oflag);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    int fd = orig(dirfd, path, oflag, mode);
    return track_open_fd(fd, path, oflag);
}

ssize_t write(int fd, const void *buf, size_t count) {
    orig_write_t orig = (orig_write_t)dlsym(RTLD_NEXT, "write");
    if (!orig) { errno = ENOSYS; return -1; }

    if (fd >= 0 && fd < MAX_FDS && atomic_load_explicit(&env_fds[fd], memory_order_relaxed)) {
        size_t new_count;
        char *fixed = fix_buffer(buf, count, &new_count);
        ssize_t ret = orig(fd, fixed, new_count);
        free(fixed);
        if (ret >= 0) return (ssize_t)count;
        return ret;
    }
    return orig(fd, buf, count);
}

int close(int fd) {
    orig_close_t orig = (orig_close_t)dlsym(RTLD_NEXT, "close");
    if (!orig) { errno = ENOSYS; return -1; }

    if (fd >= 0 && fd < MAX_FDS) {
        atomic_store_explicit(&env_fds[fd], 0, memory_order_relaxed);
    }
    return orig(fd);
}

#endif /* __linux__ */
