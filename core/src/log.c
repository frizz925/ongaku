#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int log_level = LOG_INFO;
static int log_timestamp = 0;
static int log_source = 0;
static const char *log_level_names[] = {
    "TRACE",
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL",
    NULL,
};

void log_init() {
    const char *env_name = getenv("LOG_LEVEL");
    if (env_name) {
        for (int level = LOG_TRACE; log_level_names[level]; level++) {
            const char *name = log_level_names[level];
            if (strncasecmp(name, env_name, strlen(name)) == 0) {
                log_level = level;
                break;
            }
        }
    }

    const char *env_timestamp = getenv("LOG_TIMESTAMP");
    if (env_timestamp)
        log_timestamp = atoi(env_timestamp);

    const char *env_source = getenv("LOG_SOURCE");
    if (env_source)
        log_source = atoi(env_source);
}

void log_set_level(int level) {
    log_level = level;
}

void log_write(int level, const char *file, int line, const char *fmt, ...) {
    if (level < log_level)
        return;

    char msg[4096];
    char *ptr = msg;
    char *tail = msg + sizeof(msg);

    if (log_timestamp) {
        time_t now = time(NULL);
        ptr += strftime(ptr, tail - ptr, "%F %T ", localtime(&now));
    }
    ptr += snprintf(ptr, tail - ptr, "%-5s ", log_level_names[level]);
    if (log_source)
        ptr += snprintf(ptr, tail - ptr, "%s:%d ", file, line);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ptr, tail - ptr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", msg);
    fflush(stderr);
}
