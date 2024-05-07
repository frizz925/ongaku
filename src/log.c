#include "log.h"

#include <stdio.h>
#include <time.h>

static const char *log_levels[] = {
    "TRACE",
    "DEBUG",
    "INFO",
    "WARN",
    "ERROR",
    "FATAL",
};

void log_write(int level, const char *file, int line, const char *fmt, ...) {
#ifdef LOG_LEVEL
    if (level < LOG_LEVEL)
        return;
#endif

    char msg[4096];
    char *ptr = msg;
    char *tail = msg + sizeof(msg);

    time_t now = time(NULL);
    ptr += strftime(ptr, tail - ptr, "%F %T", localtime(&now));
    ptr += snprintf(ptr, tail - ptr, " %-5s %s:%d ", log_levels[level], file, line);

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(ptr, tail - ptr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s\n", msg);
    fflush(stderr);
}
