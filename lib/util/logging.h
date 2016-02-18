#ifndef _UTILS_LOGGING_H
#define _UTILS_LOGGING_H

#include <syslog.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

/* LOG_LEVEL_TEXT[0] == "EMERG", etc. (RFC 5424) */
extern const char *LOG_LEVEL_TEXT[];

/** @brief logging facility extensions */
enum {
    /**
     * @brief
     *     maximum syslog facility number used by supported systems
     *
     * RFC5242 facilities go up to 23, which is why this is set to 23.
     * This value may change in the future.
     */
    SYSLOG_MAX_FACILITY = 23,

    /**
     * @brief
     *     Special facility that means to log to standard error instead of
     *     to syslog().
     */
    LOG_CONSOLE,

    /**
     * @brief
     *     Special facility that means to log to a custom backend
     *     function.
     *
     * If this facility is used, @c log_custom_backend_function must
     * be non-NULL.
     */
    LOG_CUSTOM_BACKEND,
};

/**
 * @brief
 *     custom backend logging function type
 *
 * @param[in] priority
 *     One of the syslog() priority levels.
 * @param[in] ident
 *     Identity based on the value of the @c ident parameter passed to
 *     OPEN_LOG().  This may be NULL.
 */
typedef void
log_custom_backend_logger(
    int priority,
    const char *restrict ident,
    const char *restrict format,
    ...);

typedef void
log_custom_backend_flush(
    void);

typedef void
log_custom_backend_close(
    void);

/**
 * @brief
 *     logging functions called if the facility is LOG_CUSTOM_BACKEND
 *
 * Everything in this variable is initialized to NULL on program
 * startup.
 */
extern struct log_custom_backend {
    /**
     * @brief
     *     custom logging function called from LOG()
     */
    log_custom_backend_logger *log;

    /**
     * @brief
     *     custom flush function called from FLUSH_LOG()
     *
     * NULL is equivalent to a do-nothing function.
     */
    log_custom_backend_flush *flush;

    /**
     * @brief
     *     custom close function called from CLOSE_LOG()
     *
     * NULL is equivalent to a do-nothing function.
     */
    log_custom_backend_close *close;
} log_custom_backend;

#define OPEN_LOG(ident, facility)                                       \
    do {                                                                \
        log_facility = (facility);                                      \
        log_ident = PACKAGE_NAME "-" ident;                             \
        switch (log_facility)                                           \
        {                                                               \
        case LOG_CONSOLE:                                               \
        case LOG_CUSTOM_BACKEND:                                        \
            /* no setup needed */                                       \
            break;                                                      \
        default:                                                        \
            openlog(log_ident, LOG_PID | LOG_PERROR, log_facility);     \
        }                                                               \
    } while (false)

#define CLOSE_LOG()                                                     \
    do {                                                                \
        switch (log_facility)                                           \
        {                                                               \
        case LOG_CONSOLE:                                               \
            /* no cleanup needed */                                     \
            break;                                                      \
        case LOG_CUSTOM_BACKEND:                                        \
            if (log_custom_backend.close)                               \
            {                                                           \
                (*log_custom_backend.close)();                          \
            }                                                           \
            break;                                                      \
        default:                                                        \
            closelog();                                                 \
        }                                                               \
    } while (false)

/**
 * @brief ensure that the log messages have been written
 */
#define FLUSH_LOG()                                                     \
    do {                                                                \
        switch (log_facility)                                           \
        {                                                               \
        case LOG_CONSOLE:                                               \
            fflush(stderr);                                             \
            break;                                                      \
        case LOG_CUSTOM_BACKEND:                                        \
            if (log_custom_backend.flush)                               \
            {                                                           \
                (*log_custom_backend.flush)();                          \
            }                                                           \
            break;                                                      \
        default:                                                        \
            /* syslog() doesn't need flushing */                        \
            break;                                                      \
        }                                                               \
    } while (false)

/**
 * Don't read or write this directly, use GET_LOG_LEVEL() and
 * SET_LOG_LEVEL() below.
 */
volatile sig_atomic_t LOG_LEVEL;

/**
 * @brief expands to the current log level
 */
#define GET_LOG_LEVEL() (LOG_LEVEL)

#define SET_LOG_LEVEL(level)                                            \
    do {                                                                \
        LOG_LEVEL = (level);                                            \
    } while (false)

#define LOG(priority, format, ...)                                      \
    do {                                                                \
        if ((priority) <= LOG_LEVEL)                                    \
        {                                                               \
            if (LOG_LEVEL >= LOG_DEBUG)                                 \
            {                                                           \
                LOG_BACKEND((priority), "%s:%d in %s(): " format,       \
                            __FILE__, __LINE__, __func__,               \
                            ## __VA_ARGS__);                            \
            }                                                           \
            else                                                        \
            {                                                           \
                LOG_BACKEND((priority), format, ## __VA_ARGS__);        \
            }                                                           \
        }                                                               \
    } while (false)

#define LOG_BACKEND(priority, format, ...)                              \
    do {                                                                \
        switch (log_facility)                                           \
        {                                                               \
        case LOG_CONSOLE:                                               \
        {                                                               \
            const char *log_backend_ident =                             \
                (NULL == log_ident) ? "" : log_ident;                   \
            const char *log_backend_ident_sep =                         \
                ('\0' == log_backend_ident[0]) ? "" : ": ";             \
            fprintf(stderr, "%s%s%s: " format "\n",                     \
                    log_backend_ident, log_backend_ident_sep,           \
                    LOG_LEVEL_TEXT[(priority)], ## __VA_ARGS__);        \
            break;                                                      \
        }                                                               \
        case LOG_CUSTOM_BACKEND:                                        \
            (*log_custom_backend.log)(                                  \
                (priority), log_ident, format, ## __VA_ARGS__);         \
            break;                                                      \
        default:                                                        \
        {                                                               \
            int log_backend_priority = (priority);                      \
            syslog(log_backend_priority, "%s: " format,                 \
                   LOG_LEVEL_TEXT[log_backend_priority],                \
                   ## __VA_ARGS__);                                     \
        }                                                               \
        }                                                               \
    } while (0)

/**
 * @brief
 *     facility passed to the latest call to OPEN_LOG()
 *
 * Do not change this directly as it may or may not affect where log
 * output goes; to change the current behavior use CLOSE_LOG()
 * followed by a new call to OPEN_LOG().
 *
 * If OPEN_LOG() is not called, this defaults to an unspecified
 * syslog() facility.
 */
extern int log_facility;

/**
 * @brief
 *     String prefixed to each log message.
 *
 * Do not change this directly as it may or may not change the prefix
 * used; to alter the prefix use CLOSE_LOG() followed by a new call to
 * OPEN_LOG().
 *
 * If OPEN_LOG() is not called, this defaults to NULL, meaning that no
 * prefix will be used.
 */
extern const char *log_ident;

#define ERROR_BUF_SIZE 256
#define ERR_LOG(err, errorbuf, format, ...)                             \
    do {                                                                \
        char err_log_dfl_buf[ERROR_BUF_SIZE];                           \
        char *err_log_buf = (errorbuf);                                 \
        err_log_buf = err_log_buf ? err_log_buf : err_log_dfl_buf;      \
        if (strerror_r((err), err_log_buf, ERROR_BUF_SIZE) == 0)        \
        {                                                               \
            LOG(LOG_ERR, format ": %s", ## __VA_ARGS__, err_log_buf);   \
        }                                                               \
        else                                                            \
        {                                                               \
            LOG(LOG_ERR, format ": error code %d", ## __VA_ARGS__, (err)); \
        }                                                               \
    } while (false)

/**
    These macros help transition from the problematic fatal() functions used in
    some of the older code. They are not intended to be used by new code.
*/
#define FATAL(format, ...)                                              \
    do {                                                                \
        fprintf(stderr, format "\n", ## __VA_ARGS__);                   \
        exit(EXIT_FAILURE);                                             \
    } while (false)
#define DONE(format, ...)                                               \
    do {                                                                \
        fprintf(stderr, format "\n", ## __VA_ARGS__);                   \
        exit(EXIT_SUCCESS);                                             \
    } while (false)


#endif
