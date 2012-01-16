#ifndef _UTILS_LOGGING_H
#define _UTILS_LOGGING_H

// NOTE: see logutils.h for older (non-syslog) logging system

#include <syslog.h>
#include <stdbool.h>
#include <string.h>


#define OPEN_LOG(ident, facility) \
    do { \
        openlog((ident), LOG_PID | LOG_PERROR, (facility)); \
    } while (false)

#define CLOSE_LOG() \
    do { \
        closelog(); \
    } while (false)

#define LOG(priority, format, ...) \
    do { \
        syslog((priority), "%s:%d in %s(): " format, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (false)


#define ERROR_BUF_SIZE 256
#define ERR_LOG(err, errorbuf, format, ...) \
    do { \
        if (strerror_r((err), (errorbuf), ERROR_BUF_SIZE) == 0) \
        { \
            syslog(LOG_ERR, "%s:%d in %s(): " format ": %s", \
                __FILE__, __LINE__, __func__, ## __VA_ARGS__, (errorbuf)); \
        } \
        else \
        { \
            syslog(LOG_ERR, "%s:%d in %s(): " format ": error code %d", \
                __FILE__, __LINE__, __func__, ## __VA_ARGS__, (err)); \
        } \
    } while (false)


#endif
