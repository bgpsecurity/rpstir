#ifndef _DB_C_LOGGING_H
#define _DB_C_LOGGING_H

#include <syslog.h>
#include <stdbool.h>
#include <string.h>

// #include "config.h"
#define DB_C_LOG_IDENT "db_c"
#define DB_C_LOG_OPTION (LOG_PERROR)
#define DB_C_LOG_FACILITY LOG_DAEMON


#define DB_C_OPEN_LOG() \
    do { \
        openlog(DB_C_LOG_IDENT, DB_C_LOG_OPTION, DB_C_LOG_FACILITY); \
    } while (false)

#define DB_C_CLOSE_LOG() \
    do { \
        closelog(); \
    } while (false)


#define DB_C_LOG(priority, format, ...) \
    do { \
        syslog((priority), "%s:%d in %s(): " format, \
            __FILE__, __LINE__, __func__, ## __VA_ARGS__); \
    } while (false)

#define ERROR_BUF_SIZE 256
#define DB_C_LOG_ERR(err, errorbuf, msg) \
    do { \
        if (strerror_r((err), (errorbuf), ERROR_BUF_SIZE) == 0) \
        { \
            syslog(LOG_ERR, "%s:%d in %s(): %s: %s", \
                __FILE__, __LINE__, __func__, (msg), (errorbuf)); \
        } \
        else \
        { \
            syslog(LOG_ERR, "%s:%d in %s(): %s: error code %d", \
                __FILE__, __LINE__, __func__, (msg), (err)); \
        } \
    } while (false)


#endif
