#ifndef _TEST_DRIVER_MYSQL_C_API_H
#define _TEST_DRIVER_MYSQL_C_API_H


#include <syslog.h>
#include <stdbool.h>


#define LOG_IDENT  PACKAGE_NAME "-db_test_driver"
#define LOG_OPTION (LOG_PERROR)
#define LOG_FACILITY LOG_USER


#define OPEN_LOG() \
    do { \
        openlog(LOG_IDENT, LOG_OPTION, LOG_FACILITY); \
    } while (false)

#define CLOSE_LOG() \
    do { \
        closelog(); \
    } while (false)


#endif  // _TEST_DRIVER_MYSQL_C_API_H
