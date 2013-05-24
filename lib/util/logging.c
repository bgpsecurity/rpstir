#include "logging.h"

volatile sig_atomic_t LOG_LEVEL = LOG_INFO;

/* RFC 5424 locks numerical values */
const char *LOG_LEVEL_TEXT[8] = {
    "EMERG",                    /* 0 */
    "ALERT",
    "CRIT",
    "ERR",
    "WARN",
    "NOTICE",
    "INFO",
    "DEBUG"                     /* 7 */
};
