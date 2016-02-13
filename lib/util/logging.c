#include "logging.h"

struct log_custom_backend log_custom_backend = {
  .log = NULL,
  .flush = NULL,
  .close = NULL,
};

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

int log_facility = LOG_USER;

const char *log_ident = NULL;
