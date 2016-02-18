// make sure strerror_r is the POSIX flavor
#define _XOPEN_SOURCE 700

#include "test/unittest.h"
#include "util/logging.h"
#include "util/stringutils.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

static char logbuf[4096] = {0};
static size_t logbuf_offset = 0;
static log_custom_backend_logger log_logger;
void
log_logger(
    int priority,
    const char *restrict ident,
    const char *restrict format,
    ...)
{
    logbuf_offset += xsnprintf(
        logbuf + logbuf_offset, sizeof(logbuf) - logbuf_offset,
        "%s %s: ", ident, LOG_LEVEL_TEXT[priority]);

    va_list arg;
    va_start(arg, format);
    logbuf_offset += xvsnprintf(
        logbuf + logbuf_offset, sizeof(logbuf) - logbuf_offset,
        format, arg);
    va_end(arg);

    logbuf_offset += xsnprintf(
        logbuf + logbuf_offset, sizeof(logbuf) - logbuf_offset,
        "\n");
}

static _Bool flushed = 0;
static log_custom_backend_flush log_flush;
void
log_flush(
    void)
{
    flushed = 1;
}

static _Bool closed = 0;
static log_custom_backend_close log_close;
void
log_close(
    void)
{
    closed = 1;
}

static const int priorities[] = {
    LOG_DEBUG,
    LOG_INFO,
    LOG_NOTICE,
    LOG_WARNING,
    LOG_ERR,
    LOG_CRIT,
    LOG_ALERT,
    LOG_EMERG,
};

static _Bool
test_logging(
    void)
{
    log_custom_backend.log = &log_logger;
    log_custom_backend.flush = &log_flush;
    log_custom_backend.close = &log_close;
    OPEN_LOG("logging-test", LOG_CUSTOM_BACKEND);

    int saved_log_level = GET_LOG_LEVEL();

    // try all log message levels against all log levels
    for (size_t i=0; i < sizeof(priorities)/sizeof(priorities[0]); ++i)
    {
        SET_LOG_LEVEL(priorities[i]);
        for (size_t j=0; j < sizeof(priorities)/sizeof(priorities[0]); ++j)
        {
            LOG(priorities[j], "LOG_LEVEL=%s (%d), message level %s (%d)",
                LOG_LEVEL_TEXT[priorities[i]], priorities[i],
                LOG_LEVEL_TEXT[priorities[j]], priorities[j]);
        }
        ERR_LOG(EACCES, NULL, "LOG_LEVEL=%s (%d), ERR_LOG(EACCES, NULL), %d",
                LOG_LEVEL_TEXT[priorities[i]], priorities[i], EACCES);
        char buf[ERROR_BUF_SIZE];
        ERR_LOG(EINVAL, buf, "LOG_LEVEL=%s (%d), ERR_LOG(EINVAL, buf), %d",
                LOG_LEVEL_TEXT[priorities[i]], priorities[i], EINVAL);
    }

    // make sure the user can turn off all logging
    SET_LOG_LEVEL(-1);
    for (size_t j=0; j < sizeof(priorities)/sizeof(priorities[0]); ++j)
    {
        LOG(priorities[j], "LOG_LEVEL=-1, message level %s (%d)",
            LOG_LEVEL_TEXT[priorities[j]], priorities[j]);
    }
    ERR_LOG(EACCES, NULL, "LOG_LEVEL=-1, ERR_LOG(EACCES, NULL), %d", EACCES);
    char buf[ERROR_BUF_SIZE];
    ERR_LOG(EINVAL, buf, "LOG_LEVEL=-1, ERR_LOG(EINVAL, buf), %d", EINVAL);

    SET_LOG_LEVEL(saved_log_level);

    FLUSH_LOG();
    CLOSE_LOG();

    // make these bigger than ERROR_BUF_SIZE to detect truncation
    char eacces_msg[2*ERROR_BUF_SIZE] = {0};
    char einval_msg[2*ERROR_BUF_SIZE] = {0};
    int err;
    err = strerror_r(EACCES, eacces_msg, sizeof(eacces_msg));
    assert(!err);
    err = strerror_r(EINVAL, einval_msg, sizeof(einval_msg));
    assert(!err);

    char expected[sizeof(logbuf)] = {0};
    xsnprintf(
        expected, sizeof(expected),
        PACKAGE_NAME "-logging-test DEBUG: " __FILE__ ":87 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), message level DEBUG (7)\n"
        PACKAGE_NAME "-logging-test INFO: " __FILE__ ":87 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), message level INFO (6)\n"
        PACKAGE_NAME "-logging-test NOTICE: " __FILE__ ":87 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), message level NOTICE (5)\n"
        PACKAGE_NAME "-logging-test WARN: " __FILE__ ":87 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), message level WARN (4)\n"
        PACKAGE_NAME "-logging-test ERR: " __FILE__ ":87 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), message level ERR (3)\n"
        PACKAGE_NAME "-logging-test CRIT: " __FILE__ ":87 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), message level CRIT (2)\n"
        PACKAGE_NAME "-logging-test ALERT: " __FILE__ ":87 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), message level ALERT (1)\n"
        PACKAGE_NAME "-logging-test EMERG: " __FILE__ ":87 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), message level EMERG (0)\n"
        PACKAGE_NAME "-logging-test ERR: " __FILE__ ":90 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), ERR_LOG(EACCES, NULL), %d: %s\n"
        PACKAGE_NAME "-logging-test ERR: " __FILE__ ":93 in test_logging(): "
        "LOG_LEVEL=DEBUG (7), ERR_LOG(EINVAL, buf), %d: %s\n"
        PACKAGE_NAME "-logging-test INFO: "
        "LOG_LEVEL=INFO (6), message level INFO (6)\n"
        PACKAGE_NAME "-logging-test NOTICE: "
        "LOG_LEVEL=INFO (6), message level NOTICE (5)\n"
        PACKAGE_NAME "-logging-test WARN: "
        "LOG_LEVEL=INFO (6), message level WARN (4)\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=INFO (6), message level ERR (3)\n"
        PACKAGE_NAME "-logging-test CRIT: "
        "LOG_LEVEL=INFO (6), message level CRIT (2)\n"
        PACKAGE_NAME "-logging-test ALERT: "
        "LOG_LEVEL=INFO (6), message level ALERT (1)\n"
        PACKAGE_NAME "-logging-test EMERG: "
        "LOG_LEVEL=INFO (6), message level EMERG (0)\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=INFO (6), ERR_LOG(EACCES, NULL), %d: %s\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=INFO (6), ERR_LOG(EINVAL, buf), %d: %s\n"
        PACKAGE_NAME "-logging-test NOTICE: "
        "LOG_LEVEL=NOTICE (5), message level NOTICE (5)\n"
        PACKAGE_NAME "-logging-test WARN: "
        "LOG_LEVEL=NOTICE (5), message level WARN (4)\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=NOTICE (5), message level ERR (3)\n"
        PACKAGE_NAME "-logging-test CRIT: "
        "LOG_LEVEL=NOTICE (5), message level CRIT (2)\n"
        PACKAGE_NAME "-logging-test ALERT: "
        "LOG_LEVEL=NOTICE (5), message level ALERT (1)\n"
        PACKAGE_NAME "-logging-test EMERG: "
        "LOG_LEVEL=NOTICE (5), message level EMERG (0)\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=NOTICE (5), ERR_LOG(EACCES, NULL), %d: %s\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=NOTICE (5), ERR_LOG(EINVAL, buf), %d: %s\n"
        PACKAGE_NAME "-logging-test WARN: "
        "LOG_LEVEL=WARN (4), message level WARN (4)\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=WARN (4), message level ERR (3)\n"
        PACKAGE_NAME "-logging-test CRIT: "
        "LOG_LEVEL=WARN (4), message level CRIT (2)\n"
        PACKAGE_NAME "-logging-test ALERT: "
        "LOG_LEVEL=WARN (4), message level ALERT (1)\n"
        PACKAGE_NAME "-logging-test EMERG: "
        "LOG_LEVEL=WARN (4), message level EMERG (0)\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=WARN (4), ERR_LOG(EACCES, NULL), %d: %s\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=WARN (4), ERR_LOG(EINVAL, buf), %d: %s\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=ERR (3), message level ERR (3)\n"
        PACKAGE_NAME "-logging-test CRIT: "
        "LOG_LEVEL=ERR (3), message level CRIT (2)\n"
        PACKAGE_NAME "-logging-test ALERT: "
        "LOG_LEVEL=ERR (3), message level ALERT (1)\n"
        PACKAGE_NAME "-logging-test EMERG: "
        "LOG_LEVEL=ERR (3), message level EMERG (0)\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=ERR (3), ERR_LOG(EACCES, NULL), %d: %s\n"
        PACKAGE_NAME "-logging-test ERR: "
        "LOG_LEVEL=ERR (3), ERR_LOG(EINVAL, buf), %d: %s\n"
        PACKAGE_NAME "-logging-test CRIT: "
        "LOG_LEVEL=CRIT (2), message level CRIT (2)\n"
        PACKAGE_NAME "-logging-test ALERT: "
        "LOG_LEVEL=CRIT (2), message level ALERT (1)\n"
        PACKAGE_NAME "-logging-test EMERG: "
        "LOG_LEVEL=CRIT (2), message level EMERG (0)\n"
        PACKAGE_NAME "-logging-test ALERT: "
        "LOG_LEVEL=ALERT (1), message level ALERT (1)\n"
        PACKAGE_NAME "-logging-test EMERG: "
        "LOG_LEVEL=ALERT (1), message level EMERG (0)\n"
        PACKAGE_NAME "-logging-test EMERG: "
        "LOG_LEVEL=EMERG (0), message level EMERG (0)\n"
        , EACCES, eacces_msg, EINVAL, einval_msg
        , EACCES, eacces_msg, EINVAL, einval_msg
        , EACCES, eacces_msg, EINVAL, einval_msg
        , EACCES, eacces_msg, EINVAL, einval_msg
        , EACCES, eacces_msg, EINVAL, einval_msg);

    TEST_STR(expected, ==, logbuf);
    TEST_STR(strerror(EINVAL), ==, buf);
    TEST(_Bool, "%d", 1, ==, flushed);
    TEST(_Bool, "%d", 1, ==, closed);

    return 1;
}

int
main(
    int argc,
    char *argv[])
{
    (void)argc;
    (void)argv;

    return test_logging() ? EXIT_SUCCESS : EXIT_FAILURE;
}
