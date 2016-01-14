#ifndef _DB_UTIL_H
#define _DB_UTIL_H

#include <inttypes.h>

#include <my_global.h>
#include <mysql.h>
#include <errmsg.h>

#include "connect.h"


/**=============================================================================
 * @note This function may alter error values, so the caller should not use
 *     mysql_stmt_errno(), nor mysql_stmt_error().
------------------------------------------------------------------------------*/
int wrap_mysql_stmt_execute(
    dbconn *conn,
    MYSQL_STMT *stmt,
    const char *err_msg_in);

int getStringByFieldname(
    char **out,
    MYSQL_RES *result,
    MYSQL_ROW row,
    char field_name[]);

/**
 * @brief Parameterized SQL expression to test a field containing
 *     binary flags.
 *
 * @param[in] field Name of the SQL field to test.
 */
#define FLAG_TESTS_EXPRESSION(field) \
    "(" field " & ? = ?)"

/**
 * @brief Number of parameters introduced by #FLAG_TESTS_EXPRESSION.
 */
#define FLAG_TESTS_PARAMETERS 2

/**
 * @brief Structure to describe multiple binary flag tests.
 */
struct flag_tests
{
    /**
     * @brief Bit mask for the flags field.
     */
    unsigned long long mask;

    /**
     * @brief Result required when ANDing the field with #mask.
     */
    unsigned long long result;
};

/**
 * @brief Initialize flag tests to an empty set of tests.
 */
void flag_tests_empty(
    struct flag_tests *tests);

/**
 * @brief Initialize flag tests to the runtime default.
 *
 * This function sets the appropriate tests as determined by the
 * program's configuration. See #addQueryFlagTests for the older
 * version of this.
 */
void flag_tests_default(
    struct flag_tests *tests);

/**
 * @brief Add a single test to the flag tests.
 *
 * @param[in,out] tests Tests to add to.
 * @param[in] flag Which flag to test. This must be >= 0 and < 64.
 * @param[in] isset Whether the flag must be set (1) or clear (0).
 */
void flag_tests_add_test_by_index(
    struct flag_tests *tests,
    uint_fast16_t flag,
    bool isset);

/**
 * @brief Add one or more tests to the flag tests.
 *
 * @param[in,out] tests Tests to add to.
 * @param[in] mask A bitmask of flags to test.
 * @param[in] isset Whether the flags must be set (1) or clear (0).
 */
void flag_tests_add_tests_by_mask(
    struct flag_tests *tests,
    unsigned long long mask,
    bool isset);

/**
 * @brief Fill in query parameters for the specified tests.
 *
 * The query being bound must contain #FLAG_TESTS_EXPRESSION, and
 * @p parameters must point into the input binding array at the point
 * where #FLAG_TESTS_EXPRESSION starts. #FLAG_TESTS_PARAMETERS
 * parameters will be written to the binding array.
 */
void flag_tests_bind(
    MYSQL_BIND *parameters,
    struct flag_tests const *tests);


#endif                          // _DB_UTIL_H
