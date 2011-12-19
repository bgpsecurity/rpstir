#ifndef _DB_UTIL_H
#define _DB_UTIL_H

#include "connect.h"


/**=============================================================================
 * @note This function may alter error values, so the caller should not use
 *     mysql_errno(), nor mysql_error().
------------------------------------------------------------------------------*/
int wrap_mysql_query(dbconn *conn, const char *qry, const char *err_msg_in);


/**=============================================================================
 * @note This function may alter error values, so the caller should not use
 *     mysql_stmt_errno(), nor mysql_stmt_error().
------------------------------------------------------------------------------*/
int wrap_mysql_stmt_execute(dbconn *conn, MYSQL_STMT *stmt, const char *err_msg_in);

int getStringByFieldname(char **out, MYSQL_RES *result, MYSQL_ROW row, char field_name[]);


#endif // _DB_UTIL_H
