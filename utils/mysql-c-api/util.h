#ifndef _DB_UTIL_H
#define _DB_UTIL_H

#include "connect.h"


int wrap_mysql_query(dbconn *conn, const char *qry);

int wrap_mysql_stmt_execute(dbconn *conn, MYSQL_STMT *stmt);

int getStringByFieldname(char **out, MYSQL_RES *result, MYSQL_ROW row, char field_name[]);


#endif // _DB_UTIL_H
