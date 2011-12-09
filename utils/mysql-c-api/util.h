#ifndef _DB_UTIL_H
#define _DB_UTIL_H


int getStringByFieldname(char **out, MYSQL_RES *result, MYSQL_ROW row, char field_name[]);


#endif // _DB_UTIL_H
