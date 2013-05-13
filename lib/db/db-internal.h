#ifndef DB_INTERNAL_H_
#define DB_INTERNAL_H_


#include <my_global.h>
#include <mysql.h>

#include "connect.h"


struct _dbconn {
    int client_flags;
    MYSQL_STMT **stmts[DB_CLIENT_NUM_TYPES];    // fixed-length array of
                                                // variable length array of
                                                // (MYSQL_STMT *)
    MYSQL *mysql;
    char *host;
    char *user;
    char *pass;
    char *db;
};


int reconnectMysqlCApi(
    struct _dbconn **old_conn);


#endif                          // DB_INTERNAL_H_
