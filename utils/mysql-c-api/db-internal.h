#ifndef DB_INTERNAL_H_
#define DB_INTERNAL_H_


#include <my_global.h>
#include <mysql.h>


struct _dbconn {
    int client_flags;
    struct _stmt_node *head;
    MYSQL *mysql;
    char *host;
    char *user;
    char *pass;
    char *db;
};


int reconnectMysqlCApi(struct _dbconn **old_conn);


#endif // DB_INTERNAL_H_
