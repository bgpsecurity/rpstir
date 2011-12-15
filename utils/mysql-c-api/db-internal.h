#ifndef DB_INTERNAL_H_
#define DB_INTERNAL_H_


#include <my_global.h>
#include <mysql.h>


struct _dbconn {
    int client_flags;
    struct _stmt_node *head;
    MYSQL *mysql;
};


#endif // DB_INTERNAL_H_
