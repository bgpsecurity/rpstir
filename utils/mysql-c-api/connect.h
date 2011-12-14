#ifndef DB_CONNECT_H
#define DB_CONNECT_H


#include <inttypes.h>

#include <my_global.h>
#include <mysql.h>


enum client_flags {
    DB_CLIENT_RTR = 1
    // assign DB_CLIENT_NEXT = 2 * DB_CLIENT_PREV
};

//typedef struct connection conn;
typedef struct connection {
    MYSQL *mysqlp;
    int client_flags;
    struct stmt_node *head;
} conn;


void *connectDb(
        int client_flags,
        const char *host,
        const char *user,
        const char *pass,
        const char *db);

void *connectDbDefault(int client_flags);

void disconnectDb(void *connp);


#endif // DB_CONNECT_H
