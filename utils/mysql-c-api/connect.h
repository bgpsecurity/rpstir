#ifndef DB_CONNECT_H
#define DB_CONNECT_H


#include <inttypes.h>


enum client_flags {
    DB_CLIENT_RTR = 1
    // assign DB_CLIENT_NEXT = 2 * DB_CLIENT_PREV
};

struct _dbconn;
typedef struct _dbconn dbconn;

dbconn *db_connect(
        int client_flags,
        const char *host,
        const char *user,
        const char *pass,
        const char *db);

dbconn *db_connect_default(int client_flags);

void db_disconnect(dbconn *conn);


#endif // DB_CONNECT_H
