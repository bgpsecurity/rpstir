#ifndef DB_CONNECT_H_
#define DB_CONNECT_H_


#include <stdbool.h>


enum client_flags {
    DB_CLIENT_RTR = 1,
    // assign DB_CLIENT_NEXT = 2 * DB_CLIENT_PREV

    DB_CLIENT_NONE = 0,
    DB_CLIENT_ALL = DB_CLIENT_RTR /* | DB_CLIENT_OTHER | ... */
};

struct _dbconn;
typedef struct _dbconn dbconn;

/**=============================================================================
 * The order for calling these is
 *     db_init()                         - per program
 *     db_connect[_default]()            - per thread
 *     { any other db functions, here }  - per thread
 *     db_disconnect()                   - per thread
 *     db_close()                        - per program
 *
 * @ret true if initialization succeeds.
------------------------------------------------------------------------------*/
bool db_init();

void db_close();

dbconn *db_connect(
        int client_type,
        const char *host,
        const char *user,
        const char *pass,
        const char *db);

dbconn *db_connect_default(int client_flags);

void db_disconnect(dbconn *conn);


#endif // DB_CONNECT_H_
