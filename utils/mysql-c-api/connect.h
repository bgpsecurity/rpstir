#ifndef DB_CONNECT_H_
#define DB_CONNECT_H_


#include <stdbool.h>


// NOTE: don't use this outside of mysql-c-api, use enum client_flags instead
enum client_types {
    DB_CLIENT_TYPE_RTR = 0,
    // DB_CLIENT_NEXT = 1 + DB_CLIENT_PREV

    DB_CLIENT_TYPES_LENGTH = 1
};

enum client_flags {
    DB_CLIENT_RTR = (1 << DB_CLIENT_TYPE_RTR),

    DB_CLIENT_NONE = 0,
    DB_CLIENT_ALL = DB_CLIENT_RTR /* | DB_CLIENT_OTHER | ... */
};

struct _dbconn;
typedef struct _dbconn dbconn;

/**=============================================================================
 * The order for calling these is
 *     db_init()                         - per program
 *     db_thread_init()                  - per thread
 *     db_connect[_default]()            - per connection
 *     { any other db functions, here }  - per connection
 *     db_disconnect()                   - per connection
 *     db_thread_close()                 - per thread
 *     db_close()                        - per program
 *
 * @ret true if initialization succeeds.
------------------------------------------------------------------------------*/
bool db_init();

void db_close();

bool db_thread_init();

void db_thread_close();

dbconn *db_connect(
        int client_flags,
        const char *host,
        const char *user,
        const char *pass,
        const char *db);

dbconn *db_connect_default(int client_flags);

void db_disconnect(dbconn *conn);


#endif // DB_CONNECT_H_
