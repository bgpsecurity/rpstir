#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "logging.h"


/*==============================================================================
------------------------------------------------------------------------------*/
static void *connectMysqlCApi(
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {
    MYSQL *mysqlp = NULL;

    mysqlp = (MYSQL*) calloc(1, sizeof(MYSQL));
    if (!mysqlp) {
        LOG(LOG_ERR, "could not alloc for MYSQL" );
        return (NULL);
    }

    if (!mysql_init(mysqlp)) {
        LOG(LOG_ERR, "insufficient memory to alloc MYSQL object");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysqlp), mysql_error(mysqlp));
        if (mysqlp) {
            free (mysqlp);
            mysqlp = NULL;
        }
        return (NULL);
    }

    if (!mysql_real_connect(mysqlp, host, user, pass, db, 0, NULL, 0) ) {
        LOG(LOG_ERR, "could not connect to MySQL db");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysqlp), mysql_error(mysqlp));
        if (mysqlp) {
            free (mysqlp);
            mysqlp = NULL;
        }
        return (NULL);
    }

    return (mysqlp);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void *connectDb(
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {

    return connectMysqlCApi(host, user, pass, db);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void *connectDbDefault() {
    const char *host = "localhost";
    const char *user = getenv("RPKI_DBUSER");
    const char *pass = getenv("RPKI_DBPASS");
    const char *db =   getenv("RPKI_DB");

    return connectMysqlCApi(host, user, pass, db);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void disconnectDb(void *connp) {
    mysql_close((MYSQL *) connp);
}
