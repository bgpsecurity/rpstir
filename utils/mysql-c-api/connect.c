#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "connect.h"
#include "db-internal.h"
#include "logging.h"
#include "prep-stmt.h"


/*==============================================================================
------------------------------------------------------------------------------*/
static void *connectMysqlCApi(
        int client_flags,
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {
    dbconn *conn = NULL;
    MYSQL *mysql = NULL;

    mysql = mysql_init(NULL);
    if (!mysql) {
        LOG(LOG_ERR, "insufficient memory to alloc MYSQL object");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysql), mysql_error(mysql));
        return NULL;
    }

    if (!mysql_real_connect(mysql, host, user, pass, db, 0, NULL, 0) ) {
        LOG(LOG_ERR, "could not connect to MySQL db");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysql), mysql_error(mysql));
        if (mysql) {mysql_close(mysql);}
        return NULL;
    }

    conn = malloc(sizeof(dbconn));
    if (!conn) {
        LOG(LOG_ERR, "could not alloc for conn" );
        if (mysql) {mysql_close(mysql);}
        return NULL;
    }
    conn->client_flags = client_flags;
    conn->mysql = mysql;
    conn->head = malloc(sizeof(struct _stmt_node));
    if (!(conn->head)) {
        LOG(LOG_ERR, "could not alloc for struct stmt_node" );
        if (conn) {free (conn); conn = NULL;}
        if (mysql) {mysql_close(mysql);}
        return NULL;
    }
    conn->head->client_flags = 0;
    conn->head->next = NULL;
    conn->head->qry_num = -1;
    conn->head->stmt = NULL;

    // TODO:  check table descriptions

    // add one of these sequences for each DB_CLIENT_*
    if (client_flags  &  DB_CLIENT_RTR) {
        if (stmtsCreateAllRtr(conn) == -1) {
            db_disconnect(conn);
            return NULL;
        }
    }

    return conn;
}


/*==============================================================================
------------------------------------------------------------------------------*/
dbconn *db_connect(
        int client_flags,
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {

    return connectMysqlCApi(client_flags, host, user, pass, db);
}


/*==============================================================================
------------------------------------------------------------------------------*/
dbconn *db_connect_default(int client_flags) {
    const char *host = "localhost";
    const char *user = getenv("RPKI_DBUSER");
    const char *pass = getenv("RPKI_DBPASS");
    const char *db =   getenv("RPKI_DB");

    return connectMysqlCApi(client_flags, host, user, pass, db);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void db_disconnect(dbconn *conn) {
    stmtNodesDeleteAll(conn);

    if (conn->head) {free(conn->head); conn->head = NULL;}

    mysql_close(conn->mysql);

    if (conn) {free(conn);}
}
