#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <my_global.h>
#include <my_sys.h>
#include <mysql.h>

#include "connect.h"
#include "db-internal.h"
#include "logging.h"
#include "prep-stmt.h"


/*==============================================================================
------------------------------------------------------------------------------*/
bool db_init() {
    int ret = mysql_library_init(0, NULL, NULL);

    if (ret)
        LOG(LOG_ERR, "could not initialize mysql library");

    return !ret;
}


/*==============================================================================
------------------------------------------------------------------------------*/
void db_close() {
    mysql_library_end();
}


/*==============================================================================
------------------------------------------------------------------------------*/
int reconnectMysqlCApi(dbconn **old_conn) {
    dbconn *conn = *old_conn;
    MYSQL *mysql = conn->mysql;

    stmtNodesDeleteAll(conn);

    // @see MySQL 5.1 Reference Manual, section 20.9.3.49 under
    //     MYSQL_OPT_RECONNECT for the reason for this unusual sequence.
    my_bool reconnect = 0;
    if (mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect)) {
        LOG(LOG_WARNING, " MySQL reconnect option might not be set properly");
    }
    if (!mysql_real_connect(mysql, conn->host, conn->user, conn->pass,
            conn->db, 0, NULL, 0) ) {
        LOG(LOG_ERR, "could not reconnect to MySQL db");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysql), mysql_error(mysql));
        if (mysql) {mysql_close(mysql);}
        return -1;
    }
    if (mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect)) {
        LOG(LOG_WARNING, " MySQL reconnect option might not be set properly");
    }

    // TODO:  check table descriptions

    // add one of these sequences for each DB_CLIENT_*
    if (conn->client_flags  &  DB_CLIENT_RTR) {
        if (stmtsCreateAllRtr(conn) == -1) {
            db_disconnect(conn);
            return -1;
        }
    }

    return 0;
}


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

    // @see MySQL 5.1 Reference Manual, section 20.9.3.49 under
    //     MYSQL_OPT_RECONNECT for the reason for this unusual sequence.
    my_bool reconnect = 0;
    if (mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect)) {
        LOG(LOG_WARNING, " MySQL reconnect option might not be set properly");
    }
    if (!mysql_real_connect(mysql, host, user, pass, db, 0, NULL, 0) ) {
        LOG(LOG_ERR, "could not connect to MySQL db");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysql), mysql_error(mysql));
        if (mysql) {mysql_close(mysql);}
        return NULL;
    }
    if (mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect)) {
        LOG(LOG_WARNING, " MySQL reconnect option might not be set properly");
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
    conn->head->client_type = 0;
    conn->head->next = NULL;
    conn->head->qry_num = -1;
    conn->head->stmt = NULL;

    // store parameters to enable reconnect
    conn->host = strdup(host);
    conn->user = strdup(user);
    conn->pass = strdup(pass);
    conn->db   = strdup(db);
    if (conn->host == NULL  ||  conn->user == NULL ||
            conn->pass == NULL  ||  conn->db == NULL) {
        LOG(LOG_ERR, "could not alloc for strings");
        db_disconnect(conn);
        return NULL;
    }

    // TODO:  check table descriptions

    if (client_flags & ~DB_CLIENT_ALL) {
        LOG(LOG_ERR, "got invalid flags");
        db_disconnect(conn);
        return NULL;
    }

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
    if (conn) {
        if (conn->head) {
            stmtNodesDeleteAll(conn);
            free(conn->head);
            conn->head = NULL;
        }

        mysql_close(conn->mysql);

        free(conn);
    }
}
