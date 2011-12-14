#include <ctype.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "connect.h"
#include "prep-stmt.h"
#include "prep-stmt-rtr.h"
#include "logging.h"


//struct connection {
//    MYSQL *mysqlp;
//    uint32_t client_type_flags;
//    struct stmt_node *head;
//};


/*==============================================================================
------------------------------------------------------------------------------*/
static void *connectMysqlCApi(
        int client_flags,
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {
    conn *connp = NULL;
    MYSQL *mysqlp = NULL;

    mysqlp = mysql_init(NULL);
    if (!mysqlp) {
        LOG(LOG_ERR, "insufficient memory to alloc MYSQL object");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (NULL);
    }

    if (!mysql_real_connect(mysqlp, host, user, pass, db, 0, NULL, 0) ) {
        LOG(LOG_ERR, "could not connect to MySQL db");
        LOG(LOG_ERR, "    %u: %s", mysql_errno(mysqlp), mysql_error(mysqlp));
        if (mysqlp) {mysql_close(mysqlp);}
        return (NULL);
    }

    connp = malloc(sizeof(conn));
    if (!connp) {
        LOG(LOG_ERR, "could not alloc for connp" );
        if (mysqlp) {mysql_close(mysqlp);}
        return (NULL);
    }
    connp->client_flags = client_flags;
    connp->mysqlp = mysqlp;
    connp->head = malloc(sizeof(struct stmt_node));
    if (!(connp->head)) {
        LOG(LOG_ERR, "could not alloc for struct stmt_node" );
        if (connp) {free (connp); connp = NULL;}
        if (mysqlp) {mysql_close(mysqlp);}
        return (NULL);
    }
    connp->head->client_flags = 0;
    connp->head->next = NULL;
    connp->head->qry_num = -1;
    connp->head->stmt = NULL;

    // TODO:  check table descriptions

    // add one of these sequences for each DB_CLIENT_*
    if (client_flags  &  DB_CLIENT_RTR) {
        if (stmtsCreateAllRtr(connp) == -1) {
            disconnectDb(connp);
            return (NULL);
        }
    }

    return (connp);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void *connectDb(
        int client_flags,
        const char *host,
        const char *user,
        const char *pass,
        const char *db) {

    return connectMysqlCApi(client_flags, host, user, pass, db);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void *connectDbDefault(int client_flags) {
    const char *host = "localhost";
    const char *user = getenv("RPKI_DBUSER");
    const char *pass = getenv("RPKI_DBPASS");
    const char *db =   getenv("RPKI_DB");

    return connectMysqlCApi(client_flags, host, user, pass, db);
}


/*==============================================================================
------------------------------------------------------------------------------*/
void disconnectDb(conn *connp) {
    stmtNodesDeleteAll(connp);

    if (connp->head) {free(connp->head); connp->head = NULL;}

    mysql_close(connp->mysqlp);
}
