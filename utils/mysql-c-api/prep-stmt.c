#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "db-internal.h"
#include "logging.h"
#include "prep-stmt.h"
#include "rtr.h"
#include "util.h"


/**=============================================================================
 * @ret 0 on success, -1 on error.
------------------------------------------------------------------------------*/
int stmtNodesAddNode(dbconn *conn,
        struct _stmt_node **node,
        char *qry) {
    MYSQL *mysql = conn->mysql;
    MYSQL_STMT *stmt = NULL;

    if ((stmt = mysql_stmt_init(mysql)) == NULL) {
        LOG(LOG_ERR, "could not alloc for prepared statement");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        return -1;
    }

    if (mysql_stmt_prepare(stmt, qry, strlen(qry))) {
        LOG(LOG_ERR, "error preparing statement");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysql), mysql_error(mysql));
        mysql_stmt_close(stmt);
        return -1;
    }

    (*node)->stmt = stmt;
    (*node)->next = conn->head->next;
    conn->head->next = *node;

    return 0;
}


/**=============================================================================
 * @ret 0 if stmt found and returned, -1 otherwise.
------------------------------------------------------------------------------*/
int stmtNodesGetStmt(MYSQL_STMT **stmt, dbconn *conn, int client_type, int qry_num) {
    stmt_node *node;
    int found_it = 0;
    (void) stmt;  // to avoid -Wunused-parameter

    node = conn->head;
    while ((node = node->next) != NULL) {
        if (node->client_flags == client_type  &&  node->qry_num == qry_num) {
            *stmt = node->stmt;
            found_it = 1;
            break;
        }
    }

    if (found_it)
        return 0;
    else
        return -1;
}


/**=============================================================================
 * @ret number of nodes deleted.
------------------------------------------------------------------------------*/
int stmtNodesDeleteNode(struct _stmt_node *head) {
    int num_nodes_deleted = 0;
    stmt_node *tmp;

    if (head->next != NULL) {
        mysql_stmt_close(head->next->stmt);
        tmp = head->next;
        head->next = tmp->next;
        free(tmp);
        num_nodes_deleted++;
    }

    return num_nodes_deleted;
}
/**=============================================================================
 * @ret number of nodes deleted.
------------------------------------------------------------------------------*/
int stmtNodesDeleteAll(dbconn *conn) {
    int num_nodes_deleted = 0;
    int ret = 0;

    while (1) {
        ret = stmtNodesDeleteNode(conn->head);
        if (ret > 0)
            num_nodes_deleted += ret;
        if (ret == 0)
            return num_nodes_deleted;
    }

    return 0;
}


/**=============================================================================
------------------------------------------------------------------------------*/
int stmtsCreateAllRtr(dbconn *conn) {
    int i;
    int ret;
    stmt_node *node;

    // Note:  keep in sync with enum in header file
    char *qrys[] = {
            "select cache_nonce from rtr_nonce",

            "select serial_num from rtr_update order by create_time desc limit 1",

            "select asn, ip_addr, is_announce "
            " from rtr_incremental "
            " where serial_num=? "
            " order by asn, ip_addr "
            " limit ?, ?"
//            "select count(*) from ?"
    };

    for (i = 0; i < DB_PSTMT_RTR_NUM_STMTS; i++) {
        // create the node
        node = malloc(sizeof(stmt_node));
        if (!node) {
            LOG(LOG_ERR, "could not alloc for struct stmt_node");
            return -1;
        }
        node->client_flags = DB_CLIENT_RTR;
        node->next = NULL;
        node->qry_num = i;
        node->stmt = NULL;

        // add the stmt to the node, and the node to the linked list
        ret = stmtNodesAddNode(conn, &node, qrys[i]);
        if (ret) {
            free(node);
            return -1;
        }
    }

    return 0;
}
