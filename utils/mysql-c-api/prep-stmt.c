#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "logging.h"
#include "prep-stmt.h"
#include "rtr.h"
#include "util.h"


/**=============================================================================
 * @ret 0 on success, -1 on error.
------------------------------------------------------------------------------*/
int stmtNodesAddNode(conn *connp,
        struct stmt_node **node,
        char *qry) {
    MYSQL *mysqlp = connp->mysqlp;
    MYSQL_STMT *stmt = NULL;

    if ((stmt = mysql_stmt_init(mysqlp)) == NULL) {
        LOG(LOG_ERR, "could not alloc for prepared statement");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        return (-1);
    }

    if (mysql_stmt_prepare(stmt, qry, strlen(qry))) {
        LOG(LOG_ERR, "error preparing statement");
        LOG(LOG_ERR, "    %u: %s\n", mysql_errno(mysqlp), mysql_error(mysqlp));
        mysql_stmt_close(stmt);
        return (-1);
    }

    (*node)->stmt = stmt;
    (*node)->next = connp->head->next;
    connp->head->next = *node;

    return (0);
}


/**=============================================================================
------------------------------------------------------------------------------*/
int stmtNodesGetStmt(MYSQL_STMT **stmt, conn *connp, int client_type, int qry_num) {
    struct stmt_node *node;
    int found_it = 0;
    (void) stmt;  // to avoid -Wunused-parameter

    node = connp->head;
    while ((node = node->next) != NULL) {
        if (node->client_flags == client_type  &&  node->qry_num == qry_num) {
            *stmt = node->stmt;
            found_it = 1;
            break;
        }
    }

    if (found_it)
        return (0);
    else
        return(-1);
}


/**=============================================================================
 * @ret number of nodes deleted.
------------------------------------------------------------------------------*/
int stmtNodesDeleteNode(struct stmt_node *head) {
    int num_nodes_deleted = 0;
    struct stmt_node *tmp;

    if (head->next != NULL) {
        mysql_stmt_close(head->next->stmt);
        tmp = head->next;
        head->next = tmp->next;
        free(tmp);
    }

    return (num_nodes_deleted);
}
/**=============================================================================
 * @ret number of nodes deleted.
------------------------------------------------------------------------------*/
int stmtNodesDeleteAll(conn *connp) {
    int num_nodes_deleted = 0;
    int ret = 0;

    while (1) {
        ret = stmtNodesDeleteNode(connp->head);
        if (ret == -1)
            return (-1);
        if (ret > 0)
            num_nodes_deleted += ret;
        if (ret == 0)
            return (num_nodes_deleted);
    }

    return (-1);
}
