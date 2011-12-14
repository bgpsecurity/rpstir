#include <my_global.h>
#include <mysql.h>

#include "connect.h"
#include "logging.h"
#include "prep-stmt.h"
#include "prep-stmt-rtr.h"


/**=============================================================================
------------------------------------------------------------------------------*/
int stmtsCreateAllRtr(conn *connp) {
    int i;
    struct stmt_node *node;

    // Note:  keep in sync with enum in header file
    char *qrys[] = {
            "select cache_nonce from rtr_nonce",
            "select serial_num from rtr_update order by create_time desc limit 1",
            "select count(*) from ?"
    };

    for (i = 0; i < DB_PSTMT_RTR_NUM_STMTS; i++) {
        // create the node
        node = malloc(sizeof(node));
        if (!node) {
            LOG(LOG_ERR, "could not alloc for node");
            return (-1);
        }
        node->client_flags = DB_CLIENT_RTR;
        node->next = NULL;
        node->qry_num = i;
        node->stmt = NULL;

        // add the stmt to the node, and the node to the linked list
        stmtNodesAddNode(connp, &node, qrys[i]);
        // TODO:  check ret
    }

    return (0);
}
