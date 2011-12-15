/**
@file
*/

#ifndef PREP_STMS_H_
#define PREP_STMS_H_


struct _stmt_node {
    int client_flags;
    struct _stmt_node *next;
    int qry_num;
    MYSQL_STMT *stmt;
};
typedef struct _stmt_node stmt_node;

int stmtNodesAddNode(dbconn *conn,
        stmt_node **node,
        char *qry);

int stmtNodesGetStmt(MYSQL_STMT **stmt,
        dbconn *conn,
        int client_type,
        int qry_num);

int stmtNodesDeleteNode(stmt_node *head);

int stmtNodesDeleteAll(dbconn *conn);

// Note:  keep in sync with array in implementation file
enum prep_stmts_rtr {
    DB_PSTMT_RTR_GET_NONCE,
    DB_PSTMT_RTR_GET_LATEST_SERNUM,
//    DB_PSTMT_RTR_GET_NUM_ROWS_IN_TABLE,
//    DB_PSTMT_RTR_READ_SER_NUM_AS_PREV,
//    DB_PSTMT_RTR_READ_SER_NUM_AS_CURRENT,
//    DB_PSTMT_RTR_SERIAL_QRY_GET_NEXT,
//    DB_PSTMT_RTR_RESET_QRY_GET_NEXT,
    DB_PSTMT_RTR_NUM_STMTS
};

int stmtsCreateAllRtr(dbconn *conn);


#endif  // PREP_STMS_H_
