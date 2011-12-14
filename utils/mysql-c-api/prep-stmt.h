/**
@file

Generic functions to init, close prepared stmts.
*/

#ifndef UTILS_DB_PREP_STMS_H
#define UTILS_DB_PREP_STMS_H


struct stmt_node {
    MYSQL_STMT *stmt;
    int client_flags;
    int qry_num;
    struct stmt_node *next;
};

int stmtNodesAddNode(conn *connp,
        struct stmt_node **node,
        char *qry);

int stmtNodesGetStmt(MYSQL_STMT **stmt,
        conn *connp,
        int client_type,
        int qry_num);

int stmtNodesDeleteNode(struct stmt_node *head);

int stmtNodesDeleteAll(conn *connp);


#endif  // UTILS_DB_PREP_STMS_H
