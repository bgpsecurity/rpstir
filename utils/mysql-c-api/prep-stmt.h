/**
@file
*/

#ifndef PREP_STMS_H_
#define PREP_STMS_H_


int stmtAddAll(dbconn *conn);

void stmtDeleteAll(dbconn *conn);

// Note:  keep in sync with array in implementation file
enum prep_stmts_rtr {
    DB_PSTMT_RTR_GET_SESSION,
    DB_PSTMT_RTR_GET_LATEST_SERNUM,
    DB_PSTMT_RTR_HAS_ROWS_RTR_UPDATE,
    DB_PSTMT_RTR_READ_SER_NUM_AS_PREV,
    DB_PSTMT_RTR_READ_SER_NUM_AS_CURRENT,
    DB_PSTMT_RTR_SERIAL_QRY_GET_NEXT,
    DB_PSTMT_RTR_RESET_QRY_GET_NEXT,
};

enum prep_stmts_chaser {
    DB_PSTMT_CHASER_GET_TIME,
    DB_PSTMT_CHASER_WRITE_TIME,
    DB_PSTMT_CHASER_GET_CRLDP,
    DB_PSTMT_CHASER_GET_SIA,
    DB_PSTMT_CHASER_GET_SIA_TRUSTED_ONLY
};


#endif  // PREP_STMS_H_
