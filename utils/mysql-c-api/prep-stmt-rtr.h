/**
	Functions used init and close prepared statements for use with the RTR
	    database.
*/

#ifndef UTILS_DB_PREP_STMS_RTR_H
#define UTILS_DB_PREP_STMS_RTR_H


// Note:  keep in sync with array in implementation file
enum prep_stmts_rtr {
    DB_PSTMT_RTR_GET_NONCE,
    DB_PSTMT_RTR_GET_LATEST_SERNUM,
    DB_PSTMT_RTR_GET_NUM_ROWS_IN_TABLE,
//    DB_PSTMT_RTR_READ_SER_NUM_AS_PREV,
//    DB_PSTMT_RTR_READ_SER_NUM_AS_CURRENT,
//    DB_PSTMT_RTR_SERIAL_QRY_GET_NEXT,
//    DB_PSTMT_RTR_RESET_QRY_GET_NEXT,
    DB_PSTMT_RTR_NUM_STMTS
};

int stmtsCreateAllRtr(conn *connp);


#endif  // UTILS_DB_PREP_STMS_RTR_H
