/**
    Functions to access the database for chaser.
*/

#ifndef _UTILS_MYSQL_CHASE_H
#define _UTILS_MYSQL_CHASE_H

#include <stdbool.h>

#include "connect.h"

#define OUT_OF_MEMORY -2
#define DB_URI_LEN 1024


int db_chaser_read_time(dbconn *conn, char *curr, size_t const curr_len);

int64_t db_chaser_read_aia(dbconn *conn, char ***results,
        int64_t *num_malloced, uint flag_no_chain, uint flag_validated);

int64_t db_chaser_read_crldp(dbconn *conn, char ***results,
        int64_t *num_malloced, char const *ts,
        int restrict_by_next_update, size_t hours);

int64_t db_chaser_read_sia(dbconn *conn, char ***results,
        int64_t *num_malloced,
        uint chase_not_yet_validated, uint validated_flag);


#endif
