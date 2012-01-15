/**
	Functions used for accessing the RTR database.
*/

#ifndef _UTILS_MYSQL_CHASE_H
#define _UTILS_MYSQL_CHASE_H

#include <stdbool.h>

#include "connect.h"


int db_chaser_init(dbconn *conn);

int db_chaser_read_time(dbconn *conn,
        char *prev, size_t const prev_len,
        char *curr, size_t const curr_len);

int db_chaser_write_time(dbconn *conn, char const *ts);

int64_t db_chaser_read_aia(dbconn *conn, char ***results,
        int64_t *num_malloced, int flag_no_chain, int flag_validated);

int64_t db_chaser_read_crldp(dbconn *conn, char ***results,
        int64_t *num_malloced, char const *ts);

int64_t db_chaser_read_sia(dbconn *conn, char ***results,
        int64_t *num_malloced,
        int trusted_only, int trusted_flag);

void db_chaser_close(dbconn *conn);


#endif
