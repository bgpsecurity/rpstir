/**
    Functions to access the database for chaser.
*/

#ifndef _UTILS_MYSQL_CHASE_H
#define _UTILS_MYSQL_CHASE_H

#include <stdbool.h>

#include "db/connect.h"

#define ERR_CHASER_OOM -2
#define DB_URI_LEN 1024

/**=============================================================================
 * @brief Read current time from the db.
 *
 * @param conn an opaque pointer to a db connection
 * @param[out] curr the current time.  Caller handles memory
 * @param curr_len size of curr
 *
 * @ret 0 on success
 *     -1 on failure
------------------------------------------------------------------------------*/
int db_chaser_read_time(
    dbconn * conn,
    char *curr,
    size_t const curr_len);


/**=============================================================================
 * @brief Get rsync URIs from AIAs from the db.
 *
 * @param conn an opaque pointer to a db connection
 * @param[out] results The URI strings.  Caller frees these.
 * @param[out] num_malloced number of pointers malloced in results
 *
 * @ret number of results filled on success
 *     -1 on failure
 *      ERR_CHASER_OOM if out of memory
------------------------------------------------------------------------------*/
int64_t db_chaser_read_aia(
    dbconn * conn,
    char ***results,
    int64_t * num_malloced);


/**=============================================================================
 * @brief Get rsync URIs from CRLDPs from the db.
 *
 * @param conn an opaque pointer to a db connection
 * @param[out] results The URI strings.  Caller frees these.
 * @param[out] num_malloced number of pointers malloced in results
 * @param ts a timestamp of form "0000-00-00 00:00:00"
 * @param seconds number of seconds
 * Retrieve URIs from CRLs whose next-update-time is earlier than ts + seconds
 *
 * @ret number of results filled on success
 *     -1 on failure
 *      ERR_CHASER_OOM if out of memory
------------------------------------------------------------------------------*/
int64_t db_chaser_read_crldp(
    dbconn * conn,
    char ***results,
    int64_t * num_malloced,
    char const *ts,
    int restrict_by_next_update,
    uint32_t seconds);

/**=============================================================================
 * @brief Get rsync URIs from SIAs from the db.
 *
 * @param conn an opaque pointer to a db connection
 * @param[out] results The URI strings.  Caller frees these.
 * @param[out] num_malloced number of pointers malloced in results
 * @param chase_not_yet_validated if true, retrieve URIs from all SIAs,
 *     else, only retrieve URIs from SIAs of validated certs
 *
 * @ret number of results filled on success
 *     -1 on failure
 *      ERR_CHASER_OOM if out of memory
------------------------------------------------------------------------------*/
int64_t db_chaser_read_sia(
    dbconn * conn,
    char ***results,
    int64_t * num_malloced,
    uint chase_not_yet_validated);


#endif
