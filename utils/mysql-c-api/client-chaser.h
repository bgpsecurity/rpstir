/**
    Functions to access the database for chaser.
*/

#ifndef _UTILS_MYSQL_CHASE_H
#define _UTILS_MYSQL_CHASE_H

#include <stdbool.h>

#include "connect.h"

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
int db_chaser_read_time(dbconn *conn, char *curr, size_t const curr_len);


/**=============================================================================
 * @brief Get rsync URIs from AIAs from the db.
 *
 * The parameters flag_no_chain and flag_validated are not intended to be set
 * to a value by the user before calling.  They are set as macro definitions
 * in the header files scm.h, scmf.h, and sqhl.h.  Using them as parameters is
 * merely a mechanism to pass those values from the header files to the db.
 *
 * @param conn an opaque pointer to a db connection
 * @param[out] results The URI strings.  Caller frees these.
 * @param[out] num_malloced number of pointers malloced in results
 * @param flag_no_chain value of the SCM_FLAG_NOCHAIN macro
 * @param flag_validated value of the SCM_FLAG_VALIDATED macro
 *
 * @ret number of results filled on success
 *     -1 on failure
 *      ERR_CHASER_OOM if out of memory
------------------------------------------------------------------------------*/
int64_t db_chaser_read_aia(dbconn *conn, char ***results,
        int64_t *num_malloced, uint flag_no_chain, uint flag_validated);


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
int64_t db_chaser_read_crldp(dbconn *conn, char ***results,
        int64_t *num_malloced, char const *ts,
        int restrict_by_next_update, uint32_t seconds);

/**=============================================================================
 * @brief Get rsync URIs from SIAs from the db.
 *
 * The parameter validated_flag is not intended to be set
 * to a value by the user before calling.  It is set as macro definition
 * in the header files scm.h, scmf.h, and sqhl.h.  Using it as a parameter is
 * merely a mechanism to pass that value from the header files to the db.
 *
 * On the other hand, the parameter chase_not_yet_validated _is_ intended to
 * be set to a value by the caller in order to influence the behavior of this
 * function.
 *
 * @param conn an opaque pointer to a db connection
 * @param[out] results The URI strings.  Caller frees these.
 * @param[out] num_malloced number of pointers malloced in results
 * @param chase_not_yet_validated if true, retrieve URIs from all SIAs,
 *     else, only retrieve URIs from SIAs of validated certs
 * @param validated_flag value of the SCM_FLAG_VALIDATED macro
 *
 * @ret number of results filled on success
 *     -1 on failure
 *      ERR_CHASER_OOM if out of memory
------------------------------------------------------------------------------*/
int64_t db_chaser_read_sia(dbconn *conn, char ***results,
        int64_t *num_malloced,
        uint chase_not_yet_validated, uint validated_flag);


#endif
