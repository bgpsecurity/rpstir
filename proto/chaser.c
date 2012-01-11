/**
 * This is the chaser program, which tracks down all the URIs of all the
 * authorities that have signed certs.  It outputs the URIs to stdout.
 *
 * yet to do:
 * - check all return values.  free memory before any quit
 * - check how we define subsume.  Andrew:
 *       The real definition is this: A subsumes B if "rsync --recursive"
 *       on A automatically retrieves B.  This usually happens when A is a
 *       directory and B lives within it or within a subdirectory.
 * - implement chase-not-yet-validated
 * - check uri for validity before adding to list
 * - coordinate return values with caller
 * - consider OOM killer in notes about `man realloc`
 *
 * test cases:
 * - is x subsumed by y?
 * - are trailing chars removed?
 * - are bad chars warned, removed?
 * - correct output for -a, -c, -s, -t, -y combinations?
 * - can crafted bad uri crash the program?  or get thru?
 * - start from very small array size to test realloc of uris
 * - add multiple uris that are semicolon delimited on a single line
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "err.h"
#include "logging.h"
#include "mysql-c-api/connect.h"
#include "mysql-c-api/client-chaser.h"

#define CHASER_LOG_IDENT PACKAGE_NAME "-chaser"
#define CHASER_LOG_FACILITY LOG_DAEMON


static char    **uris = NULL;
//static size_t  uris_max_sz = 1024 * 1024;
static size_t  uris_max_sz = 2;
static size_t  num_uris = 0;

static size_t const TS_LEN = 20;  // "0000-00-00 00:00:00" plus '\0'
static char *timestamp_prev;
static char *timestamp_curr;
static char const * const  RSYNC_SCHEME = "rsync://";


/**=============================================================================
 * @note This function only does a string comparison, not a file lookup.
 * @ret 1 if str2 is a file or directory under str1.
 *      0 otherwise.
------------------------------------------------------------------------------*/
static int is_subsumed (const char *str1, const char *str2) {
    if (!str1)
        return 0;

    if (strncmp (str1, str2, strlen (str1)) != 0)
        return 0;
    if (strlen (str1) == strlen (str2))
        return 1;
    if (str1 [strlen(str1) - 1] == '/')
        return 1;
    if (str2 [strlen(str1)] == '/')
        return 1;

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static void free_uris() {
    if (!uris)
        return;

    while (num_uris) {
        if (uris[num_uris]) {
            free(uris[num_uris]);
        }
        uris[num_uris] = NULL;
        num_uris--;
    }
    if (uris[0]) {
        free(uris[0]);
    }
    uris[0] = NULL;

    free(uris);
}


/**=============================================================================
 * callback function for searchscm that just notes that parent exists
------------------------------------------------------------------------------*/
/*static int foundIt(scmcon *conp, scmsrcha *s, int numLine) {
    (void) conp; (void) numLine;  // silence compiler warnings
    parentCount++;
    return 0;
}*/

/**=============================================================================
 * @note caller frees param "in"
 * TODO:  handle returns from this function
 * TODO:  handle semi-colon separated uris
------------------------------------------------------------------------------*/
static int append_uri(char *in) {
    if (!in) {
        LOG(LOG_ERR, "bad input\n");
        return -1;
    }

    // check if array is big enough
    if (num_uris == uris_max_sz) {
        uris_max_sz *= 1.6;
        uris = (char **) realloc(uris, uris_max_sz * sizeof(char *));
        if (!uris) {
            LOG(LOG_ERR, "Could not realloc for uris");
            return -2;
        }
    }

    char *start = in;

    // trim leading space and quote
    size_t len = strlen(start);
    while ((' ' == start[0]  ||  '\'' == start[0]  ||  '"' == start[0])
            &&  len > 0) {
        start += 1;
        len--;
    }

    // trim rsync scheme
    size_t len_scheme = strlen(RSYNC_SCHEME);
    if (!strncmp(RSYNC_SCHEME, start, len)) {
        start += len_scheme;
    }

    // trim trailing space and newline
    len = strlen(start);
    while ((' ' == start[0]  ||  '\n' == start[len - 1])  &&  len > 0) {
        start[len - 1] = '\0';
        len--;
    }

    // an arbitrary limit
    if (len < 10) {
        LOG(LOG_DEBUG, "skipping input:  %s", in);
        return 0;
    }

    uris[num_uris] = strdup(start);
    if (!uris[num_uris]) {
        LOG(LOG_ERR, "Could not alloc for uri");
        return -2;
    }
    num_uris++;

    return 0;
}

/**=============================================================================
 * @note Add aia field if cert has no parent.
 *
 * sql:  select aki, aia from rpki_cert where flags matches SCM_FLAG_NOCHAIN;
------------------------------------------------------------------------------*/
static int query_aia(dbconn *conn) {
/*    scmtab   *table = NULL;
    scmsrcha *srcha;
    size_t const NUM_FIELDS = 2;
    scmsrch  srch[NUM_FIELDS];
    ulong    context_field = 0;
    int      status;
    char     msg[1024];

    srcha = newsrchscm(NULL, NUM_FIELDS, 0, 0);

    table = findtablescm(scmp, "certificate");
    if (table == NULL) {
        LOG(LOG_ERR, "Cannot find table metadata\n");
        return -1;
    }

    srcha->vec = srch;
    srcha->sname = NULL;
    srcha->ntot = 2;
    srcha->where = NULL;
    srcha->wherestr = NULL;
    srcha->context = &context_field;
    srcha->nused = 0;
    srcha->vald = 0;
    msg[0] = 0;
    addFlagTest(msg, SCM_FLAG_NOCHAIN, 1, 0);
    addcolsrchscm(srcha, "aki", SQL_C_CHAR, SKISIZE);
    addcolsrchscm(srcha, "aia", SQL_C_CHAR, SIASIZE);
    status = searchscm(connect, table, srcha, NULL, handleAIAResults,
            SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (status != ERR_SCM_NOERR) {
        LOG(LOG_ERR, "Error chasing AIAs: %s (%d)",
                err2string(status), status);
        freesrchscm(srcha);
        return -1;
    }

    freesrchscm(srcha);
*/
    return 0;
}

/**=============================================================================
 * @note Get CRLDP info from db.
 *
 * add crldp field if cert either has no crl or crl is out-of-date
 * sql:  select crldp from rpki_cert left join rpki_crl
 *       on rpki_cert.aki = rpki_crl.aki
 *       where rpki_crl.filename is null or rpki_crl.next_upd < timestamp_curr;
------------------------------------------------------------------------------*/
static int query_crldp(dbconn *db) {
    char **results = NULL;
    int64_t num_malloced = 0;
    int64_t ret;
    int64_t i;

    ret = db_chaser_read_crldp(db, &results, &num_malloced, timestamp_curr);
    LOG(LOG_DEBUG, "read %" PRIi64 " lines from db;  %" PRIi64 " were null",
            num_malloced, num_malloced - ret);
    if (ret == -1) {
        return -1;
    } else {
        for (i = 0; i < ret; i++) {
            fprintf(stderr, "%s\n", results[i]);
            append_uri(results[i]);
            free(results[i]);
            results[i] = NULL;
        }
        if (results) free(results);
    }

    return 0;
}

/**=============================================================================
 * @note Add sia field.
 *
 * sql:  select sia from rpki_cert;
------------------------------------------------------------------------------*/
static int query_sia(dbconn *db, int trusted_only) {
/*    scmtab   *table = NULL;
    scmsrcha *srcha;
    size_t const NUM_FIELDS = 1;
    scmsrch  srch[NUM_FIELDS];
    ulong    context_field = 0;
    int      status;

    srcha = newsrchscm(NULL, NUM_FIELDS, 0, 0);

    table = findtablescm(scmp, "certificate");
    if (table == NULL) {
        LOG(LOG_ERR, "Cannot find table metadata\n");
        return -1;
    }

    srcha->vec = srch;
    srcha->sname = NULL;
    srcha->ntot = 2;
    srcha->where = NULL;
    srcha->wherestr = NULL;
    srcha->context = &context_field;
    srcha->nused = 0;
    srcha->vald = 0;
    addcolsrchscm(srcha, "sia", SQL_C_CHAR, SIASIZE);
    status = searchscm(connect, table, srcha, NULL, handleSIAResults,
            SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (status != ERR_SCM_NOERR) {
        LOG(LOG_ERR, "Error chasing SIAs: %s (%d)",
                err2string(status), status);
        freesrchscm(srcha);
        return -1;
    }

    freesrchscm(srcha);
*/
    return 0;
}

/**=============================================================================
 * @note Get the current time, and read the last time chaser ran from db.
 *
 * sql:  select current_timestamp, ch_last from rpki_metadata;
------------------------------------------------------------------------------*/
static int query_read_timestamps(dbconn *db) {
    int ret;

    ret = db_chaser_read_time(db,
            timestamp_prev, TS_LEN,
            timestamp_curr, TS_LEN);
    if (ret) {
        LOG(LOG_ERR, "didn't read times");
        // TODO:  handle the error
        return -1;
    }

    LOG(LOG_DEBUG, "previous ts:  %s", timestamp_prev);
    LOG(LOG_DEBUG, " current ts:  %s", timestamp_curr);

    return 0;
}

/**=============================================================================
 * @note Write timestamp to db.
 *
 * sql:  update rpki_metadata set ch_last = current time;
------------------------------------------------------------------------------*/
static int query_write_timestamp(dbconn *db) {
    int ret;

    ret = db_chaser_write_time(db, timestamp_curr);
    if (ret) {
        LOG(LOG_ERR, "didn't write time");
        // TODO:  handle the error
        return -1;
    }

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int printUsage() {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  -a          chase AIAs, default = don't chase AIAs\n");
    fprintf(stderr, "  -c          do not chase CRLDPs, default = chase CRLDPs\n");
    fprintf(stderr, "  -f filename configuration file\n");
    fprintf(stderr, "  -s          do not chase SIAs, default = chase SIAs\n");
    fprintf(stderr, "  -t          chase only Trust Anchor URIs from the database\n");
    fprintf(stderr, "                  default = don't chase only TAs\n");
    fprintf(stderr, "                  overrides options:  acsy\n");
    fprintf(stderr, "  -y          chase not-yet-validated, default = don't chase not-yet-validated\n");
    fprintf(stderr, "  -h          this help listing\n");
    return -1;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int compare_str_p(const void *p1, const void *p2) {
    return strcmp(*(char* const *) p1, *(char* const *) p2);
}

/**=============================================================================
------------------------------------------------------------------------------*/
int main(int argc, char **argv) {
    int chase_aia = 0;
    int chase_crldp = 1;
    int chase_sia = 1;
    int chase_only_ta = 0;
    int chase_not_yet_validated = 0;
    int load_uris_from_file = 0;

    char   *config_file = "initial_chaser.config";
    FILE   *fp;

    char   msg[1024];  // temp string storage
    size_t i;

    // parse the command-line flags
    int ch;
    while ((ch = getopt(argc, argv, "acf:styh")) != -1) {
        switch (ch) {
        case 'a':
            chase_aia = 1;
            break;
        case 'c':
            chase_crldp = 0;
            break;
        case 'f':
            load_uris_from_file = 1;
            config_file = optarg;
            break;
        case 's':
            chase_sia = 0;
            break;
        case 't':
            chase_only_ta = 1;
            break;
        case 'y':
            // TODO:  implement this in queries
            chase_not_yet_validated = 1;
            break;
        case 'h':
        default:
            return printUsage();
        }
    }

    OPEN_LOG(CHASER_LOG_IDENT, CHASER_LOG_FACILITY);
    (void) setbuf(stdout, NULL);
    uris = calloc(sizeof(char *), uris_max_sz);
    if (!uris) {
        LOG(LOG_ERR, "Could not allocate memory for URI list.");
        return -2;
    }

    // expecting one rsync uri per line, no whitespace, staring with "DIR="
    //   max length of uri is a little less than sizeof(msg)
    char const *LINE_PREFIX = "DIR=";
    size_t const LEN_PREFIX = strlen(LINE_PREFIX);
    if (load_uris_from_file) {
        fp = fopen(config_file, "r");
        if (!fp) {
            LOG(LOG_WARNING, "Could not open file: %s", config_file);
            goto cant_open_file;
        }

        while (fgets (msg, sizeof(msg), fp) != NULL) {
            if (strncmp(LINE_PREFIX, msg, LEN_PREFIX)) {
                continue;
            }
            if (sizeof(msg) == strlen(msg)) {
                LOG(LOG_WARNING, "uri string too long, dropping:  %s", msg);
                continue;
            }
            append_uri(&msg[LEN_PREFIX]);
        }

        fclose(fp);
        LOG(LOG_DEBUG, "loaded %zu rsync uris from file: %s", num_uris, config_file);
    }
    cant_open_file:

    LOG(LOG_DEBUG, "Searching database for rsync uris...");

    timestamp_prev = (char*)calloc(TS_LEN, sizeof(char));
    timestamp_curr = (char*)calloc(TS_LEN, sizeof(char));
    if (!timestamp_prev  ||  !timestamp_curr) {
        LOG(LOG_ERR, "out of memory");
        return -1;
    }

    // initialize database
    if (!db_init()) {
        LOG(LOG_ERR, "can't initialize global DB state");
        return -1;
    }
    dbconn *db = db_connect_default(DB_CLIENT_CHASER);
    if (db == NULL) {
        LOG(LOG_ERR, "can't connect to database");
        return -1;
    }

    // look up rsync uris from the db
    if(chase_only_ta) {
        query_sia(db, 1);
    } else {
        query_read_timestamps(db);

        if (chase_crldp)
            query_crldp(db);

        if (chase_aia)
            query_aia(db);

        if (chase_sia)
            query_sia(db, 0);
    }
    query_write_timestamp(db);
    if (timestamp_prev) free(timestamp_prev);
    if (timestamp_curr) free(timestamp_curr);
    if (db != NULL) {
        db_disconnect(db);
        db_close();
    }

    LOG(LOG_DEBUG, "found total of %zu rsync uris", num_uris);

    if (num_uris == 0)
        return 0;

    // sort uris[]
    qsort(uris, num_uris, sizeof (char *), compare_str_p);

    // remove subsumed entries from uris[]
    size_t lo, hi;
    for (lo = 0, hi = 1; hi < num_uris; hi++) {
        if (is_subsumed(uris[lo], uris[hi])) {
            free(uris[hi]);
            uris[hi] = NULL;
        } else {
            lo = hi;
        }
    }

    // compact uris[]
    lo = hi = 0;
    size_t new_max = num_uris;
    while (1) {
        while (lo < num_uris  &&  uris[lo] != NULL)
            lo++;
        if (lo >= hi)
            hi = lo + 1;
        while (hi < num_uris  &&  uris[hi] == NULL)
            hi++;
        if (hi >= num_uris  ||  lo >= num_uris)
            break;
        uris[lo] = uris[hi];
        uris[hi] = NULL;
        new_max = lo;
        lo++;
        hi++;
    }
    LOG(LOG_DEBUG, "compacted rsync uris from %zu to %zu", num_uris, new_max);
    num_uris = new_max;

    // print to stdout
    LOG(LOG_DEBUG, "outputting %zu rsync uris", num_uris);
    for (i = 0; i < num_uris; i++) {
        fprintf(stdout, "%s%s\n", RSYNC_SCHEME, uris[i]);
    }

    // release memory
    free_uris();

    CLOSE_LOG();

    return 0;
}
