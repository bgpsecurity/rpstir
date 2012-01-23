/**
 * This is the chaser program, which tracks down all the URIs of all the
 * authorities that have signed certs.  It outputs the URIs to stdout.
 *
 * yet to do:
 * - update INSTRUCTIONS for additional_rsync_uris.config
 * - check all return values (handle_uri_string).  free memory before any quit
 * - consider OOM killer in notes about `man realloc`
 *
 * test cases:
 * - is x subsumed by y?
 * - are trailing chars removed?
 * - properly distinguish crldps based on next_upd?
 * - correct output for cmd-line combinations?
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
#include "scm.h"  // for SCM_FLAG_FOO
#include "scmf.h"  // for SCM_FLAG_FOO
#include "sqhl.h"  // for SCM_FLAG_FOO

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
 * @pre str1 precedes str2, lexicographically.
 * @ret 1 if str2 is a file or directory under str1.
 *      0 otherwise.
------------------------------------------------------------------------------*/
static int is_subsumed(const char *str1, const char *str2) {
    if (!str1)
        return 0;

    size_t len1;

    if (strncmp (str1, str2, len1 = strlen (str1)) != 0)
        return 0;
    if (strlen (str1) == strlen (str2))
        return 1;
    if (str1 [len1 - 1] == '/')
        return 1;
    if (str2 [len1] == '/')
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
    if (uris[num_uris]) {
        free(uris[num_uris]);
    }
    uris[num_uris] = NULL;

    free(uris);
}

/**=============================================================================
// TODO:  David:  let ? and # pass.  Probly not relevant to rsync.
// TODO:  David is checking what he wants me to do with isprint().Andrew:  warn. uri rfc mention this?
// TODO:  collapse:  //  (helps is_subsumed() algo, no change to semantics)  (Andrew:  warn)
------------------------------------------------------------------------------*/
static int check_uri_chars(char *in) {


    return 0;
}

/**=============================================================================
 * @note caller frees param "in"
------------------------------------------------------------------------------*/
static int append_uri(char const *in) {
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

    uris[num_uris] = strdup(in);
    if (!uris[num_uris]) {
        LOG(LOG_ERR, "Could not alloc for uri");
        return -2;
    }
    num_uris++;

    return 0;
}

/**=============================================================================
 * @note caller frees param "in"
------------------------------------------------------------------------------*/
static void handle_uri_string(char const *in) {
    char *copy;
    char *section;
    size_t const DST_SZ = 1030;
    char scrubbed_str[DST_SZ];
    // TODO:  Using ; as delimiter is planned to change when the db schema is updated.
    char const delimiter[] = ";";
    size_t len_in = strlen(in);
    size_t len;

    copy = malloc((len_in + 1) * sizeof(char));
    if (!copy) {
        LOG(LOG_ERR, "out of memory");
        return;
    }
    memcpy(copy, in, len_in);
    copy[len_in] = '\0';
    char * const ptr = copy;

    // split by semicolons
    section = strtok(copy, delimiter);
    while (section) {
        //TODO:  any change to a uri gets a warning, at least
        // trim leading space and quote
        len = strlen(section);
        while ((' ' == section[0]  ||  '\'' == section[0]  ||  '"' == section[0])
                &&  len > 0) {
            section += 1;
            len--;
        }

        // trim trailing space, newline, and quote
        len = strlen(section);
        while ((' ' == section[len - 1]  ||  '\n' == section[len - 1]  ||
                '\'' == section[len - 1]  ||  '"' == section[len - 1])  &&  len > 0) {
            section[len - 1] = '\0';
            len--;
        }

        // check,trim rsync scheme
        size_t len_scheme = strlen(RSYNC_SCHEME);
        if (!strncmp(RSYNC_SCHEME, section, len_scheme)) {
            section += len_scheme;
        } else {
            scrub_for_print(scrubbed_str, section, DST_SZ, NULL, "");
            LOG(LOG_WARNING, "dropping non-rsync uri:  \"%s\"", scrubbed_str);
            section = strtok(NULL, delimiter);
            continue;
        }

        // regex check  (this may move to check_chars)
        if (check_uri_chars(section)) {
            scrub_for_print(scrubbed_str, section, DST_SZ, NULL, "");
            LOG(LOG_WARNING, "possible invalid rsync uri, skipping:  \"%s\"", scrubbed_str);
            section = strtok(NULL, delimiter);
            continue;
        }

        // append to uris[]
        append_uri(section);

        section = strtok(NULL, delimiter);
    }

    if (ptr) free(ptr);

    return;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int query_aia(dbconn *db) {
    char **results = NULL;
    int64_t num_malloced = 0;
    int64_t ret;
    int64_t i;
    size_t const DST_SZ = 1030;
    char scrubbed_str[DST_SZ];

    ret = db_chaser_read_aia(db, &results, &num_malloced,
            SCM_FLAG_VALIDATED, SCM_FLAG_NOCHAIN);
    if (ret == -1) {
        return -1;
    } else {
        LOG(LOG_DEBUG, "read %" PRIi64 " aia lines from db;  %" PRIi64 " were null",
                num_malloced, num_malloced - ret);
        for (i = 0; i < ret; i++) {
            scrub_for_print(scrubbed_str, results[i], DST_SZ, NULL, "");
            LOG(LOG_DEBUG, "%s\n", scrubbed_str);
            handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
        }
        if (results) free(results);
    }

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int query_crldp(dbconn *db, int restrict_by_next_update, size_t num_hours) {
    char **results = NULL;
    int64_t num_malloced = 0;
    int64_t ret;
    int64_t i;
    size_t const DST_SZ = 1030;
    char scrubbed_str[DST_SZ];

    ret = db_chaser_read_crldp(db, &results, &num_malloced, timestamp_curr,
            restrict_by_next_update, num_hours);
    if (ret == -1) {
        return -1;
    } else {
        LOG(LOG_DEBUG, "read %" PRIi64 " crldp lines from db;  %" PRIi64 " were null",
                num_malloced, num_malloced - ret);
        for (i = 0; i < ret; i++) {
            scrub_for_print(scrubbed_str, results[i], DST_SZ, NULL, "");
            LOG(LOG_DEBUG, "%s\n", scrubbed_str);
            handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
        }
        if (results) free(results);
    }

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int query_sia(dbconn *db, int chase_not_yet_validated) {
    char **results = NULL;
    int64_t num_malloced = 0;
    int64_t ret;
    int64_t i;
    size_t const DST_SZ = 1030;
    char scrubbed_str[DST_SZ];

    ret = db_chaser_read_sia(db, &results, &num_malloced,
            chase_not_yet_validated, SCM_FLAG_VALIDATED);
    if (ret == -1) {
        return -1;
    } else {
        LOG(LOG_DEBUG, "read %" PRIi64 " sia lines from db;  %" PRIi64 " were null",
                num_malloced, num_malloced - ret);
        for (i = 0; i < ret; i++) {
            scrub_for_print(scrubbed_str, results[i], DST_SZ, NULL, "");
            LOG(LOG_DEBUG, "%s\n", scrubbed_str);
            handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
        }
        if (results) free(results);
    }

    return 0;
}

/**=============================================================================
 * @brief Get the current time; and read the last time chaser ran from db.
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
 * @note Write timestamp to db as last time chaser ran.
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
    fprintf(stderr, "  -a           chase AIAs  (default:  don't chase AIAs)\n");
    fprintf(stderr, "  -d hours     chase CRLs where 'next update < hours'  (default:  chase all CRLs)\n");
    fprintf(stderr, "  -f filename  use filename instead of 'additional_rsync_uris.config'\n");
    fprintf(stderr, "  -y           chase not-yet-validated  (default:  only chase validated)\n");
    fprintf(stderr, "  -h           this listing\n");
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
    int    chase_aia = 0;
    int    restrict_crls_by_next_update = 0;
    size_t num_hours = 0;
    int    chase_not_yet_validated = 0;
    int    load_uris_from_file = 0;

    char   *config_file = "additional_rsync_uris.config";
    FILE   *fp;

    char   msg[1024];  // temp string storage
    size_t i;
    char   delimiter = '\0';
    size_t const DST_SZ = 1030;
    char   scrubbed_str[DST_SZ];

    // parse the command-line flags
    int ch;
    while ((ch = getopt(argc, argv, "acd:f:styh")) != -1) {
        switch (ch) {
        case 'a':
            chase_aia = 1;
            break;
        case 'd':
            restrict_crls_by_next_update = 1;
            num_hours = (size_t) strtoul(optarg, NULL, 10);
            break;
        case 'f':
            load_uris_from_file = 1;
            config_file = optarg;
            break;
        case 'y':
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

    // read uris from file
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
                scrub_for_print(scrubbed_str, msg, DST_SZ, NULL, "");
                LOG(LOG_WARNING, "uri string too long, dropping:  %s", scrubbed_str);
                continue;
            }
            handle_uri_string(&msg[LEN_PREFIX]);
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
        db_close();
        return -1;
    }

    // look up rsync uris from the db
    query_read_timestamps(db);
    query_crldp(db, restrict_crls_by_next_update, num_hours);

    if (chase_aia)
        query_aia(db);

    query_sia(db, chase_not_yet_validated);

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
        if (lo >= num_uris)
            break;
        if (hi >= num_uris) {
            new_max = lo;
            break;
        }
        uris[lo] = uris[hi];
        uris[hi] = NULL;
        new_max = lo + 1;
        lo++;
        hi++;
    }
    LOG(LOG_DEBUG, "compacted rsync uris from %zu to %zu", num_uris, new_max);
    num_uris = new_max;

    // print to stdout
    LOG(LOG_DEBUG, "outputting %zu rsync uris", num_uris);
    for (i = 0; i < num_uris; i++) {
        fprintf(stdout, "%s%s", RSYNC_SCHEME, uris[i]);
        putchar(delimiter);
    }

    free_uris();

    CLOSE_LOG();

    return 0;
}
