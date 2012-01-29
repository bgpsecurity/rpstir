/**
 * This is the chaser program, which tracks down all the URIs of all the
 * authorities that have signed certs.  It outputs the URIs to stdout.
 *
 * yet to do:
 * - check all return values (handle_uri_string).  free memory before any quit
 * - consider OOM killer in notes about `man realloc`
 *
 * test cases:
 * - is x subsumed by y?
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
#include "stringutils.h"

#define CHASER_LOG_IDENT PACKAGE_NAME "-chaser"
#define CHASER_LOG_FACILITY LOG_DAEMON


static char    **uris = NULL;
static size_t  uris_max_sz = 1024 * 1024;
static size_t  num_uris = 0;

static size_t const TS_LEN = 20;  // "0000-00-00 00:00:00" plus '\0'
static char *timestamp_prev;
static char *timestamp_curr;
static char const * const  RSYNC_SCHEME = "rsync://";
static int remove_nonprintables = 0;


/**=============================================================================
 * @note This function only does a string comparison, not a file lookup.
 * @pre str1 <= str2, lexicographically.
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
 * rsync://foo.com/../ should be removed
 * rsync://foo.com/a/../b should be collapsed to rsync://foo.com/b
 * rsync://foo.com/a/../.. should be removed
 *
 * @note Might modify parameter.
 * @ret 0 if input was not modified
 *     -1 if input was modified, but remains valid
 *     -2 if input was invalid
------------------------------------------------------------------------------*/
static int remove_dot_dot(char *s) {
    int modified = 0;
    int found_dots = 1;
    int found_slash;
    size_t i;
    size_t j;
    size_t len;
    size_t dots_lo;
    size_t dots_hi;
    size_t dir_lo;

    while (found_dots) {
        found_dots = 0;
        len = strlen(s);

        // find "/.."
        for (i = 0; i < len - 2; i++) {
            if ('/' == s[i]  &&  '.' == s[i + 1]  &&  '.' == s[i + 2])
                dots_lo = i;
            else
                continue;

            if (i + 3 == len  ||  (i + 3 < len  &&  '/' == s[i + 3])) {
                dots_hi = i + 2;
                found_dots = 1;
                break;
            }
        }

        if (!found_dots)
            break;

        // find preceding dir
        found_slash = 0;
        for (i = dots_lo - 1; i > 0; i--) {
            if ('/' == s[i]) {
                dir_lo = i;
                found_slash = 1;
                break;
            }
        }

        if (!found_slash)
            return -2;

        // remove preceding dir
        for (i = 0, j = 0; i < len; i++) {
            if (i < dir_lo  ||  i > dots_hi) {
                s[j] = s[i];
                j++;
            }
        }
        s[j] = s[i];
        modified = 1;
    }

    if (modified)
        return -1;

    return 0;
}

/**=============================================================================
 * @note Might modify parameter.
 * @ret 0 if input was not modified
 *     -1 if input was modified, but remains valid
 *     -2 if input was invalid
------------------------------------------------------------------------------*/
static int check_uri_chars(char *str) {
    int modified = 0;
    int found_dots = 0;
    size_t i;
    size_t j;
    char prev;
    char this;
    int ret;

    // remove nonprintables
    if (remove_nonprintables) {
        for (i = 0, j = 0; i < strlen(str); i++) {
            if (isprint(str[i])) {
                str[j] = str[i];
                j++;
            } else {
                modified = 1;
            }
        }
        str[j] = str[i];
    }

    // Check for "..".  Collapse "//" to "/".  Collapse "/./" to "/".
    prev = str[0];
    for (i = 1, j = 1; i < strlen(str); i++) {
        if ('/' == (this = str[i])  &&  '/' == prev) {
            // neither copy the char, nor increment j
            modified = 1;
        } else if ('.' == (this = str[i])  &&  '.' == prev) {
            found_dots = 1;
            str[j] = str[i];
            j++;
            prev = this;
        } else if ('.' == (this = str[i])  &&  '/' == prev  &&
                ('/' == str[i + 1]  ||  '\0' == str[i + 1])) {
            // neither copy the char, nor increment j
            // increment i one extra
            modified = 1;
            i++;
        } else {
            str[j] = str[i];
            j++;
            prev = this;
        }
    }
    str[j] = str[i];

    if (found_dots) {
        ret = remove_dot_dot(str);
        if (-1 == ret)
            modified = 1;
        else if (-2 == ret)
            return ret;
    }

    if (modified)
        return 1;

    return 0;
}

/**=============================================================================
 * @note caller frees param "in"
------------------------------------------------------------------------------*/
static int append_uri(char const *in) {
    // check if array is big enough
    if (num_uris == uris_max_sz) {
        uris_max_sz *= 1.6;
        uris = (char **) realloc(uris, uris_max_sz * sizeof(char *));
        if (!uris) {
            LOG(LOG_ERR, "Could not realloc for uris");
            return OUT_OF_MEMORY;
        }
    }

    // copy input to array
    uris[num_uris] = strdup(in);
    if (!uris[num_uris]) {
        LOG(LOG_ERR, "Could not alloc for uri");
        return OUT_OF_MEMORY;
    }
    num_uris++;

    return 0;
}

/**=============================================================================
 * @note caller frees param "in"
------------------------------------------------------------------------------*/
static int handle_uri_string(char const *in) {
    size_t const DST_SZ = DB_URI_LEN + 1;
    char *section;
    char scrubbed_str[DST_SZ];
    char scrubbed_str2[DST_SZ];
    char *ptr;
    size_t len_in = strlen(in);
    int ret;
    size_t i, j, next_i;

    section = (char*) malloc(sizeof(char) * (DB_URI_LEN + 1));
    if (!section)
        return OUT_OF_MEMORY;
    ptr = section;

    // TODO:  Using ; as delimiter is planned to change when the db schema is updated.
    // split by semicolons
    section[0] = '\0';
    for (i = 0, j = 0; i < len_in + 1; i++) {
        if (';' == in[i]  ||  '\0' == in[i]) {
            section[j] = '\0';
            next_i = i + 1;
            break;
        } else {
            section[j++] = in[i];
        }
    }
    while ('\0' != section[0]) {
        // check,trim rsync scheme
        size_t len_scheme = strlen(RSYNC_SCHEME);
        if (!strncasecmp(RSYNC_SCHEME, section, len_scheme)) {
            section += len_scheme;
        } else {
            scrub_for_print(scrubbed_str, section, DST_SZ, NULL, "");
            LOG(LOG_DEBUG, "dropping non-rsync uri:  \"%s\"", scrubbed_str);
            goto get_next_section;
        }

        scrub_for_print(scrubbed_str, section, DST_SZ, NULL, "");
        // remove some special characters
        ret = check_uri_chars(section);
        if (-1 == ret) {
            scrub_for_print(scrubbed_str2, section, DST_SZ, NULL, "");
            LOG(LOG_WARNING, "modified rsync uri, replaced:  \"%s\" with \"%s\"",
                    scrubbed_str, scrubbed_str2);
            goto get_next_section;
        } else if (-2 == ret) {
            LOG(LOG_WARNING, "possible invalid rsync uri, dropping:  \"%s\"", scrubbed_str);
            goto get_next_section;
        }

        // append to uris[]
        if (OUT_OF_MEMORY == append_uri(section)) {
            if (ptr)  free(ptr);
            return OUT_OF_MEMORY;
        }

        get_next_section:
        section[0] = '\0';
        for (i = next_i, j = 0; i < len_in + 1; i++) {
            if (';' == in[i]  ||  '\0' == in[i]) {
                section[j] = '\0';
                next_i = i + 1;
                break;
            } else {
                section[j++] = in[i];
            }
        }
    }

    if (ptr)  free(ptr);

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int query_aia(dbconn *db) {
    char **results = NULL;
    int64_t num_malloced = 0;
    int64_t result;
    int64_t i;
    int ret;
//    size_t const DST_SZ = DB_URI_LEN + 1;
//    char scrubbed_str[DST_SZ];

    result = db_chaser_read_aia(db, &results, &num_malloced,
            SCM_FLAG_VALIDATED, SCM_FLAG_NOCHAIN);
    if (result == -1) {
        return -1;
    } else {
        LOG(LOG_DEBUG, "read %" PRIi64 " aia lines from db;  %" PRIi64 " were null",
                num_malloced, num_malloced - result);
        for (i = 0; i < result; i++) {
//            scrub_for_print(scrubbed_str, results[i], DST_SZ, NULL, "");
//            LOG(LOG_DEBUG, "%s\n", scrubbed_str);
            ret = handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
            if (OUT_OF_MEMORY == ret) {
                if (results) free(results);
                return ret;
            }
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
    int64_t result;
    int64_t i;
    int ret;
//    size_t const DST_SZ = DB_URI_LEN + 1;
//    char scrubbed_str[DST_SZ];

    result = db_chaser_read_crldp(db, &results, &num_malloced, timestamp_curr,
            restrict_by_next_update, num_hours);
    if (result == -1) {
        return -1;
    } else {
        LOG(LOG_DEBUG, "read %" PRIi64 " crldp lines from db;  %" PRIi64 " were null",
                num_malloced, num_malloced - result);
        for (i = 0; i < result; i++) {
//            scrub_for_print(scrubbed_str, results[i], DST_SZ, NULL, "");
//            LOG(LOG_DEBUG, "%s\n", scrubbed_str);
            ret = handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
            if (OUT_OF_MEMORY == ret) {
                if (results) free(results);
                return ret;
            }
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
    int64_t result;
    int64_t i;
    int ret;
//    size_t const DST_SZ = DB_URI_LEN + 1;
//    char scrubbed_str[DST_SZ];

    result = db_chaser_read_sia(db, &results, &num_malloced,
            chase_not_yet_validated, SCM_FLAG_VALIDATED);
    if (result == -1) {
        return -1;
    } else {
        LOG(LOG_DEBUG, "read %" PRIi64 " sia lines from db;  %" PRIi64 " were null",
                num_malloced, num_malloced - result);
        for (i = 0; i < result; i++) {
//            scrub_for_print(scrubbed_str, results[i], DST_SZ, NULL, "");
//            LOG(LOG_DEBUG, "%s\n", scrubbed_str);
            ret = handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
            if (OUT_OF_MEMORY == ret) {
                if (results) free(results);
                return ret;
            }
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
        LOG(LOG_ERR, "didn't write timestamp to db");
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
    fprintf(stderr, "  -p           remove nonprintable chars from uris  (default:  don't remove)\n");
    fprintf(stderr, "  -t           for testing, don't access the database\n");
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
    int    skip_database = 0;

    char   *config_file = "additional_rsync_uris.config";
    FILE   *fp;

    // size = length of string + \0 + \n + char to detect oversized
    char   msg[DB_URI_LEN + 3];  // temp string storage
    size_t i;
    char   output_delimiter = '\0';
    size_t const DST_SZ = sizeof(msg);
    char   scrubbed_str[DST_SZ];  // for printing user input

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
            config_file = optarg;
            break;
        case 'p':
            remove_nonprintables = 1;
            break;
        case 't':
            skip_database = 1;
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
    fp = fopen(config_file, "r");
    if (!fp) {
        LOG(LOG_ERR, "Could not open file: %s", config_file);
        goto cant_open_file;
    }
    while (fgets (msg, sizeof(msg), fp) != NULL) {
        if (strncasecmp(RSYNC_SCHEME, msg, strlen(RSYNC_SCHEME))) {
            continue;
        }
        // strip the trailing \n from fgets
        if (0 < strlen(msg))
            msg[strlen(msg) - 1] = '\0';
        if (DB_URI_LEN < strlen(msg)) {
            scrub_for_print(scrubbed_str, msg, DST_SZ, NULL, "");
            snprintf(msg, 50, "%s", scrubbed_str);
            LOG(LOG_WARNING, "uri from file too long, dropping:  %s <truncated>", msg);
            continue;
        }
        if (handle_uri_string(msg)) {
            scrub_for_print(scrubbed_str, msg, DST_SZ, NULL, "");
            LOG(LOG_WARNING, "did not load uri from file:  %s", scrubbed_str);
        }
    }
    fclose(fp);
    LOG(LOG_DEBUG, "loaded %zu rsync uris from file: %s", num_uris, config_file);
    cant_open_file:

    if (skip_database) {
        LOG(LOG_WARNING, "Test mode - not looking in the database for rsync uris...");
        goto skip_database_for_testing;
    }
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
    int db_ok = 1;
    if (query_read_timestamps(db))
        db_ok = 0;
    if (db_ok  &&  query_crldp(db, restrict_crls_by_next_update, num_hours))
        db_ok = 0;
    if (db_ok  &&  chase_aia) {
        if (query_aia(db))
            db_ok = 0;
    }
    if (db_ok  &&  query_sia(db, chase_not_yet_validated))
        db_ok = 0;
    if (db_ok  &&  query_write_timestamp(db))
        db_ok = 0;
    // cleanup
    if (timestamp_prev) free(timestamp_prev);
    if (timestamp_curr) free(timestamp_curr);
    if (db != NULL) {
        db_disconnect(db);
        db_close();
    }
    if (!db_ok) {
        return -1;
    }
    skip_database_for_testing:
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
        putchar(output_delimiter);
    }

    free_uris();

    CLOSE_LOG();

    return 0;
}
