/**
 * This is the chaser program, which tracks down all the URIs of all the
 * authorities that have signed certs.  It outputs the URIs to stdout.
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "rpki/err.h"
#include "util/logging.h"
#include "config/config.h"
#include "db/connect.h"
#include "db/clients/chaser.h"
#include "util/stringutils.h"

#define CHASER_LOG_IDENT PACKAGE_NAME "-chaser"
#define CHASER_LOG_FACILITY LOG_DAEMON


static char **uris = NULL;
static size_t uris_max_sz = 20;
static size_t num_uris = 0;

static size_t const TS_LEN = 20;        // "0000-00-00 00:00:00" plus '\0'
static char *timestamp_curr;
static char const *const RSYNC_SCHEME = "rsync://";


/**=============================================================================
 * @note This function only does a string comparison, not a file lookup.
 * @pre str1 <= str2, lexicographically.
 * @ret 1 if str2 is a file or directory under str1.
 *      0 otherwise.
------------------------------------------------------------------------------*/
static int is_subsumed(
    const char *str1,
    const char *str2)
{
    if (!str1)
        return 0;

    size_t len1;

    if (strncmp(str1, str2, len1 = strlen(str1)) != 0)
        return 0;
    if (strlen(str1) == strlen(str2))
        return 1;
    if (str1[len1 - 1] == '/')
        return 1;
    if (str2[len1] == '/')
        return 1;

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static void free_uris(
    )
{
    size_t i;

    if (!uris)
        return;

    for (i = 0; i < num_uris; i++)
    {
        free(uris[i]);
        uris[i] = NULL;
    }
    num_uris = 0;

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
static int remove_dot_dot(
    char *s)
{
    int modified = 0;
    int found_dots = 1;
    int found_slash;
    size_t i;
    size_t j;
    size_t len;
    size_t dots_lo;
    size_t dots_hi;
    size_t dir_lo;

    while (found_dots)
    {
        found_dots = 0;
        len = strlen(s);

        // find "/.."
        for (i = 0; i < len - 2; i++)
        {
            if ('/' == s[i] && '.' == s[i + 1] && '.' == s[i + 2])
                dots_lo = i;
            else
                continue;

            if (i + 3 == len || (i + 3 < len && '/' == s[i + 3]))
            {
                dots_hi = i + 2;
                found_dots = 1;
                break;
            }
        }

        if (!found_dots)
            break;

        // protect i in for loop from being very large
        if (1 > dots_lo)        // authority section of uri must have some
                                // chars
            return -2;

        // find preceding dir
        found_slash = 0;
        for (i = dots_lo - 1; i > 0; i--)
        {
            if ('/' == s[i])
            {
                dir_lo = i;
                found_slash = 1;
                break;
            }
        }

        if (!found_slash)
            return -2;

        // remove preceding dir
        for (i = 0, j = 0; i < len; i++)
        {
            if (i < dir_lo || i > dots_hi)
            {
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
static int check_uri_chars(
    char *str)
{
    int modified = 0;
    int found_dots = 0;
    size_t i;
    size_t j;
    char prev;
    char this;
    int ret;

    // if bad char, drop and warn
    char bad_chars[] = " \"#$<>?\\^`{|}";
    char ch;
    for (i = 0; '\0' != str[i]; i++)
    {
        ch = str[i];
        if (' ' > ch || '~' < ch || NULL != strchr(bad_chars, ch))
        {
            LOG(LOG_WARNING, "unallowed char(s) found in URI");
            return -2;
        }
    }

    // Check for "..".  Collapse "//" to "/".  Collapse "/./" to "/".
    prev = str[0];
    for (i = 1, j = 1; '\0' != str[i]; i++)
    {
        if ('/' == (this = str[i]) && '/' == prev)
        {
            // neither copy the char, nor increment j
            modified = 1;
        }
        else if ('.' == (this = str[i]) && '.' == prev)
        {
            found_dots = 1;
            str[j] = str[i];
            j++;
            prev = this;
        }
        else if ('.' == (this = str[i]) && '/' == prev &&
                 ('/' == str[i + 1] || '\0' == str[i + 1]))
        {
            // neither copy the char, nor increment j
            // increment i one extra
            modified = 1;
            i++;
        }
        else
        {
            str[j] = str[i];
            j++;
            prev = this;
        }
    }
    str[j] = str[i];

    if (found_dots)
    {
        ret = remove_dot_dot(str);
        if (-1 == ret)
            modified = 1;
        else if (-2 == ret)
            return ret;
    }

    if (modified)
        return -1;

    return 0;
}

/**=============================================================================
 * @note caller frees param "in"
------------------------------------------------------------------------------*/
static int append_uri(
    char const *in)
{
    // check if array is big enough
    if (num_uris == uris_max_sz)
    {
        uris_max_sz *= 1.6;
        uris = (char **)realloc(uris, uris_max_sz * sizeof(char *));
        if (!uris)
        {
            LOG(LOG_ERR, "Could not realloc for uris");
            return ERR_CHASER_OOM;
        }
    }

    // copy input to array
    uris[num_uris] = strdup(in);
    if (!uris[num_uris])
    {
        LOG(LOG_ERR, "Could not alloc for uri");
        return ERR_CHASER_OOM;
    }
    num_uris++;

    return 0;
}

/**=============================================================================
 * Warn if no path segments.
 * If module only, use trailing slash, else no trailing slash.
 *
 * @note Call this after instances of "//" have been collapsed.
 *
 * @note Might modify parameter.
 * @param in is of the general form "authority/module/path"
 *
 * @ret 0 if input was not modified
 *     -1 if input was modified, but remains valid
 *     -2 if input was invalid
 *     -3 if input becomes too long with added '/'
------------------------------------------------------------------------------*/
static int check_trailing_slash(
    char *in)
{
    size_t len = strlen(in);
    size_t i;
    size_t end_of_authority = 0;
    size_t end_of_module = 0;

    // find end of authority
    i = 0;
    while (i < len)
    {
        if ('/' == in[i])
        {
            end_of_authority = i;
            break;
        }
        else
            i++;
    }
    if (0 == end_of_authority)
        return -2;

    // find end of module
    i += 2;
    while (i < len)
    {
        if ('/' == in[i])
        {
            end_of_module = i;
            break;
        }
        else
            i++;
    }

    // if no '/' found to terminate module section
    if (!end_of_module)
    {
        if (end_of_authority == len - 1)        // no module section
            return -2;
        if ('/' != in[len - 1])
        {
            if (len + strlen(RSYNC_SCHEME) + 1 > DB_URI_LEN)    // +1 for the
                                                                // added '/'
                return -3;
            in[len] = '/';
            in[len + 1] = '\0';
            return -1;
        }
    }

    // if uri ends with "module/"
    if (end_of_module == len - 1)
        return 0;

    // if path does not end with '/'
    if ('/' != in[len - 1])
        return 0;

    // path ends with '/'
    if ('/' == in[len - 1])
        in[len - 1] = '\0';

    return -1;
}

/**=============================================================================
 * @note caller frees param "in"
 *
 * TODO:  unit test for max_length needs to change when DB_URI_LEN changes.  Fix that.
------------------------------------------------------------------------------*/
static int handle_uri_string(
    char const *in)
{
    size_t const DST_SZ = DB_URI_LEN + 1;
    char *section;
    char scrubbed_str[DST_SZ];
    char scrubbed_str2[DST_SZ];
    char *ptr;
    size_t len_in = strlen(in);
    int ret;
    size_t i,
        j,
        next_i;

    section = (char *)malloc(sizeof(char) * (DB_URI_LEN + 1));
    if (!section)
        return ERR_CHASER_OOM;
    ptr = section;

    // TODO: Using ';' as delimiter is planned to change when the db schema is 
    // updated.
    // split by semicolons
    section[0] = '\0';
    for (i = 0, j = 0; i < len_in + 1; i++)
    {
        if (';' == in[i] || '\0' == in[i])
        {
            section[j] = '\0';
            next_i = i + 1;
            break;
        }
        else
        {
            section[j++] = in[i];
        }
    }
    while ('\0' != section[0])
    {
        // check,trim rsync scheme
        size_t len_scheme = strlen(RSYNC_SCHEME);
        if (!strncasecmp(RSYNC_SCHEME, section, len_scheme))
        {
            section += len_scheme;
        }
        else
        {
            scrub_for_print(scrubbed_str, section, DST_SZ, NULL, "");
            LOG(LOG_WARNING, "dropping non-rsync uri:  \"%s\"", scrubbed_str);
            goto get_next_section;
        }

        // remove some special characters
        scrub_for_print(scrubbed_str, section, DST_SZ, NULL, "");
        ret = check_uri_chars(section);
        if (-1 == ret)
        {
            scrub_for_print(scrubbed_str2, section, DST_SZ, NULL, "");
            LOG(LOG_WARNING,
                "modified rsync uri, replaced:  \"%s\" with \"%s\"",
                scrubbed_str, scrubbed_str2);
        }
        else if (-2 == ret)
        {
            LOG(LOG_WARNING, "invalid rsync uri, dropping:  \"%s\"",
                scrubbed_str);
            goto get_next_section;
        }

        // handle trailing '/'
        scrub_for_print(scrubbed_str, section, DST_SZ, NULL, "");
        ret = check_trailing_slash(section);
        if (-1 == ret)
        {
            scrub_for_print(scrubbed_str2, section, DST_SZ, NULL, "");
            LOG(LOG_WARNING,
                "modified rsync uri, replaced:  \"%s\" with \"%s\"",
                scrubbed_str, scrubbed_str2);
        }
        else if (-2 == ret)
        {
            LOG(LOG_WARNING, "invalid rsync uri, dropping:  \"%s\"",
                scrubbed_str);
            goto get_next_section;
        }
        else if (-3 == ret)
        {
            snprintf(scrubbed_str2, 50, "%s", scrubbed_str);
            LOG(LOG_WARNING, "uri too long, dropping:  %s <truncated>",
                scrubbed_str2);
            goto get_next_section;
        }

        // append to uris[]
        if (ERR_CHASER_OOM == append_uri(section))
        {
            if (ptr)
                free(ptr);
            return ERR_CHASER_OOM;
        }

      get_next_section:
        section[0] = '\0';
        for (i = next_i, j = 0; i < len_in + 1; i++)
        {
            if (';' == in[i] || '\0' == in[i])
            {
                section[j] = '\0';
                next_i = i + 1;
                break;
            }
            else
            {
                section[j++] = in[i];
            }
        }
    }

    if (ptr)
        free(ptr);

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int query_aia(
    dbconn * db)
{
    char **results = NULL;
    int64_t num_malloced = 0;
    int64_t num_results;
    int64_t i;
    int ret;

    num_results = db_chaser_read_aia(db, &results, &num_malloced);
    if (-1 == num_results)
    {
        return -1;
    }
    else if (ERR_CHASER_OOM == num_results)
    {
        return ERR_CHASER_OOM;
    }
    else
    {
        LOG(LOG_DEBUG,
            "read %" PRIi64 " aia lines from db;  %" PRIi64 " were null",
            num_malloced, num_malloced - num_results);
        for (i = 0; i < num_results; i++)
        {
            ret = handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
            if (ERR_CHASER_OOM == ret)
            {
                for (++i; i < num_results; ++i)
                {
                    free(results[i]);
                }
                free(results);
                return ret;
            }
        }
        if (results)
            free(results);
    }

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int query_crldp(
    dbconn * db,
    int restrict_by_next_update,
    size_t num_seconds)
{
    char **results = NULL;
    int64_t num_malloced = 0;
    int64_t num_results;
    int64_t i;
    int ret;

    num_results =
        db_chaser_read_crldp(db, &results, &num_malloced, timestamp_curr,
                             restrict_by_next_update, num_seconds);
    if (-1 == num_results)
    {
        return -1;
    }
    else if (ERR_CHASER_OOM == num_results)
    {
        return ERR_CHASER_OOM;
    }
    else
    {
        LOG(LOG_DEBUG,
            "read %" PRIi64 " crldp lines from db;  %" PRIi64 " were null",
            num_malloced, num_malloced - num_results);
        for (i = 0; i < num_results; i++)
        {
            ret = handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
            if (ERR_CHASER_OOM == ret)
            {
                for (++i; i < num_results; ++i)
                {
                    free(results[i]);
                }
                free(results);
                return ret;
            }
        }
        if (results)
            free(results);
    }

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int query_sia(
    dbconn * db,
    uint chase_not_yet_validated)
{
    char **results = NULL;
    int64_t num_malloced = 0;
    int64_t num_results;
    int64_t i;
    int ret;

    num_results = db_chaser_read_sia(db, &results, &num_malloced,
                                     chase_not_yet_validated);
    if (-1 == num_results)
    {
        return -1;
    }
    else if (ERR_CHASER_OOM == num_results)
    {
        return ERR_CHASER_OOM;
    }
    else
    {
        LOG(LOG_DEBUG,
            "read %" PRIi64 " sia lines from db;  %" PRIi64 " were null",
            num_malloced, num_malloced - num_results);
        for (i = 0; i < num_results; i++)
        {
            ret = handle_uri_string(results[i]);
            free(results[i]);
            results[i] = NULL;
            if (ERR_CHASER_OOM == ret)
            {
                for (++i; i < num_results; ++i)
                {
                    free(results[i]);
                }
                free(results);
                return ret;
            }
        }
        if (results)
            free(results);
    }

    return 0;
}

/**=============================================================================
 * @brief Get the current time from the db.
------------------------------------------------------------------------------*/
static int query_read_timestamp(
    dbconn * db)
{
    int ret;

    ret = db_chaser_read_time(db, timestamp_curr, TS_LEN);
    if (ret)
    {
        LOG(LOG_ERR, "didn't read time");
        return -1;
    }

    LOG(LOG_DEBUG, " current ts:  %s", timestamp_curr);

    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int compare_str_p(
    const void *p1,
    const void *p2)
{
    return strcmp(*(char *const *)p1, *(char *const *)p2);
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int printUsage(
    )
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr,
            "  -a           chase AIAs  (default:  don't chase AIAs)\n");
    fprintf(stderr,
            "  -d seconds   chase CRLs where 'next update < seconds'  (default:  chase all CRLs)\n");
    fprintf(stderr,
            "  -f filename  use filename instead of 'additional_rsync_uris.config'\n");
    fprintf(stderr,
            "  -s           delimit output with newlines  (default:  null byte)\n");
    fprintf(stderr, "  -t           for testing, don't access the database\n");
    fprintf(stderr,
            "  -y           chase not-yet-validated  (default:  only chase validated)\n");
    fprintf(stderr, "  -h           this listing\n");
    return -1;
}

/**=============================================================================
 * @ ret 0 on success
 *      -1 on failure
------------------------------------------------------------------------------*/
int main(
    int argc,
    char **argv)
{
    int chase_aia = 0;
    int restrict_crls_by_next_update = 0;
    size_t num_seconds = 0;
    uint chase_not_yet_validated = 0;
    int skip_database = 0;
    int ret;
    int consumed;

    char *config_file = "additional_rsync_uris.config";
    FILE *fp;

    // size = length of string + \0 + \n + char to detect oversized
    char msg[DB_URI_LEN + 3];   // temp string storage
    size_t i;
    char output_delimiter = '\0';
    size_t const DST_SZ = sizeof(msg);
    char scrubbed_str[DST_SZ];  // for printing user input

    // parse the command-line flags
    int ch;
    while ((ch = getopt(argc, argv, "ad:f:styh")) != -1)
    {
        switch (ch)
        {
        case 'a':
            chase_aia = 1;
            break;
        case 'd':
            restrict_crls_by_next_update = 1;
            if (sscanf(optarg, "%zu%n", &num_seconds, &consumed) < 1 ||
                (size_t) consumed < strlen(optarg))
            {
                fprintf(stderr, "Invalid number of seconds: %s\n", optarg);
                printUsage();
                return EXIT_FAILURE;
            }
            break;
        case 'f':
            config_file = optarg;
            break;
        case 's':
            output_delimiter = '\n';
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
    (void)setbuf(stdout, NULL);

    if (!my_config_load())
    {
        LOG(LOG_ERR, "Could not load configuration");
        return EXIT_FAILURE;
    }

    uris = malloc(sizeof(char *) * uris_max_sz);
    if (!uris)
    {
        LOG(LOG_ERR, "Could not allocate memory for URI list.");
        return -1;
    }

    // read uris from file
    fp = fopen(config_file, "r");
    if (!fp)
    {
        LOG(LOG_ERR, "Could not open file: %s", config_file);
        goto cant_open_file;
    }
    while (fgets(msg, sizeof(msg), fp) != NULL)
    {
        if (strncasecmp(RSYNC_SCHEME, msg, strlen(RSYNC_SCHEME)))
        {
            continue;
        }
        // strip the trailing \n from fgets
        if (0 < strlen(msg))
            msg[strlen(msg) - 1] = '\0';
        if (DB_URI_LEN < strlen(msg))
        {
            scrub_for_print(scrubbed_str, msg, DST_SZ, NULL, "");
            snprintf(msg, 50, "%s", scrubbed_str);
            LOG(LOG_WARNING,
                "uri from file too long, dropping:  %s <truncated>", msg);
            continue;
        }
        if (ERR_CHASER_OOM == handle_uri_string(msg))
            return -1;
    }
    fclose(fp);
    LOG(LOG_DEBUG, "loaded %zu rsync uris from file: %s", num_uris,
        config_file);
  cant_open_file:

    if (skip_database)
    {
        LOG(LOG_WARNING,
            "Test mode - not looking in the database for rsync uris");
        goto skip_database_for_testing;
    }
    LOG(LOG_DEBUG, "Searching database for rsync uris...");
    timestamp_curr = (char *)calloc(TS_LEN, sizeof(char));
    if (!timestamp_curr)
    {
        LOG(LOG_ERR, "out of memory");
        return -1;
    }
    // initialize database
    if (!db_init())
    {
        LOG(LOG_ERR, "can't initialize global DB state");
        return -1;
    }
    dbconn *db = db_connect_default(DB_CLIENT_CHASER);
    if (db == NULL)
    {
        LOG(LOG_ERR, "can't connect to database");
        db_close();
        return -1;
    }

    // look up rsync uris from the db
    int db_ok = 1;
    if (query_read_timestamp(db))
        db_ok = 0;
    if (db_ok)
    {
        ret = query_crldp(db, restrict_crls_by_next_update, num_seconds);
        if (ERR_CHASER_OOM == ret)
            return -1;
        if (-1 == ret)
            db_ok = 0;
    }
    if (db_ok && chase_aia)
    {
        ret = query_aia(db);
        if (ERR_CHASER_OOM == ret)
            return -1;
        if (-1 == ret)
            db_ok = 0;
    }
    if (db_ok)
    {
        ret = query_sia(db, chase_not_yet_validated);
        if (ERR_CHASER_OOM == ret)
            return -1;
        if (-1 == ret)
            db_ok = 0;
    }
    // cleanup
    if (timestamp_curr)
        free(timestamp_curr);
    if (db != NULL)
    {
        db_disconnect(db);
        db_close();
    }
    if (!db_ok)
    {
        LOG(LOG_ERR, "error attempting to read rsync uris from db");
        return -1;
    }
  skip_database_for_testing:
    LOG(LOG_DEBUG, "found total of %zu rsync uris", num_uris);
    if (num_uris == 0)
        return 0;

    // sort uris[]
    qsort(uris, num_uris, sizeof(char *), compare_str_p);

    // remove subsumed entries from uris[]
    size_t lo,
        hi;
    for (lo = 0, hi = 1; hi < num_uris; hi++)
    {
        if (is_subsumed(uris[lo], uris[hi]))
        {
            free(uris[hi]);
            uris[hi] = NULL;
        }
        else
        {
            lo = hi;
        }
    }

    // compact uris[]
    lo = hi = 0;
    size_t new_max = num_uris;
    while (1)
    {
        while (lo < num_uris && uris[lo] != NULL)
            lo++;
        if (lo >= hi)
            hi = lo + 1;
        while (hi < num_uris && uris[hi] == NULL)
            hi++;
        if (lo >= num_uris)
            break;
        if (hi >= num_uris)
        {
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
    // for n URIs, use n delimiters
    LOG(LOG_DEBUG, "outputting %zu rsync uris", num_uris);
    for (i = 0; i < num_uris; i++)
    {
        fprintf(stdout, "%s%s", RSYNC_SCHEME, uris[i]);
        putchar(output_delimiter);
    }

    free_uris();

    config_unload();

    CLOSE_LOG();

    return 0;
}
