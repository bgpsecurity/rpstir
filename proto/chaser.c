/**
 * This is the chaser program, which tracks down all the URIs of all the
 * authorities that have signed certs.  It outputs the URIs to stdout.
 *
 * yet to do:
 * - alloc more memory as needed
 * - fix memory leak from addcolsrchscm()
 * - fix unidentified memory leak
 * - check how we define subsume
 * - add cmd-line flags that Andrew listed
 * - check uri for validity before adding to list
 * - possibly cache some high level directories, to check is_subsumed before insert
 * - ? trim trailing slash or newline?
 * - trim "rsync://" for internal storage, or for printing?
 * - check all return values.  free memory before any quit
 * - consider OOM killer in notes about `man realloc`
 *
 * test cases:
 * - is x subsumed by y?
 * - are trailing chars removed?
 * - are bad chars warned, removed?
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "err.h"
#include "logging.h"
#include "scm.h"
#include "scmf.h"
#include "sqhl.h"

#define CHASER_LOG_IDENT PACKAGE_NAME "-chaser"
#define CHASER_LOG_FACILITY LOG_DAEMON


static char **uris = NULL;
//static size_t uris_max_sz = 1024 * 1024;
static size_t uris_max_sz = 2;
static size_t num_uris = 0;
static char *prevTimestamp;
static char *currTimestamp;

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
//    while (num_uris > 7) {
//        fprintf(stderr, "line %u\n", __LINE__);
        if (uris[num_uris]) {
//            fprintf(stderr, "line %u\n", __LINE__);
            free(uris[num_uris]);
//            fprintf(stderr, "line %u\n", __LINE__);
        }
//        fprintf(stderr, "line %u\n", __LINE__);
        uris[num_uris] = NULL;
//        fprintf(stderr, "line %u\n", __LINE__);
        num_uris--;
//        fprintf(stderr, "num_uris:  %zu\n", num_uris);
        fprintf(stderr, "uris[%2zu]:  0x%.8x:  0x%.8x:  %s\n",
                num_uris, (uint) &uris[num_uris], (uint) uris[num_uris], uris[num_uris]);
    }

    free(uris);
}

/**=============================================================================
 * static variables for searching for parent
------------------------------------------------------------------------------*/
static scmsrcha parentSrch;
static scmsrch  parentSrch1[1];
static char parentWhere[1024];
static unsigned long parentBlah = 0;
static int parentNeedsInit = 1;
static int parentCount;
static scmtab *theCertTable = NULL;

/**=============================================================================
 * callback function for searchscm that just notes that parent exists
------------------------------------------------------------------------------*/
static int foundIt(scmcon *conp, scmsrcha *s, int numLine) {
    (void) conp; (void) numLine;  // silence compiler warnings
    parentCount++;
    return 0;
}

/**=============================================================================
 * TODO:  handle returns from this function
------------------------------------------------------------------------------*/
static int append_uri(const char *in) {
    if (!in) {
        LOG(LOG_ERR, "bad input\n");
        return -1;
    }

    // check if array is big enough
    if (num_uris == uris_max_sz) {
        uris_max_sz *= 1.6;
        fprintf(stdout, "before realloc(), uris:  %zu\n", uris_max_sz * sizeof(uris));
        uris = (char **) realloc(uris, uris_max_sz * sizeof(char *));
        if (!uris) {
            LOG(LOG_ERR, "Could not realloc for uris");
            return -2;
        }
    }

    uris[num_uris] = strdup(in);

    if (!uris[num_uris]) {
        LOG(LOG_ERR, "out of memory\n");
        return -1;
    }

    // trim trailing newlines
    int len = strlen(uris[num_uris]);
    while ('\n' == uris[num_uris][len - 1] && len > 0) {
        uris[num_uris][len - 1] = '\0';
        len--;
    }

    num_uris++;
    return 0;
}

/**=============================================================================
 * callback function for searchscm that accumulates the aia's
------------------------------------------------------------------------------*/
static int handleAIAResults(scmcon *conp, scmsrcha *s, int numLine) {
    (void) conp; (void) numLine;  // silence compiler warnings
    if (parentNeedsInit) {
        parentNeedsInit = 0;
        parentSrch.sname = NULL;
        parentSrch.where = NULL;
        parentSrch.ntot = 1;
        parentSrch.nused = 0;
        parentSrch.context = &parentBlah;
        parentSrch.wherestr = parentWhere;
        parentSrch.vec = parentSrch1;
        addcolsrchscm(&parentSrch, "filename", SQL_C_CHAR, FNAMESIZE);
    }
    snprintf(parentWhere, sizeof(parentWhere), "ski=\"%s\"",
            (char *) s->vec[0].valptr);
    parentCount = 0;
    searchscm(conp, theCertTable, &parentSrch, NULL, foundIt,
            SCM_SRCH_DOVALUE_ALWAYS, NULL);
    if (parentCount == 0) {
        char *str = (char *) s->vec[1].valptr;
        append_uri(str);
    }
    return 0;
}


/**=============================================================================
 * callback function for searchscm that accumulates the crldp's
 * note that a CRLDP in the cert table can now be a single URI or a set
 *   of URIs separated by semicolons
------------------------------------------------------------------------------*/
static int handleCRLDPResults(scmcon *conp, scmsrcha *s, int numLine) {
    char *res;
    char *oneres;

    (void) conp; (void) numLine;  // silence compiler warnings
    res = (char *)(s->vec[0].valptr);
    oneres = strtok(res, ";");
    while (oneres  &&  oneres[0] != 0) {
        append_uri(oneres);
        oneres = strtok(NULL, ";");
    }
    return 0;
}

/**=============================================================================
 * callback function for searchscm that accumulates the sia's
------------------------------------------------------------------------------*/
static int handleSIAResults(scmcon *conp, scmsrcha *s, int numLine) {
    char *res;
    char *oneres;

    (void) conp; (void) numLine;  // silence compiler warnings
    res = (char *)(s->vec[0].valptr);
    oneres = strtok(res, ";");
    while(oneres  &&  oneres[0] != 0) {
        append_uri(oneres);
        oneres = strtok(NULL, ";");
    }
    return 0;
}

/**=============================================================================
 * callback function for searchscm that records the timestamps
------------------------------------------------------------------------------*/
static int handleTimestamps(scmcon *conp, scmsrcha *s, int numLine) {
    (void) conp; (void) numLine;  // silence compiler warnings
    currTimestamp = (char *) s->vec[0].valptr;
    prevTimestamp = (char *) s->vec[1].valptr;
    return 0;
}

/**=============================================================================
------------------------------------------------------------------------------*/
static int printUsage() {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  -f filename rsync configuration file to model on\n");
    fprintf(stderr, "  -t          run by grabbing only Trust Anchor URIs from the database\n");
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
    scm      *scmp = NULL;
    scmcon   *connect = NULL;
    scmtab   *table = NULL;
    scmsrcha srch;
    scmsrch  srch1[2];

    char     msg[1024];  // temp storage
    ulong    blah = 0;  // used for srch.context field
    size_t   i;
    int      ch, status;  // return code for scm ops
    int      num_dirs;  // counter for dirs found in initial_rsync.config
    int      ta_only = 0;  // cmd-line opt
    int      chase_sia = 1;  // change to cmd-line opt
    char     dirs[50][120];  // get strings from initial_rsync.config to put into uris.
    char     str[180];  // temp storage
    char     *str2;  // temp storage
    char     *orig_file = "initial_rsync.config";
    FILE     *fp;

    OPEN_LOG(CHASER_LOG_IDENT, CHASER_LOG_FACILITY);

    (void) setbuf(stdout, NULL);

    // parse the command-line flags
    while ((ch = getopt(argc, argv, "f:th")) != -1) {
        switch (ch) {
        case 'f':   // configuration file
//            orig_file = optarg;
            break;
        case 't':   // chase trust anchor SIAs only
            ta_only = 1;
            break;
        case 'h':   // help
        default:
            return printUsage();
        }
    }

    // read in from rsync config file
    // TODO:  Is reading from file still needed?
    //        Is there a max length per uri, max # uris from file?
    //        Get rid of strdup, strtok (or assign to freeable var)
    fp = fopen(orig_file, "r");
    checkErr(fp == NULL, "Unable to open rsync config file: %s\n", orig_file);
    dirs[0][0] = 0;
    while (fgets (msg, sizeof(msg), fp) != NULL) {
        sscanf (strtok (strdup (msg), "="), "%s", str);
        if (strcmp (str, "DIRS") == 0) {
            str2 = strtok (strtok (NULL, "\""), " ");
            for (num_dirs = 0; num_dirs < 50; str2 = strtok (NULL, " ")) {
                if (str2 == NULL) break;
                if (strlen (str2) > 0) {
                    strncpy (dirs[num_dirs++], str2, sizeof(dirs[0]));
                }
            }
        }
    }
    fclose(fp);
    if (!dirs[0][0])
        LOG(LOG_WARNING, "DIRS variable not specified in config file\n");

    // initialize database
    scmp = initscm();
    checkErr(scmp == NULL, "Cannot initialize database schema\n");
    connect = connectscm(scmp->dsn, msg, sizeof(msg));
    checkErr(connect == NULL, "Cannot connect to database: %s\n", msg);

    // Run chaser
    // Prepare a blank new URI list.
    if (uris) {
        free_uris();
        uris = NULL;
        num_uris = 0;
    }
    uris = calloc(sizeof(char *), uris_max_sz);
    if (!uris) {
        LOG(LOG_ERR, "Could not allocate memory for URI list.");
        exit(1);
    }

    // load from current repositories
    for (i = 0; i < num_dirs; i++) {
        snprintf(str, sizeof(str), RSYNC_PREFIX "%s", dirs[i]);
        fprintf(stderr, "========= from file got:  %s\n", str);
        if (strlen(str) > strlen(RSYNC_PREFIX) + 1) {
            append_uri(str);
        }
    }

    LOG(LOG_INFO, "Searching database for URIs...");

    // set up query
    srch.vec = srch1;
    srch.sname = NULL;
    srch.ntot = 2;
    srch.where = NULL;
    srch.wherestr = NULL;
    srch.context = &blah;

    if(!ta_only) {
        // find the current time and last time chaser ran
        // select current_timestamp, ch_last from rpki_metadata;
        // currTimestamp = current_timestamp;
        // prevTimestamp = ch_last;
        table = findtablescm(scmp, "metadata");
        checkErr(table == NULL, "Cannot find table metadata\n");
        srch.nused = 0;
        srch.vald = 0;
        addcolsrchscm(&srch, "current_timestamp", SQL_C_CHAR, 24);
        addcolsrchscm(&srch, "ch_last", SQL_C_CHAR, 24);
        status = searchscm(connect, table, &srch, NULL, handleTimestamps,
                SCM_SRCH_DOVALUE_ALWAYS, NULL);

        // add crldp field if cert either has no crl or crl is out-of-date
        // select crldp from rpki_cert left join rpki_crl
        //   on rpki_cert.aki = rpki_crl.aki
        //   where rpki_crl.filename is null or rpki_crl.next_upd < currTimestamp;
        table = findtablescm(scmp, "certificate");
        checkErr(table == NULL, "Cannot find table certificate\n");
        theCertTable = table;
        srch.nused = 0;
        srch.vald = 0;
        snprintf(msg, sizeof(msg),
                "rpki_crl.filename is null or rpki_crl.next_upd < \"%s\"",
                currTimestamp);
        srch.wherestr = msg;
        addcolsrchscm(&srch, "crldp", SQL_C_CHAR, SIASIZE);
        status = searchscm(connect, table, &srch, NULL, handleCRLDPResults,
                SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN_CRL, NULL);
        free(srch1[0].valptr);
        free(srch1[0].colname);

        // add aia field if cert has no parent
        // select aki, aia from rpki_cert where flags matches SCM_FLAG_NOCHAIN;
        srch.nused = 0;
        srch.vald = 0;
        msg[0] = 0;
        addFlagTest(msg, SCM_FLAG_NOCHAIN, 1, 0);
        addcolsrchscm(&srch, "aki", SQL_C_CHAR, SKISIZE);
        addcolsrchscm(&srch, "aia", SQL_C_CHAR, SIASIZE);
        status = searchscm(connect, table, &srch, NULL, handleAIAResults,
                SCM_SRCH_DOVALUE_ALWAYS, NULL);
        free(srch1[0].valptr);
        free(srch1[1].valptr);
        free(srch1[0].colname);
        free(srch1[1].colname);

        // add sia field (command line option)
        // select sia from rpki_cert;
        if (chase_sia) {
            srch.nused = 0;
            srch.vald = 0;
            msg[0] = 0;
            srch.where = NULL;
            srch.wherestr = NULL;
            addcolsrchscm(&srch, "sia", SQL_C_CHAR, SIASIZE);
            status = searchscm(connect, table, &srch, NULL, handleSIAResults,
                    SCM_SRCH_DOVALUE_ALWAYS, NULL);
            if (status != ERR_SCM_NOERR) {
                LOG(LOG_ERR, "Error chasing SIAs: %s (%d)",
                        err2string(status), status);
            }
            free(srch1[0].valptr);
            free(srch1[0].colname);
        }
    } else {  // this ends the normal operation
        // select sia from rpki_cert where flags match;
        table = findtablescm(scmp, "certificate");
        checkErr(table == NULL, "Cannot find table certificate\n");
        theCertTable = table;
        srch.nused = 0;
        srch.vald = 0;
        snprintf(msg, sizeof(msg),"((flags%%%d)>=%d)",2*SCM_FLAG_TRUSTED, SCM_FLAG_TRUSTED);
        srch.wherestr = msg;
        addcolsrchscm(&srch, "sia", SQL_C_CHAR, SIASIZE);
        status = searchscm(connect, table, &srch, NULL, handleSIAResults,
                SCM_SRCH_DOVALUE_ALWAYS, NULL);
        free(srch1[0].valptr);
        free(srch1[0].colname);
    }

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
    num_uris = new_max;

    // print to stdout
    for (i = 0; i < num_uris; i++) {
        fprintf(stdout, "%zu:  %s\n", i, uris[i]);
    }

    // write timestamp into database
    table = findtablescm(scmp, "metadata");
    snprintf(msg, sizeof(msg), "update %s set ch_last=\"%s\";",
            table->tabname, currTimestamp);
    status = statementscm_no_data(connect, msg);

    // release memory
    disconnectscm(connect);
    if (scmp)
        freescm(scmp);
    free_uris();

    CLOSE_LOG();

    return 0;
}
