#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "rpki/scm.h"
#include "rpki/scmf.h"
#include "rpki/err.h"
#include "rpki/cms/roa_utils.h"
#include "rpki/myssl.h"
#include "rpki/sqhl.h"
#include "rpki/querySupport.h"
#include "util/logutils.h"


/*
 * $Id$ 
 */

/****************
 * This is the query client, which allows a user to read information
 * out of the database and the repository.
 * The standard query is to read all ROA's from the DB and output their
 * BGP filter entries.
 * However, there are options to read any type of objects, choosing
 * a variety of different values to display, and filtering based on
 * a variety of different fields.
 * Other options include whether to validate the roas and certs and
 * what to do during validation when encountering an "unknown" validity.
 **************/

#define MAX_VALS 20
#define MAX_CONDS 10

#define BAD_OBJECT_TYPE \
  "\nBad object type; must be roa, cert, crl, man[ifest] or rpsl\n\n"

/*
 * I hate to use all these static variables, but the problem is
 * that there's no other way to pass them on to all the callback
 * functions that are used to process SQL queries
 */
static FILE *output;            /* place to print output (file or screen) */
static int rejectStaleChain = 0;
static int rejectStaleManifest = 0;
static int rejectStaleCRL = 0;
static int rejectNoManifest = 0;
static int rejectNotYet = 0;
static QueryField *globalFields[MAX_VALS];      /* to pass into handleResults */
static int useLabels,
    multiline,
    validate,
    valIndex;
static char *objectType;
static int isROA = 0,
    isCert = 0,
    isCRL = 0,
    isRPSL = 0,
    isManifest = 0;
static scm *scmp = NULL;
static scmcon *connection = NULL;


struct {
    char *objectName;
    char *tableName;
} tableNames[] =
{
    {
    "cert", "certificate"},
    {
    "roa", "roa"},
    {
    "crl", "crl"},
    {
    "manifest", "manifest"},
    {
    "rpsl", "roa"},};


static unsigned int oldasn;              // needed for grouping by AS#
static int v4size = 0,
    v6size = 0;
static char *v4members = NULL,
    *v6members = NULL;

static void emptyRPSL(
    )
{
    char *hdrp = "route-set: RS-RPKI-ROA-FOR-V%d:AS%u\n";
    if (v4members != NULL)
    {
        fprintf(output, hdrp, 4, oldasn);
        fprintf(output, "%s\n", v4members);
        free(v4members);
        v4members = NULL;
        v4size = 0;
    }
    if (v6members != NULL)
    {
        fprintf(output, hdrp, 6, oldasn);
        fprintf(output, "%s\n", v6members);
        free(v6members);
        v6members = NULL;
        v6size = 0;
    }
}

/*
 * callback function for searchscm that prints the output 
 */
static int handleResults(
    scmcon * conp,
    scmsrcha * s,
    int numLine)
{
    int result = 0;
    int display;
    char resultStr[MAX_RESULT_SZ];

    conp = conp;
    numLine = numLine;          // silence compiler warnings
    if (validate)
    {
        if (!checkValidity
            ((isROA || isRPSL || isManifest
              || isCRL) ? (char *)s->vec[valIndex].valptr : NULL,
             isCert ? *((unsigned int *)s->vec[valIndex].valptr) : 0, scmp,
             connection))
            return 0;
    }

    if (isRPSL)
    {
        unsigned int asn = 0;
        char *ip_addrs = 0;
        const char *filename = 0;

        for (display = 0; globalFields[display] != NULL; display++)
        {
            QueryField *field = globalFields[display];
            if (!strcasecmp(field->name, "ip_addrs"))
            {
                if (s->vec[display].avalsize != SQL_NULL_DATA)
                    ip_addrs = (char *)s->vec[display].valptr;
                else
                    ip_addrs = NULL;
            }
            else if (!strcasecmp(field->name, "asn"))
            {
                if (s->vec[display].avalsize != SQL_NULL_DATA)
                    asn = *(unsigned int *)s->vec[display].valptr;
                else
                    asn = 0;
            }
            else if (!strcasecmp(field->name, "filename"))
            {
                if (s->vec[display].avalsize != SQL_NULL_DATA)
                    filename = (char *)s->vec[display].valptr;
                else
                    filename = "";
            }
            else
                log_msg(LOG_WARNING, "unexpected field %s in RPSL query",
                        field->name);
        }
        if (asn == 0 || ip_addrs == 0)
        {
            log_msg(LOG_ERR, "incomplete result returned in RPSL query: %s",
                    (asn == 0) ? "no asn" : "no ip_addrs");
        }
        else
        {
            if (asn != oldasn)
                emptyRPSL();
            oldasn = asn;
            // 0 == ipv4, 1 == ipv6
            int i,
                numprinted = 0;

            for (i = 0; i < 2; ++i)
            {
                char *end,
                   *f2,
                   *f = ip_addrs;

                // format one line of ip_addrs:
                // "ip_addr/prefix_len[/max_prefix_len]\n"
                while ((end = strchr(f, '\n')) != 0)
                {
                    *end = '\0';
                    // take out max_prefix_len from string
                    f2 = strchr(f, '/');
                    f2 = strchr(f2 + 1, '/');
                    if (f2)
                        *f2 = '\0';
                    if ((i == 0 && strchr(f, ':') == 0) ||
                        (i == 1 && strchr(f, ':') != 0))
                    {
                        int need = strlen(f) + 10 + strlen(filename) + 3;
                        if (i == 0)
                        {
                            if (!v4members)
                                v4members = (char *)calloc(1, need + 1);
                            else
                                v4members =
                                    realloc(v4members, (v4size + need + 1));
                            sprintf(&v4members[v4size], "members: %s # %s\n",
                                    f, filename);
                            v4size += need;
                            v4members[v4size] = 0;
                        }
                        else
                        {
                            need += 3;
                            if (!v6members)
                                v6members = (char *)calloc(1, need + 1);
                            else
                                v6members =
                                    realloc(v6members, (v6size + need + 1));
                            sprintf(&v6members[v6size],
                                    "mp-members: %s # %s\n", f, filename);
                            v6size += need;
                            v6members[v6size] = 0;
                        }
                        ++numprinted;
                    }
                    if (f2)
                        *f2 = '/';
                    *end = '\n';
                    // skip past the newline and try for another one
                    f = end + 1;
                }
            }
            emptyRPSL();
        }
        return (0);
    }

    // normal query result (not RPSL)
    for (display = 0; globalFields[display] != NULL; display++)
    {
        QueryField *field = globalFields[display];
        if (field->displayer != NULL)
        {
            result += field->displayer(s, result, resultStr);
        }
        else if (s->vec[result].avalsize != SQL_NULL_DATA)
        {
            if (field->sqlType == SQL_C_CHAR || field->sqlType == SQL_C_BINARY)
                snprintf(resultStr, MAX_RESULT_SZ,
                         "%s", (char *)s->vec[result].valptr);
            else
                snprintf(resultStr, MAX_RESULT_SZ,
                         "%d", *((unsigned int *)s->vec[result].valptr));
            result++;
        }
        else
        {
            resultStr[0] = '\0';
            result++;
        }
        if (multiline)
            fprintf(output, "%s ", (display == 0) ? "*" : " ");
        if (useLabels)
            fprintf(output, "%s = %s  ", field->heading, resultStr);
        else
            fprintf(output, "%s  ", resultStr);
        if (multiline)
            fprintf(output, "\n");
    }
    if (!multiline)
        fprintf(output, "\n");
    return (0);
}

/*
 * given the object type (aka query type) we are looking for, tell 
 */
/*
 * caller which table to search 
 */
static char *tableName(
    char *objType)
{
    size_t i;
    for (i = 0; i < countof(tableNames); ++i)
    {
        if (!strcasecmp(objType, tableNames[i].objectName))
            return (tableNames[i].tableName);
    }
    return 0;
}

/*
 * sets up and performs the database query, and handles the results 
 */
static int doQuery(
    char **displays,
    char **filters,
    char *orderp)
{
    scmtab *table = NULL;
    scmsrcha srch;
    scmsrch srch1[MAX_VALS];
    char whereStr[MAX_CONDS * 20];
    char errMsg[1024];
    int srchFlags = SCM_SRCH_DOVALUE_ALWAYS;
    unsigned long blah = 0;
    int i,
        j,
        status;
    QueryField *field,
       *field2;
    char *name;
    int maxW = MAX_CONDS * 20;

    (void)setbuf(stdout, NULL);
    scmp = initscm();
    checkErr(scmp == NULL, "Cannot initialize database schema\n");
    connection = connectscm(scmp->dsn, errMsg, 1024);
    checkErr(connection == NULL, "Cannot connect to database: %s\n", errMsg);
    connection->mystat.tabname = objectType;
    table = findtablescm(scmp, tableName(objectType));
    checkErr(table == NULL, "Cannot find table %s\n", objectType);

    /*
     * set up where clause, i.e. the filter 
     */
    srch.where = NULL;
    whereStr[0] = 0;

    if (filters == NULL || filters[0] == NULL)
    {
        srch.wherestr = NULL;
    }
    else
    {
        whereStr[0] = (char)0;
        for (i = 0; filters[i] != NULL; i++)
        {
            if (i != 0)
                strncat(whereStr, " AND ", maxW - strlen(whereStr));
            name = strtok(filters[i], ".");
            strncat(whereStr, name, maxW - strlen(whereStr));
            field = findField(name);
            checkErr(field == NULL || field->description == NULL,
                     "Unknown field name: %s\n", name);
            checkErr(field->flags & Q_JUST_DISPLAY,
                     "Field only for display: %s\n", name);
            name = strtok(NULL, ".");
            if (!name)
                checkErr(1, "No comparison operator\n");
            if (strcasecmp(name, "eq") == 0)
            {
                strncat(whereStr, "=", maxW - strlen(whereStr));
            }
            else if (strcasecmp(name, "ne") == 0)
            {
                strncat(whereStr, "<>", maxW - strlen(whereStr));
            }
            else if (strcasecmp(name, "lt") == 0)
            {
                strncat(whereStr, "<", maxW - strlen(whereStr));
            }
            else if (strcasecmp(name, "gt") == 0)
            {
                strncat(whereStr, ">", maxW - strlen(whereStr));
            }
            else if (strcasecmp(name, "le") == 0)
            {
                strncat(whereStr, "<=", maxW - strlen(whereStr));
            }
            else if (strcasecmp(name, "ge") == 0)
            {
                strncat(whereStr, ">=", maxW - strlen(whereStr));
            }
            else
            {
                checkErr(1, "Bad comparison operator: %s\n", name);
            }
            strncat(whereStr, "\"", maxW - strlen(whereStr));
            name = strtok(NULL, "");
            for (j = 0; j < (int)strlen(name); j++)
            {
                if (name[j] == '#')
                    name[j] = ' ';
            }
            strncat(whereStr, name, maxW - strlen(whereStr));
            strncat(whereStr, "\"", maxW - strlen(whereStr));
        }
        srch.wherestr = whereStr;
    }

    if (validate)
    {
        addQueryFlagTests(whereStr, srch.wherestr != NULL);
        srch.wherestr = whereStr;
    }
    /*
     * set up columns to select 
     */
    srch.vec = srch1;
    srch.sname = NULL;
    srch.ntot = MAX_VALS;
    srch.nused = 0;
    srch.vald = 0;
    srch.context = &blah;
    for (i = 0; displays[i] != NULL; i++)
    {
        field = findField(displays[i]);
        checkErr(field == NULL || field->description == NULL,
                 "Unknown field name: %s\n", displays[i]);
        globalFields[i] = field;
        name = (field->dbColumn == NULL) ? displays[i] : field->dbColumn;
        while (name != NULL)
        {
            field2 = findField(name);
            addcolsrchscm(&srch, name, field2->sqlType, field2->maxSize);
            if (field->flags & Q_REQ_JOIN)
                srchFlags = srchFlags | SCM_SRCH_DO_JOIN;
            name =
                (name == field->otherDBColumn) ? NULL : field->otherDBColumn;
        }
    }
    globalFields[i] = NULL;
    if (validate)
    {
        valIndex = srch.nused;
        if (isROA || isRPSL || isManifest || isCRL)
        {
            char *ski;
            if (isCRL)
            {
                ski = "aki";
            }
            else
            {
                ski = "ski";
            }
            field2 = findField(ski);
            addcolsrchscm(&srch, ski, field2->sqlType, field2->maxSize);
        }
        else if (isCert)
            addcolsrchscm(&srch, "local_id", SQL_C_ULONG, 8);
    }

    /*
     * do query 
     */
    status = searchscm(connection, table, &srch, NULL, handleResults, srchFlags,
                       (isRPSL) ? "asn" : orderp);
    for (i = 0; i < srch.nused; i++)
    {
        free(srch.vec[i].colname);
        free(srch1[i].valptr);
    }
    return status;
}

/*
 * show what options the user has for fields for display and filtering 
 */
static int listOptions(
    )
{
    int i,
        j;

    checkErr((!isROA) && (!isCRL) && (!isCert) && (!isRPSL) &&
             (!isManifest), BAD_OBJECT_TYPE);
    printf("\nPossible fields to display or use in clauses for a %s:\n",
           objectType);
    for (i = 0; i < getNumFields(); i++)
    {
        if (getFields()[i].description == NULL)
            continue;
        if (((getFields()[i].flags & Q_FOR_ROA) && isROA) ||
            ((getFields()[i].flags & Q_FOR_CRL) && isCRL) ||
            ((getFields()[i].flags & Q_FOR_CERT) && isCert) ||
            ((getFields()[i].flags & Q_FOR_MAN) && isManifest))
        {
            printf("  %s: %s\n", getFields()[i].name,
                   getFields()[i].description);
            if (getFields()[i].flags & Q_JUST_DISPLAY)
            {
                for (j = 0; j < (int)strlen(getFields()[i].name) + 4; j++)
                    printf(" ");
                printf("(Note: This can be used only for display.)\n");
            }
        }
    }
    printf("\n");
    return 0;
}

/*
 * add all fields appropriate for this type (user sent '-d all') 
 */
static int addAllFields(
    char *displays[],
    int numDisplays)
{
    int i;

    for (i = 0; i < getNumFields(); ++i)
    {
        if (getFields()[i].description == NULL)
            continue;
        if (((getFields()[i].flags & Q_FOR_ROA) && isROA) ||
            ((getFields()[i].flags & Q_FOR_CRL) && isCRL) ||
            ((getFields()[i].flags & Q_FOR_MAN) && isManifest) ||
            ((getFields()[i].flags & Q_FOR_CERT) && isCert))
        {
            displays[numDisplays++] = getFields()[i].name;
        }
    }
    return numDisplays;
}

/*
 * add fields needed for RPSL query 
 */
static int addRPSLFields(
    char *displays[],
    int numDisplays)
{
    // XXX hack... just add these by hand
    // XXX worse hack... we have hard-coded SQL field names scattered
    // throughout the code. Help us if we ever change the schema.
    displays[0] = "asn";        /* we only need asn and ip_addrs */
    displays[1] = "ip_addrs";
    displays[2] = "filename";   /* added for commentary */
    return 3;                   /* number of fields added */
}

/*
 * Help user by showing the possible arguments 
 */
static int printUsage(
    )
{
    printf("\nPossible usages:\n  query -r [-o <outfile>] [-s <specsFile>]\n");
    printf
        ("     Note that this is the form that a typical user should always use.\n");
    printf("     It produces the expected output of the system: RPSL.\n");
    printf("     Other forms are only for developers and advanced users\n");
    printf("       to view the supporting data.\n");
    printf("  query -l <type>\n");
    printf
        ("  query -t <type> -d <disp1>...[ -d <dispn>] [-f <cls1>]...[ -f <clsn>] [-o <outfile>] [-s <specsFile>] [-i] [-n] [-m]\n\nSwitches:\n");
    printf("  -r: Output the RPSL data\n");
    printf("  -o <filename>: print results to filename (default is screen)\n");
    printf
        ("  -s <filename>: filename specifies how to handle different types of staleness.\n");
    printf("      See the sample specifications file sampleQuerySpecs\n");
    printf
        ("  -l <type>: list the possible display fields for the type, where type is\n");
    printf("     roa, cert, crl, or manifest.\n");
    printf
        ("  -t <type>: the type of object requested: roa, cert, crl, or man[ifest]\n");
    printf("  -d <field>: display a field of the object (or 'all')\n");
    printf
        ("  -f <field>.<op>.<value>: filter where op is a comparison operator\n");
    printf
        ("     (eq, ne, gt, lt, ge, le).  To include a space in value use '#'.\n");
    printf("  -m: multiline, i.e. each field on a different line\n");
    printf("  -n: do not display labels for fields\n");
    printf("  -i: display even invalid roas and certificates\n");
    printf("  -x <field>: sort output in order of field values\n");
    printf("\n");
    printf("Note: All switches are case insensitive\n");
    printf("Note: RPSL format is route-set:\n");
    printf
        ("route-set: RS-RPKI-ROA-FOR-V4:ASnnnn (or RS-RPKI-ROA-FOR-V6:ASnnnn\n");
    printf("members: <route-prefix> (or mp-members: <route-prefix>)\n");
    return -1;
}

static void setObjectType(
    char *aType)
{
    objectType = aType;
    if (!strcasecmp(objectType, "man") ||
        !strcasecmp(objectType, "mft") || !strcasecmp(objectType, "mnf"))
        objectType = "manifest";
    isROA = (strcasecmp(objectType, "roa") == 0);
    isCRL = (strcasecmp(objectType, "crl") == 0);
    isCert = (strcasecmp(objectType, "cert") == 0);
    isManifest = (strcasecmp(objectType, "manifest") == 0);
    setIsManifest(isManifest);
    isRPSL = (strcasecmp(objectType, "rpsl") == 0);
}

int main(
    int argc,
    char **argv)
{
    char *displays[MAX_VALS],
       *clauses[MAX_CONDS],
       *orderp = NULL;
    int i,
        status;
    int numDisplays = 0;
    int numClauses = 0;

    if (log_init("query.log", "query", LOG_DEBUG, LOG_DEBUG) != 0)
    {
        perror("Could not initialize query client log file");
        exit(1);
    }
    output = stdout;
    useLabels = 1;
    multiline = 0;
    validate = 1;
    if (argc == 1)
        return printUsage();
    if (strcasecmp(argv[1], "-l") == 0)
    {
        if (argc != 3)
            return printUsage();
        setObjectType(argv[2]);
        return listOptions();
    }
    for (i = 1; i < argc; i += 2)
    {
        if (strcasecmp(argv[i], "-r") == 0)
        {
            setObjectType("rpsl");
            useLabels = 0;
            i--;
        }
        else if (strcasecmp(argv[i], "-i") == 0)
        {
            validate = 0;
            i--;
        }
        else if (strcasecmp(argv[i], "-n") == 0)
        {
            useLabels = 0;
            i--;
        }
        else if (strcasecmp(argv[i], "-m") == 0)
        {
            multiline = 1;
            i--;
        }
        else if (argc == (i + 1))
        {
            return printUsage();
        }
        else if (strcasecmp(argv[i], "-t") == 0)
        {
            setObjectType(argv[i + 1]);
        }
        else if (strcasecmp(argv[i], "-d") == 0)
        {
            displays[numDisplays++] = argv[i + 1];
        }
        else if (strcasecmp(argv[i], "-f") == 0)
        {
            clauses[numClauses++] = argv[i + 1];
        }
        else if (strcasecmp(argv[i], "-o") == 0)
        {
            output = fopen(argv[i + 1], "w");
        }
        else if (strcasecmp(argv[i], "-x") == 0)
        {
            orderp = argv[i + 1];
        }
        else if (strcasecmp(argv[i], "-s") == 0)
        {
            if (parseStalenessSpecsFile(argv[i + 1]))
                return -1;
            getSpecsVals(&rejectStaleChain, &rejectStaleManifest,
                         &rejectStaleCRL, &rejectNoManifest, &rejectNotYet);
        }
        else
        {                       // unknown switch
            return printUsage();
        }
    }
    if (isRPSL)
    {
        checkErr(numDisplays != 0, "-d should not be used with RPSL query\n");
        numDisplays = addRPSLFields(displays, 0);
    }
    checkErr((!isROA) && (!isCRL) && (!isCert) && (!isRPSL) &&
             (!isManifest), BAD_OBJECT_TYPE);
    checkErr(numDisplays == 0 && isRPSL == 0, "Need to display something\n");
    if (numDisplays == 1 && strcasecmp(displays[0], "all") == 0)
        numDisplays = addAllFields(displays, 0);
    displays[numDisplays++] = NULL;
    clauses[numClauses++] = NULL;
    if ((status = doQuery(displays, clauses, orderp)) < 0)
        log_msg(LOG_ERR, "%s", err2string(status));
    log_close();
    return status;
}
