#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <mysql.h>

#include "rpki/scm.h"
#include "rpki/scmf.h"
#include "rpki/err.h"
#include "rpki/cms/roa_utils.h"
#include "rpki/myssl.h"
#include "rpki/sqhl.h"
#include "rpki/querySupport.h"
#include "config/config.h"
#include "util/logging.h"
#include "util/stringutils.h"


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
  "\nBad object type; must be roa, cert, crl, man[ifest], or gbr\n\n"

/*
 * I hate to use all these static variables, but the problem is
 * that there's no other way to pass them on to all the callback
 * functions that are used to process SQL queries
 */
static FILE *output;            /* place to print output (file or screen) */
static QueryField *globalFields[MAX_VALS];      /* to pass into handleResults */
static int useLabels,
    multiline,
    validate,
    valIndex;
static char *objectType;
static int isROA = 0,
    isCert = 0,
    isCRL = 0,
    isManifest = 0,
    isGBR = 0;
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
    "gbr", "ghostbusters"},
};


/*
 * callback function for searchscm that prints the output 
 */
static int handleResults(
    scmcon * conp,
    scmsrcha * s,
    ssize_t numLine)
{
    int result = 0;
    int display;
    char resultStr[MAX_RESULT_SZ];
    int i;

    UNREFERENCED_PARAMETER(numLine);
    if (validate)
    {
        if (!checkValidity
            ((isROA || isManifest || isGBR
              || isCRL) ? (char *)s->vec[valIndex].valptr : NULL,
             isCert ? *((unsigned int *)s->vec[valIndex].valptr) : 0, scmp,
             connection))
            return 0;
    }

    for (display = 0; globalFields[display] != NULL; display++)
    {
        QueryField *field = globalFields[display];
        if (field->displayer != NULL)
        {
            result += field->displayer(
                scmp, conp, s, result, resultStr);
        }
        else if (s->vec[result].avalsize != SQL_NULL_DATA)
        {
            if (field->sqlType == SQL_C_CHAR)
            {
                xsnprintf(resultStr, MAX_RESULT_SZ,
                          "%s", (char *)s->vec[result].valptr);
            }
            else if (field->sqlType == SQL_C_BINARY)
            {
                xsnprintf(resultStr, MAX_RESULT_SZ, "0x");
                for (i = 0;
                     i < s->vec[result].avalsize && MAX_RESULT_SZ > 2 + 2*i;
                     ++i)
                {
                    xsnprintf(resultStr + 2 + 2*i, MAX_RESULT_SZ - (2 + 2*i),
                              "%02" PRIX8,
                              ((uint8_t *)s->vec[result].valptr)[i]);
                }
                if (strlen("0x") + 2 * s->vec[result].avalsize >= MAX_RESULT_SZ &&
                    MAX_RESULT_SZ > strlen("..."))
                {
                    xsnprintf(resultStr + MAX_RESULT_SZ - (1 + strlen("...")),
                              1 + strlen("..."), "...");
                }
            }
            else
                xsnprintf(resultStr, MAX_RESULT_SZ,
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
            char escaped [strlen(name)*2+1];
            mysql_escape_string(escaped, name, strlen(name));

            strncat(whereStr, escaped, maxW - strlen(whereStr));
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
        if (isROA || isManifest || isCRL || isGBR)
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
                       orderp);
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

    checkErr((!isROA) && (!isCRL) && (!isCert) &&
             (!isManifest) && (!isGBR), BAD_OBJECT_TYPE);
    printf("\nPossible fields to display or use in clauses for a %s:\n",
           objectType);
    for (i = 0; i < getNumFields(); i++)
    {
        if (getFields()[i].description == NULL)
            continue;
        if (((getFields()[i].flags & Q_FOR_ROA) && isROA) ||
            ((getFields()[i].flags & Q_FOR_CRL) && isCRL) ||
            ((getFields()[i].flags & Q_FOR_CERT) && isCert) ||
            ((getFields()[i].flags & Q_FOR_MAN) && isManifest) ||
            ((getFields()[i].flags & Q_FOR_GBR) && isGBR))
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
            ((getFields()[i].flags & Q_FOR_CERT) && isCert) ||
            ((getFields()[i].flags & Q_FOR_GBR) && isGBR))
        {
            displays[numDisplays++] = getFields()[i].name;
        }
    }
    return numDisplays;
}

/*
 * Help user by showing the possible arguments 
 */
static int printUsage(
    )
{
    printf("\nPossible usages:\n");
    printf("  query -l <type>\n");
    printf
        ("  query -t <type> -d <disp1>...[ -d <dispn>] [-f <cls1>]...[ -f <clsn>] [-o <outfile>] [-i] [-n] [-m]\n\nSwitches:\n");
    printf("  -o <filename>: print results to filename (default is screen)\n");
    printf
        ("  -l <type>: list the possible display fields for the type, where type is\n");
    printf("     roa, cert, crl, gbr, or manifest.\n");
    printf
        ("  -t <type>: the type of object requested: roa, cert, crl, gbr, or man[ifest]\n");
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
    isGBR = (strcasecmp(objectType, "gbr") == 0);
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

    OPEN_LOG("query", LOG_USER);
    if (!my_config_load())
    {
        LOG(LOG_ERR, "can't initialize configuration");
        exit(EXIT_FAILURE);
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
        if (strcasecmp(argv[i], "-i") == 0)
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
        else
        {                       // unknown switch
            return printUsage();
        }
    }
    checkErr((!isROA) && (!isCRL) && (!isCert) &&
             (!isManifest) && (!isGBR), BAD_OBJECT_TYPE);
    checkErr(numDisplays == 0, "Need to display something\n");
    if (numDisplays == 1 && strcasecmp(displays[0], "all") == 0)
        numDisplays = addAllFields(displays, 0);
    displays[numDisplays++] = NULL;
    clauses[numClauses++] = NULL;
    status = doQuery(displays, clauses, orderp);
    if (status == ERR_SCM_NODATA)
    {
        LOG(LOG_DEBUG, "%s", err2string(status));
        status = 0;
    }
    else if (status < 0)
    {
        LOG(LOG_ERR, "%s", err2string(status));
    }
    config_unload();
    CLOSE_LOG();
    return status;
}
