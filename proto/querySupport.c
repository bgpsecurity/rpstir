
/*
 * $Id: query.c 857 2009-09-30 15:27:40Z dmontana $ 
 */

/****************
 * Functions and flags shared by query and server code
 ****************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mysql.h>

#include "globals.h"
#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "roa_utils.h"
#include "querySupport.h"
#include "err.h"
#include "myssl.h"

static int rejectStaleChain = 0;
static int rejectStaleManifest = 0;
static int rejectStaleCRL = 0;
static int rejectNoManifest = 0;
static int rejectNotYet = 0;

/*
 * routine to parse the filter specification file which determines how to
 * handle the various meta-data SCM_FLAG_XXX flags (ignore, matchset,
 * matchclr) 
 */
int parseStalenessSpecsFile(
    char *specsFilename)
{
    char str[WHERESTR_SIZE],
        str2[WHERESTR_SIZE],
        str3[WHERESTR_SIZE];
    FILE *input = fopen(specsFilename, "r");

    if (input == NULL)
    {
        printf("Could not open specs file: %s\n", specsFilename);
        exit(-1);
    }
    while (fgets(str, WHERESTR_SIZE, input))
    {
        int got = sscanf(str, "%s %s", str2, str3);
        if (got == 0)
            continue;
        if (str2[0] == '#')
            continue;
        if (got == 1)
        {
            perror("Bad format for specs file\n");
            return -1;
        }
        if (strcmp(str2, "StaleCRL") == 0)
        {
            rejectStaleCRL = str3[0] == 'n' || str3[0] == 'N';
        }
        else if (strcmp(str2, "StaleManifest") == 0)
        {
            rejectStaleManifest = str3[0] == 'n' || str3[0] == 'N';
        }
        else if (strcmp(str2, "StaleValidationChain") == 0)
        {
            rejectStaleChain = str3[0] == 'n' || str3[0] == 'N';
        }
        else if (strcmp(str2, "NoManifest") == 0)
        {
            rejectNoManifest = str3[0] == 'n' || str3[0] == 'N';
        }
        else if (strcmp(str2, "NotYet") == 0)
        {
            rejectNotYet = str3[0] == 'n' || str3[0] == 'N';
        }
        else
        {
            printf("Bad keyword in specs file: %s\n", str2);
            return -1;
        }
    }
    return 0;
}

void getSpecsVals(
    int *rejectStaleChainp,
    int *rejectStaleManifestp,
    int *rejectStaleCRLp,
    int *rejectNoManifestp,
    int *rejectNotYetp)
{
    *rejectStaleChainp = rejectStaleChain;
    *rejectStaleManifestp = rejectStaleManifest;
    *rejectStaleCRLp = rejectStaleCRL;
    *rejectNoManifestp = rejectNoManifest;
    *rejectNotYetp = rejectNotYet;
}

void addQueryFlagTests(
    char *whereStr,
    int needAnd)
{
    addFlagTest(whereStr, SCM_FLAG_VALIDATED, 1, needAnd);
    if (rejectStaleChain)
        addFlagTest(whereStr, SCM_FLAG_NOCHAIN, 0, 1);
    if (rejectStaleCRL)
        addFlagTest(whereStr, SCM_FLAG_STALECRL, 0, 1);
    if (rejectStaleManifest)
        addFlagTest(whereStr, SCM_FLAG_STALEMAN, 0, 1);
    if (rejectNoManifest)
        addFlagTest(whereStr, SCM_FLAG_ONMAN, 1, 1);
    if (rejectNotYet)
        addFlagTest(whereStr, SCM_FLAG_NOTYET, 0, 1);
}


/*
 * all these static variables are used for efficiency, so that
 * there is no need to initialize them with each call to checkValidity
 */
static scmtab *validTable = NULL;
static scmsrcha *validSrch = NULL,
    *anySrch = NULL;
char *validWhereStr;
static char *whereInsertPtr;
static int found;
static char *nextSKI,
   *nextSubject;

/*
 * callback to indicate that parent found 
 */
static int registerFound(
    scmcon * conp,
    scmsrcha * s,
    int numLine)
{
    conp = conp;
    s = s;
    numLine = numLine;
    found = 1;
    return 0;
}

/*
 * check the valdity via the db of the cert whose ski or localID is given 
 */
int checkValidity(
    char *ski,
    unsigned int localID,
    scm * scmp,
    scmcon * connect)
{
    int status;

    // set up main part of query only once, instead of once per object
    if (validTable == NULL)
    {
        validTable = findtablescm(scmp, "certificate");
        validSrch = newsrchscm(NULL, 3, 0, 1);
        QueryField *field = findField("aki");
        addcolsrchscm(validSrch, "aki", field->sqlType, field->maxSize);
        char *now = LocalTimeToDBTime(&status);
        field = findField("issuer");
        addcolsrchscm(validSrch, "issuer", field->sqlType, field->maxSize);
        validWhereStr = validSrch->wherestr;
        validWhereStr[0] = 0;
        if (rejectStaleChain)
            snprintf(validWhereStr, WHERESTR_SIZE, "valto>\"%s\"", now);
        free(now);
        addFlagTest(validWhereStr, SCM_FLAG_VALIDATED, 1, rejectStaleChain);
        if (rejectStaleChain)
            addFlagTest(validWhereStr, SCM_FLAG_NOCHAIN, 0, 1);
        if (rejectStaleCRL)
            addFlagTest(validWhereStr, SCM_FLAG_STALECRL, 0, 1);
        if (rejectStaleManifest)
            addFlagTest(validWhereStr, SCM_FLAG_STALEMAN, 0, 1);
        if (rejectNotYet)
            addFlagTest(validWhereStr, SCM_FLAG_NOTYET, 0, 1);
        if (rejectNoManifest)
        {
            int len = strlen(validWhereStr);
            snprintf(&validWhereStr[len], WHERESTR_SIZE - len,
                     " and (((flags%%%d)>=%d) or ((flags%%%d)<%d) or ((flags%%%d)>=%d))",
                     2 * SCM_FLAG_ONMAN, SCM_FLAG_ONMAN, 2 * SCM_FLAG_CA,
                     SCM_FLAG_CA, 2 * SCM_FLAG_TRUSTED, SCM_FLAG_TRUSTED);
        }
        whereInsertPtr = &validWhereStr[strlen(validWhereStr)];
        nextSKI = (char *)validSrch->vec[0].valptr;
        nextSubject = (char *)validSrch->vec[1].valptr;

        if (!rejectStaleChain)
        {
            anySrch = newsrchscm(NULL, 1, 0, 1);
            field = findField("flags");
            addcolsrchscm(anySrch, "flags", field->sqlType, field->maxSize);
        }
    }

    // now do the part specific to this cert
    int firstTime = 1;
    char prevSKI[128];
    // keep going until trust anchor, where AKI = SKI
    while (firstTime || (strcmp(nextSKI, prevSKI) != 0))
    {
        if (firstTime)
        {
            firstTime = 0;
            if (ski)
            {
                snprintf(whereInsertPtr, WHERESTR_SIZE - strlen(validWhereStr),
                         " and ski=\"%s\"", ski);
                strncpy(prevSKI, ski, 128);
            }
            else
            {
                snprintf(whereInsertPtr, WHERESTR_SIZE - strlen(validWhereStr),
                         " and local_id=\"%d\"", localID);
                prevSKI[0] = 0;
            }
        }
        else
        {
            char escaped_subject[2 * strlen(nextSubject) + 1];
            mysql_escape_string(escaped_subject, nextSubject,
                                strlen(nextSubject));
            snprintf(whereInsertPtr, WHERESTR_SIZE - strlen(validWhereStr),
                     " and ski=\"%s\" and subject=\"%s\"", nextSKI,
                     escaped_subject);
            strncpy(prevSKI, nextSKI, 128);
        }
        found = 0;
        status = searchscm(connect, validTable, validSrch, NULL,
                           registerFound, SCM_SRCH_DOVALUE_ALWAYS, NULL);
        if (!found)
        {                       // no parent cert
            if (rejectStaleChain)
                return 0;
            snprintf(anySrch->wherestr, WHERESTR_SIZE, "%s",
                     whereInsertPtr + 5);
            status =
                searchscm(connect, validTable, anySrch, NULL, registerFound,
                          SCM_SRCH_DOVALUE_ALWAYS, NULL);
            return !found;
        }
    }
    return 1;
}


/*
 * combines dirname and filename into a pathname 
 */
static int pathnameDisplay(
    scmsrcha * s,
    int idx1,
    char *returnStr)
{
    snprintf(returnStr, MAX_RESULT_SZ, "%s/%s",
             (char *)s->vec[idx1].valptr, (char *)s->vec[idx1 + 1].valptr);
    return 2;
}

/*
 * create space-separated string of serial numbers 
 */
static int displaySNList(
    scmsrcha * s,
    int idx1,
    char *returnStr)
{
    uint8_t *snlist;
    unsigned int i,
        snlen;
    char *hexs;
    char nomem[] = "out-of-memory";

    snlen = *((unsigned int *)(s->vec[idx1].valptr));
    snlist = (uint8_t *)s->vec[idx1 + 1].valptr;
    returnStr[0] = 0;
    for (i = 0; i < snlen; i++)
    {
        hexs = hexify(SER_NUM_MAX_SZ, &snlist[SER_NUM_MAX_SZ * i], HEXIFY_X);
        if (hexs == NULL)
        {
            // XXX: there should be a better way to signal an error
            hexs = nomem;
        }
        snprintf(&returnStr[strlen(returnStr)],
                 MAX_RESULT_SZ - strlen(returnStr), "%s%s",
                 (i == 0) ? "" : " ", hexs);
        if (hexs == nomem)
        {
            break;
        }
        free(hexs);
    }
    return 2;
}

/*
 * helper function for displayFlags 
 */
static void addFlagIfSet(
    char *returnStr,
    unsigned int flags,
    unsigned int flag,
    char *str)
{
    if (flags & flag)
    {
        snprintf(&returnStr[strlen(returnStr)],
                 MAX_RESULT_SZ - strlen(returnStr), "%s%s",
                 (returnStr[0] == 0) ? "" : " | ", str);
    }
}

static void addFlagIfUnset(
    char *returnStr,
    unsigned int flags,
    unsigned int flag,
    char *str)
{
    if (!(flags & flag))
    {
        snprintf(&returnStr[strlen(returnStr)],
                 MAX_RESULT_SZ - strlen(returnStr), "%s%s",
                 (returnStr[0] == 0) ? "" : " | ", str);
    }
}

static int isManifest = 0;

void setIsManifest(
    int val)
{
    isManifest = val;
}

/*
 * create list of all flags set to true 
 */
static int displayFlags(
    scmsrcha * s,
    int idx1,
    char *returnStr)
{
    unsigned int flags = *((unsigned int *)(s->vec[idx1].valptr));
    returnStr[0] = 0;
    addFlagIfSet(returnStr, flags, SCM_FLAG_CA, "CA");
    addFlagIfSet(returnStr, flags, SCM_FLAG_TRUSTED, "TRUSTED");
    addFlagIfSet(returnStr, flags, SCM_FLAG_VALIDATED, "VALIDATED");
    if ((flags & SCM_FLAG_VALIDATED))
    {
        if ((flags & SCM_FLAG_NOCHAIN))
            addFlagIfSet(returnStr, flags, SCM_FLAG_NOCHAIN, "NOCHAIN");
        else
            addFlagIfUnset(returnStr, flags, SCM_FLAG_NOCHAIN, "CHAINED");
    }
    addFlagIfSet(returnStr, flags, SCM_FLAG_NOTYET, "NOTYET");
    addFlagIfSet(returnStr, flags, SCM_FLAG_STALECRL, "STALECRL");
    addFlagIfSet(returnStr, flags, SCM_FLAG_STALEMAN, "STALEMAN");
    if (!isManifest)
    {
        addFlagIfSet(returnStr, flags, SCM_FLAG_ONMAN, "ONMAN");
    }
    addFlagIfSet(returnStr, flags, SCM_FLAG_HASPARACERT, "HASPARACERT");
    addFlagIfSet(returnStr, flags, SCM_FLAG_ISPARACERT, "ISPARACERT");
    addFlagIfSet(returnStr, flags, SCM_FLAG_ISTARGET, "ISTARGET");
    return 1;
}

/*
 * the set of all query fields 
 */
static QueryField fields[] = {
    {
     "filename",
     "the filename where the data is stored in the repository",
     Q_FOR_ROA | Q_FOR_CRL | Q_FOR_CERT | Q_FOR_MAN | Q_FOR_RTA,
     SQL_C_CHAR, FNAMESIZE,
     NULL, NULL,
     "Filename", NULL,
     },
    {
     "pathname",
     "full pathname (directory plus filename) where the data is stored",
     Q_JUST_DISPLAY | Q_FOR_ROA | Q_FOR_CERT | Q_FOR_CRL | Q_FOR_MAN |
     Q_FOR_RTA | Q_REQ_JOIN,
     -1, 0,
     "dirname", "filename",
     "Pathname", pathnameDisplay,
     },
    {
     "dirname",
     "the directory in the repository where the data is stored",
     Q_FOR_ROA | Q_FOR_CRL | Q_FOR_CERT | Q_FOR_MAN | Q_FOR_RTA | Q_REQ_JOIN,
     SQL_C_CHAR, DNAMESIZE,
     NULL, NULL,
     "Directory", NULL,
     },
    {
     "ski",
     "subject key identifier",
     Q_FOR_ROA | Q_FOR_CERT | Q_FOR_MAN,
     SQL_C_CHAR, SKISIZE,
     NULL, NULL,
     "SKI", NULL,
     },
    {
     "ski_ee",
     "rta ee subject key identifier",
     Q_FOR_RTA,
     SQL_C_CHAR, SKISIZE,
     NULL, NULL,
     "EE_SKI", NULL,
     },
    {
     "ski_rta",
     "rta subject key identifier",
     Q_FOR_RTA,
     SQL_C_CHAR, SKISIZE,
     NULL, NULL,
     "RTA_SKI", NULL,
     },
    {
     "aki",
     "authority key identifier",
     Q_FOR_CRL | Q_FOR_CERT,
     SQL_C_CHAR, SKISIZE,
     NULL, NULL,
     "AKI", NULL,
     },
    {
     "sia",
     "Subject Information Access",
     Q_FOR_CERT,
     SQL_C_CHAR, SIASIZE,
     NULL, NULL,
     "SIA", NULL,
     },
    {
     "aia",
     "Authority Information Access",
     Q_FOR_CERT,
     SQL_C_CHAR, SIASIZE,
     NULL, NULL,
     "AIA", NULL,
     },
    {
     "crldp",
     "CRL Distribution Points",
     Q_FOR_CERT,
     SQL_C_CHAR, SIASIZE,
     NULL, NULL,
     "CRLDP", NULL,
     },
    {
     "ip_addrs",                /* name of the field */
     "the set of IP addresses assigned by the ROA",
     Q_JUST_DISPLAY | Q_FOR_ROA,        /* flags */
     SQL_C_CHAR, 32768,         /* sql return type, size */
     NULL,                      /* use this for query, not name */
     NULL,                      /* second field for query */
     "IP Addresses",            /* name of column for printout */
     NULL,                      /* function for display string */
     },
    {
     "asn",
     "autonomous system number",
     Q_FOR_ROA,
     SQL_C_ULONG, 8,
     NULL, NULL,
     "AS#", NULL,
     },
    {
     "issuer",
     "system that issued the cert/crl",
     Q_FOR_CERT | Q_FOR_CRL,
     SQL_C_CHAR, SUBJSIZE,
     NULL, NULL,
     "Issuer", NULL,
     },
    {
     "valfrom",
     "date/time from which the cert is valid",
     Q_FOR_CERT,
     SQL_C_CHAR, 32,
     NULL, NULL,
     "Valid From", NULL,
     },
    {
     "valto",
     "date/time to which the cert is valid",
     Q_FOR_CERT,
     SQL_C_CHAR, 32,
     NULL, NULL,
     "Valid To", NULL,
     },
    {
     "last_upd",
     "last update time of the object",
     Q_FOR_CRL,
     SQL_C_CHAR, 32,
     NULL, NULL,
     "Last Update", NULL,
     },
    {
     "this_upd",
     "last update time of the object",
     Q_FOR_MAN,
     SQL_C_CHAR, 32,
     NULL, NULL,
     "This Update", NULL,
     },
    {
     "next_upd",
     "next update time of the object",
     Q_FOR_CRL | Q_FOR_MAN,
     SQL_C_CHAR, 32,
     NULL, NULL,
     "Next Update", NULL,
     },
    {
     "crlno",
     "CRL number",
     Q_JUST_DISPLAY | Q_FOR_CRL,
     SQL_C_BINARY, 20,
     NULL, NULL,
     "CRL#", NULL,
     },
    {
     "sn",
     "serial number",
     Q_JUST_DISPLAY | Q_FOR_CERT,
     SQL_C_BINARY, 20,
     NULL, NULL,
     "Serial#", NULL,
     },
    {
     "snlen",
     "number of serial numbers in crl",
     Q_FOR_CRL,
     SQL_C_ULONG, 8,
     NULL, NULL,
     "SNLength", NULL,
     },
    {
     "snlist",
     NULL,
     Q_JUST_DISPLAY | Q_FOR_CRL,
     SQL_C_BINARY, 16000000,
     NULL, NULL,
     NULL, NULL,
     },
    {
     "files",
     "All the filenames in the manifest",
     Q_JUST_DISPLAY | Q_FOR_MAN,
     SQL_C_BINARY, 160000,
     NULL, NULL,
     "FilesInMan", NULL,
     },
    {
     "serial_nums",
     "list of serials numbers",
     Q_JUST_DISPLAY | Q_FOR_CRL,
     -1, 0,
     "snlen", "snlist",
     "Serial#s", displaySNList,
     },
    {
     "flags",
     "which flags are set in the database",
     Q_JUST_DISPLAY | Q_FOR_CERT | Q_FOR_CRL | Q_FOR_ROA | Q_FOR_MAN |
     Q_FOR_RTA,
     SQL_C_ULONG, 8,
     NULL, NULL,
     "Flags Set", displayFlags,
     }
};

/*
 * look up particular query field in the list of all possible fields 
 */
QueryField *findField(
    char *name)
{
    int i;
    int size = sizeof(fields) / sizeof(fields[0]);
    for (i = 0; i < size; i++)
    {
        if (strcasecmp(name, fields[i].name) == 0)
            return &fields[i];
    }
    return NULL;
}

QueryField *getFields(
    )
{
    return fields;
}

int getNumFields(
    )
{
    return countof(fields);
}
