#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "scm.h"
#include "scmf.h"
#include "err.h"
#include "roa_utils.h"
#include "myssl.h"
#include "sqhl.h"

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  David Montana
 *
 * ***** END LICENSE BLOCK ***** */

/*
  $Id$
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
#define MAX_RESULT_SZ 8192

typedef int (*displayfunc)(scmsrcha *s, int idx1, char* returnStr);

typedef struct _QueryField    /* field to display or filter on */
{
  char     *name;	      /* name of the field */
  int      justDisplay;       /* true if not allowed to filter on field */
  int      forROAs;           /* true if field is used in a ROA */
  int      forCRLs;           /* true if field is used in a CRL */
  int      forCerts;          /* true if field is used in a cert */
  int      sqlType;           /* what type of data to expect from query */
  int      maxSize;           /* how much space to allocate for response */
  char     *dbColumn;         /* if not NULL, use this for query, not name */
  char     *otherDBColumn;    /* if not NULL, second field for query */
  char     *heading;          /* name of column heading to use in printout */
  int      requiresJoin;      /* do join with dirs table to get dirname */
  displayfunc displayer;      /* function for display string, NULL if std */
  char     *description;      /* one-line description for user help */
} QueryField;

int pathnameDisplay (scmsrcha *s, int idx1, char* returnStr);
int displayEntry (scmsrcha *s, int idx1, char* returnStr);
int displaySNList (scmsrcha *s, int idx1, char* returnStr);

/* the set of all query fields */
static QueryField fields[] = {
  {"filter", 1, 1, 0, 0, SQL_C_CHAR, 4096, NULL, NULL, "Filter Entry",
   0, NULL, "the entry in the BGP filter file"},
  {"filename", 0, 1, 1, 1, SQL_C_CHAR, FNAMESIZE, NULL, NULL, "Filename", 0,
   NULL, "the filename where the data is stored in the repository"},
  {"pathname", 1, 1, 1, 1, -1, 0, "dirname", "filename",
   "Pathname", 1, pathnameDisplay,
   "full pathname (directory plus filename) where the data is stored"},
  {"dirname", 0, 1, 1, 1, SQL_C_CHAR, DNAMESIZE, NULL, NULL, "Directory", 1,
   NULL, "the directory in the repository where the data is stored"},
  {"ski", 0, 1, 0, 1, SQL_C_CHAR, SKISIZE, NULL, NULL, "SKI", 0, NULL,
   "subject key identifier"},
  {"aki", 0, 0, 1, 1, SQL_C_CHAR, SKISIZE, NULL, NULL, "AKI", 0, NULL,
   "authority key identifier"},
  {"sia", 0, 0, 0, 1, SQL_C_CHAR, SIASIZE, NULL, NULL, "SIA", 0, NULL,
   "Subject Information Access"},
  {"aia", 0, 0, 0, 1, SQL_C_CHAR, SIASIZE, NULL, NULL, "AIA", 0, NULL,
   "Authority Information Access"},
  {"crldp", 0, 0, 0, 1, SQL_C_CHAR, SIASIZE, NULL, NULL, "CRLDP", 0, NULL,
   "CRL Distribution Points"},
  {"asn", 0, 1, 0, 0, SQL_C_ULONG, 8, NULL, NULL, "AS#", 0, NULL,
   "autonomous system number"},
  {"issuer", 0, 0, 1, 1, SQL_C_CHAR, SUBJSIZE, NULL, NULL, "Issuer", 0,
   NULL, "system that issued the cert/crl"},
  {"valfrom", 0, 0, 0, 1, SQL_C_CHAR, 32, NULL, NULL, "Valid From", 0,
   NULL, "date/time from which the cert is valid"},
  {"valto", 0, 0, 0, 1, SQL_C_CHAR, 32, NULL, NULL, "Valid To", 0,
   NULL, "date/time to which the cert is valid"},
  {"last_upd", 0, 0, 1, 0, SQL_C_CHAR, 32, NULL, NULL, "Last Update", 0,
   NULL, "last update time of the CRL"},
  {"next_upd", 0, 0, 1, 0, SQL_C_CHAR, 32, NULL, NULL, "Next Update", 0,
   NULL, "next update time of the CRL"},
  {"crlno", 0, 0, 1, 0, SQL_C_ULONG, 8, NULL, NULL, "CRL#", 0,
   NULL, "CRL number"},
  {"sn", 0, 0, 0, 1, SQL_C_ULONG, 8, NULL, NULL, "Serial#", 0,
   NULL, "serial number"},
  {"snlen", 0, 0, 1, 0, SQL_C_ULONG, 8, NULL, NULL, "SNLength", 0, NULL, "number of serial numbers in list"},
  {"snlist", 1, 0, 1, 0, SQL_C_BINARY, 16000000, NULL, NULL, NULL,
   0, NULL, NULL},
  {"serial_nums", 1, 0, 1, 0, -1, 0, "snlen", "snlist", "Serial#s", 0,
   displaySNList, "list of serials numbers"}
};

/* look up particular query field in the list of all possible fields */
static QueryField *findField (char *name)
{
  int i;
  int size = sizeof (fields) / sizeof (fields[0]);
  for (i = 0; i < size; i++) {
    if (strcasecmp (name, fields[i].name) == 0) return &fields[i];
  }
  return NULL;
}

/* combines dirname and filename into a pathname */
int pathnameDisplay (scmsrcha *s, int idx1, char* returnStr)
{
  snprintf (returnStr, MAX_RESULT_SZ, "%s/%s",
	    (char *) s->vec[idx1].valptr, (char *) s->vec[idx1+1].valptr);
  return 2;
}

/* create space-separated string of serial numbers */
int displaySNList (scmsrcha *s, int idx1, char* returnStr)
{
  unsigned long long *snlist;
  unsigned int i, snlen;

  snlen = *((unsigned int *) (s->vec[idx1].valptr));
  snlist = (unsigned long long *) s->vec[idx1+1].valptr;
  returnStr[0] = 0;
  for (i = 0; i < snlen; i++) {
    snprintf (&returnStr[strlen(returnStr)], MAX_RESULT_SZ-strlen(returnStr),
	      "%s%llu", (i == 0) ? "" : " ", snlist[i]);
  }
  return 2;
}

/*
 * I hate to use all these static variables, but the problem is
 * that there's no other way to pass them on to all the callback
 * functions that are used to process SQL queries
 */
static FILE *output;  /* place to print output (file or screen) */
static int rejectStaleChain = 0;
static int rejectStaleManifest = 0;
static int rejectStaleCRL = 0;
static int rejectNoManifest = 0;
static QueryField *globalFields[MAX_VALS];  /* to pass into handleResults */
static int useLabels, multiline, validate, valIndex;
static char *objectType;
static int isROA = 0, isCert = 0, isCRL = 0, isRPSL = 0;
static scm      *scmp = NULL;
static scmcon   *connect = NULL;

/* reads a roa from a file in order to determine the filter entry */
int displayEntry (scmsrcha *s, int idx1, char* returnStr)
{
  struct ROA *roa;
  (void) pathnameDisplay (s, idx1, returnStr);
  int format = (strncmp (".pem", &returnStr[strlen(returnStr)-4], 4) == 0) ?
               FMT_PEM : FMT_DER;
  checkErr (roaFromFile (returnStr, format, 0, &roa) != 0,
            "Error reading ROA: %s\n", returnStr);
  roaGenerateFilter (roa, NULL, NULL, returnStr);
  roaFree(roa);
  return 2;
}

/*
 * all these static variables are used for efficiency, so that
 * there is no need to initialize them with each call to checkValidity
 */
static scmtab   *validTable = NULL;
static scmsrcha *validSrch = NULL;
char  *validWhereStr;
static char     *whereInsertPtr;
static int      found;
static char     *nextSKI, *nextSubject;

/* callback to indicate that parent found */
static int registerFound (scmcon *conp, scmsrcha *s, int numLine) {
  conp = conp; s = s; numLine = numLine;
  found = 1;
  return 0;
}

/* check the valdity via the db of the cert whose ski or localID is given */
static int checkValidity (char *ski, unsigned int localID) {
  int status;

  // set up main part of query only once, instead of once per object
  if (validTable == NULL) {
    validTable = findtablescm (scmp, "certificate");
    validSrch = newsrchscm(NULL, 3, 0, 1);
    QueryField *field = findField ("aki");
    addcolsrchscm (validSrch, "aki", field->sqlType, field->maxSize);
    field = findField ("issuer");
    addcolsrchscm (validSrch, "issuer", field->sqlType, field->maxSize);
    char *now = LocalTimeToDBTime (&status);
    validWhereStr = validSrch->wherestr;
    validWhereStr[0] = 0;
    if (rejectStaleChain)
      snprintf (validWhereStr, WHERESTR_SIZE, "valto>\"%s\"", now);
    free (now);
    addFlagTest(validWhereStr, SCM_FLAG_VALIDATED, 1,
		rejectStaleChain);
    if (rejectStaleChain)
      addFlagTest(validWhereStr, SCM_FLAG_NOCHAIN, 0, 1);
    if (rejectStaleCRL)
      addFlagTest(validWhereStr, SCM_FLAG_STALECRL, 0, 1);
    if (rejectStaleManifest)
      addFlagTest(validWhereStr, SCM_FLAG_STALEMAN, 0, 1);
    if (rejectNoManifest)
      addFlagTest(validWhereStr, SCM_FLAG_NOVALIDMAN, 0, 1);
    whereInsertPtr = &validWhereStr[strlen(validWhereStr)];
    nextSKI = (char *) validSrch->vec[0].valptr;
    nextSubject = (char *) validSrch->vec[1].valptr;
  }

  // now do the part specific to this cert
  int firstTime = 1;
  char prevSKI[128];
  // keep going until trust anchor, where AKI = SKI
  while (firstTime || (strcmp (nextSKI, prevSKI) != 0)) {
    if (firstTime) {
      firstTime = 0;
      if (ski) {
        snprintf (whereInsertPtr, WHERESTR_SIZE-strlen(validWhereStr),
		  " and ski=\"%s\"", ski);
	strncpy (prevSKI, ski, 128);
      } else {
        snprintf (whereInsertPtr, WHERESTR_SIZE-strlen(validWhereStr),
		  " and local_id=\"%d\"", localID);
	prevSKI[0] = 0;
      }
    } else {
      snprintf (whereInsertPtr, WHERESTR_SIZE-strlen(validWhereStr),
		" and ski=\"%s\" and subject=\"%s\"", nextSKI, nextSubject);
      strncpy (prevSKI, nextSKI, 128);
    }
    found = 0;
    status = searchscm (connect, validTable, validSrch, NULL,
                        registerFound, SCM_SRCH_DOVALUE_ALWAYS);
    if (! found) return 0;  // no parent cert
  }
  return 1;
}

/* callback function for searchscm that prints the output */
static int handleResults (scmcon *conp, scmsrcha *s, int numLine)
{
  int result = 0;
  int display;
  char resultStr[MAX_RESULT_SZ];

  conp = conp; numLine = numLine;  // silence compiler warnings
  if (validate) {
    if (!checkValidity (isROA ? (char *) s->vec[valIndex].valptr : NULL,
			isCert ? *((unsigned int *)s->vec[valIndex].valptr) : 0))
	return 0;
  }
  for (display = 0; globalFields[display] != NULL; display++) {
    QueryField *field = globalFields[display];
    if (field->displayer != NULL) {
      result += field->displayer (s, result, resultStr);
    } else {
      if (field->sqlType == SQL_C_CHAR)
        snprintf (resultStr, MAX_RESULT_SZ,
		  "%s", (char *) s->vec[result].valptr);
      else
        snprintf (resultStr, MAX_RESULT_SZ,
		  "%d", *((unsigned int *) s->vec[result].valptr));
      result++;
    }
    if (multiline) fprintf (output, "%s ", (display == 0) ? "*" : " ");
    if (useLabels) 
      fprintf (output, "%s = %s  ", field->heading, resultStr);
    else
      fprintf (output, "%s  ", resultStr);
    if (multiline) fprintf (output, "\n");
  }
  if (! multiline) fprintf (output, "\n");
  return(0);
}

/* sets up and performs the database query, and handles the results */
static int doQuery (char **displays, char **filters)
{
  scmtab   *table = NULL;
  scmsrcha srch;
  scmsrch  srch1[MAX_VALS];
  char     whereStr[MAX_CONDS*20];
  char     errMsg[1024];
  int      srchFlags = SCM_SRCH_DOVALUE_ALWAYS;
  unsigned long blah = 0;
  int      i, j, status;
  QueryField *field, *field2;
  char     *name;
  int      maxW = MAX_CONDS*20;

  checkErr ((! isROA) && (! isCRL) && (! isCert) && (! isRPSL),
            "\nBad object type; must be roa, cert, crl, or RPSL\n\n");
  (void) setbuf (stdout, NULL);
  scmp = initscm();
  checkErr (scmp == NULL, "Cannot initialize database schema\n");
  connect = connectscm (scmp->dsn, errMsg, 1024);
  checkErr (connect == NULL, "Cannot connect to database: %s\n", errMsg);
  connect->mystat.tabname = objectType;
  table = findtablescm (scmp, isCert ? "certificate" : objectType);
  checkErr (table == NULL, "Cannot find table %s\n", objectType);

  /* set up where clause, i.e. the filter */
  srch.where = NULL;
  whereStr[0] = 0;
  if (filters == NULL || filters[0] == NULL) {
    srch.wherestr = NULL;
  } else {
    whereStr[0] = (char) 0;
    for (i = 0; filters[i] != NULL; i++) {
      if (i != 0) strncat (whereStr, " AND ", maxW-strlen(whereStr));
      name = strtok (filters[i], ".");
      strncat (whereStr, name, maxW-strlen(whereStr));
      field = findField (name);
      checkErr (field == NULL || field->description == NULL,
		"Unknown field name: %s\n", name);
      checkErr (field->justDisplay, "Field only for display: %s\n", name);
      name = strtok (NULL, ".");
      if (strcasecmp (name, "eq") == 0) {
        strncat (whereStr, "=", maxW-strlen(whereStr));
      } else if (strcasecmp (name, "ne") == 0) {
        strncat (whereStr, "<>", maxW-strlen(whereStr));
      } else if (strcasecmp (name, "lt") == 0) {
        strncat (whereStr, "<", maxW-strlen(whereStr));
      } else if (strcasecmp (name, "gt") == 0) {
        strncat (whereStr, ">", maxW-strlen(whereStr));
      } else if (strcasecmp (name, "le") == 0) {
        strncat (whereStr, "<=", maxW-strlen(whereStr));
      } else if (strcasecmp (name, "ge") == 0) {
        strncat (whereStr, ">=", maxW-strlen(whereStr));
      } else {
        checkErr (1, "Bad comparison operator: %s\n", name);
      }
      strncat (whereStr, "\"", maxW-strlen(whereStr));
      name = strtok (NULL, "");
      for (j = 0; j < (int)strlen(name); j++) {
	if (name[j] == '#') name[j] = ' ';
      }
      strncat (whereStr, name, maxW-strlen(whereStr));
      strncat (whereStr, "\"", maxW-strlen(whereStr));
    }
    srch.wherestr = whereStr;
  }
  if (validate) {
    addFlagTest(whereStr, SCM_FLAG_VALIDATED, 1, srch.wherestr != NULL);
    if (rejectStaleChain)
      addFlagTest(whereStr, SCM_FLAG_NOCHAIN, 0, 1);
    if (rejectStaleCRL)
      addFlagTest(whereStr, SCM_FLAG_STALECRL, 0, 1);
    if (rejectStaleManifest)
      addFlagTest(whereStr, SCM_FLAG_STALEMAN, 0, 1);
    if (rejectNoManifest)
      addFlagTest(whereStr, SCM_FLAG_NOVALIDMAN, 0, 1);
    srch.wherestr = whereStr;
  }

  /* set up columns to select */
  srch.vec = srch1;
  srch.sname = NULL;
  srch.ntot = MAX_VALS;
  srch.nused = 0;
  srch.vald = 0;
  srch.context = &blah;
  for (i = 0; displays[i] != NULL; i++) {
    field = findField (displays[i]);
    checkErr (field == NULL || field->description == NULL,
	      "Unknown field name: %s\n", displays[i]);
    globalFields[i] = field;
    name = (field->dbColumn == NULL) ? displays[i] : field->dbColumn;
    while (name != NULL) {
      field2 = findField (name);
      addcolsrchscm (&srch, name, field2->sqlType, field2->maxSize);
      if (field->requiresJoin) srchFlags = srchFlags | SCM_SRCH_DO_JOIN;
      name = (name == field->otherDBColumn) ? NULL : field->otherDBColumn;
    }
  }
  globalFields[i] = NULL;
  if (validate) {
    valIndex = srch.nused;
    if (isROA) {
      field2 = findField ("ski");
      addcolsrchscm (&srch, "ski", field2->sqlType, field2->maxSize);
    } else if (isCert) {
      addcolsrchscm (&srch, "local_id", SQL_C_ULONG, 8);
    }
  }

  /* do query */
  status = searchscm (connect, table, &srch, NULL, handleResults, srchFlags);
  for (i = 0; i < srch.nused; i++) {
    free (srch.vec[i].colname);
    free (srch1[i].valptr);
  }
  return status;
}

/* parse the specs telling which non-perfect ROA's to accept */
static void parseSpecsFile(char *specsFilename)
{
  char str[WHERESTR_SIZE], str2[WHERESTR_SIZE], str3[WHERESTR_SIZE];
  FILE *input = fopen (specsFilename, "r");
  if (input == NULL) {
    printf ("Could not open specs file: %s\n", specsFilename);
    exit(-1);
  }
  while (fgets (str, WHERESTR_SIZE, input)) {
    int got = sscanf(str, "%s %s", str2, str3);
    if (got == 0) continue;
    if (str2[0] == '#') continue;
    if (got == 1) perror ("Bad format for specs file\n");
    if (strcmp(str2, "StaleCRL") == 0) {
      rejectStaleCRL = str3[0] == 'n' || str3[0] == 'N';
    } else if (strcmp(str2, "StaleManifest") == 0) {
      rejectStaleManifest = str3[0] == 'n' || str3[0] == 'N';
    } else if (strcmp(str2, "StaleValidationChain") == 0) {
      rejectStaleChain = str3[0] == 'n' || str3[0] == 'N';
    } else if (strcmp(str2, "NoManifest") == 0) {
      rejectNoManifest = str3[0] == 'n' || str3[0] == 'N';
    } else {
      printf ("Bad keyword in specs file: %s\n", str2);
      exit(-1);
    }
  }
}

/* show what options the user has for fields for display and filtering */
static int listOptions()
{
  int i, j;
  
  checkErr ((! isROA) && (! isCRL) && (! isCert) && (! isRPSL),
            "\nBad object type; must be roa, cert, crl, or rpsl\n\n");
  printf ("\nPossible fields to display or use in clauses for a %s:\n",
          objectType);
  for (i = 0; i < countof(fields); i++) {
    if (fields[i].description == NULL) continue;
    if ((fields[i].forROAs && isROA) || (fields[i].forCRLs && isCRL) ||
        (fields[i].forCerts && isCert)) {
      printf ("  %s: %s\n", fields[i].name, fields[i].description);
      if (fields[i].justDisplay) {
        for (j = 0; j < (int)strlen (fields[i].name) + 4; j++) printf (" ");
        printf ("(Note: This can be used only for display.)\n");
      }
    }
  }
  printf ("\n");
  return 0;
}

/* add all fields appropriate for this type (user sent '-d all') */
static int addAllFields(char *displays[], int numDisplays)
{
  int i;

  for (i = 0; i < countof(fields); ++i) {
    if (fields[i].description == NULL) continue;
    if ((fields[i].forROAs && isROA) || (fields[i].forCRLs && isCRL) ||
        (fields[i].forCerts && isCert)) {
	displays[numDisplays++] = fields[i].name;
    }
  }
  return numDisplays;
}

/* Help user by showing the possible arguments */
static int printUsage()
{
  printf ("\nPossible usages:\n  query -a [-o <outfile>] [-s <specsFile>]\n");
  printf ("  query -l <type>\n");
  printf ("  query -t <type> -d <disp1>...[ -d <dispn>] [-f <cls1>]...[ -f <clsn>] [-o <outfile>] [-v] [-n] [-m]\n\nSwitches:\n");
  printf ("  -a: short cut for -t roa -d filter -v -n\n");
  printf ("  -o: name of output file for the results (omitted = screen)\n");
  printf ("  -s: input filename where how to handle non-perfect objects specified\n");
  printf ("      see the sample specifications file sampleQuerySpecs\n");
  printf ("  -l: list the possible display fields and clauses for a given type (roa, cert, or crl)\n");
  printf ("  -t: the type of object requested (roa, cert, crl, or rpsl)\n");
  printf ("  -d: the name of one field of the object to display (or 'all')\n");
  printf ("  -f: one clause to use for filtering; a clause has the form\n");
  printf ("      <fieldName>.<op>.<value>, where op is a comparison operator\n");
  printf ("      (eq, ne, gt, lt, ge, le); to include a space in value,\n");
  printf ("      put a # where the space should be\n");
  printf ("  -v: only display valid roa's and cert's\n");
  printf ("  -n: no labels for the data fields displayed\n");
  printf ("  -m: multiline, i.e. each field on a different line\n\n");
  printf ("\n");
  printf ("Note: RPSL format is route-set:\n");
  printf ("route-set: RS-RPKI-ROA-FOR-V4:ASnnnn (or RS-RPKI-ROA-FOR-V6:ASnnnn\n");
  printf ("members: <route-prefix>\n");
  return -1;
}

static void setObjectType (char *aType)
{
  objectType = aType;
  isROA = strcasecmp (objectType, "roa") == 0;
  isCRL = strcasecmp (objectType, "crl") == 0;
  isCert = strcasecmp (objectType, "cert") == 0;
  isRPSL = strcasecmp (objectType, "rpsl") == 0;
}

int main(int argc, char **argv) 
{
  char *displays[MAX_VALS], *clauses[MAX_CONDS];
  int i, status;
  int numDisplays = 0;
  int numClauses = 0;

  startSyslog ("query");
  output = stdout;
  useLabels = 1;
  multiline = 0;
  validate = 0;
  if (argc == 1) return printUsage();
  if (strcasecmp (argv[1], "-l") == 0) {
    if (argc != 3) return printUsage();
    setObjectType (argv[2]);
    return listOptions();
  }
  for (i = 1; i < argc; i += 2) {
    if (strcasecmp (argv[i], "-a") == 0) {
      setObjectType ("roa");
      displays [numDisplays++] = "filter";
      validate = 1;
      useLabels = 0;
      i--;
    } else if (strcasecmp (argv[i], "-v") == 0) {
      validate = 1;
      i--;
    } else if (strcasecmp (argv[i], "-n") == 0) {
      useLabels = 0;
      i--;
    } else if (strcasecmp (argv[i], "-m") == 0) {
      multiline = 1;
      i--;
    } else if (argc == (i+1)) {
      return printUsage();
    } else if (strcasecmp (argv[i], "-t") == 0) {
      setObjectType (argv[i+1]);
    } else if (strcasecmp (argv[i], "-d") == 0) {
      displays [numDisplays++] = argv[i+1];
    } else if (strcasecmp (argv[i], "-f") == 0) {
      clauses [numClauses++] = argv[i+1];
    } else if (strcasecmp (argv[i], "-o") == 0) {
      output = fopen (argv[i+1], "w");
    } else if (strcasecmp (argv[i], "-s") == 0) {
      parseSpecsFile(argv[i+1]);
    } else {      // unknown switch
      return printUsage();
    }
  }
  checkErr (numDisplays == 0, "Need to display something\n");
  if (numDisplays == 1 && strcasecmp(displays[0], "all") == 0)
      numDisplays = addAllFields(displays, 0);
  displays[numDisplays++] = NULL;
  clauses[numClauses++] = NULL;
  status = doQuery (displays, clauses);
  stopSyslog();
  return status;
}
