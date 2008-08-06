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

int pathnameDisplay (scmsrcha *s, int idx1, char* returnStr);
int displayEntry (scmsrcha *s, int idx1, char* returnStr, int returnStrLen);
int displaySNList (scmsrcha *s, int idx1, char* returnStr);

typedef int (*displayfunc)(scmsrcha *s, int idx1, char* returnStr);

#define Q_JUST_DISPLAY  0x01
#define Q_FOR_ROA       0x02
#define Q_FOR_CRL       0x04
#define Q_FOR_CERT      0x08
#define Q_REQ_JOIN	0x10
typedef struct _QueryField    /* field to display or filter on */
{
  char     *name;	      /* name of the field */
  char     *description;      /* one-line description for user help */
  int      flags;	      /* flags (see Q_xyz above) */
  int      sqlType;           /* what type of data to expect from query */
  int      maxSize;           /* how much space to allocate for response */
  char     *dbColumn;         /* if not NULL, use this for query, not name */
  char     *otherDBColumn;    /* if not NULL, second field for query */
  char     *heading;          /* name of column heading to use in printout */
  displayfunc displayer;      /* function for display string, NULL if std */
} QueryField;

/* the set of all query fields */
static QueryField fields[] = {
  {
    "filter",			/* name of the field */
    "the entry in the BGP filter file",
    Q_JUST_DISPLAY|Q_FOR_ROA,	/* flags */
    SQL_C_CHAR, 4096, 		/* sql return type, size */
    NULL, 			/* use this for query, not name */
    NULL, 			/* second field for query */
    "Filter Entry",		/* name of column for printout */
    NULL, 			/* function for display string */
  },
  {
    "filename", 
    "the filename where the data is stored in the repository",
    Q_FOR_ROA|Q_FOR_CRL|Q_FOR_CERT, 
    SQL_C_CHAR, FNAMESIZE, 
    NULL, NULL, 
    "Filename", NULL, 
  },
  {
    "pathname",
    "full pathname (directory plus filename) where the data is stored",
    Q_JUST_DISPLAY|Q_FOR_ROA|Q_FOR_CERT|Q_FOR_CRL|Q_REQ_JOIN,
    -1, 0, 
    "dirname", "filename", 
    "Pathname", pathnameDisplay,
  },
  {
    "dirname",
    "the directory in the repository where the data is stored",
    Q_FOR_ROA|Q_FOR_CRL|Q_FOR_CERT|Q_REQ_JOIN,
    SQL_C_CHAR, DNAMESIZE,
    NULL, NULL,
    "Directory", NULL,
  },
  {
    "ski", 
    "subject key identifier",
    Q_FOR_ROA|Q_FOR_CERT,
    SQL_C_CHAR, SKISIZE,
    NULL, NULL,
    "SKI", NULL,
  },
  {
    "aki", 
    "authority key identifier",
    Q_FOR_CRL|Q_FOR_CERT,
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
    Q_FOR_CERT|Q_FOR_CRL,
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
    "last update time of the CRL",
    Q_FOR_CRL,
    SQL_C_CHAR, 32,
    NULL, NULL, 
    "Last Update", NULL,
  },
  {
    "next_upd",
    "next update time of the CRL",
    Q_FOR_CRL,
    SQL_C_CHAR, 32,
    NULL, NULL,
    "Next Update", NULL, 
  },
  {
    "crlno",
    "CRL number",
    Q_FOR_CRL,
    SQL_C_ULONG, 8, 
    NULL, NULL,
    "CRL#", NULL,
  },
  {
    "sn",
    "serial number",
    Q_FOR_CERT,
    SQL_C_ULONG, 8,
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
    Q_JUST_DISPLAY|Q_FOR_CRL,
    SQL_C_BINARY, 16000000,
    NULL, NULL,
    NULL, NULL,
  },
  {
    "serial_nums",
    "list of serials numbers",
    Q_JUST_DISPLAY|Q_FOR_CRL,
    -1, 0,
    "snlen", "snlist",
    "Serial#s", displaySNList,
  }
};

struct {
  char *objectName;
  char *tableName;
} tableNames[] = {
  { "cert", "certificate" },
  { "roa", "roa" },
  { "crl", "crl" },
  { "rpsl", "roa" },
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
int displayEntry (scmsrcha *s, int idx1, char* returnStr, int returnStrLen)
{
  struct ROA *roa;
  (void) pathnameDisplay (s, idx1, returnStr);
  int format = (strncmp (".pem", &returnStr[strlen(returnStr)-4], 4) == 0) ?
               FMT_PEM : FMT_DER;
  checkErr (roaFromFile (returnStr, format, 0, &roa) != 0,
            "Error reading ROA: %s\n", returnStr);
  roaGenerateFilter (roa, NULL, NULL, returnStr, returnStrLen);
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
  // XXX hack-- print out RPSL here for now, should factor out
  // XXX No differentiation between ipv4 and ipv6
  if (isRPSL) {
    unsigned long long asn = 0;
    char *filter = 0;
    char *filename = 0;

    for (display = 0; globalFields[display] != NULL; display++) {
      QueryField *field = globalFields[display];
      if (!strcasecmp(field->name, "filter"))
	filter = (char *)s->vec[display].valptr;
      else if (!strcasecmp(field->name, "asn"))
	asn = *(unsigned long long *) s->vec[display].valptr;
      else if (!strcasecmp(field->name, "filename"))
	filename = (char *)s->vec[display].valptr;
      else
	fprintf(stderr, "warning: unexpected field %s in RPSL query\n",
		field->name);
    }
    if (asn == 0 || filter == 0) {
      fprintf(stderr, "incomplete result returned in RPSL query: ");
      if (asn == 0) 
	fprintf(stderr, "no asn\n");
      if (filter == 0) 
	fprintf(stderr, "no filter\n");
    } else {
      // gross hack. 0 == ipv4, 1 == ipv6
      int i, numprinted = 0;

      for (i = 0; i < 2; ++i) {
	char *end, *f = filter;
	int first = 1;

	// format of filters: some number of "sid<space>asnum<space>filter\n"
	while ((end = strchr(f, '\n')) != 0) {
	  *end = '\0';
	  // skip sid and asnum
	  if ((f = strchr(f, ' ')) == 0) continue;
	  ++f;
	  if ((f = strchr(f, ' ')) == 0) continue;
	  ++f;
	  if ((i == 0 && strchr(f, ':') == 0) ||
	      (i == 1 && strchr(f, ':') != 0)) {
	    if (first) {
	      fprintf(output, "route-set: RS-RPKI-ROA-FOR-V%c:AS",
		      ((i == 0) ? '4' : '6'));
	      // is it > 2^32? split into two pieces
	      if (asn >= ((unsigned long long)1 << 32)) {
		fprintf(output, "%lld.%lld", (asn >> 32), 
			(asn & (((unsigned long long)1 << 32) - 1)));
	      } else {
		fprintf(output, "%lld", asn);
	      }
	      fprintf(output, "  # %s\n", filename ? filename : "???");
	    }
	    first = 0;
	    fputs((i == 0) ? "members" : "mp-members", output);
	    fprintf(output, ": %s\n", f);
	    ++numprinted;
	  }
	  *end = '\n';
	  // skip past the newline and try for another one
	  f = end + 1;
	}
	if (!first)
	  fprintf(output, "\n");
      }
    }
    return(0);
  }

  // normal query result (not RPSL)
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

/* given the object type (aka query type) we are looking for, tell */
/* caller which table to search */
static char *tableName(char *objType)
{
  int i;
  for (i = 0; i < countof(tableNames); ++i) {
    if (!strcasecmp(objType, tableNames[i].objectName))
      return (tableNames[i].tableName);
  }
  return 0;
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
            "\nBad object type; must be roa, cert, crl, or rpsl\n\n");
  (void) setbuf (stdout, NULL);
  scmp = initscm();
  checkErr (scmp == NULL, "Cannot initialize database schema\n");
  connect = connectscm (scmp->dsn, errMsg, 1024);
  checkErr (connect == NULL, "Cannot connect to database: %s\n", errMsg);
  connect->mystat.tabname = objectType;
  table = findtablescm (scmp, tableName(objectType));
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
      checkErr (field->flags & Q_JUST_DISPLAY, "Field only for display: %s\n", name);
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
      if (field->flags & Q_REQ_JOIN) srchFlags = srchFlags | SCM_SRCH_DO_JOIN;
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
    if (((fields[i].flags & Q_FOR_ROA) && isROA) || 
	((fields[i].flags & Q_FOR_CRL) && isCRL) ||
        ((fields[i].flags & Q_FOR_CERT) && isCert)) {
      printf ("  %s: %s\n", fields[i].name, fields[i].description);
      if (fields[i].flags & Q_JUST_DISPLAY) {
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
    if (((fields[i].flags & Q_FOR_ROA) && isROA) || 
	((fields[i].flags & Q_FOR_CRL) && isCRL) ||
        ((fields[i].flags & Q_FOR_CERT) && isCert)) {
	displays[numDisplays++] = fields[i].name;
    }
  }
  return numDisplays;
}

/* add fields needed for RPSL query */
static int addRPSLFields(char *displays[], int numDisplays)
{
  // XXX hack... just add these by hand
  // XXX worse hack... we have hard-coded SQL field names scattered
  // throughout the code. Help us if we ever change the schema.
  displays[0] = "asn";		/* we only need asn and filter*/
  displays[1] = "filter"; 
  displays[2] = "filename";	/* added for commentary */
  return 3;			/* number of fields added */
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
  if (isRPSL) {
    checkErr (numDisplays != 0, "-d should not be used with RPSL query\n");
    numDisplays = addRPSLFields(displays, 0);
  }
  checkErr (numDisplays == 0 && isRPSL == 0, "Need to display something\n");
  if (numDisplays == 1 && strcasecmp(displays[0], "all") == 0)
      numDisplays = addAllFields(displays, 0);
  displays[numDisplays++] = NULL;
  clauses[numClauses++] = NULL;
  status = doQuery (displays, clauses);
  stopSyslog();
  return status;
}
