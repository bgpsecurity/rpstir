
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "scm.h"
#include "scmf.h"
#include "err.h"

/****************
 * Read all ROA's from DB and print them out
 **************/

#define checkErr(test, printArgs...) \
  if (test) { \
     (void) fprintf (stderr, printArgs); \
     return -1; \
  }

#define MAX_VALS 20
#define MAX_CONDS 10

static int fillInSrch (scmsrch *srch, int isChar, unsigned int sz,
                       int colno, char *colname)
{
  srch->colno = colno;
  srch->sqltype = isChar ? SQL_C_CHAR : SQL_C_ULONG;
  srch->colname = colname;
  srch->avalsize = 0;
  srch->valsize = isChar ? sz : sizeof (unsigned int);
  srch->valptr = calloc (sz, sizeof (char));
  checkErr (srch->valptr == NULL, "Not enough memory\n");
  return 0;
}

static int handleResults (scmcon *conp, scmsrcha *s, int idx)
{
  conp = conp; idx = idx;  // silence compiler warnings
  fprintf (stderr, "ASN = %d File = %s/%s\n   SKI = %s\n",
           *((unsigned int *) s->vec[2].valptr), (char *) s->vec[3].valptr,
           (char *) s->vec[0].valptr, (char *) s->vec[1].valptr);
  return(0);
}

static int listOptions (char *objectType)
{
  if (strcasecmp (objectType, "roa") == 0) {
    printf ("\nPossble fields to display or use in clauses for a roa:\n");
    printf ("  filename: the filename where the roa is stored in the repository\n");
    printf ("  pathname: full pathname (including the filename) where the roa is stored\n");
    printf ("            (Note: This can be used only for display.)\n");
    printf ("  ski: signing key for the roa\n");
    printf ("  asn: autonomous system number referred to by the roa\n");
    printf ("  addrrng: IP address ranges referred to by the roa\n");
    printf ("           (Note: This can be used only for display.)\n\n");
    return 0;
  }
  if (strcasecmp (objectType, "cert") == 0) {
    printf ("Unimplemented\n");
    return 0;
  }
  if (strcasecmp (objectType, "crl") == 0) {
    printf ("Unimplemented\n");
    return 0;
  }
  printf ("Bad object type\n");
  return -1;
}

static int printUsage()
{
  printf ("\nPossible usages:\n  doQuery -a\n");
  printf ("  doQuery -l <type>\n");
  printf ("  doQuery -t <type> -d <disp1>...[ -d <dispn>] [-c <cls1>]...[ -c <clsn>]\n\nSwitches:\n");
  printf ("  -a: short cut for type=roa, no clauses, and display ski, asn, and addrrng\n");
  printf ("  -l: list the possible display fields and clauses for a given type\n");
  printf ("  -t: the type of object requested (roa, cert, or crl)\n");
  printf ("  -d: the name of one field of the object to display\n");
  printf ("  -c: one clause to use for filtering; a clause has the form\n");
  printf ("      <fieldName><op><value>, where op is a comparative operator\n");
  printf ("      such as =, <>, >, ...\n\n");
  return -1;
}

int main(int argc, char **argv) 
{
  scm      *scmp = NULL;
  scmcon   *connect = NULL;
  scmtab   *table = NULL;
  scmsrcha srch;
  scmsrch  srch1[MAX_VALS];
  scmkva   where;
  scmkv    where1[MAX_CONDS];
  char     errMsg[1024];
  unsigned long blah = 0;
  int      status, i;
  char     *objectType = "ROA";

  if (argc == 1) return printUsage();
  if (strcasecmp (argv[1], "-l") == 0) {
    if (argc != 3) return printUsage();
    return listOptions (argv[2]);
  }
  if (strcasecmp (argv[1], "-t") == 0) {
    printf ("Unimplemented option\n");
    return -1;
  }
  if (strcasecmp (argv[1], "-a") != 0) return printUsage();
  if (argc > 2) return printUsage();

  (void)setbuf(stdout, NULL);
  scmp = initscm();
  checkErr (scmp == NULL, "Cannot initialize database schema\n");
  connect = connectscm (scmp->dsn, errMsg, 1024);
  checkErr (connect == NULL, "Cannot connect to %s: %s\n", scmp->dsn, errMsg);
  connect->mystat.tabname = objectType;
  table = findtablescm (scmp, objectType); 
  checkErr (table == NULL, "Cannot find table %s\n", objectType);
  srch.where = NULL;
  srch.wherestr = NULL;
  if (fillInSrch (&srch1[0], 1, 256, 1, "filename")) return -1;
  if (fillInSrch (&srch1[1], 1, 128, 2, "ski")) return -1;
  if (fillInSrch (&srch1[2], 0, 1, 3, "asn")) return -1;
  if (fillInSrch (&srch1[3], 1, 4096, 4, "dirname")) return -1;
  srch.vec = srch1;
  srch.sname = NULL;
  srch.ntot = 4;
  srch.nused = 4;
  srch.vald = 0;
  srch.context = &blah;
  status = searchscm (connect, table, &srch, NULL, handleResults,
                      SCM_SRCH_DOVALUE_ALWAYS | SCM_SRCH_DO_JOIN);
  for (i = 0; i < 4; i++) {
    free (srch1[i].valptr);
  }
  return 0;
}
