/*
  $Id$
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "scm.h"

static scmtab APKI_TAB[2];
static scm    APKI_SCM;

scm *initscm(void)
{
  int len;

  len = strlen(APKI_DSN) + strlen(APKI_DB) + strlen(APKI_DBUSER) + 30;
  APKI_TAB[0] = APKI_CERT;
  APKI_TAB[1] = APKI_CRL;
  APKI_SCM.dsn = (char *)calloc(len, sizeof(char));
  (void)sprintf(APKI_SCM.dsn, "%s;DATABASE=%s;USER=%s;",
		APKI_DSN, APKI_DB, APKI_DBUSER);
  APKI_SCM.tables = &APKI_TAB[0];
  APKI_SCM.ntables = 2;
  return(&APKI_SCM);
}

#ifdef TEST

int main(void)
{
  scm *scmp;
  int  i;

  scmp = initscm();
  (void)printf("DSN name is %s\n", scmp->dsn);
  (void)printf("Number of tables is %d\n", scmp->ntables);
  for(i=0;i<scmp->ntables;i++)
    {
      (void)printf("\t\t%d\t%s\t%s\n", i,
		   scmp->tables[i].tabname,
		   scmp->tables[i].hname);
    }
  return(0);
}

#endif
