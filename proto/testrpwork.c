/*
  $Id: rcli.c 836 2008-12-29 20:32:04Z cgardiner $
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>
#include <netdb.h>
#ifdef __NetBSD__
#include <netinet/in.h>
#endif
#ifdef __FreeBSD__
#include <netinet/in.h>
#endif

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include "err.h"

static void fatal(char *msg)
  {
  fprintf(stderr, "%s\n", msg);
  exit(0);
  }

int main(int argc, char **argv)
  {
  scm *scmp = NULL;
  scmcon *conp = NULL;
  scmtab *table = NULL;
  char errMsg[1024];

  if ((scmp = initscm()) == NULL) fatal("Can't initialize database");
  if ((conp = connectscm(scmp->dsn, errMsg, 1024)) == NULL)
    fatal("Can't connect");
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  if (!(table = findtablescm(scmp, "certificate")))
    fatal("Can't get table");
  if (argc != 2) fatal("Need name of control file");
  int ansr = read_SKI_blocks(scmp, conp, argv[1]);
  if (ansr < 0) fprintf(stderr, "Had error %d: %s\n", ansr, err2string(ansr));
  fatal("Finished");
  return 0;
  }
