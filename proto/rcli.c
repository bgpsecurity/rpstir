/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <getopt.h>
#include <time.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"
#include "myssl.h"
#include "err.h"

static char *tdir = NULL;   // top level dir of the repository
static int   tdirlen = 0;   // length of tdir

/*
  Perform the delete operation. Return 0 on success and a negative
  error code on failure.
*/

static int deleteop(scmcon *conp, scm *scmp)
{
  int sta;

  if ( conp == NULL || scmp == NULL || scmp->db == NULL ||
       scmp->db[0] == 0 )
    {
      (void)fprintf(stderr, "Internal error in deleteop()\n");
      return(-1);
    }
// drop the database, destroying all tables in the process
  sta = deletedbscm(conp, scmp->db);
  if ( sta == 0 )
    (void)printf("Delete operation succeeded\n");
  else
    (void)fprintf(stderr, "Delete operation failed: %s\n",
		  geterrorscm(conp));
  return(sta);
}

/*
  Perform the create operation. Return 0 on success and a negative
  error code on failure.
*/

static int createop(scmcon *conp, scm *scmp)
{
  int sta;

  if ( conp == NULL || scmp == NULL || scmp->db == NULL ||
       scmp->db[0] == 0 )
    {
      (void)fprintf(stderr, "Internal error in createop()\n");
      return(-1);
    }
// step 1: create the database itself
  sta = createdbscm(conp, scmp->db, scmp->dbuser);
  if ( sta == 0 )
    (void)printf("Create database operation succeeded\n");
  else
    {
      (void)fprintf(stderr, "Create database operation failed: %s\n",
		    geterrorscm(conp));
      return(sta);
    }
// step 2: create all the tables in the database
  sta = createalltablesscm(conp, scmp);
  if ( sta == 0 )
    (void)printf("Create tables operation succeeded\n");
  else
    (void)fprintf(stderr, "Create table %s failed: %s\n",
		  gettablescm(conp), geterrorscm(conp));
  return(sta);
}

#ifdef BURLINGAME

// burlingame count function

static int burlc(scmcon *conp, scmsrcha *s, int cnt)
{
  UNREFERENCED_PARAMETER(conp);
  UNREFERENCED_PARAMETER(s);
  (void)printf("Row count is %d\n", cnt);
  return(0);
}

static int burlv(scmcon *conp, scmsrcha *s, int idx)
{
  TIMESTAMP_STRUCT *ts;
  int glart = 0;
  int tmp;
  int i;

  UNREFERENCED_PARAMETER(conp);
  (void)printf("Burlv called with idx %d\n", idx);
  for(i=0;i<s->nused;i++)
    {
      (void)printf("\t%s\t", s->vec[i].colname);
      if ( s->vec[i].avalsize > 0 )
	{
	  switch ( s->vec[i].sqltype )
	    {
	    case SQL_C_ULONG:
	      (void)printf("%d\n", tmp=*(int *)(s->vec[i].valptr));
	      glart += tmp;
	      break;
	    case SQL_C_CHAR:
	      (void)printf("%s\n", (char *)(s->vec[i].valptr));
	      break;
	    case SQL_C_TIMESTAMP:
	      ts = (TIMESTAMP_STRUCT *)(s->vec[i].valptr);
	      (void)printf("%d:%d:%d %d %d %d\n",
			   ts->hour, ts->minute, ts->second,
			   ts->day, ts->month, ts->year);
	      break;
	    default:
	      (void)printf("huh\n");
	      break;
	    }
	}
    }
  if ( s->context )
    *(int *)(s->context) = glart;
  return(0);
}

#endif // BURLINGAME

static int create2op(scm *scmp, scmcon *conp, char *topdir)
{
  scmkva  aone;
  scmkv   one;
  scmtab *mtab;
  int     sta;

  if ( conp == NULL || scmp == NULL || scmp->db == NULL ||
       scmp->db[0] == 0 )
    {
      (void)fprintf(stderr, "Internal error in create2op()\n");
      return(-1);
    }
  if ( topdir == NULL || topdir[0] == 0 )
    {
      (void)fprintf(stderr, "Must specify a top level repository directory\n");
      return(-2);
    }
// step 1: locate the metadata table
  mtab = findtablescm(scmp, "METADATA");
  if ( mtab == NULL )
    {
      (void)fprintf(stderr, "Cannot find METADATA table\n");
      return(-3);
    }
// step 2: translate "topdir" into an absolute path
  tdir = r2adir(topdir);
  if ( tdir == NULL )
    {
      (void)fprintf(stderr, "Invalid directory: %s\n", topdir);
      return(-4);
    }
// step 3: init the metadata table
  one.column = "rootdir";
  one.value = tdir;
  aone.vec = &one;
  aone.ntot = 1;
  aone.nused = 1;
  sta = insertscm(conp, mtab, &aone);
  if ( sta == 0 )
    (void)printf("Init metadata table succeeded\n");
  else
    (void)fprintf(stderr, "Init metadata table failed: %s\n",
		  geterrorscm(conp));
#ifdef BURLINGAME
// burlingame test code
  {
    unsigned int iii = 0;
    unsigned int jjj;
    unsigned int id;
    scmsrcha    *narr;

// get, set, get the max directory id
    sta = getmaxidscm(scmp, conp, mtab, "DIRECTORY", &iii);
    if ( sta < 0 )
      {
	(void)fprintf(stderr, "getmaxidscm() failed with err %s (%d)\n",
		      err2string(sta), sta);
	return(sta);
      }
    (void)printf("Id is %u\n", iii);
    sta = setmaxidscm(scmp, conp, mtab, "DIRECTORY", 57);
    if ( sta < 0 )
      {
	(void)fprintf(stderr, "setmaxidscm() failed with err %s (%d)\n",
		      err2string(sta), sta);
	return(sta);
      }
    sta = getmaxidscm(scmp, conp, mtab, "DIRECTORY", &jjj);
    if ( sta < 0 )
      {
	(void)fprintf(stderr, "getmaxidscm() failed with err %s (%d)\n",
		      err2string(sta), sta);
	return(sta);
      }
    (void)printf("New id is %u\n", jjj);
// do a search
    narr = newsrchscm("burlingame", 10, sizeof(int));
    (void)printf("Search array is 0x%x\n", (unsigned)narr);
    if ( narr == NULL )
      return(ERR_SCM_NOMEM);
    sta = addcolsrchscm(narr, "rootdir", SQL_C_CHAR, 1024);
    if ( sta == 0 )
      sta = addcolsrchscm(narr, "flags", SQL_C_ULONG,
			  sizeof(int));
    if ( sta == 0 )
      sta = addcolsrchscm(narr, "cert_max", SQL_C_ULONG,
			  sizeof(int));
    if ( sta == 0 )
      sta = addcolsrchscm(narr, "local_id", SQL_C_ULONG,
			  sizeof(int));
    if ( sta == 0 )
      sta = addcolsrchscm(narr, "inited", SQL_C_TIMESTAMP,
			  sizeof(TIMESTAMP_STRUCT));
    if ( sta == 0 )
      sta = addcolsrchscm(narr, "dir_max", SQL_C_ULONG,
			  sizeof(int));
    if ( sta < 0 )
      {
	(void)fprintf(stderr, "addcolsrchscm() failed with err %s (%d)\n",
		      err2string(sta), sta);
	return(sta);
      }
    sta = searchscm(conp, mtab, narr, burlc, burlv,
		    SCM_SRCH_DOCOUNT|SCM_SRCH_DOVALUE_ALWAYS);
    (void)printf("Search returns %d\n", sta);
    if ( sta == 0 )
      (void)printf("Context was %d\n",
		   *(int *)(narr->context));
    freesrchscm(narr);
    if ( sta < 0 )
      return(sta);
// reset the max directory id back to 0
    sta = setmaxidscm(scmp, conp, mtab, "DIRECTORY", 0);
    if ( sta < 0 )
      {
	(void)fprintf(stderr, "setmaxidscm() failed with err %s (%d)\n",
		      err2string(sta), sta);
	return(sta);
      }
// insert some directories
    sta = findorcreatedir(scmp, conp, mtab, tdir, &id);
    (void)printf("focdir(%s) status %d id %u\n", tdir, sta, id);
    sta = findorcreatedir(scmp, conp, mtab, "/tmp", &id);
    (void)printf("focdir(%s) status %d id %u\n", "/tmp", sta, id);
    sta = findorcreatedir(scmp, conp, mtab, "//var/tmp", &id);
    (void)printf("focdir(%s) status %d id %u\n", "//var/tmp", sta, id);
    sta = findorcreatedir(scmp, conp, mtab, "/fred/leon/burger", &id);
    (void)printf("focdir(%s) status %d id %u\n", "/fred/leon/burger", sta, id);
    sta = findorcreatedir(scmp, conp, mtab, "/tmp", &id);
    (void)printf("focdir(%s) status %d id %u\n", "/tmp", sta, id);
    sta = findorcreatedir(scmp, conp, mtab, tdir, &id);
    (void)printf("focdir(%s) status %d id %u\n", tdir, sta, id);
#ifdef BURLINGAME_TIMING
    {
      time_t tmo;
      char   numo[16];
      int    i;

// do a timing test
      time(&tmo);
      (void)printf("Start %s", ctime(&tmo));
      for(i=0;i<100000;i++)
	{
	  (void)sprintf(numo, "/tmp/%d", i+1);
	  sta = findorcreatedir(scmp, conp, mtab, numo, &id);
	}
      time(&tmo);
      (void)printf("End %s", ctime(&tmo));
    }
#endif
  }
#endif
  return(sta);
}

/*
  Safely print a message to stderr that we are out of memory.
  Cannot use (f)printf since it can try to allocate memory.
*/

static void membail(void)
{
  static char oom[] = "Out of memory!\n";

  (void)write(fileno(stderr), oom, strlen(oom));
}

/*
  Print a usage message.
*/

static void usage(void)
{
  (void)printf("Usage:\n");
  (void)printf("\t-t topdir\tcreate all database tables\n");
  (void)printf("\t-x\tdestroy all database tables\n");
  (void)printf("\t-y\tforce operation: do not ask for confirmation\n");
  (void)printf("\t-q\tdisplay database state\n");
  (void)printf("\t-d dir\tdelete the indicated file\n");
  (void)printf("\t-f file\tprocess the indicated file\n");
  (void)printf("\t-F file\tprocess the indicated trusted file\n");
  (void)printf("\t-w port\tstart an rsync listener on port\n");
  (void)printf("\t-h\tdisplay usage and exit\n");
}

/*
  Ask a yes or no question. Returns 1 for yes, 0 for no, -1 for error.
*/

static int yorn(char *q)
{
  char ans[8];

  if ( q == NULL || q[0] == 0 )
    return(-1);
  (void)printf("%s? ", q);
  memset(ans, 0, 8);
  if ( fgets(ans, 8, stdin) == NULL || ans[0] == 0 ||
       toupper(ans[0]) != 'Y' )
    return(0);
  else
    return(1);
}

#ifdef CRLI_TEST

static int cfunc(scm *scmp, scmcon *conp, char *issuer, unsigned long long sn)
{
  UNREFERENCED_PARAMETER(scmp);
  UNREFERENCED_PARAMETER(conp);

  (void)printf("CRL iterator: %s %lld\n", issuer, sn);
  if ( sn%3 == 0 )
    {
      (void)printf("\tDeleting this sn\n");
      return(1);
    }
  else
    return(0);
}

#endif

// putative command line args:
//   -t topdir           create all tables, set rep root to "topdir"
//   -x                  destroy all tables
//   -y                  force operation, don't ask
//   -h                  print help
//   -d dir              recursively process dir
//   -D dir              recursively process dir, assume trusted
//   -f file             process the given file
//   -F file             process the given trusted file
//   -w port             operate in wrapper mode using the given socket port

int main(int argc, char **argv)
{
  scmcon *testconp = NULL;
  scmcon *realconp = NULL;
  scm    *scmp = NULL;
  char   *thedelfile = NULL;
  char   *topdir = NULL;
  char   *thefile = NULL;
  char   *outfile = NULL;
  char   *outfull = NULL;
  char   *outdir = NULL;
  char   *tmpdsn = NULL;
  char   *password = NULL;
  char    errmsg[1024];
  int ians = 0;
  int do_create = 0;
  int do_delete = 0;
  int do_sockopts = 0;
  int really = 0;
  int trusted = 0;
  int force = 0;
  int porto = 0;
  int sta = 0;
  int c;

  (void)setbuf(stdout, NULL);
  if ( argc <= 1 )
    {
      usage();
      return(1);
    }
  while ( (c = getopt(argc, argv, "t:xyhd:f:F:w:")) != EOF )
    {
      switch ( c )
	{
	case 't':
	  do_create++;
	  topdir = optarg;
	  break;
	case 'x':
	  do_delete++;
	  break;
	case 'y':
	  force++;
	  break;
	case 'D':
	  trusted++;
	case 'd':
	  thedelfile = optarg;
	  break;
	case 'F':
	  trusted++;
	case 'f':
	  thefile = optarg;
	  break;
	case 'w':
	  do_sockopts++;
	  porto = atoi(optarg);
	  break;
	case 'h':
	  usage();
	  return(0);
	default:
	  (void)fprintf(stderr, "Invalid option '%c'\n", c);
	  usage();
	  return(1);
	}
    }
  if ( force == 0 )
    {
      if ( do_delete > 0 )
	{
	  ians = yorn("Do you REALLY want to delete all database tables");
	  if ( ians <= 0 )
	    {
	      (void)printf("Delete operation cancelled\n");
	      return(1);
	    }
	  really++;
	}
      if ( (do_create > 0) && (really == 0) )
	{
	  ians = yorn("Do you REALLY want to create all database tables");
	  if ( ians <= 0 )
	    {
	      (void)printf("Create operation cancelled\n");
	      return(1);
	    }
	  really++;
	}
    }
  scmp = initscm();
  if ( scmp == NULL )
    {
      (void)fprintf(stderr,
		    "Internal error: cannot initialize database schema\n");
      return(-2);
    }
/*
  If a create or delete operation is being performed, then a test dsn
  will be needed; create it now and defer the creation of the
  real dsn until later. Otherwise, create the real dsn.

  A test dsn is needed for operations that operate on the overall
  database state as opposed to the apki tables, namely the create and
  delete operations.

  Note that this code is done here in main() rather than in a subroutine
  in order to avoid passing parameter(s) on the stack that contain the
  root database password.
*/
  if ( (do_create+do_delete) > 0 )
    {
/*
  These privileged operations will need a password.
*/
      password = getpass("Enter MySQL root password: ");
      tmpdsn = makedsnscm(scmp->dsnpref, "test", "root", password);
      if ( password != NULL )
	memset(password, 0, strlen(password));
      if ( tmpdsn == NULL )
	{
	  membail();
	  return(-1);
	}
      testconp = connectscm(tmpdsn, errmsg, 1024);
      memset(tmpdsn, 0, strlen(tmpdsn));
      free((void *)tmpdsn);
      if ( testconp == NULL )
	{
	  (void)fprintf(stderr, "Cannot connect to DSN: %s\n",
			errmsg);
	  freescm(scmp);
	  return(-1);
	}
    }
  else
    {
      realconp = connectscm(scmp->dsn, errmsg, 1024);
      if ( realconp == NULL )
	{
	  (void)fprintf(stderr, "Cannot connect to DSN %s: %s\n",
			scmp->dsn, errmsg);
	  freescm(scmp);
	  return(-1);
	}
    }
/*
  Process command line options in the following order: delete, create, dofile,
  dodir, listener.
*/
  if ( do_delete > 0 )
    sta = deleteop(testconp, scmp);
  if ( do_create > 0 && sta == 0 )		/* first phase of create */
    sta = createop(testconp, scmp);
/*
  Don't need the test connection any more
*/
  if ( testconp != NULL )
    {
      disconnectscm(testconp);
      testconp = NULL;
    }
/*
  If there has been an error, bail out.
*/
  if ( sta < 0 )
    {
      if ( realconp != NULL )
	disconnectscm(realconp);
      freescm(scmp);
      if ( tdir != NULL )
	free((void *)tdir);
      return(sta);
    }
/*
  If a connection to the real DSN has not been opened yet, open it now.
*/
  if ( realconp == NULL )
    {
      realconp = connectscm(scmp->dsn, errmsg, 1024);
      if ( realconp == NULL )
	{
	  (void)fprintf(stderr, "Cannot connect to DSN %s: %s\n",
			scmp->dsn, errmsg);
	  freescm(scmp);
	  if ( tdir != NULL )
	    free((void *)tdir);
	  return(-1);
	}
    }
/*
  If a create operation was requested, complete it now.
*/
  if ( do_create > 0 && sta == 0 )
    sta = create2op(scmp, realconp, topdir);
/*
  If the top level repository directory is not set, then retrieve it from
  the database.
*/
  if ( tdir == NULL && sta == 0 )
    {
      tdir = retrieve_tdir(scmp, realconp, &sta);
      if ( tdir == NULL )
	(void)fprintf(stderr,
		      "Cannot retrieve top level repository info from DB\n");
    }
  if ( sta == 0 )
    {
      (void)printf("Top level repository directory is %s\n", tdir);
      tdirlen = strlen(tdir);
    }
/*
  Setup for actual SSL operations
*/
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  if ( thefile != NULL && sta == 0 )
    {
// Check that the file is in the repository, ask if not and force is off
      sta = splitdf(NULL, NULL, thefile, &outdir, &outfile, &outfull);
      if ( sta == 0 )
	{
	  if ( strncmp(tdir, outdir, tdirlen) != 0 && force == 0 )
	    {
	      ians = yorn("That file is not in the repository. Proceed anyway");
	      if ( ians <= 0 )
		sta = 1;
	    }
	  if ( strstr(outdir, "TRUST") != NULL )
	    trusted++;
// if the user has declared it to be trusted, or if it is in a TRUSTed
// directory ask for verification unless force is set
	  if ( trusted > 0 && force == 0 && sta == 0 )
	    {
	      ians = yorn("Really declare this file as trusted");
	      if ( ians <= 0 )
		sta = 1;
	    }
	  if ( sta == 1 )
	    (void)printf("File operation cancelled\n");
	  if ( sta == 0 )
	    {
	      sta = add_object(scmp, realconp, outfile, outdir, outfull,
			       trusted);
	      if ( sta < 0 )
		(void)fprintf(stderr, "Could not add file %s: error %s (%d)\n",
			      thefile, err2string(sta), sta);
	    }
	  free((void *)outdir);
	  free((void *)outfile);
	  free((void *)outfull);
	}
    }
  if ( thedelfile != NULL && sta == 0 )
    {
      sta = splitdf(NULL, NULL, thedelfile, &outdir, &outfile, &outfull);
      if ( sta == 0 )
	{
	  sta = delete_object(scmp, realconp, outfile, outdir, outfull);
	  if ( sta < 0 )
	    (void)fprintf(stderr, "Could not delete file %s: error %s (%d)\n",
			  thefile, err2string(sta), sta);
	  free((void *)outdir);
	  free((void *)outfile);
	  free((void *)outfull);
	}
    }
  if ( do_sockopts > 0 && sta == 0 )
    {
      // GAGNON
    }
#ifdef BFLAGS_TEST
  {
    unsigned int flags = 0;
    unsigned int lid = 0;
    scmtab *t2p;
    scmkva  where;
    scmkv   w;
    int     sta2;

    t2p = findtablescm(scmp, "CERTIFICATE");
    if ( t2p != NULL )
      {
	w.column = "filename";
	w.value = "2.cer.pem";
	where.vec = &w;
	where.ntot = 1;
	where.nused = 1;
	sta2 = getflagsidscm(realconp, t2p, &where, &flags, &lid);
	if ( sta2 >= 0 )
	  {
	    (void)printf("Get flags: local_id %u flags 0x%x\n", lid, flags);
	    sta2 = setflagsscm(realconp, t2p, &where, 0x347);
	    if ( sta2 >= 0 )
	      {
		(void)printf("Set flags: ok\n");
		sta2 = getflagsidscm(realconp, t2p, &where, &flags, &lid);
		if ( sta2 >= 0 )
		  {
		    (void)printf("Get flags: local_id %u flags 0x%x\n",
				 lid, flags);
		  }
	      }
	  }
      }
    
  }
#endif
#ifdef CRLI_TEST
  sta = iterate_crl(scmp, realconp, model_cfunc);
  (void)printf("Iterate_crl status was %d\n", sta);
#endif
#ifdef CV_TEST
  sta = certificate_validity(scmp, realconp);
  (void)printf("Certificate_validity status was %d\n", sta);
#endif
  if ( realconp != NULL )
    disconnectscm(realconp);
  freescm(scmp);
  if ( tdir != NULL )
    free((void *)tdir);
  return(sta);
}
