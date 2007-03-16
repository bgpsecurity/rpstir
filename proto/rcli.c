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

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "diru.h"

#ifdef NOTDEF
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ui.h>
#include <openssl/safestack.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#include <openssl/bn.h>

#define F(A) { if ( (A) != NULL ) free((void *)(A)); }

// print one extension

static void printex(X509_EXTENSION *ex)
{
  X509V3_EXT_METHOD    *meth;
  AUTHORITY_KEYID      *aki;
  BASIC_CONSTRAINTS    *bk;
  STACK_OF(DIST_POINT) *crld;
  const unsigned char  *uleon;
  GENERAL_NAMES *gen;
  GENERAL_NAME  *gen1;
  DIST_POINT    *point;
  void *exts;
  char *leon;
  int   j;
  int   k;

  meth = X509V3_EXT_get(ex);
  //      (void)printf("\tMethod pointer 0x%x\n", meth);
  if ( meth == NULL )
    return;
  uleon = ex->value->data;
  if ( meth->it )
    exts = ASN1_item_d2i(NULL, &uleon, ex->value->length,
			 ASN1_ITEM_ptr(meth->it));
  else
    exts = meth->d2i(NULL, &uleon, ex->value->length);
  //      (void)printf("\tExtension data pointer 0x%x\n", exts);
  if ( exts == NULL )
    return;
  switch ( meth->ext_nid )
    {
    case NID_basic_constraints:
      bk = (BASIC_CONSTRAINTS *)exts;
      if ( bk->ca == 0 )
	(void)printf("\t\tCA: FALSE\n");
      else
	(void)printf("\t\tCA: TRUE\n");
      break;
    case NID_subject_key_identifier:
      if ( meth->i2s != NULL )
	{
	  leon = meth->i2s(meth, exts);
	  if ( leon != NULL )
	    {
	      (void)printf("\t\t%s\n", leon);
	      OPENSSL_free(leon);
	    }
	}
      break;
    case NID_authority_key_identifier:
      aki = (AUTHORITY_KEYID *)exts;
      if ( aki->keyid != NULL )
	{
	  leon = hex_to_string(aki->keyid->data, aki->keyid->length);
	  if ( leon != NULL )
	    {
	      (void)printf("\t\t%s\n", leon);
	      OPENSSL_free(leon);
	    }
	}
      else
	{
	  (void)printf("Certificate with AKI=ISSUER/SNO\n");
	  (void)printf("This is PROHIBITED by the profile\n");
	}
      break;
    case NID_crl_distribution_points:
      crld = (STACK_OF(DIST_POINT) *)exts;
      for(j=0;j<sk_DIST_POINT_num(crld);j++)
	{
	  point = sk_DIST_POINT_value(crld, j);
	  if ( point->distpoint != NULL )
	    {
//	      (void)printf("\t\tCRLDP(%d):\n", j+1);
	      gen = point->distpoint->name.fullname;
	      for(k=0;k<sk_GENERAL_NAME_num(gen);k++)
		{
		  gen1 = sk_GENERAL_NAME_value(gen, k);
// TODO: must handle wider set of cases here, incl DIRNAME
		  (void)printf("\t\t%s\n", gen1->d.ia5->data);
		}
	    }
	}
      break;
// TODO: SIA and AIA
    default:
      break;
    }
  if ( meth->it )
    ASN1_item_free(exts, ASN1_ITEM_ptr(meth->it));
  else
    meth->ext_free(exts);
}

// cycle through all filenames on the command line and process them
// as certs

int main(int argc, char **argv)
{
  X509_EXTENSION *ex;
  ASN1_INTEGER   *a1;
  ASN1_OBJECT    *ao;
  ASN1_GENERALIZEDTIME *nb4;
  ASN1_GENERALIZEDTIME *af4;
  unsigned long   ell;
  X509_CINF      *ci;
  BIGNUM *bn;
  BIO    *cert;
  X509   *x = NULL;
  char   *leon;
  unsigned char *bef;
  unsigned char *aft;
  char    buf[256];
  int     sta;
  int     excnt;
  int     i;
  int     j;

  if ( argc < 2 )
    return(1);
  (void)setbuf(stdout, NULL);
  cert = BIO_new(BIO_s_file());
  // (void)printf("BIO pointer is 0x%x\n", cert);
  if ( cert == NULL )
    return(-1);
  for(j=1;j<argc;j++)
    {
      sta = BIO_read_filename(cert, argv[j]);
      (void)printf("Status reading %s: %d\n", argv[j], sta);
      if ( sta <= 0 )
	continue;
      x = d2i_X509_bio(cert, NULL);
      //      (void)printf("X509 pointer is 0x%x\n", x);
      if ( x == NULL )
	continue;
      leon = X509_NAME_oneline(X509_get_issuer_name(x), NULL, 0);
      (void)printf("Issuer: %s\n", leon);
      leon = X509_NAME_oneline(X509_get_subject_name(x), NULL, 0);
      (void)printf("Subject: %s\n", leon);
      a1 = X509_get_serialNumber(x);
      bn = ASN1_INTEGER_to_BN(a1, NULL);
      if ( bn == NULL )
	{
	  X509_free(x);
	  continue;
	}
      leon = BN_bn2dec(bn);
      (void)printf("Serial number: %s\n", leon);
      BN_free(bn);
      nb4 = X509_get_notBefore(x);
      af4 = X509_get_notAfter(x);
      ASN1_STRING_to_UTF8(&bef, (ASN1_STRING *)nb4);
      ASN1_STRING_to_UTF8(&aft, (ASN1_STRING *)af4);
      (void)printf("Validity from %s to %s\n", bef, aft);
      ell = X509_subject_name_hash(x);
      (void)printf("Subject name hash: 0x%x\n", ell);
      (void)printf("Number of extensions: %d\n",
		   excnt=X509_get_ext_count(x));
      ci = x->cert_info;
      //      (void)printf("Certificate info pointer is 0x%x\n", ci);
      //      (void)printf("Extensions pointer is 0x%x\n", ci->extensions);
      for(i=0;i<excnt;i++)
	{
	  ex = sk_X509_EXTENSION_value(ci->extensions, i);
      // (void)printf("\tExtension %d: 0x%x\n", i+1, ex);
	  ao = X509_EXTENSION_get_object(ex);
	  memset(buf, 0, 256);
	  sta = OBJ_obj2txt(buf, 256, ao, 0);
	  if ( sta > 0 && buf[0] != 0 )
	    {
	      (void)printf("\tExtension %d: %s\n", i+1, buf);
//	      if ( strstr(buf, "Key Identifier") != NULL )
		printex(ex);
	    }
	}
      X509_free(x);
    }
  return(0);
}

#endif

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
  char   *tdir;
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
	(void)fprintf(stderr, "getmaxidscm() failed with err %d\n", sta);
	return(sta);
      }
    (void)printf("Id is %u\n", iii);
    sta = setmaxidscm(scmp, conp, mtab, "DIRECTORY", 57);
    if ( sta < 0 )
      {
	(void)fprintf(stderr, "setmaxidscm() failed with err %d\n", sta);
	return(sta);
      }
    sta = getmaxidscm(scmp, conp, mtab, "DIRECTORY", &jjj);
    if ( sta < 0 )
      {
	(void)fprintf(stderr, "getmaxidscm() failed with err %d\n", sta);
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
	(void)fprintf(stderr, "addcolsrchscm() failed with err %d\n", sta);
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
	(void)fprintf(stderr, "setmaxidscm() failed with err %d\n", sta);
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
  }
  free((void *)tdir);
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
  (void)printf("\t-d dir\tprocess all files in dir\n");
  (void)printf("\t-f file\tprocess the indicated file\n");
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

// putative command line args:
//   -t topdir           create all tables, set rep root to "topdir"
//   -x                  destroy all tables
//   -y                  force operation, don't ask
//   -h                  print help
//   -d dir              recursively process everything in dir
//   -f file             process the given file
//   -w port             operate in wrapper mode using the given socket port

int main(int argc, char **argv)
{
  scmcon *testconp = NULL;
  scmcon *realconp = NULL;
  scm    *scmp = NULL;
  char   *thedir = NULL;
  char   *topdir = NULL;
  char   *thefile = NULL;
  char   *tmpdsn = NULL;
  char   *password = NULL;
  char    errmsg[1024];
  int ians = 0;
  int do_create = 0;
  int do_delete = 0;
  int do_sockopts = 0;
  int really = 0;
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
  while ( (c = getopt(argc, argv, "t:xyhd:f:w:")) != EOF )
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
	case 'd':
	  thedir = optarg;
	  break;
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
	  return(-1);
	}
    }
/*
  If a create operation was requested, complete it now.
*/
  if ( do_create > 0 )
    {
      sta = create2op(scmp, realconp, topdir);
      if ( sta < 0 )
	{
	  disconnectscm(realconp);
	  freescm(scmp);
	  return(sta);
	}
    }
  if ( thefile != NULL )
    {
      // GAGNON
    }
  if ( thedir != NULL )
    {
      // GAGNON
    }
  if ( do_sockopts > 0 )
    {
      // GAGNON
    }
  if ( realconp != NULL )
    disconnectscm(realconp);
  freescm(scmp);
  return(0);
}
