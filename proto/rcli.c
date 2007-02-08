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
  (void)printf("\t-t\tcreate all database tables\n");
  (void)printf("\t-x\tdestroy all database tables\n");
  (void)printf("\t-y\tforce operation: do not ask for confirmation\n");
  (void)printf("\t-q\tdisplay database state\n");
  (void)printf("\t-d dir\tprocess all files in dir\n");
  (void)printf("\t-f file\tprocess the indicated file\n");
  (void)printf("\t-w port\tstart an rsync listener on port\n");
  (void)printf("\t-h\tdisplay usage and exit\n");
}

// putative command line args:
//   -t                  create all tables
//   -x                  destroy all tables
//   -y                  force operation, don't ask
//   -q                  display database state
//   -h                  print help
//   -d dir              recursively process everything in dir
//   -f file             process the given file
//   -w port             operate in wrapper mode using the given socket port

int main(int argc, char **argv)
{
  scmcon *testconp = NULL;
  scmcon *realconp = NULL;
  scm    *scmp = NULL;
  char *thedir = NULL;
  char *thefile = NULL;
  char *tmpdsn = NULL;
  char *password = NULL;
  char  errmsg[1024];
  char  ans[8];
  int do_create = 0;
  int do_delete = 0;
  int do_fileops = 0;
  int do_sockopts = 0;
  int do_query = 0;
  int really = 0;
  int force = 0;
  int porto = 0;
  int needpwd = 0;
  int sta;
  int c;

  (void)setbuf(stdout, NULL);
  if ( argc <= 1 )
    {
      usage();
      return(1);
    }
  while ( (c = getopt(argc, argv, "txyqhd:f:w:")) != EOF )
    {
      switch ( c )
	{
	case 't':
	  do_create++;
	  needpwd++;
	  break;
	case 'x':
	  do_delete++;
	  needpwd++;
	  break;
	case 'y':
	  force++;
	  break;
	case 'q':
	  do_query++;
	  break;
	case 'd':
	  thedir = strdup(optarg);
	  if ( thedir == NULL )
	    {
	      membail();
	      return(-1);
	    }
	  do_fileops++;
	  break;
	case 'f':
	  thefile = strdup(optarg);
	  if ( thefile == NULL )
	    {
	      membail();
	      return(-1);
	    }
	  do_fileops++;
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
	  (void)printf("Do you REALLY want to delete all database tables? ");
	  memset(ans, 0, 8);
	  if ( fgets(ans, 8, stdin) == NULL || ans[0] == 0 ||
	       toupper(ans[0]) != 'Y' )
	    {
	      (void)printf("Operation cancelled\n");
	      return(1);
	    }
	  really++;
	}
      if ( (do_create > 0) && (really == 0) )
	{
	  (void)printf("Do you REALLY want to create all database tables? ");
	  memset(ans, 0, 8);
	  if ( fgets(ans, 8, stdin) == NULL || ans[0] == 0 ||
	       toupper(ans[0]) != 'Y' )
	    {
	      (void)printf("Operation cancelled\n");
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
  Get the root password to the database if necessary. GAGNON
*/
  if ( needpwd > 0 )
    password = getpass("Enter MySQL root password: ");
/*
  Process command line options in the following order: delete, create, dofile,
  dodir, query, listener.
*/
  if ( do_delete > 0 )
    {
/*
  For a delete operation we do not want to connect to the apki
  database, we want to connect to the test database.
*/
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
      sta = deletedbscm(testconp, scmp->db);
      if ( sta == 0 )
	(void)printf("Delete operation succeeded\n");
      else
	{
	  (void)printf("Delete operation failed: %s\n",
		       geterrorscm(testconp));
	  disconnectscm(testconp);
	  freescm(scmp);
	  return(-1);
	}
    }
  if ( do_create > 0 )
    {
/*
  For a delete operation we do not want to connect to the apki
  database, we want to connect to the test database.
*/
      if ( tmpdsn == NULL )
	{
	  tmpdsn = makedsnscm(scmp->dsnpref, "test", "root", password);
	  if ( password != NULL )
	    memset(password, 0, strlen(password));
	  if ( tmpdsn == NULL )
	    {
	      membail();
	      return(-1);
	    }
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
      sta = createdbscm(testconp, scmp->db, scmp->dbuser);
      if ( sta == 0 )
	(void)printf("Create database operation succeeded\n");
      else
	{
	  (void)printf("Create database operation failed: %s\n",
		       geterrorscm(testconp));
	  disconnectscm(testconp);
	  freescm(scmp);
	  return(sta);
	}
      sta = createalltablesscm(testconp, scmp);
      if ( sta == 0 )
	(void)printf("Create tables operation succeeded\n");
      else
	{
	  (void)printf("Create table %s failed: %s\n",
		       gettablescm(testconp), geterrorscm(testconp));
	  disconnectscm(testconp);
	  freescm(scmp);
	  return(sta);
	}
    }
  if ( do_fileops > 0 )
    {
      if ( thefile != NULL )
	{
	  // GAGNON
	}
      if ( thedir != NULL )
	{
	  // GAGNON
	}
    }
  if ( do_query > 0 )
    {
      // GAGNON
    }
  if ( do_sockopts > 0 )
    {
      // GAGNON
    }
  freescm(scmp);
  return(0);
}
