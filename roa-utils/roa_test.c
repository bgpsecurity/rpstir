/*
  $Id$
*/

#include "roa_utils.h"

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"

int main(int argc, char** argv)
{
  struct ROA *roa = NULL;
  struct ROA *roa2 = NULL;
  char  *filename_cnf = NULL;
  char   filename_der[16] = "";
  char   filename_pem[16] = "";
  char   errmsg[1024];
  FILE   *fp = NULL;
  scmcon *conp;
  scm    *scmp;
  X509   *cert;
  char   *ski;
  int     sta = 0;
  
  if ( argc < 2 )
    filename_cnf = "roa.cnf";
  else
    filename_cnf = argv[1];
  strcpy(filename_der, "mytest.roa.der");
  strcpy(filename_pem, "mytest.roa.pem");
  sta = roaFromConfig(filename_cnf, 0, &roa);
  if ( sta < 0 )
    {
      (void)fprintf(stderr, "roaFromConfig(%s) failed with error %s (%d)\n",
		    filename_cnf, err2string(sta), sta);
      return sta;
    }
  sta = roaToFile(roa, filename_pem, FMT_PEM);
  if ( sta < 0 )
    {
      (void)fprintf(stderr, "roaToFile(%s) failed with error %s (%d)\n",
		    filename_pem, err2string(sta), sta);
      return sta;
    }
  roaFree(roa);
  sta = roaFromFile(filename_pem, FMT_PEM, cTRUE, &roa2);
  if ( sta < 0 )
    {
      (void)fprintf(stderr, "roaFromFile(%s) failed with error %s (%d)\n",
		    filename_pem, err2string(sta), sta);
      return sta;
    }
  ski = (char *)roaSKI(roa2);
  if ( ski == NULL || ski[0] == 0 )
    {
      (void)fprintf(stderr, "ROA has NULL SKI\n");
      return -2;
    }
  scmp = initscm();
  if ( scmp == NULL )
    {
      roaFree(roa2);
      (void)fprintf(stderr,
		    "Internal error: cannot initialize database schema\n");
      return -3;
    }
  memset(errmsg, 0, 1024);
  conp =  connectscm(scmp->dsn, errmsg, 1024);
  if ( conp == NULL )
    {
      (void)fprintf(stderr, "Cannot connect to DSN %s: %s\n",
		    scmp->dsn, errmsg);
      roaFree(roa2);
      freescm(scmp);
      return -4;
    }
  cert = (X509 *)roa_parent(scmp, conp, ski, &sta);
  disconnectscm(conp);
  freescm(scmp);
  if ( cert == NULL )
    {
      (void)fprintf(stderr, "ROA has no parent: error %s (%d)\n",
		    err2string(sta), sta);
      roaFree(roa2);
      return sta;
    }
  sta = roaValidate2(roa2, cert);
  X509_free(cert);
  if ( sta < 0 )
    {
      (void)fprintf(stderr, "ROA failed semantic validation: error %s (%d)\n",
		    err2string(sta), sta);
      roaFree(roa2);
      return sta;
    }
  fp = fopen("roa.txt", "a");
  if ( fp == NULL )
    {
      (void)fprintf(stderr, "Cannot open roa.txt\n");
      roaFree(roa2);
      return -5;
    }
  sta = roaGenerateFilter(roa2, NULL, fp);
  roaFree(roa2);
  (void)fclose(fp);
  if ( sta < 0 )
    {
      (void)fprintf(stderr, "Cannot generate ROA filter output: error %s (%d)\n",
		    err2string(sta), sta);
      return sta;
    }
  return 0;
}
