/*
  $Id$
*/

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Verison 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Joshua Gruenspecht, Mark Reynolds
 *
 * ***** END LICENSE BLOCK ***** */

#include "roa_utils.h"

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "err.h"

static unsigned char *myreadfile(char *fn, int *stap)
{
  struct stat mystat;
  char *outptr = NULL;
  char *ptr;
  int   outsz = 0;
  int   sta;
  int   fd;
  int   rd;

  if ( stap == NULL )
    return(NULL);
  if ( fn == NULL || fn[0] == 0 )
    {
      *stap = ERR_SCM_INVALARG;
      return(NULL);
    }
  fd = open(fn, O_RDONLY);
  if ( fd < 0 )
    {
      *stap = ERR_SCM_COFILE;
      return(NULL);
    }
  memset(&mystat, 0, sizeof(mystat));
  if ( fstat(fd, &mystat) < 0 || mystat.st_size == 0 )
    {
      (void)close(fd);
      *stap = ERR_SCM_COFILE;
      return(NULL);
    }
  ptr = (char *)calloc(mystat.st_size, sizeof(char));
  if ( ptr == NULL )
    {
      (void)close(fd);
      *stap = ERR_SCM_NOMEM;
      return(NULL);
    }
  rd = read(fd, ptr, mystat.st_size);
  (void)close(fd);
  if ( rd != mystat.st_size )
    {
      free((void *)ptr);
      ptr = NULL;
      *stap = ERR_SCM_COFILE;
    }
  else
    *stap = 0;
  if ( strstr(fn, ".pem") == NULL )
    return((unsigned char *)ptr); /* not a PEM file, just plain DER */
  sta = decode_b64((unsigned char *)ptr, mystat.st_size, (unsigned char **)&outptr, &outsz, "ROA");
  free((void *)ptr);
  if ( sta < 0 )
    {
      if ( outptr != NULL )
	{
	  free((void *)outptr);
	  outptr = NULL;
	}
    }
  return((unsigned char *)outptr);
}

int main(int argc, char** argv)
{
  struct ROA    *roa = NULL;
  struct ROA    *roa2 = NULL;
  unsigned char *blob = NULL;
  FILE   *fp = NULL;
  scmcon *conp;
  scm    *scmp;
  X509   *cert;
  char    filename_der[16] = "";
  char    filename_pem[16] = "";
  char    errmsg[1024];
  char   *filename_cnf = NULL;
  char   *ski;
  char   *fn = NULL;
  int     sta = 0;
  
  if ( argc < 2 )
    filename_cnf = "roa.cnf";
  else
    filename_cnf = argv[1];
  strncpy(filename_der, "mytest.roa.der", sizeof(filename_der)-1);
  strncpy(filename_pem, "mytest.roa.pem", sizeof(filename_pem)-1);
  sta = roaFromConfig(filename_cnf, 0, &roa);
  if ( sta < 0 )
    {
      (void)fprintf(stderr, "roaFromConfig(%s) failed with error %s (%d)\n",
		    filename_cnf, err2string(sta), sta);
      return sta;
    }
  sta = roaToFile(roa, filename_pem, FMT_PEM);
  roaFree(roa);
  if ( sta < 0 )
    {
      (void)fprintf(stderr, "roaToFile(%s) failed with error %s (%d)\n",
		    filename_pem, err2string(sta), sta);
      return sta;
    }
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
      free(ski);
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
      free(ski);
      freescm(scmp);
      return -4;
    }
  cert = (X509 *)roa_parent(scmp, conp, ski, &fn, &sta);
  disconnectscm(conp);
  freescm(scmp);
  free(ski);
  if ( cert == NULL )
    {
      (void)fprintf(stderr, "ROA has no parent: error %s (%d)\n",
		    err2string(sta), sta);
      roaFree(roa2);
      return sta;
    }
  blob = myreadfile(fn, &sta);
  if ( blob == NULL )
    {
      (void)fprintf(stderr, "Cannot read certificate from %s: error %s (%d)\n",
		    fn, err2string(sta), sta);

      X509_free(cert);
      roaFree(roa2);
      return(sta);
    }
  sta = roaValidate2(roa2, blob);
  free((void *)blob);
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
