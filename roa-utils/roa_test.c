/*
  $Id$
*/

#include "roa_utils.h"

int main(int argc, char** argv)
{
  struct ROA *roa;
  int iRet = 0;
  char filename[16] = "";
  char filename2[16] = "";
  
  strcpy(filename, "roa.cnf");
  strcpy(filename2, "test.der");
  iRet = roaFromConfig(filename, 0, &roa);
  if (TRUE == iRet)
    iRet = roaToFile(roa, filename2, FMT_DER);
  if (FALSE == iRet)
    return 1;
  else
    return 0;
}

/*
int main(int argc, char** argv)
{
  scmcon *conp;
  X509   *cert;
  char   *ski;
  int     valid = -1;
  int     sta;
  ROA    *r;

  printf("Running ROA tests...");
  // conp = openDBConnection(); or fail
  sta = roaCreateFromConf(fname, &r);
  if (0 != sta)
  {
     printf("Bad creation!");
     return -1;
  }
  sta = roaValidate(r);
  if (0 != sta)
  {
     printf("Failed validation!");
     return -2;
  }
  else
  {
     ski = roaSKI(r);
     if ( NULL == ski )
     {
        printf("Bad SKI translation!");
        return -3;        
     }
     else
     {
       cert = find_certificate(conp, ski, NULL, NULL, &sta);
       if ( cert != NULL && sta == 0 ) {
         valid = roaValidate2(r, cert);
       }
     }

  }
  if (-1 == valid)
  {
     printf("Validity test 2 failed!");
     return -4;
  }
  else
  {
     printf("Test successful!");
     return 0;
  }
}
*/
