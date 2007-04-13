/*
  $Id$
*/

#include "roa_utils.h"

int main(int argc, char** argv)
{
  struct ROA *roa;
  struct ROA *roa2;
  int iRet = 0;
  char filename_cnf[16] = "";
  char filename_der[16] = "";
  char filename_pem[16] = "";
  FILE *fp = NULL;
  //scmcon *conp;
  //X509   *cert;
  //char   *ski;
  //int     sta;
  
  strcpy(filename_cnf, "roa.cnf");
  strcpy(filename_der, "mytest.roa.der");
  strcpy(filename_pem, "mytest.roa.pem");
  iRet = roaFromConfig(filename_cnf, 0, &roa);
  if (TRUE == iRet)
    iRet = roaToFile(roa, filename_pem, FMT_PEM);
  if (TRUE == iRet)
    iRet = roaFromFile(filename_pem, FMT_PEM, TRUE, &roa2);
  if (TRUE == iRet)
    {
      fp = fopen("roa.txt", "a");
      if (fp) {
	// JFG - Add these back in when ready to test validation
	//ski = roaSKI(r);
	//if ( NULL != ski ) {
	//cert = find_certificate(conp, ski, NULL, NULL, &sta);
	//if ( cert != NULL && sta == 0 )
	iRet = roaGenerateFilter(roa2, NULL, fp);
      }
      fclose(fp);
    }
  if (FALSE == iRet)
    return 1;
  else
    return 0;
}
