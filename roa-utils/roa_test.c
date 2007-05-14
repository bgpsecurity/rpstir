/*
  $Id$
*/

#include "roa_utils.h"

int main(int argc, char** argv)
{
  struct ROA *roa;
  struct ROA *roa2;
  int  sta = 0;
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
  sta = roaFromConfig(filename_cnf, 0, &roa);
  if (0 == sta)
    sta = roaToFile(roa, filename_pem, FMT_PEM);
  if (0 == sta)
    sta = roaFromFile(filename_pem, FMT_PEM, cTRUE, &roa2);
  if (0 == sta)
    {
      fp = fopen("roa.txt", "a");
      if (fp) {
	// JFG - Add these back in when ready to test validation
	//ski = roaSKI(r);
	//if ( NULL != ski ) {
	//cert = find_certificate(conp, ski, NULL, NULL, &sta);
	//if ( cert != NULL && sta == 0 )
	sta = roaGenerateFilter(roa2, NULL, fp);
      }
      fclose(fp);
    }
  if (sta < 0)
    return 1;
  else
    return 0;
}
