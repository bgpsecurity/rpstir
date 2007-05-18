#include "cert_check.h"

/* stub main */

int
main(int argc, char *argv[])
{
  X509 *x;
  int ret;
  
  /* stub test main for cert_check */
  if (argc != 2) {
    printf("usage: %s file\n", argv[0]);
    exit(0);
  }
  
  x = x509_from_file(argv[1]);
  if (!x) {
    fprintf(stderr, "x509_from_file(%s) returned NULL\n", argv[1]);
    exit(0);
  }
  
  
  /* need to suck this one in as it pulls through the X509 extensions
     and loads them into the X509 structure so we can deal with them
     in a more straightforward fashion.
   x509_v3_cache_extensions(x);
  */
  x509v3_load_extensions(x);
  
  print_flags(x);
  print_key_usage(x);
  print_extended_key_usage(x);
  printf("------\n");
  printf("Comparing against CA_CERT:\n");
  ret = rescert_profile_chk(x, CA_CERT);
  if (ret == TRUE)
    printf("profile check against CA_CERT: TRUE\n");
  else
    printf("profile check against CA_CERT: FALSE\n");
  printf("------\n");
  printf("Comparing against TA_CERT:\n");
  ret = rescert_profile_chk(x, TA_CERT);
  if (ret == TRUE)
    printf("profile check against TA_CERT: TRUE\n");
  else
    printf("profile check against TA_CERT: FALSE\n");
  printf("------\n");
  printf("Comparing against EE_CERT\n");
  ret = rescert_profile_chk(x, EE_CERT);
  if (ret == TRUE)
    printf("profile check against EE_CERT: TRUE\n");
  else
    printf("profile check against EE_CERT: FALSE\n");
  printf("------\n");
  printf("Comparing against UNK_CERT\n");
  ret = rescert_profile_chk(x, UNK_CERT);
  if (ret == TRUE)
    printf("profile check against UNK_CERT: TRUE\n");
  else
    printf("profile check against UNK_CERT: FALSE\n");
  printf("------\n");
  
  
  X509_free(x);                                               
                                                              
  return(1);                                                  
}                                                             

