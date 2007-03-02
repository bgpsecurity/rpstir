#include "stub_main.h"

int
main(int argc, char *argv[])
{

  FILE *cert_fp;
  X509 *cert=NULL;
  int ret;

  ret = 0;

  if (argc != 2)
    usage(argv[0]);

  cert_fp = fopen(argv[1], "r");
  if (cert_fp < 0) {
    fprintf(stderr, "Could not open file: %s\n", argv[1]);
    exit(-1);
  }

  cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
  if (!cert) {
    fprintf(stderr, "Error reading cert from: %s\n", argv[1]);
    exit(-1);
  }

  ret = verify_cert(cert);

  printf("verify_cert returned: %d\n", ret);

  X509_free(cert);
  fclose(cert_fp);

  return(ret);
}
