#include <stdio.h>
#include "roa_utils.h"
#include "cryptlib.h"

/* $Id$ */

int main(int argc, char **argv)
  {
  struct ROA roa;
  struct Certificate cert;
  int siz;
  uchar *buf;

  ROA(&roa, 0);
  Certificate(&cert, 0);
  if (argc < 3) fprintf(stderr, "Need argv[1] for roa and [2] for cert\n");
  else if ((siz = get_casn_file(&roa.self, argv[1], 0)) < 0) 
    fprintf(stderr, "Reading roa failed at %d (%X) %s\n", -siz, -siz, casn_err_struct.asn_map_string);
  else if ((siz = get_casn_file(&cert.self, argv[2], 0)) < 0) 
    fprintf(stderr, "reading cert failed at %d (%X) %s\n", -siz, -siz, 
      casn_err_struct.asn_map_string);
  else
    {
    siz = size_casn(&cert.self);
    buf = (uchar *)calloc(1, siz);
    encode_casn(&cert.self, buf);
    fprintf(stderr, "Checking %s\n", (roaValidate2(&roa, buf) < 0)? "failed.":
      "SUCCEEDED!");
    }
  return 0;
  } 
