#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "casn.h"
#include "roa.h"
#include "crlv2.h"

void fatal(char *msg, char *param, char *param2)
  {
  fprintf(stderr, msg, param, param2);
  exit(1);
  }

int main(int argc, char ** argv)
  {
  struct ROA roa;
  struct Certificate certificate;
  struct CertificateRevocationList crl;
  char *buf;
  int bsize;

  ROA(&roa, (ushort)0);
  Certificate(&certificate, (ushort)0);
  CertificateRevocationList(&crl, (ushort)0);

  if (argc < 2)
    {
    fatal ("Usage [-r ROAfile] [-c Certificatefile] [-l crl] [-m manifestfile]\n", 
      (char *)0, (char *)0);
    exit(1);
    }
  if (*argv[1] != '-') 
    fatal("First argument must begin with '-'\n", (char *)0, (char *)0);
  char *p = argv[1];
  if (p[1] == 'c')
    {
    if (get_casn_file(&certificate.self, argv[2], 0) < 0) 
        fatal("Error reading %s at %s\n", argv[2], casn_err_struct.asn_map_string);
    bsize = dump_size(&certificate.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&certificate.self, buf);
    printf(buf);
    }
  else if (p[1] == 'r' || p[1] == 'm')
    {
    if (get_casn_file(&roa.self, argv[2], 0) < 0) 
        fatal("Error reading %s at %s\n", argv[2], casn_err_struct.asn_map_string);
    bsize = dump_size(&roa.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&roa.self, buf);
    printf(buf);
    }
  else if (p[1] == 'l')
    {
    if (get_casn_file(&crl.self, argv[2], 0) < 0) 
        fatal("Error reading %s at %s\n", argv[2], casn_err_struct.asn_map_string);
    bsize = dump_size(&crl.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&crl.self, buf);
    printf(buf);
    }
  exit(1);
  }
   
