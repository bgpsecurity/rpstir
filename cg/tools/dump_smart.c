#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "casn.h"
#include "roa.h"

void fatal(char *msg, char *param)
  {
  fprintf(stderr, msg, param);
  exit(1);
  }

int main(int argc, char ** argv)
  {
  struct ROA roa;
  struct Certificate certificate;
  struct Manifest manifest;
  char *buf;
  int bsize;

  ROA(&roa, (ushort)0);
  Certificate(&certificate, (ushort)0);
  Manifest(&manifest, (ushort)0);

  if (argc < 2)
    {
    fatal ("Usage [-r ROAfile] [-c Certificatefile] [-m manifestfile]\n", (char *)0);
    exit(1);
    }
  if (*argv[1] != '-') fatal("First argument must begin with '-'\n", (char *)0);
  char *p = argv[1];
  if (p[1] == 'c')
    {
    if (get_casn_file(&certificate.self, argv[2], 0) < 0) 
        fatal("Error reading %s\n", argv[2]);
    bsize = dump_size(&certificate.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&certificate.self, buf);
    printf(buf);
    }
  else if (p[1] == 'r')
    {
    if (get_casn_file(&roa.self, argv[2], 0) < 0) 
        fatal("Error reading %s\n", argv[2]);
    bsize = dump_size(&roa.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&roa.self, buf);
    printf(buf);
    }
  else if (p[1] == 'm')
    {
    if (get_casn_file(&manifest.self, argv[2], 0) < 0) 
        fatal("Error reading %s\n", argv[2]);
    bsize = dump_size(&manifest.self);
    buf = (char *)calloc(1, bsize + 8);
    dump_casn(&manifest.self, buf);
    printf(buf);
    }
  exit(1);
  }
   
