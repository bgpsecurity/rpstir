#include <stdio.h>
#include "roa.h"

int main(int argc, char **argv)
  {
  struct ROA roa;
  ROA(&roa, (ushort)0);
  get_casn_file(&roa.self, argv[1], 0);
  char *buf = (char *)calloc(1, dump_size(&roa.self));
  dump_casn(&roa.self, buf);
  printf(buf);
  return 0;
  }
