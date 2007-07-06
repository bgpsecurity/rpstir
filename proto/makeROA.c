#include "roa_utils.h"
#include "err.h"

/*
  $Id$
*/

int main(int argc, char** argv)
{
  struct ROA *roa;
  char filename[128];
  int isPEM;

  checkErr (argc != 4, "Usage: makeRoa configFile outputPrefix pemOrDer\n");
  checkErr (! roaFromConfig (argv[1], 0, &roa),
            "Could not read config from %s\n", argv[1]);
  isPEM = tolower (argv[3][0]) != 'd';
  snprintf (filename, 128, "%s.roa.%s", argv[2], isPEM ? "pem" : "der");
  checkErr (! roaToFile (roa, filename, isPEM ? FMT_PEM : FMT_DER),
            "Could not write file: %s\n", filename);
  return 0;
}
