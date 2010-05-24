#include "roa_utils.h"
#include "err.h"

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
 *
 * Contributor(s):  David Montana
 *
 * ***** END LICENSE BLOCK ***** */

/*
  $Id$
*/

int main(int argc, char** argv)
{
  struct ROA roa;
  char filename[256];
  int isPEM;

  checkErr(argc != 4, "Usage: makeRoa configFile outputPrefix pemOrDer\n");
  checkErr(! roaFromConfig (argv[1], 0, &roa),
            "Could not read config from %s\n", argv[1]);
  isPEM = tolower ((int)(argv[3][0])) != 'd';
  snprintf (filename, sizeof(filename), "%s.roa.%s", argv[2], isPEM ? "pem" : "der");
  checkErr(! roaToFile (&roa, filename, isPEM ? FMT_PEM : FMT_DER),
            "Could not write file: %s\n", filename);
  return 0;
}
