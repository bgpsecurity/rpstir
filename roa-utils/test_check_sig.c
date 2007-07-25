#include <stdio.h>
#include "roa_utils.h"
#include "cryptlib.h"

/* $Id$ */

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Verison 1.0
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

int main(int argc, char **argv)
  {
  struct ROA roa;
  struct Certificate cert;

  ROA(&roa, 0);
  Certificate(&cert, 0);
  if (argc < 3) fprintf(stderr, "Need argv[1] for roa and [2] for key\n");
  else if (get_casn_file(&roa.self, argv[1], 0) < 0) fprintf(stderr, "Reading roa failed\n");
  else if (get_casn_file(&cert.self, argv[2], 0) < 0) fprintf(stderr, "reading cert failed\n");
  else fprintf(stderr, "Checking %s\n", (check_sig(&roa, &cert) < 0)? "failed.":
    "SUCCEEDED!");
  return 0;
  } 
