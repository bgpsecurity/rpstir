#include <stdio.h>
#include "roa_utils.h"
#include "cryptlib.h"

/* $Id$ */

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
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
  int siz;

  ROA(&roa, 0);
  if (argc < 2) fprintf(stderr, "Need argv[1] for roa\n");
  else 
    {
    printf("Testing %s and %s\n", argv[1], argv[2]);
    if ((siz = get_casn_file(&roa.self, argv[1], 0)) < 0) 
      fprintf(stderr, "Reading roa failed at %d (%X) %s\n", -siz, -siz, 
        casn_err_struct.asn_map_string);
    else
      {
      fprintf(stderr, "Checking %s\n", (roaValidate2(&roa) < 0)? "failed.":
        "SUCCEEDED!");
      }
    }
  return 0;
  } 
