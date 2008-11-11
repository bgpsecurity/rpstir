/*
  $Id: roa_create.c 453 2007-07-25 15:30:40Z mreynolds $
*/

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
 * Contributor(s):  Joshua Gruenspecht
 *
 * ***** END LICENSE BLOCK ***** */

/*
This contains the ROA to- and ROA from- conf file function
calls.  They wrap the roaToFile and roaFromFile calls defined
in roa_serialize.c, and are defined in roa_utils.h.
*/

#include "roa_utils.h"

// ROA_utils.h contains the headers for including these functions

int roaFromConfig(char *fname, int doval, struct ROA* rp)
{
  return roaFromFile(fname, FMT_CONF, doval, rp);
}

int roaToConfig(struct ROA* roa, char *fname)
{
  UNREFERENCED_PARAMETER(roa);
  UNREFERENCED_PARAMETER(fname);

  return ERR_SCM_NOTIMPL;
  // currently unspecified (not yet required)
  // return roaToFile(roa, fname, FMT_CONF);
}
