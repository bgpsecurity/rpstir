#include <stdio.h>
#include "roa_utils.h"
#include "cryptlib.h"

/* $Id: test_manifest.c 453 2007-07-25 15:30:40Z mreynolds $ */

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
  struct Certificate *certp;
  char *dirp;
  struct badfile **badfilespp;
  int err;

  ROA(&roa, 0);
  if (argc < 2) {
      fprintf(stderr, "usage: %s directory manifest [manifest ...]\n");
      return 0;
  }
  argv++;
  dirp = *argv++;
  for (; *argv != NULL; argv++) {

      /* read and decode the file */
      if (get_casn_file(&roa.self, *argv, 0) != 0) {
	  fprintf(stderr, "Reading roa failed\n");
	  continue;
      }

      /* XXX we get this but never do anything with it */
      certp = (struct Certificate *)
	  member_casn(&roa.content.signedData.certificates.self, 0);
      if (certp == NULL) {
          fprintf(stderr, "Couldn't get certificate in roa\n");
	  continue;
      }

      /* see if it has the right content type (manifest) */
      if (diff_objid(&roa.content.signedData.encapContentInfo.eContentType, 
		     id_roa_pki_manifest)) {
          fprintf(stderr, "%s not a manifest\n", *argv);
	  continue;
      }

      /* validate the manifest */
      err = manifestValidate2(&roa, dirp, &badfilespp);
      fprintf(stderr, "Checking %s ", *argv);
      if (err != 0) {
	  fprintf(stderr, "failed.\n");
	  if (badfilespp != NULL) {
              fprintf(stderr,  "    Bad files were:\n");
              struct badfile **bf;
              for (bf = badfilespp; bf && *bf; bf++)
		  fprintf(stderr, "        %s\n", (*bf)->fname);
	  }
	  continue;
      }
      fprintf(stderr, "SUCCEEDED\n");
  }
  return 0;
} 
