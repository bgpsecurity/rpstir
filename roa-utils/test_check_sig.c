#include <stdio.h>
#include "roa_utils.h"
#include "cryptlib.h"

/* $Id$ */


int main(int argc, char **argv)
  {
  struct ROA roa;
  struct Certificate *certp;

  ROA(&roa, 0);
  if (argc < 2) fprintf(stderr, "Need argvs for roa(s)\n");
  else for (argv++; argv && *argv; argv++)
      {
      if (get_casn_file(&roa.self, argv[0], 0) < 0) fprintf(stderr, "Reading roa failed\n");
      else if (!(certp = (struct Certificate *)member_casn(&roa.content.signedData.certificates.self, 0)))
          fprintf(stderr, "Couldn't get certificate in roa\n");
      else 
        {
        char *n = "something else";
        if (!diff_objid(&roa.content.signedData.encapContentInfo.eContentType, id_roa_pki_manifest)) n = argv[0];
        else if (!diff_objid(&roa.content.signedData.encapContentInfo.eContentType, id_routeOriginAttestation)) n = "ROA";
        fprintf(stderr, "Checking %s %s\n", n, (check_sig(&roa, certp) < 0)? "failed.":
            "SUCCEEDED!");
        }
      }
  return 0;
  } 
