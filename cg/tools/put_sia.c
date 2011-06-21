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
 * Copyright (C) Raytheon BBN Technologies Corp. 2008-2011.
 * All Rights Reserved.
 *
 * Contributor(s):  Andrew Chi
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include "certificate.h"

struct SIA_request {
  char *accessMethod;
  char *accessLocation;
};

static struct SIA_request *
new_sia_request(const char *accessMethod, const char *accessLocation) {
  struct SIA_request *r = NULL;
  
  if (!accessMethod || !accessLocation)
    return NULL;

  r = (struct SIA_request *)malloc(sizeof(struct SIA_request));
  if (!r) {
    return NULL;
  }

  r->accessMethod = strcpy(accessMethod);
  if (!r->accessMethod) {
    free(r);
    return NULL;
  }

  r->accessLocation = strcpy(accessLocation);
  if (!r->accessLocation) {
    free(r->accessMethod);
    free(r);
    return NULL;
  }
  
  return r;
}

static void free_sia_request(SIA_request *r) {
  if (r) {
    if (r->accessMethod) {
      free(r->accessMethod);
      r->accessMethod = NULL;
    }
    if (r->accessLocation) {
      free(r->accessLocation);
      r->accessLocation = NULL;
    }
    free(r);
  }
}

static struct Extension *findExtension(struct Extensions *extsp, char *oid)
  {
  struct Extension *extp;
  if (!num_items(&extsp->self)) 
    return (struct Extension *)0;

  for (extp = (struct Extension *)member_casn(&extsp->self, 0);
    extp && diff_objid(&extp->extnID, oid);
    extp = (struct Extension *)next_of(&extp->self));
  return extp;
  }


static void usage(int argc, char *argv[])
{
  fprintf(stderr,
	  "Modify Subject Information Access URI(s) in a certificate.\n"
	  "\n"
	  "Usage: %s [options] <certificate_file>\n"
	  "\n"
	  "Options:\n"
	  "    -d    \tDelete any existing SIA access descriptions\n"
          "    -r URI\tAdd URI w/ access method id-ad-caRepository\n"
          "    -m URI\tAdd URI w/ access method id-ad-rpkiManifest\n"
          "    -s URI\tAdd URI w/ access method id-ad-signedObject\n"
          "    -h    \tShow this help file\n",
	  argv[0]);
}

int main(int argc, char *argv[])
{
  int c = 0;			/* command line option character */
  int delete_existing = 0;      /* delete existing SIA access descriptions */
  struct SIA_request *sia_requests; /* command line arguments
                                       specifying SIA URLs to add to
                                       the certificate */
  
  const char *file = NULL;	/* certificate file */
  struct Certificate cert;	/* ASN.1 certificate object */
  struct Extension *extp;	/* ASN.1 X.509 extension pointer */
  struct SubjectInfoAccess *siap; /* ASN.1 SIA pointer */
  struct AccessDescription *adp; /* ASN.1 AccessDescription pointer */
  int ret;			/* return value */

  /* Parse command line arguments. */
  opterr = 0;
  while ((c = getopt (argc, argv, "dm")) != -1) {
    switch (c)
      {
      case 'd':
	option_dir = 1;
	break;
      case 'r':                 /* id-ad-caRepository */
	/* add an SIA_request to the list */
	break;
      case 'm':                 /* id-ad-rpkiManifest */
	/* add an SIA_request to the list */
	break;
      case 's':                 /* id-ad-signedObject */
	/* add an SIA_request to the list */
	break;
      case 'h':
        usage(argc, argv);
        return -1;
      case '?':
	if (isprint (optopt))
	  fprintf(stderr, "Unknown option `-%c'.\n", optopt);
	else
	  fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
	usage(argc, argv);
	return -1;
      default:
	usage(argc, argv);
	return -1;
      }
  }
  if (optind >= argc) {         /* no arguments remain? */
    usage(argc, argv);
    return -1;
  }
  file = argv[optind];

  /* Parse certificate. */
  Certificate(&cert, (unsigned short)0); /* constructor */
  ret = get_casn_file(&cert.self, (char*)file, 0);
  if (ret < 0)
    {
      fprintf(stderr, "Could not open file: %s\n", file);
      return -2;
    }

  /* Find SIA extension. */
  extp = findExtension(&cert.toBeSigned.extensions, id_pe_subjectInfoAccess);
  if (!extp) {
    fprintf(stderr, "Error: could not locate SIA extension.\n");
    return -3;
  }
  siap = &extp->extnValue.subjectInfoAccess;

  /* For each AccessDescription... */

  /* Clean up. */
  delete_casn(&cert.self);
  return 0;
}
