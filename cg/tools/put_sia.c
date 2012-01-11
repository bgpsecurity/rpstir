
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include "certificate.h"

#define MAX_SIA_ACC_DESCR 100 /* maximum number of access descriptions */

struct SIA_request {
  const char *accessMethod;
  const char *accessLocation;
};

/* Command line options will request zero or more SIA URLs to be added
   to the certificate.  sia_requests[] and num_sia_requests keep a
   record of these. */
struct SIA_request sia_requests[MAX_SIA_ACC_DESCR];
int num_sia_requests = 0;


static void usage(int argc, char *argv[])
{
  fprintf(stderr,
	  "Modify Subject Information Access URI(s) in a certificate.\n"
	  "\n"
	  "Usage: %s [options] <certificate_file>\n"
	  "\n"
	  "Options:\n"
	  "    -d    \tDelete all existing SIA access descriptions\n"
          "    -r URI\tAdd URI w/ access method id-ad-caRepository\n"
          "    -m URI\tAdd URI w/ access method id-ad-rpkiManifest\n"
          "    -s URI\tAdd URI w/ access method id-ad-signedObject\n"
          "    -h    \tShow this help file\n",
	  argv[0]);
}


/* Add SIA request (usually from command line) to the global list.
   Return 0 on success, -1 on failure.  NOTE: we copy the URI string,
   and never free it.  This is technically a memory leak, but it's
   only the command line arguments so we don't care.  */
static int add_sia_request(char type, const char *URI)
{
  if (!URI || (type != 'r' && type != 'm' && type != 's'))
    return -1;

  if (num_sia_requests > MAX_SIA_ACC_DESCR - 1) {
    fprintf(stderr, "Error: maximum SIA access descriptions (%d) exceeded.\n",
            MAX_SIA_ACC_DESCR);
    return -1;
  }

  switch (type)
    {
    case 'r':
      sia_requests[num_sia_requests].accessMethod = id_ad_caRepository;
      break;
    case 'm':
      sia_requests[num_sia_requests].accessMethod = id_ad_rpkiManifest;
      break;
    case 's':
      sia_requests[num_sia_requests].accessMethod = id_ad_signedObject;
      break;
    default:
      return -1;
    }
  sia_requests[num_sia_requests].accessLocation = strdup(URI);
  
  num_sia_requests++;
  
  return 0;
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

static struct Extension *makeExtension(struct Extensions *extsp, char *idp)
  {
    struct Extension *extp;
    if (!(extp = findExtension(extsp, idp)))
      {
	extp = (struct Extension *)inject_casn(&extsp->self,
					       num_items(&extsp->self));
      }
    else clear_casn(&extp->self);
    
    write_objid(&extp->extnID, idp);
    return extp;
  }

int main(int argc, char *argv[])
{
  
  int delete_existing = 0;      /* delete existing SIA access descriptions */
  const char *file = NULL;	/* certificate file */
  struct Certificate cert;	/* ASN.1 certificate object */
  struct Extension *extp;	/* ASN.1 X.509 extension pointer */
  struct SubjectInfoAccess *siap; /* ASN.1 SIA pointer */
  
  int c = 0;			/* getopt option character */
  int i;                        /* loop counter */
  int ret;			/* return value */

  /* Parse command line arguments. */
  opterr = 0;
  while ((c = getopt (argc, argv, "dr:m:s:h")) != -1) {
    switch (c)
      {
      case 'd':
	delete_existing = 1;
	break;
      case 'r':                 /* id-ad-caRepository */
	if (add_sia_request('r', optarg) != 0) {
          fprintf(stderr, "Error: failed to add URI request -r %s\n", optarg);
          return -1;
        }
	break;
      case 'm':                 /* id-ad-rpkiManifest */
	if (add_sia_request('m', optarg) != 0) {
          fprintf(stderr, "Error: failed to add URI request -m %s\n", optarg);
          return -1;
        }
	break;
      case 's':                 /* id-ad-signedObject */
	if (add_sia_request('s', optarg) != 0) {
          fprintf(stderr, "Error: failed to add URI request -s %s\n", optarg);
          return -1;
        }
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

  /* Find or create SIA extension. */
  extp = findExtension(&cert.toBeSigned.extensions, id_pe_subjectInfoAccess);
  if (!extp) {
    extp = makeExtension(&cert.toBeSigned.extensions, id_pe_subjectInfoAccess);
    if (!extp) {
      fprintf(stderr, "Could not create SIA extension.\n");
      return -3;
    }
  }
  siap = &extp->extnValue.subjectInfoAccess;

  /* Optionally delete existing AccessDescriptions. */
  if (delete_existing) {
    clear_casn(&siap->self);    /* This messes up the "DEFINED BY"
                                   flag, so we need to set it again in
                                   the next line.  */
    if (write_objid(&extp->extnID, id_pe_subjectInfoAccess) < 0) {
      fprintf(stderr, "Error clearing existing URIs.\n");
      return -1;
    }
  }

  /* For each AccessDescription request, insert it. */
  for (i = 0; i < num_sia_requests; i++) {
    int current_size;
    struct AccessDescription *adp; /* ASN.1 AccessDescription pointer */

    /* Append new entry. */
    current_size = num_items(&siap->self);
    adp = (struct AccessDescription *)inject_casn(&siap->self, current_size);
    if (!adp) {
      fprintf(stderr, "Error: failed to append access description.\n");
      return -1;
    }

    if (write_objid(&adp->accessMethod,
                    (char*)sia_requests[i].accessMethod) < 0) {
      fprintf(stderr, "Error: failed to set access method.\n");
      return -1;
    }

    if (write_casn(&adp->accessLocation.url,
                   (unsigned char *)sia_requests[i].accessLocation,
                   strlen(sia_requests[i].accessLocation)) < 0) {
      fprintf(stderr, "Error: failed to set access location.\n");
      return -1;
    }
  }

  /* Check for non-empty SIA (RFC 5280) */
  if (num_items(&siap->self) == 0) {
    fprintf(stderr,
            "SIA must have at least one AccessDescription, per RFC5280.\n");
    return -1;
  }

  /* Write to file. */
  if (put_casn_file(&cert.self, (char *)file, 0) < 0) {
    fprintf(stderr, "Error: failed to write %s\n", file);
    return -4;
  }

  /* Clean up. */
  delete_casn(&cert.self);
  return 0;
}
