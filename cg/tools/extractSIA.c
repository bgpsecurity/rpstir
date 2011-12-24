
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include "certificate.h"

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
	  "Extracts a Subject Information Access URI from a certificate "
	  "and writes it to stdout.\n"
	  "\n"
	  "Usage: %s [options] <certificate_file>\n"
	  "\n"
	  "Options:\n"
	  "    -d\tRetrieve SIA directory URI (default)\n"
	  "    -m\tRetrieve SIA manifest URI\n",
	  argv[0]);
}

int main(int argc, char *argv[])
{
  int c = 0;			/* command line option character */
  int option_dir = 0;		/* retrieve SIA directory URL */
  int option_mft = 0;		/* retrieve SIA manifest URL */
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
      case 'm':
	option_mft = 1;
	break;
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
  /* If no selection, default to directory. */
  if (option_dir == 0 && option_mft == 0)
    option_dir = 1;
  if (optind >= argc) {
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

  /* For each AccessDescription, print the accessLocation URI if the
     accessMethod matches the user requested SIA type: directory or
     manifest. */
  for (adp = (struct AccessDescription*)member_casn(&siap->self, 0);
       adp != NULL; adp = (struct AccessDescription*)next_of(&adp->self)) {
    char *rsync_uri = NULL;
    int len = 0;
    int print_this_one = 0;
    
    if (diff_objid(&adp->accessMethod, id_ad_rpkiManifest) == 0 &&
	option_mft) {
      /* Manifest */
      print_this_one = 1;
    } else if (diff_objid(&adp->accessMethod, id_ad_caRepository) == 0 &&
	       option_dir) {
      /* Directory */
      print_this_one = 1;
    } else if (diff_objid(&adp->accessMethod, id_ad_signedObject) == 0) {
      /* Signed Object */
      print_this_one = 1;
    }

    if (!print_this_one)
      continue;
    
    /* print manifest URI */
    len = vsize_casn(&adp->accessLocation.self);
    rsync_uri = (char*)calloc(len + 2, 1);
    if (!rsync_uri) {
      fprintf(stderr, "Memory allocation failure on %d bytes!\n", len + 2);
      continue;
    }
    ret = read_casn(&adp->accessLocation.self, (unsigned char*)rsync_uri);
    if (ret < len) {
      fprintf(stderr, "Read failure: got %d, expected %d bytes\n", ret, len);
    } else {
      printf("%s\n", rsync_uri);
    }
    free(rsync_uri);
  }

  /* Clean up. */
  delete_casn(&cert.self);
  return 0;
}
