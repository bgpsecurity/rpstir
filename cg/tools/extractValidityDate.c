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

static void usage(int argc, char *argv[])
{
  fprintf(stderr,
	  "Extracts a validity date (notBefore/notAfter) from a certificate "
	  "and writes it to stdout.\n"
	  "\n"
	  "Usage: %s [options] <certificate_file>\n"
	  "\n"
	  "Options:\n"
	  "    -b\tRetrieve notBefore (default is to extract both)\n"
	  "    -a\tRetrieve notAfter\n",
	  argv[0]);
}

static int fprintDate(FILE *fp, struct CertificateValidityDate *date)
{
  int date_len;			/* length of date string */
  char *date_str = NULL;	/* date string */
  int ret;

  if (!fp || !date) {
    fprintf(stderr, "Invalid input to fprintDate\n");
    return -1;
  }
  
  date_len = vsize_casn(&date->self);
  date_str = (char*)calloc(date_len+2, 1);
  if (!date_str) {
    fprintf(stderr, "Memory allocation failure\n");
    return -1;
  }
  ret = read_casn(&date->self, (unsigned char*)date_str);
  if (ret < date_len) {
    fprintf(stderr, "Read failure: got %d, expected %d bytes\n", ret,date_len);
  } else {
    fprintf(fp, "%s\n", date_str);
  }
  free(date_str);

  return 0;
}

int main(int argc, char *argv[])
{
  int c = 0;			/* command line option character */
  int option_notbefore = 0;	/* retrieve notBefore date */
  int option_notafter = 0;	/* retrieve notAfter date */
  const char *file = NULL;	/* certificate file */
  struct Certificate cert;	/* ASN.1 certificate object */
  int ret;			/* return value */
  
  /* Parse command line arguments. */
  opterr = 0;
  while ((c = getopt (argc, argv, "ba")) != -1) {
    switch (c)
      {
      case 'b':
	option_notbefore = 1;
	break;
      case 'a':
	option_notafter = 1;
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
  /* If no selection, default to both dates. */
  if (option_notbefore == 0 && option_notafter == 0) {
    option_notbefore = 1;
    option_notafter = 1;
  }
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

  /* Extract dates */
  if (option_notbefore)
    fprintDate(stdout, &cert.toBeSigned.validity.notBefore);
  if (option_notafter)
    fprintDate(stdout, &cert.toBeSigned.validity.notAfter);

  /* Clean up. */
  delete_casn(&cert.self);
  return 0;
}
