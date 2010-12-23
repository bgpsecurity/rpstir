#include <stdio.h>
#include "certificate.h"

// Extract the SubjectPublicKeyInfo section from a certificate.  This
// tool is useful for handling Trust Anchor Locators (draft-ietf-sidr-ta).

int main(int argc, char **argv)
{
  char *certfile;
  char *outfile;
  struct Certificate cert;
  // struct SubjectPublicKeyInfo *pubkeyinfo;

  /* Process input and output file command line arguments. */
  if (argc < 2 || argc > 3)
    {
      fprintf(stderr, "Usage: %s certfile [outfile]\n", argv[0]);
      return 1;
    }
  certfile = argv[1];
  if (argc == 3) {
    outfile = argv[2];
  } else {
    outfile = NULL;		/* will be equivalent to stdout */
  }
  
  Certificate(&cert, (ushort)0);
  if (get_casn_file(&cert.self, certfile, 0) <= 0)
    {
      fprintf(stderr, "Error reading file %s\n", certfile);
      return 1;
    }
  if (put_casn_file(&cert.toBeSigned.subjectPublicKeyInfo.self,
		    outfile, outfile?0:1) < 0)
    {
      fprintf(stderr, "Error writing file\n");
      return 1;
    }
  return 0;
}
