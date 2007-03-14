#include "roa.h"

ROA *roaFromFile(char *fname, int fmt, int doval, int *errp);

/*
  Read in a ROA from a file and potentially perform validation.
  "fname" is the name of the file containing the putative ROA.
  If "fmt" is 0 this function attempts to intuit the file format
  based on the first CR or LF delimited line in the file and also
  the filename; if "fmt" is non-zero then it is an OpenSSL enum value
  specifying the file format (binary DER or PEM encoded DER).
  
  If "doval" is any nonzero value then the ROA will also be semantically
  validated using all steps that do not require access to the database;
  if "doval" is 0 only ASN.1 syntatic validation will be performed.

  On success a ROA data structure, as defined in roa.h, is returned
  and errp is set to 0.  On failure NULL is returned and errp is
  set to a negative error code.

  The non-NULL return from this function is allocated memory that
  must be freed by a call to roaFree().
*/

int roaToFile(ROA *r, char *fname, int fmt);

/*
  This function is the inverse of the previous function.  The ROA
  defined by "r" is written to the file named "fname" using the format
  "fmt".  If "fmt" is 0 the output form is the default (PEM encoded DER).

  On success this function returns 0; on failure it returns a negative
  error code.
*/

char *roaSKI(ROA *r);

/*
  This utility function extracts the SKI from a ROA and formats it in
  the canonical ASCII format hex:hex:...:hex, suitable for use in DB
  lookups.  On failure this function returns NULL.

  Note that this function returns a pointer to allocated memory that
  must be free()d by the caller.
*/

int roaValidate(ROA *r);

/*
  This function performs all validations steps on a ROA that do not
  require database access.  On success it returns 0; on failure, it
  returns a negative error code.
*/

int roaValidate2(ROA *r, X509 *x);

/*
  This function performs all validations steps on a ROA that require
  an X509 certificate to have been fetched from the database. It returns 0
  on sucess and a negative error code on failure. It is assumed that this
  function is called as follows:

      scmcon *conp; // previously opened DB connection
      X509   *cert;
      char   *ski;
      int     valid = -1;
      int     sta;

      sta = roaValidate(r);
      if ( sta == 0 ) {
        ski = roaSKI(r);
	if ( ski != NULL ) {
	  cert = find_certificate(conp, ski, NULL, NULL, &sta);
	  if ( cert != NULL && sta == 0 ) {
            valid = roaValidate2(r, cert);
          }
        }
      }
*/

void roaFree(ROA *r);

/*
  This function frees all memory allocated when "r" was created. It
  is permissible for "r" to be NULL, in which case nothing happens.
  If "r" is non-NULL, however, it must point to a syntatically valid
  ROA structure (which need not have been semantically validated, however).
*/
