/*
  $Id$
*/

#ifndef _ERR_H_
#define _ERR_H_

/*
  Error codes
*/

#define ERR_SCM_NOERR         0
#define ERR_SCM_COFILE       -1  	/* cannot open file */
#define ERR_SCM_NOMEM        -2	        /* out of memory */
#define ERR_SCM_INVALARG     -3	        /* invalid argument */
#define ERR_SCM_SQL          -4         /* SQL error */
#define ERR_SCM_INVALCOL     -5	        /* invalid column */
#define ERR_SCM_NULLCOL      -6         /* null column */
#define ERR_SCM_NOSUCHTAB    -7         /* no such table */
#define ERR_SCM_NODATA       -8         /* no matching data in table */
#define ERR_SCM_NULLVALP     -9         /* null value pointer */
#define ERR_SCM_INVALSZ     -10         /* invalid size */
#define ERR_SCM_ISLINK      -11	        /* links not processed */
#define ERR_SCM_BADFILE     -12         /* invalid file */
#define ERR_SCM_INVALFN     -13	        /* inconsistent filename */
#define ERR_SCM_NOTADIR     -14         /* not a directory */
#define ERR_SCM_INTERNAL    -15	        /* internal error */
#define ERR_SCM_X509        -16         /* X509 error */
#define ERR_SCM_BADCERT     -17	        /* error reading cert */
#define ERR_SCM_NOSUBJECT   -18         /* subject in cert missing */
#define ERR_SCM_NOISSUER    -19         /* issuer in cert missing */
#define ERR_SCM_NOSN        -20         /* serial number in cert missing */
#define ERR_SCM_BIGNUMERR   -21         /* error converting ASN.1 to a bignum */
#define ERR_SCM_NONB4       -22         /* not-before field is missing */
#define ERR_SCM_NONAF       -23         /* not-after field is missing */
#define ERR_SCM_INVALDT     -24         /* invalid date/time */
#define ERR_SCM_BADEXT      -25         /* extension error */
#define ERR_SCM_INVALEXT    -26         /* invalid extension */
#define ERR_SCM_XPROFILE    -27         /* profile violation */
#define ERR_SCM_MISSEXT     -28         /* missing extension */
#define ERR_SCM_NOTSS       -29         /* not self-signed */
#define ERR_SCM_NOTVALID    -30         /* cert validation error */
#define ERR_SCM_CERTCTX     -31	        /* cannot create cert context */
#define ERR_SCM_X509STACK   -32         /* x509 stack creation error */
#define ERR_SCM_STORECTX    -33         /* store ctx creation error */
#define ERR_SCM_STOREINIT   -34         /* store init error */
#define ERR_SCM_NOAKI       -35         /* missing aki */
#define ERR_SCM_CRL         -36         /* CRL error */
#define ERR_SCM_BADCRL      -37         /* error reading CRL */
#define ERR_SCM_NOTIMPL     -38         /* not implemented */
#define ERR_SCM_INVALASID   -39         /* invalid AS# */
#define ERR_SCM_INVALSKI    -40         /* invalid SKI */
#define ERR_SCM_INVALIPB    -41         /* invalid IP address block */
#define ERR_SCM_INVALIPL    -42         /* invalid IP address length */
#define ERR_SCM_INVALVER    -43         /* invalid version */
#define ERR_SCM_INVALASN    -44         /* ASN.1 library error */

#define ERR_SCM_MAXERR      -44

/* macro that prints an error string and call return if a condition is true */
#define checkErr(test, printArgs...) \
  if (test) { \
     (void) fprintf (stderr, printArgs); \
     return -1; \
  }

extern char *err2string(int err);

#endif
