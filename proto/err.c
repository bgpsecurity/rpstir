/*
  $Id$
*/

#include <stdio.h>

#include "err.h"

static char *errs[] =
  {
    "No error",			    /* ERR_SCM_NOERR */
    "Cannot open file",             /* ERR_SCM_COFILE */
    "Out of memory",                /* ERR_SCM_NOMEM */
    "Invalid argument",             /* ERR_SCM_INVALARG */
    "SQL error",                    /* ERR_SCM_SQL */
    "Invalid column",               /* ERR_SCM_INVALCOL */
    "Null column",                  /* ERR_SCM_NULLCOL */
    "No such table",                /* ERR_SCM_NOSUCHTAB */
    "No data",                      /* ERR_SCM_NODATA */
    "Null value",                   /* ERR_SCM_NULLVALP */
    "Invalid size",                 /* ERR_SCM_INVALSZ */
    "Link skipped",                 /* ERR_SCM_ISLINK */
    "Invalid file",                 /* ERR_SCM_BADFILE */
    "Inconsistent filename",        /* ERR_SCM_INVALFN */
    "Not a directory",              /* ERR_SCM_NOTADIR */
    "Internal error",               /* ERR_SCM_INTERNAL */
    "X509 error",                   /* ERR_SCM_X509 */
    "Error reading cert",           /* ERR_SCM_BADCERT */
    "Missing subject field",        /* ERR_SCM_NOSUBJECT */
    "Missing issuer field",         /* ERR_SCM_NOISSUER */
    "Missing serial number",        /* ERR_SCM_NOSN */
    "Bignum error",                 /* ERR_SCM_BIGNUMERR */
    "Missing start date",           /* ERR_SCM_NONB4 */
    "Missing end date",             /* ERR_SCM_NONAF */
    "Invalid date/time",            /* ERR_SCM_INVALDT */
    "Extension error",              /* ERR_SCM_BADEXT */
    "Invalid extension",            /* ERR_SCM_INVALEXT */
    "Profile violation",            /* ERR_SCM_XPROFILE */
    "Missing extension",            /* ERR_SCM_MISSEXT */
    "Not self-signed",              /* ERR_SCM_NOTSS */
    "Certificate validation error", /* ERR_SCM_NOTVALID */
    "Certificate context error",    /* ERR_SCM_CERTCTX */
    "X509 stack error",             /* ERR_SCM_X509STACK */
    "Certificate store error",      /* ERR_SCM_STORECTX */
    "Cert store init error",        /* ERR_SCM_STOREINIT */
    "Missing AKI",                  /* ERR_SCM_NOAKI */
    "CRL error",                    /* ERR_SCM_CRL */
    "Error reading CRL"             /* ERR_SCM_BADCRL */
    "Not implemented",		    /* ERR_SCM_NOTIMPL */
    "Invalid AS number",	    /* ERR_SCM_INVALASID */
    "Invalid SKI",                  /* ERR_SCM_INVALSKI */
    "Invalid IP address block",     /* ERR_SCM_INVALIPB */
    "Invalid IP address length",    /* ERR_SCM_INVALIPL */
    "Invalid version number",       /* ERR_SCM_INVALVER */
    "ASN.1 library error",          /* ERR_SCM_INVALASN */
    "Not an EE certificate",        /* ERR_SCM_NOTEE */
  } ;

char *err2string(int err)
{
  if ( err > 0 || err < ERR_SCM_MAXERR )
    return(NULL);
  return(errs[-err]);
}
