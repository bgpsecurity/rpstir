/*
  $Id$
*/

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
 * Contributor(s):  Mark Reynolds
 *
 * ***** END LICENSE BLOCK ***** */

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
    "Invalid size",                 /* ERR_SCM_INVALSZ -10 */

    "Link skipped",                 /* ERR_SCM_ISLINK */
    "Invalid file",                 /* ERR_SCM_BADFILE */
    "Inconsistent filename",        /* ERR_SCM_INVALFN */
    "Not a directory",              /* ERR_SCM_NOTADIR */
    "Internal error",               /* ERR_SCM_INTERNAL */
    "X509 error",                   /* ERR_SCM_X509 */
    "Error reading cert",           /* ERR_SCM_BADCERT */
    "Missing subject field",        /* ERR_SCM_NOSUBJECT */
    "Missing issuer field",         /* ERR_SCM_NOISSUER */
    "Missing serial number",        /* ERR_SCM_NOSN -20 */

    "Bignum error",                 /* ERR_SCM_BIGNUMERR */
    "Missing start date",           /* ERR_SCM_NONB4 */
    "Missing end date",             /* ERR_SCM_NONAF */
    "Invalid date/time",            /* ERR_SCM_INVALDT */
    "Extension error",              /* ERR_SCM_BADEXT */
    "Invalid extension",            /* ERR_SCM_INVALEXT */
    "Profile violation",            /* ERR_SCM_XPROFILE */
    "Missing extension",            /* ERR_SCM_MISSEXT */
    "Not self-signed",              /* ERR_SCM_NOTSS */
    "Certificate validation error", /* ERR_SCM_NOTVALID -30 */

    "Certificate context error",    /* ERR_SCM_CERTCTX */
    "X509 stack error",             /* ERR_SCM_X509STACK */
    "Certificate store error",      /* ERR_SCM_STORECTX */
    "Cert store init error",        /* ERR_SCM_STOREINIT */
    "Missing AKI",                  /* ERR_SCM_NOAKI */
    "CRL error",                    /* ERR_SCM_CRL */
    "Error reading CRL",            /* ERR_SCM_BADCRL */
    "Not implemented",		    /* ERR_SCM_NOTIMPL */
    "Invalid AS number",	    /* ERR_SCM_INVALASID */
    "Invalid SKI",                  /* ERR_SCM_INVALSKI -40 */

    "Invalid IP address block",     /* ERR_SCM_INVALIPB */
    "Invalid IP address length",    /* ERR_SCM_INVALIPL */
    "Invalid version number",       /* ERR_SCM_INVALVER */
    "ASN.1 library error",          /* ERR_SCM_INVALASN */
    "Not an EE certificate",        /* ERR_SCM_NOTEE */
    "Invalid certificate flags",    /* ERR_SCM_BADFLAGS */
    "Bad certificate version",      /* ERR_SCM_BADVERS */
    "Extension must be critical",   /* ERR_SCM_NCEXT */
    "Must be CA cert",              /* ERR_SCM_NOTCA */
    "Pathlen invalid",              /* ERR_SCM_BADPATHLEN -50 */

    "Missing basic constraints",    /* ERR_SCM_NOBC */
    "Duplicate basic constraints",  /* ERR_SCM_DUPBC */
    "Cannot be CA cert",            /* ERR_SCM_ISCA */
    "Extension cannot be critical", /* ERR_SCM_CEXT */
    "Missing SKI",                  /* ERR_SCM_NOSKI */
    "Duplicate SKI",                /* ERR_SCM_DUPSKI */
    "authCertIssuer present",       /* ERR_SCM_ACI */
    "AuthCertSN present",           /* ERR_SCM_ACSN */
    "Duplicate AKI",                /* ERR_SCM_DUPAKI */
    "Missing key usage",            /* ERR_SCM_NOKUSAGE -60 */

    "Duplicate key usage",          /* ERR_SCM_DUPKUSAGE */
    "CRLDP in TA cert",             /* ERR_SCM_CRLDPTA */
    "Missing CRLDP",                /* ERR_SCM_NOCRLDP */
    "Duplicate CRLDP",              /* ERR_SCM_DUPCRLDP */
    "CRLDP with subfields",         /* ERR_SCM_CRLDPSF */
    "Cannot get CRLDP name field",  /* ERR_SCM_CRLDPNM */
    "CRLDP not a URI",              /* ERR_SCM_BADCRLDP */
    "Missing AIA",                  /* ERR_SCM_NOAIA */
    "Duplicate AIA",                /* ERR_SCM_DUPAIA */
    "AIA not a URI",                /* ERR_SCM_BADAIA -70 */

    "Missing SIA",                  /* ERR_SCM_NOSIA */
    "Duplicate SIA",                /* ERR_SCM_DUPSIA */
    "SIA not a URI",                /* ERR_SCM_BADSIA */
    "Missing policy ext",           /* ERR_SCM_NOPOLICY */
    "Duplicate policy ext",         /* ERR_SCM_DUPPOLICY */
    "Invalid policy qualifiers",    /* ERR_SCM_POLICYQ */
    "Invalid OID",                  /* ERR_SCM_BADOID */
    "Missing RFC3779 ext",          /* ERR_SCM_NOIPAS */
    "Duplicate IP resources",       /* ERR_SCM_DUPIP */
    "Duplicate AS# resources",      /* ERR_SCM_DUPAS -80 */

    "Invalid signature",            /* ERR_SCM_INVALSIG */
    "Hashable string size error",   /* ERR_SCM_HSSIZE */
    "Hashable string read error",   /* ERR_SCM_HSREAD */
    "Bad address family",           /* ERR_SCM_BADAF */
    "Bad digest algorithm",         /* ERR_SCM_BADDA */
    "Bad Content type",             /* ERR_SCM_BADCT */
    "Bad attributes",               /* ERR_SCM_BADATTR */
    "Invalid addr family",          /* ERR_SCM_INVALFAM */
    "No signature",                 /* ERR_SCM_NOSIG */
    
    "Duplicate signature",          /* ERR_SCM_DUPSIG -90 */
  } ;

char *err2string(int err)
{
  if ( err > 0 || err < ERR_SCM_MAXERR )
    return(NULL);
  return(errs[-err]);
}
