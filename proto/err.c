#include <stdio.h>

#include "err.h"

static char *errs[-(ERR_SCM_MAXERR) + 1] =
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
    "Bad filename or file not found", /* ERR_SCM_BADFILE */
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
    "Invalid version number",       /* ERR_SCM_BADVERSION */
    "ASN.1 library error",          /* ERR_SCM_INVALASN */
    "Not an EE certificate",        /* ERR_SCM_NOTEE */
    "Invalid certificate flags",    /* ERR_SCM_BADFLAGS */
    "Bad certificate version",      /* ERR_SCM_BADCERTVERS */
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
    "Unsigned attributes",          /* ERR_SCM_UNSIGATTR */
    "Invalid IP family",            /* ERR_SCM_INVALFAM */
    "No signature",                 /* ERR_SCM_NOSIG */
    "Duplicate signature",          /* ERR_SCM_DUPSIG -90 */

    "Error creating hash",          /* ERR_SCM_BADMKHASH */
    "Error in FileAndHash",         /* ERR_SCM_FAH */
    "Wrong number of certificates", /* ERR_SCM_BADNUMCERTS */
    "Invalid dates",                /* ERR_SCM_BADDATES */
    "Differing algorithms in cert", /* ERR_SCM_BADALG */
    "Basic constraints in EE cert", /* ERR_SCM_BCPRES */
    "Error in SignerInfos",         /* ERR_SCM_BADSIGINFO */
    "Error making para-certificate", /* ERR_SCM_BADPARACERT */
    "Invalid IP numbers",           /* ERR_SCM_BADIPRANGE */
    "Invalid constraints entry",    /* ERR_SCM_BADSKIBLOCK -100*/

    "Conflicting constraint entry", /* ERR_SCM_USECONFLICT */
    "Can't open constraints file",  /* ERR_SCM_NOSKIFILE */
    "Can't find RP certificate",    /* ERR_SCM_NORPCERT */
    "Defective constraints file",   /* ERR_SCM_BADSKIFILE */
    "Error signing para-cert",      /* ERR_SCM_SIGNINGERR */
    "Invalid ROA",                  /* ERR_SCM_INVALROA */
    "Invalid RTA",                  /* ERR_SCM_INVALRTA */
    "Invalid manifest",             /* ERR_SCM_INVALMAN */
    "Error writing EE cert",        /* ERR_SCM_WRITE_EE */
    "Key too small",                /* ERR_SCM_SMALLKEY -110 */

    "Invalid indefinite ASN.1 length",  /* ERR_SCM_ASN1_LTH */
    "Certificate expired",          /* ERR_SCM_EXPIRED */
    "Invalid subject name",         /* ERR_SCM_BADSUBJECT */
    "Invalid issuer name",          /* ERR_SCM_BADISSUER */
    "Invalid AKI",                  /* ERR_SCM_INVALAKI */
    "No rsync URI in CRLDP",        /* ERR_SCM_CRLDPNMRS */
    "Bad serial number",	    /* ERR_SCM_BADSERNUM */
    "Should not have CRL",          /* ERR_SCM_HASCRL */
    "Error starting Cryptlib",      /* ERR_SCM_CRYPTLIB */
    "Bad hash algorithm",           /* ERR_SCM_BADHASHALG -120 */

    "Bad number of digest algorithms", /* ERR_SCM_BADDIGALGS */
    "Bad number of signer infos",   /* ERR_SCM_NUMSIGINFO */
    "Invalid signer infos version", /* ERR_SCM_SIGINFOVER */
    "Invalid signer info sid",      /* ERR_SCM_SIGINFOSID */
    "Invalid signer info time",     /* ERR_SCM_SIGINFOTIM */
    "Invalid CMS version",          /* ERR_SCM_BADCMSVER */
    "Invalid message digest",       /* ERR_SCM_MSGDIGEST */
    "Invalid signed attributes",    /* ERR_SCM_BADSIGATTRS */
    "Invalid content type",         /* ERR_SCM_BADCONTTYPE */
    "Invalid binary signing time",  /* ERR_SCM_BINSIGTIME -130 */

    "Invalid signature algorithm",  /* ERR_SCM_BADSIGALG */
    "Invalid ROA version",          /* ERR_SCM_BADROAVER */
    "Invalid manifest version",     /* ERR_SCM_BADMANVER */
    "Invalid AS numbers",           /* ERR_SCM_BADASRANGE */
    "AS number outside range",      /* ERR_SCM_BADASNUM */
    "No IP addresses",              /* ERR_SCM_NOIPADDR */
    "No AS number",                 /* ERR_SCM_NOASNUM */
    "ROA IP addresses not in EE",   /* ERR_SCM_ROAIPMISMATCH */
    "IP addresses overlap",         /* ERR_SCM_IPTOUCH */

    "Bad hash in manifest",         /* ERR_SCM_BADMFTHASH -140 */
    "Invalid digest in CMS",        /* ERR_SCM_BADDIGEST */
    "Wrong manifest hash in DB",    /* ERR_SCM_MADMFTDBHASH */
    "Missing CRL version",          /* ERR_SCM_NOCRLVER */
    "Wrong CRL version",            /* ERR_SCM_BADCRLVER */
    "CRL Entry Extension present",  /* ERR_SCM_CRLENTRYEXT */
    "Invalid filename in manifest", /* ERR_SCM_BADMFTFILENAME */
    "Invalid revocation date",      /* ERR_SCM_BADREVDATE */
    "Invalid revoked serial number", /* ERR_SCM_BADREVSNUM */ 
    "No CRL number extension",      /* ERR_SCM_NOCRLNUM */
    "Invalid manifest number",      /* ERR_SCM_BADMFTNUM */
    "Duplicate file in manifest"    /* ERR_SCM_DUPMFTFNAME */
  } ;

char *err2string(int err)
{
  if ( err > 0 || err < ERR_SCM_MAXERR )
    return(NULL);
  return(errs[-err]);
}
