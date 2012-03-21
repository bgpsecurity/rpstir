#ifndef _MYERR_H_
#define _MYERR_H_

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
#define ERR_SCM_NOTEE       -45         /* not an EE cert */
#define ERR_SCM_BADFLAGS    -46         /* cert flags don't match cert type */
#define ERR_SCM_BADCERTVERS -47         /* bad certificate version */
#define ERR_SCM_NCEXT       -48         /* extension must be critical */
#define ERR_SCM_NOTCA       -49         /* cA boolean should have been set */
#define ERR_SCM_BADPATHLEN  -50         /* pathlen should not have been present */
#define ERR_SCM_NOBC        -51         /* missing basic constraints */
#define ERR_SCM_DUPBC       -52         /* duplicate basic constraints */
#define ERR_SCM_ISCA        -53         /* cA boolean set in EE cert */
#define ERR_SCM_CEXT        -54         /* non-critical extension marked as crit */
#define ERR_SCM_NOSKI       -55         /* SKI extension missing */
#define ERR_SCM_DUPSKI      -56         /* duplicate SKI extension */
#define ERR_SCM_ACI         -57         /* authCertIssuer present, shouldn't be */
#define ERR_SCM_ACSN        -58         /* authCertSN present, shouldn't be */
#define ERR_SCM_DUPAKI      -59         /* duplicate AKI */
#define ERR_SCM_NOKUSAGE    -60         /* missing key usage ext */
#define ERR_SCM_DUPKUSAGE   -61         /* duplicate key usage */
#define ERR_SCM_CRLDPTA     -62         /* CRLDP found in TA cert */
#define ERR_SCM_NOCRLDP     -63         /* missing CRLDP */
#define ERR_SCM_DUPCRLDP    -64         /* duplicate CRLDP */
#define ERR_SCM_CRLDPSF     -65         /* CRLDP has subfields, shouldn't */
#define ERR_SCM_CRLDPNM     -66         /* cannot get name component of CRLDP */
#define ERR_SCM_BADCRLDP    -67         /* CLRDP not a URI */
#define ERR_SCM_NOAIA       -68         /* missing AIA */
#define ERR_SCM_DUPAIA      -69         /* duplicate AIA */
#define ERR_SCM_BADAIA      -70         /* AIA not a URI */
#define ERR_SCM_NOSIA       -71         /* missing SIA */
#define ERR_SCM_DUPSIA      -72         /* duplicate SIA */
#define ERR_SCM_BADSIA      -73         /* SIA not a URI */
#define ERR_SCM_NOPOLICY    -74         /* missing policy extension */
#define ERR_SCM_DUPPOLICY   -75         /* duplicate policy extension */
#define ERR_SCM_POLICYQ     -76         /* policy qualifiers shouldn't be present */
#define ERR_SCM_BADOID      -77         /* invalid/unexpected OID */
#define ERR_SCM_NOIPAS      -78         /* missing IP or AS# resources */
#define ERR_SCM_DUPIP       -79         /* duplicate IP resource extension */
#define ERR_SCM_DUPAS       -80         /* duplicate AS2 resource extension */
#define ERR_SCM_INVALSIG    -81         /* invalid signature */
#define ERR_SCM_HSSIZE      -82         /* error sizing hashable string */
#define ERR_SCM_HSREAD      -83         /* error reading hashable string */
#define ERR_SCM_BADAF       -84         /* bad address family */
#define ERR_SCM_BADDA       -85         /* bad digest algorithm */
#define ERR_SCM_BADCT       -86         /* bad content type */
#define ERR_SCM_UNSIGATTR   -87         /* unsigned attributes */
#define ERR_SCM_INVALFAM    -88         /* invalid IP family */
#define ERR_SCM_NOSIG       -89         /* no signature */
#define ERR_SCM_DUPSIG      -90         /* duplicate signature */
#define ERR_SCM_BADMKHASH   -91         /* error making hash */
#define ERR_SCM_BADFAH      -92         /* error reading FileAndHash */
#define ERR_SCM_BADNUMCERTS -93         /* wrong number of certificates */
#define ERR_SCM_BADDATES    -94         /* invalid dates */
#define ERR_SCM_BADALG      -95         /* differing algorithms in certificate */
#define ERR_SCM_BCPRES      -96         /* basic constraints present in EE cert */
#define ERR_SCM_BADSIGINFO  -97         /* error in SignerInfo */
#define ERR_SCM_BADPARACERT -98         /* error making paracert */
#define ERR_SCM_BADIPRANGE  -99         /* invalid IP numbers */
#define ERR_SCM_BADSKIBLOCK -100        /* invalid constraints entry */
#define ERR_SCM_USECONFLICT -101        /* conflicting usages */
#define ERR_SCM_NOSKIFILE   -102        /* can't open constraints file */
#define ERR_SCM_NORPCERT    -103        /* Can't find RP certificate */
#define ERR_SCM_BADSKIFILE  -104        /* defective constraints file */
#define ERR_SCM_SIGNINGERR  -105        /* error signing para-cert */
#define ERR_SCM_INVALROA    -106        /* invalid ROA */
#define ERR_SCM_INVALRTA    -107        /* invalid RTA */
#define ERR_SCM_INVALMAN    -108        /* invalid manifest */
#define ERR_SCM_WRITE_EE    -109        /* error writing EE certificate */
#define ERR_SCM_SMALLKEY    -110        /* key too small */
#define ERR_SCM_ASN1_LTH    -111        /* invalid ASN.1 length */
#define ERR_SCM_EXPIRED     -112        /* certificate expired */
#define ERR_SCM_BADSUBJECT  -113        /* invalid subject name */
#define ERR_SCM_BADISSUER   -114        /* invalid issuer name */
#define ERR_SCM_INVALAKI    -115        /* invalid AKI */
#define ERR_SCM_CRLDPNMRS   -116        /* no rsync URI in CRLDP */
#define ERR_SCM_BADSERNUM   -117        /* bad serial number */
#define ERR_SCM_HASCRL      -118        /* should not have CRL */
#define ERR_SCM_CRYPTLIB    -119        /* error starting Cryptlib */
#define ERR_SCM_BADHASHALG  -120        /* bad hash algorithm */
#define ERR_SCM_BADNUMDALG  -121        /* bad number of digest algorithms */
#define ERR_SCM_NUMSIGINFO  -122        /* bad number of signer infos */
#define ERR_SCM_SIGINFOVER  -123        /* invalid signer infos version */
#define ERR_SCM_SIGINFOSID  -124        /* invalid signer info sid */
#define ERR_SCM_SIGINFOTIM  -125        /* invalid signer info time */
#define ERR_SCM_BADCMSVER   -126        /* invalid CMS version */
#define ERR_SCM_BADMSGDIGEST -127       /* invalid message digest */
#define ERR_SCM_BADSIGATTRS -128        /* invalid signed attributes */
#define ERR_SCM_BADCONTTYPE -129        /* invalid content type */
#define ERR_SCM_BINSIGTIME  -130        /* invalid binary signing time */
#define ERR_SCM_BADSIGALG   -131        /* invalid signature algorithm */
#define ERR_SCM_BADROAVER   -132        /* invalid ROA version */
#define ERR_SCM_BADMANVER   -133        /* invalid manifest version */
#define ERR_SCM_BADASRANGE  -134        /* invalid AS numbers */
#define ERR_SCM_BADASNUM    -135        /* AS number outside range */ 
#define ERR_SCM_NOIPADDR    -136        /* no IP addresses */
#define ERR_SCM_NOASNUM     -137        /* no AS numbers */
#define ERR_SCM_ROAIPMISMATCH -138      /* ROA IP addressess aren't covered by EE's IPs */
#define ERR_SCM_IPTOUCH     -139        /* IP addresses overlap */
#define ERR_SCM_BADMFTHASH  -140        /* bad manifest hash */
#define ERR_SCM_BADDIGEST   -141        /* invalid digest */
#define ERR_SCM_BADMFTDBHASH -142       /* wrong manifest hash in DB */
#define ERR_SCM_NOCRLVER    -143        /* missing CRL version */
#define ERR_SCM_BADCRLVER   -144        /* wrong CRL version */
#define ERR_SCM_CRLENTRYEXT -145        /* CRL Entry Extension present */
#define ERR_SCM_BADMFTFILENAME -146     /* invalid filename in a manifest */
#define ERR_SCM_BADREVDATE  -147        /* Invalid revocation date */
#define ERR_SCM_BADREVSNUM  -148        /* Invalid revoked serial number */
#define ERR_SCM_NOCRLNUM    -149        /* No CRL number extension */
#define ERR_SCM_BADMFTNUM   -150        /* invalid manifest number */
#define ERR_SCM_MFTDUPFILE  -151        /* duplicate file in manifest */
#define ERR_SCM_EKU         -152        /* EKU present when it shouldn't be */
#define ERR_SCM_UNSUPPUBKEY -153        /* Unsupported Public Key Info */
#define ERR_SCM_BADASRDI    -154        /* Routing Domain Identifier(s) present */
#define ERR_SCM_MAXERR      -154

/* macro that prints an error string and call return if a condition is true */
#define checkErr(test, printArgs...) \
  if (test) { \
     (void) fprintf (stderr, printArgs); \
     return -1; \
  }

extern char *err2string(int errr);

#endif
