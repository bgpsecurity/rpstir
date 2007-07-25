/*
  $Id$
*/

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Verison 1.0
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

#ifndef _SQHL_H_
#define _SQHL_H_

/*
  Object types
*/

#define OT_UNKNOWN      0
#define OT_CER          1	/* DER encoded certificate */
#define OT_CRL          2	/* DER encoded CRL */
#define OT_ROA          3	/* DER encoded ROA */
#define OT_MAXBASIC     3

#define OT_PEM_OFFSET   128

#define OT_CER_PEM      (OT_CER+OT_PEM_OFFSET) /* PEM encoded certificate */
#define OT_CRL_PEM      (OT_CRL+OT_PEM_OFFSET) /* PEM encoded CRL */
#define OT_ROA_PEM      (OT_ROA+OT_PEM_OFFSET) /* PEM encoded ROA */

/*
  Certificate types
*/

#define CA_CERT       1
#define EE_CERT       2
#define TA_CERT       3
#define UN_CERT       4

/*
  Flags
*/

#define SCM_FLAG_CA           0x1    /* certificate authority */
#define SCM_FLAG_TRUSTED      0x2    /* trusted */
#define SCM_FLAG_VALID        0x4    /* valid */
#define SCM_FLAG_UNKNOWN      0x8    /* unknown because crl stale */
#define SCM_FLAG_NOTYET      0x10    /* not yet valid */
#define SCM_FLAG_NOCHAIN     0x20    /* missing pieces on chain to anchor */

/*
  Data types
*/

typedef int (*crlfunc)(scm *scmp, scmcon *conp, char *issuer, char *aki,
		       unsigned long long sn);

typedef struct _crlinfo
{
  scm     *scmp;
  scmcon  *conp;
  scmtab  *tabp;
  crlfunc  cfunc;
} crlinfo;

/*
  Prototypes
*/

extern int   findorcreatedir(scm *scmp, scmcon *conp, char *dirname,
			     unsigned int *idp);
extern int   add_object(scm *scmp, scmcon *conp, char *outfile, char *outdir,
			char *outfull, int utrust);
extern int   delete_object(scm *scmp, scmcon *conp, char *outfile,
			   char *outdir, char *outfull);
extern int   infer_filetype(char *fname);
extern int   add_cert(scm *scmp, scmcon *conp, char *outfile, char *outfull,
		      unsigned int id, int utrust, int typ,
		      unsigned int *cert_id);
extern int   add_crl(scm *scmp, scmcon *conp, char *outfile, char *outfull,
		     unsigned int id, int utrust, int typ);
extern int   add_roa(scm *scmp, scmcon *conp, char *outfile, char *outfull,
		     unsigned int id, int utrust, int typ);
extern int   getflagsidscm(scmcon *conp, scmtab *tabp, scmkva *where,
			   unsigned int *pflags, unsigned int *lidp);
extern int   iterate_crl(scm *scmp, scmcon *conp, crlfunc cfunc);
extern int   model_cfunc(scm *scmp, scmcon *conp, char *issuer, char *aki,
			 unsigned long long sn);
extern int   deletebylid(scmcon *conp, scmtab *tabp, unsigned int lid);
extern int   certificate_validity(scm *scmp, scmcon *conp);
extern int   ranlast(scm *scmp, scmcon *conp, char *whichcli);

extern char *retrieve_tdir(scm *scmp, scmcon *conp, int *stap);

// return code is really an X509 *
extern void *roa_parent(scm *scmp, scmcon *conp, char *ski, char **fn,
			int *stap);

extern void  startSyslog(char *appName);
extern void  stopSyslog(void);

#endif
