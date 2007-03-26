/*
  $Id$
*/

#ifndef _SQHL_H_
#define _SQHL_H_

extern int   findorcreatedir(scm *scmp, scmcon *conp, scmtab *mtab,
			     char *dirname, unsigned int *idp);
extern int   add_object(scm *scmp, scmcon *conp, char *outfile, char *outdir,
			char *outfull, int utrust);
extern int   delete_object(scm *scmp, scmcon *conp, char *outfile, char *outdir,
			   char *outfull);
extern int   infer_filetype(char *fname);
extern int   add_cert(scm *scmp, scmcon *conp, char *outfile, char *outfull,
		      unsigned int id, int utrust, int typ);
extern int   add_crl(scm *scmp, scmcon *conp, char *outfile, char *outfull,
		     unsigned int id, int utrust, int typ);
extern int   add_roa(scm *scmp, scmcon *conp, char *outfile, char *outfull,
		     unsigned int id, int utrust, int typ);
extern int   getflagsidscm(scmcon *conp, scmtab *tabp, scmkva *where,
			   unsigned int *pflags, unsigned int *lidp);

extern char *retrieve_tdir(scm *scmp, scmcon *conp, int *stap);

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
  Flags
*/

#define SCM_FLAG_CA             0x1    /* certificate authority */
#define SCM_FLAG_SS             0x2    /* self signed */
#define SCM_FLAG_TRUSTED        0x4    /* trusted */
#define SCM_FLAG_VALID          0x8    /* valid */

#define SCM_FLAG_NOTYET      0x1000    /* not yet valid */
#define SCM_FLAG_EXPIRED     0x2000    /* expired */
#define SCM_FLAG_REVOKED     0x4000    /* CRL nuked it */
#define SCM_FLAG_REMOVED     0x8000    /* rsync removed it */
#define SCM_FLAG_PINV       0x10000    /* parent not valid */

#endif
