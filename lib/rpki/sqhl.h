/*
 * $Id$ 
 */


#ifndef _SQHL_H_
#define _SQHL_H_

#include <stdio.h>
#include "db_constants.h"

#include "rpki-object/certificate.h"

/*
 * Object types 
 */

#define OT_UNKNOWN      0
#define OT_CER          1       /* DER encoded certificate */
#define OT_CRL          2       /* DER encoded CRL */
#define OT_ROA          3       /* DER encoded ROA */
#define OT_MAN          4       /* manifests are only DER for now */
#define OT_RTA          5       /* DER encoded RTA */
#define OT_ETA          6
#define OT_MAXBASIC     6

#define OT_PEM_OFFSET   128

#define OT_CER_PEM      (OT_CER+OT_PEM_OFFSET)  /* PEM encoded certificate */
#define OT_CRL_PEM      (OT_CRL+OT_PEM_OFFSET)  /* PEM encoded CRL */
#define OT_ROA_PEM      (OT_ROA+OT_PEM_OFFSET)  /* PEM encoded ROA */
#define OT_MAN_PEM      (OT_MAN+OT_PEM_OFFSET)  /* PEM encoded manifest */

/*
 * Certificate types 
 */

#define CA_CERT       1
#define EE_CERT       2
#define TA_CERT       3
#define UN_CERT       4


/*
 * certain fields need to have "rsync URIs". The only test we perform for now
 * is to verify that the field starts with this text 
 */
#define RSYNC_PREFIX "rsync://"
#define RSYNC_PREFIX_LEN (sizeof(RSYNC_PREFIX) - 1)

/*
 * Data types 
 */

typedef int (
    *crlfunc) (
    scm * scmp,
    scmcon * conp,
    char *issuer,
    char *aki,
    uint8_t *sn);

typedef struct _crlinfo {
    scm *scmp;
    scmcon *conp;
    scmtab *tabp;
    crlfunc cfunc;
} crlinfo;

struct goodoid {
    int lth;
    unsigned char *oid;
};

/*
 * Prototypes 
 */

extern int findorcreatedir(
    scm * scmp,
    scmcon * conp,
    char *dirname,
    unsigned int *idp);
extern int add_object(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    int utrust);
extern int delete_object(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int dir_id);
extern int infer_filetype(
    char *fname);
extern int add_cert(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ,
    unsigned int *cert_id,
    int constraining);
extern int add_crl(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);
extern int add_roa(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);
extern int add_manifest(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);
extern int add_rta(
    scm * scmp,
    scmcon * conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);
extern int iterate_crl(
    scm * scmp,
    scmcon * conp,
    crlfunc cfunc);
extern int model_cfunc(
    scm * scmp,
    scmcon * conp,
    char *issuer,
    char *aki,
    uint8_t *sn);
extern int deletebylid(
    scmcon * conp,
    scmtab * tabp,
    unsigned int lid);
extern int certificate_validity(
    scm * scmp,
    scmcon * conp);
extern int ranlast(
    scm * scmp,
    scmcon * conp,
    char *whichcli);
extern int addStateToFlags(
    unsigned int *flags,
    int isValid,
    char *filename,
    char *fullpath,
    scm * scmp,
    scmcon * conp);
extern int set_cert_flag(
    scmcon * conp,
    unsigned int id,
    unsigned int flags);
extern struct cert_answers *find_cert_by_aKI(
    char *ski,
    char *aki,
    scm * sscmp,
    scmcon * conp);
extern struct cert_answers *find_parent_cert(
    char *,
    char *,
    scmcon *);
extern struct cert_answers *find_trust_anchors(
    scm * sscmp,
    scmcon * conp);
extern struct Extension *get_extension(
    struct Certificate *certp,
    char *idp,
    int *count);
extern int read_SKI_blocks(
    scm * scmp,
    scmcon * conp,
    char *skiblockfile);
extern char *retrieve_tdir(
    scm * scmp,
    scmcon * conp,
    int *stap);

// return code is really an X509 *
extern void *roa_parent(
    scm * scmp,
    scmcon * conp,
    char *ski,
    char **fn,
    int *stap);

extern void startSyslog(
    char *appName);
extern void stopSyslog(
    void);
extern void setallowexpired(
    int v);

extern void sqcleanup(
    void);

#endif
