#ifndef _SQHL_H_
#define _SQHL_H_

#include <stdio.h>
#include "db_constants.h"
#include "scm.h"
#include "scmf.h"

#include "rpki-object/certificate.h"

/*
 * Object types
 */

#define OT_UNKNOWN      0
#define OT_CER          1       /* DER encoded certificate */
#define OT_CRL          2       /* DER encoded CRL */
#define OT_ROA          3       /* DER encoded ROA */
#define OT_MAN          4       /* manifests are only DER for now */
#define OT_GBR          5
#define OT_MAXBASIC     5

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
    *crlfunc)(
    scm *scmp,
    scmcon *conp,
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

/*
 * Find a directory in the directory table, or create it if it is not found.
 * Return the id in idp. The function returns 0 on success and a negative
 * error code on failure.
 *
 * It is assumed that the existence of the putative directory has already been
 * verified.
 */
extern int findorcreatedir(
    scm *scmp,
    scmcon *conp,
    char *dirname,
    unsigned int *idp);

/*
 * Add the indicated object to the DB. If "trusted" is set then verify that
 * the object is self-signed. Note that this add operation may result in the
 * directory also being added.
 *
 * Symlinks and files that are not regular files are not processed.
 *
 * This function returns 0 on success and a negative error code on failure.
 */
extern int add_object(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    int utrust);

/*
 * Delete an object. First find the object's directory. If it is not found
 * then we are done. If it is found, then find the corresponding (filename,
 * dir_id) combination in the appropriate table and issue the delete SQL call.
 */
extern int delete_object(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int dir_id);

/**
 * @brief
 *     Infer the object type based on which file extensions are present.
 *
 * @param[in] fname
 *     File pathname.  This MUST NOT be NULL.
 *
 * @return
 *     An object type code depending on the filename suffix:
 *       - `.cer`: ::OT_CER
 *       - `.crl`: ::OT_CRL
 *       - `.roa`: ::OT_ROA
 *       - `.man`, `.mft`, `.mnf`: ::OT_MAN
 *       - `.gbr`: ::OT_GBR
 *       - `.cer.pem`: ::OT_CER_PEM
 *       - `.crl.pem`: ::OT_CRL_PEM
 *       - `.roa.pem`: ::OT_ROA_PEM
 *       - `.man.pem`, `.mft.pem`, `.mnf.pem`: ::OT_MAN_PEM
 *       - all others: ::OT_UNKNOWN.
 */
extern int infer_filetype(
    const char *fname);

/*
 * Add a certificate to the DB. If utrust is set, check that it is self-signed
 * first. Validate the cert and add it.
 *
 * This function returns 0 on success and a negative error code on failure.
 */
extern int add_cert(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ,
    unsigned int *cert_id,
    int constraining);

/*
 * Add a CRL to the DB.  This function returns 0 on success and a negative
 * error code on failure.
 */
extern int add_crl(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);

extern int add_roa(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);

/*
 * Add a manifest to the database
 */
extern int add_manifest(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);

/*
    Add a ghostbusters record to the database
*/
extern int add_ghostbusters(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);

extern int add_rta(
    scm *scmp,
    scmcon *conp,
    char *outfile,
    char *outdir,
    char *outfull,
    unsigned int id,
    int utrust,
    int typ);

/*
 * Iterate through all CRLs in the DB, recursively processing each CRL to
 * obtain its (issuer, snlist) information. For each SN in the list, call a
 * specified function (persumably a certificate revocation function) on that
 * (issuer, sn) combination.
 *
 * On success this function returns 0.  On failure it returns a negative error
 * code.
 */
extern int iterate_crl(
    scm *scmp,
    scmcon *conp,
    crlfunc cfunc);

/*
 * This is the model callback function for iterate_crl. For each (issuer, sn)
 * pair with sn != 0 it attempts to find a certificate with those values in
 * the DB. If found, it then attempts to delete the certificate and all its
 * children. Note that in deleting an EE certificate, some of its children may
 * be ROAs, so this table has to be searched as well.
 *
 * This function returns 1 if it deleted something, 0 if it deleted nothing
 * and a negative error code on failure.
 */
extern int revoke_cert_by_serial(
    scm *scmp,
    scmcon *conp,
    char *issuer,
    char *aki,
    uint8_t *sn);

/*
 * Delete a particular local_id from a table.
 */
extern int deletebylid(
    scmcon *conp,
    scmtab *tabp,
    unsigned int lid);

/*
 * This function sweeps through all certificates. If it finds any that are
 * valid but marked as NOTYET, it clears the NOTYET bit and sets the VALID
 * bit. If it finds any where the start validity date (valfrom) is in the
 * future, it marks them as NOTYET. If it finds any where the end validity
 * date (valto) is in the past, it deletes them.
 */
extern int certificate_validity(
    scm *scmp,
    scmcon *conp);

/*
 * Update the metadata table to indicate when a particular client ran last.
 */
extern int ranlast(
    scm *scmp,
    scmcon *conp,
    char *whichcli);

extern int addStateToFlags(
    unsigned int *flags,
    int isValid,
    char *filename,
    char *fullpath,
    scm *scmp,
    scmcon *conp);

extern int set_cert_flag(
    scmcon *conp,
    unsigned int id,
    unsigned int flags);

extern struct cert_answers *find_cert_by_aKI(
    char *ski,
    char *aki,
    scm *sscmp,
    scmcon *conp);

/*
 * Get the parent certificate by using the issuer and the aki of "x" to look
 * it up in the db. If "x" has already been broken down in "cf" just use the
 * issuer/aki from there, otherwise look it up from "x". The db lookup will
 * return the filename and directory name of the parent cert, as well as its
 * flags. Set those flags into "pflags"
 */
extern struct cert_answers *find_parent_cert(
    char *,
    char *,
    scmcon *);

extern struct cert_answers *find_trust_anchors(
    scm *sscmp,
    scmcon *conp);

extern struct Extension *get_extension(
    struct Certificate *certp,
    char *idp,
    int *count);

extern int read_SKI_blocks(
    scm *scmp,
    scmcon *conp,
    char *skiblockfile);

extern char *retrieve_tdir(
    scm *scmp,
    scmcon *conp,
    int *stap);

/*
 * Given the SKI of a ROA, this function returns the X509 * structure for the
 * corresponding EE certificate (or NULL on error).
 */
// return code is really an X509 *
extern void *roa_parent(
    scm *scmp,
    scmcon *conp,
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
