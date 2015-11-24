#ifndef LIB_RPKI_SQHL_H
#define LIB_RPKI_SQHL_H

#include <stdio.h>
#include "db_constants.h"
#include "scm.h"
#include "scmf.h"

#include "rpki-object/certificate.h"

/**
 * @brief
 *     Object types
 */
typedef enum {
    OT_UNKNOWN = 0,

    /** @brief DER encoded certificate */
    OT_CER,
    /** @brief DER encoded CRL */
    OT_CRL,
    /** @brief DER encoded ROA */
    OT_ROA,
    /** @brief manifests are only DER for now */
    OT_MAN,
    OT_GBR,

    OT_MAXBASIC_PLUS_ONE,
    /** @brief highest-valued DER type */
    OT_MAXBASIC = OT_MAXBASIC_PLUS_ONE - 1,
    /**
     * @brief
     *     difference between DER and PEM equivalent types
     *
     * The types that are less than ::OT_PEM_OFFSET are DER types and
     * the types that are greater than or equal to ::OT_PEM_OFFSET are
     * PEM types.  The PEM types are exactly ::OT_PEM_OFFSET greater
     * than their corresponding DER types (e.g., `OT_CRL_PEM == OT_CRL
     * + OT_PEM_OFFSET`).
     */
    OT_PEM_OFFSET,

    /** @brief PEM encoded certificate */
    OT_CER_PEM,
    /** @brief PEM encoded CRL */
    OT_CRL_PEM,
    /** @brief PEM encoded ROA */
    OT_ROA_PEM,
    /** @brief PEM encoded manifest */
    OT_MAN_PEM,

} object_type;

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

/**
 * @brief
 *     Delete an object.
 *
 * First find the object's directory.  If it is not found then we are
 * done.  If it is found, then find the corresponding (filename,
 * dir_id) combination in the appropriate table and issue the delete
 * SQL call.
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
 *     A value from ::object_type depending on the filename suffix:
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

/**
 * @brief
 *     Iterate through all CRLs in the DB, recursively processing each
 *     CRL to obtain its (issuer, snlist) information.
 *
 * For each SN in the list, call a specified function (persumably a
 * certificate revocation function) on that (issuer, sn) combination.
 *
 * @return
 *     On success this function returns 0.  On failure it returns a
 *     negative error code.
 */
extern int iterate_crl(
    scm *scmp,
    scmcon *conp,
    crlfunc cfunc);

/**
 * @brief
 *     model callback function for iterate_crl()
 *
 * For each (issuer, sn) pair with sn != 0 it attempts to find a
 * certificate with those values in the DB.  If found, it then
 * attempts to delete the certificate and all its children.  Note that
 * in deleting an EE certificate, some of its children may be ROAs, so
 * this table has to be searched as well.
 *
 * @return
 *     1 if it deleted something, 0 if it deleted nothing and a
 *     negative error code on failure.
 */
extern int revoke_cert_by_serial(
    scm *scmp,
    scmcon *conp,
    char *issuer,
    char *aki,
    uint8_t *sn);

/**
 * @brief
 *     Delete a particular local_id from a table.
 */
extern int deletebylid(
    scmcon *conp,
    scmtab *tabp,
    unsigned int lid);

/**
 * @brief
 *     sweep through certificates, checking validity
 *
 * If this function finds any certificates that are valid but marked
 * as NOTYET, it clears the NOTYET bit and sets the VALID bit.  If it
 * finds any where the start validity date (valfrom) is in the future,
 * it marks them as NOTYET.  If it finds any where the end validity
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

/**
 * @warning
 *     The following functions all use the same static memory and must
 *     not be called concurrently (including multiple concurrent
 *     invocations of the same function):
 *       * find_parent_cert()
 *       * find_cert_by_aKI()
 *       * find_trust_anchors()
 *     Any call to any of these functions overwrites the results
 *     returned from a previous call to any of these functions.
 */
extern struct cert_answers *find_cert_by_aKI(
    char *ski,
    char *aki,
    scm *sscmp,
    scmcon *conp);

/**
 * @brief
 *     Get parent certificates by looking up the cert's issuer and AKI
 *     in the db.
 *
 * @warning
 *     The following functions all use the same static memory and must
 *     not be called concurrently (including multiple concurrent
 *     invocations of the same function):
 *       * find_parent_cert()
 *       * find_cert_by_aKI()
 *       * find_trust_anchors()
 *     Any call to any of these functions overwrites the results
 *     returned from a previous call to any of these functions.
 *
 * @param[in] ski
 *     The subject key identifier (SKI) of each parent certificate
 *     (the child's AKI).  This MUST NOT be NULL.
 * @param[in] subject
 *     The subject of each parent certificate (the child's issuer).
 *     This may be NULL, in which case only @p ski is used to perform
 *     the search.
 * @param[in] conp
 *     Database connection.  This MUST NOT be NULL.
 * @return
 *     The certificates that match the given @p ski and @p subject.
 */
extern struct cert_answers *find_parent_cert(
    char *ski,
    char *subject,
    scmcon *conp);

/**
 * @warning
 *     The following functions all use the same static memory and must
 *     not be called concurrently (including multiple concurrent
 *     invocations of the same function):
 *       * find_parent_cert()
 *       * find_cert_by_aKI()
 *       * find_trust_anchors()
 *     Any call to any of these functions overwrites the results
 *     returned from a previous call to any of these functions.
 */
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

/**
 * @brief
 *     returns the X509 * structure for a ROA's corresponding EE
 *     certificate
 *
 * @param[in] ski
 *     SKI of the ROA
 * @param[out] fn
 *     If non-NULL, the full pathname of the parent certificate will
 *     be written to the buffer at this location.  The buffer must
 *     have size at least @c PATH_MAX.  This may be NULL.
 * @return
 *     an X509 * on success, NULL on error
 */
extern void *roa_parent(
    scm *scmp,
    scmcon *conp,
    char *ski,
    char *fn,
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
