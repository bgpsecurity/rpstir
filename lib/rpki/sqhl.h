#ifndef LIB_RPKI_SQHL_H
#define LIB_RPKI_SQHL_H

#include "err.h"

#include "db_constants.h"
#include "scm.h"
#include "scmf.h"
#include <openssl/x509v3.h>
#include <stdio.h>

#include "rpki-object/certificate.h"
#include "configlib/configlib.h"

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

#define CA_CERT 1
#define EE_CERT 2
#define TA_CERT 3
#define UN_CERT 4

/*
 * certain fields need to have "rsync URIs". The only test we perform for now
 * is to verify that the field starts with this text
 */
#define RSYNC_PREFIX "rsync://"
#define RSYNC_PREFIX_LEN (sizeof(RSYNC_PREFIX) - 1)

/*
 * Data types
 */

typedef err_code crlfunc(scm *scmp, scmcon *conp, char *issuer, char *aki,
                         uint8_t *sn);

typedef struct _crlinfo {
  scm *scmp;
  scmcon *conp;
  scmtab *tabp;
  crlfunc *cfunc;
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
err_code findorcreatedir(scm *scmp, scmcon *conp, const char *dirname,
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
err_code add_object(scm *scmp, scmcon *conp, char *outfile, char *outdir,
                    char *outfull, int utrust);

/**
 * @brief
 *     Delete an object.
 *
 * First find the object's directory.  If it is not found then we are
 * done.  If it is found, then find the corresponding (filename,
 * dir_id) combination in the appropriate table and issue the delete
 * SQL call.
 */
err_code delete_object(scm *scmp, scmcon *conp, char *outfile, char *outdir,
                       char *outfull, unsigned int dir_id);

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
object_type infer_filetype(const char *fname);

/*
 * Add a certificate to the DB. If utrust is set, check that it is self-signed
 * first. Validate the cert and add it.
 *
 * This function returns 0 on success and a negative error code on failure.
 */
err_code add_cert(scm *scmp, scmcon *conp, char *outfile, char *outfull,
                  unsigned int id, int utrust, object_type typ,
                  unsigned int *cert_id);

/*
 * Add a CRL to the DB.  This function returns 0 on success and a negative
 * error code on failure.
 */
err_code add_crl(scm *scmp, scmcon *conp, char *outfile, char *outfull,
                 unsigned int id, int utrust, object_type typ);

err_code add_roa(scm *scmp, scmcon *conp, char *outfile, char *outdir,
                 char *outfull, unsigned int id, int utrust, object_type typ);

/*
 * Add a manifest to the database
 */
err_code add_manifest(scm *scmp, scmcon *conp, char *outfile, char *outdir,
                      char *outfull, unsigned int id, int utrust,
                      object_type typ);

/*
    Add a ghostbusters record to the database
*/
err_code add_ghostbusters(scm *scmp, scmcon *conp, char *outfile, char *outdir,
                          char *outfull, unsigned int id, int utrust,
                          object_type typ);

extern int add_rta(scm *scmp, scmcon *conp, char *outfile, char *outdir,
                   char *outfull, unsigned int id, int utrust, int typ);

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
err_code iterate_crl(scm *scmp, scmcon *conp, crlfunc *cfunc);

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
crlfunc revoke_cert_by_serial;

/**
 * @brief
 *     Delete a particular local_id from a table.
 */
err_code deletebylid(scmcon *conp, scmtab *tabp, unsigned int lid);

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
err_code certificate_validity(scm *scmp, scmcon *conp);

err_code addStateToFlags(unsigned int *flags, int isValid, char *filename,
                         char *fullpath, scm *scmp, scmcon *conp);

err_code set_cert_flag(scmcon *conp, unsigned int id, unsigned int flags);

/**
 * @warning
 *     This function uses static memory and is not thread-safe.  Any
 *     call to this function overwrites the results returned from a
 *     previous call to this function.
 */
extern struct cert_answers *find_cert_by_aKI(char *ski, char *aki, scm *sscmp,
                                             scmcon *conp);

/**
 * @warning
 *     This function uses static memory and is not thread-safe.  Any
 *     call to this function overwrites the results returned from a
 *     previous call to this function.
 */
extern struct cert_answers *find_trust_anchors(scm *sscmp, scmcon *conp);

extern struct Extension *get_extension(struct Certificate *certp, char *idp,
                                       int *count);

extern char *retrieve_tdir(scm *scmp, scmcon *conp, err_code *stap);

extern void startSyslog(char *appName);

extern void stopSyslog(void);

extern void setallowexpired(int v);

extern void sqcleanup(void);

enum Mode { Read, IPv4_Read, IPv6_Read, AS_Read };

typedef struct _IPv4 {
  char min[16];
  char max[16];
  struct _IPv4 *next;
} _IPv4;
typedef struct _IPv6 {
  char min[40];
  char max[40];
  struct _IPv6 *next;
} _IPv6;
typedef struct _AS {
  unsigned long long min;
  unsigned long long max;
  struct _AS *next;
} _AS;
typedef struct _RS {
  _IPv4 *ipv4_set;
  _IPv6 *ipv6_set;
  _AS *as_set;
} RS;

void trim_string(char *str);
void AddIPv4ToRSNode(RS *node, char min[16], char max[16]);
void AddIPv6ToRSNode(RS *node, char min[40], char max[40]);
void AddASToRSNode(RS *node, unsigned long long min, unsigned long long max);
err_code get_result_rs(RS *up_rs, RS *self_rs, RS *result_rs);
RS *InitializeRSNode();
void freeRSNode(RS *node);
void save_node_as_file(RS *result, char *filename);
err_code add_cert_validation_reconsidered(scmcon *conp, char *ski,
                                          char *subject, unsigned int cert_id,
                                          char *resource_file_path);
_Bool isROA_file(char *filename);
#endif
