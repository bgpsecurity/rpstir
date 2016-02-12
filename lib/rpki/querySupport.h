#ifndef LIB_RPKI_QUERYSUPPORT_H
#define LIB_RPKI_QUERYSUPPORT_H

/**
 * @file
 *
 * @brief
 *     Functions and flags shared by query and server code
 */

#include "scmf.h"

/**
 * @brief
 *     put the appropriate tests for @c SCM_FLAG_XXX flags in the
 *     where string of a query
 */
extern void addQueryFlagTests(
    char *whereStr,
    int needAnd);

/**
 * @brief
 *     prototype for a function for displaying a field
 */
typedef int
displayfunc(
    scm *scmp,
    scmcon *connection,
    scmsrcha *s,
    int idx1,
    char *returnStr);

/**
 * @brief
 *     attributes of a field to display or filter on
 */
typedef struct _QueryField {
    /** @brief name of the field */
    char *name;
    /** @brief one-line description for user help */
    char *description;
    /** @brief flags (see @c Q_xyz above) */
    int flags;
    /** @brief what type of data to expect from query */
    int sqlType;
    /** @brief how much space to allocate for response */
    int maxSize;
    /** @brief if not NULL, use this for query, not name */
    char *dbColumn;
    /** @brief if not NULL, second field for query */
    char *otherDBColumn;
    /** @brief name of column heading to use in printout */
    char *heading;
    /** @brief function for display string, NULL if std */
    displayfunc *displayer;
} QueryField;

/**
 * @brief
 *     Find the attributes of a particular field to query on
 */
extern QueryField *findField(
    char *name);

/**
 * @brief
 *     The set of all the fields
 */
extern QueryField *getFields(
    void);

/**
 * @brief
 *     The total number of fields
 */
extern int getNumFields(
    void);

/**
 * @brief
 *     check the validity of a cert in the db
 *
 * @param[in] ski
 *     If non-NULL, the subject key identifier identifying the
 *     certificate to check.  If NULL, the certificate to check is
 *     identified by @p localID.
 * @param[in] localID
 *     Identifies the certificate if @p ski is NULL.  This parameter
 *     is ignored if @p ski is not NULL.
 * @param[in] scmp
 *     Database schema pointer.
 * @param[in] connect
 *     Database connection pointer.
 * @return
 *     True (non-zero) if the certificate is valid, false (0)
 *     otherwise.
 */
extern int checkValidity(
    char *ski,
    unsigned int localID,
    scm *scmp,
    scmcon *connect);

/**
 * @brief
 *     displayFlags() needs to know if object is a manifest
 */
void setIsManifest(
    int val);

#define Q_JUST_DISPLAY  0x01
#define Q_FOR_ROA       0x02
#define Q_FOR_CRL       0x04
#define Q_FOR_CERT      0x08
#define Q_REQ_JOIN	0x10
#define Q_FOR_MAN       0x20
#define Q_FOR_GBR       0x40

#define MAX_RESULT_SZ (128 * 1024)

#endif /* !LIB_RPKI_QUERYSUPPORT_H */
