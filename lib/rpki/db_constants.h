#ifndef _PROTO_DB_CONSTANTS_H
#define _PROTO_DB_CONSTANTS_H


/*
 * Signature validation states
 */

#define SIGVAL_UNKNOWN     0
#define SIGVAL_NOTPRESENT  1
#define SIGVAL_VALID       2
#define SIGVAL_INVALID     3

/*
 * Flags
 */

/** @brief certificate authority */
#define SCM_FLAG_CA           0x1
/** @brief trusted */
#define SCM_FLAG_TRUSTED      0x2
/** @brief at some point, chain existed */
#define SCM_FLAG_VALIDATED    0x4
/** @brief now missing links on chain to anchor */
#define SCM_FLAG_NOCHAIN      0x8
/** @brief too early, not yet ready */
#define SCM_FLAG_NOTYET       0x10
/** @brief assoc crl of self or ancestor stale */
#define SCM_FLAG_STALECRL     0x20
/** @brief assoc man of self or ancestor stale */
#define SCM_FLAG_STALEMAN     0x40
/** @brief has associated valid manifest */
#define SCM_FLAG_ONMAN        0x100
/** @brief is a paracert */
#define SCM_FLAG_ISPARACERT   0x200
/** @brief has a paracert */
#define SCM_FLAG_HASPARACERT  0x400
/** @brief is a target for LTA work */
#define SCM_FLAG_ISTARGET     0x800


#endif
