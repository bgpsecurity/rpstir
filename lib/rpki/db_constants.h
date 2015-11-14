#ifndef LIB_RPKI_DB_CONSTANTS_H
#define LIB_RPKI_DB_CONSTANTS_H


/**
 * @brief
 *     Signature validation states
 */
typedef enum {
    SIGVAL_UNKNOWN = 0,
    SIGVAL_NOTPRESENT,
    SIGVAL_VALID,
    SIGVAL_INVALID,
} sigval_state;

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
