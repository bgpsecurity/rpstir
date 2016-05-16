#ifndef LIB_RPKI_DB_CONSTANTS_H
#define LIB_RPKI_DB_CONSTANTS_H


/**
 * @brief
 *     Signature validation states
 */
typedef enum {
    // Use a negative value to force sigval_state to be a signed type.
    // This prevents ancient versions of gcc from complaining with
    // "comparison of unsigned expression < 0 is always false"
    SIGVAL_silence_bogus_gcc_warning = -1,

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
// The following flags were previously defined but have been deleted:
//   - 0x200 was SCM_FLAG_ISPARACERT
//   - 0x400 was SCM_FLAG_HASPARACERT
//   - 0x800 was SCM_FLAG_ISTARGET
// These flags were used for LTAM (draft-ietf-sidr-ltamgmt) but that
// draft has been superseded by SLURM (draft-ietf-sidr-slurm).


#endif
