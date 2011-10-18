/** @file */

/* This file keeps global constants.
 * Sections are
 * - external standards
 * - internal
 * - ...
 *
 * The top of the file contains a terse listing of actual constants.
 * Descriptions or rationalizations for a particular constant may exist in a
 * commented section further down the file. */

#ifndef GLOBALS_H_
#define GLOBALS_H_


/* =============================================================================
--------------------------- Based on external standards ----------------------*/
#define SER_NUM_MAX_SZ				20
#define SUBJ_PUBKEY_EXPONENT		65537
#define SUBJ_PUBKEY_EXPONENT_SZ		3
#define SUBJ_PUBKEY_MAX_SZ			280
#define SUBJ_PUBKEY_MODULUS_SZ		256


/* =============================================================================
----------------------------------- Internal ---------------------------------*/


/* =============================================================================
---------------------------------- Descriptions --------------------------------
SUBJ_PUBKEY_EXPONENT
draft-ietf-sidr-rpki-algs-05, 3. Asymmetric Key Pair Formats
  The RSA key pairs used to compute the signatures MUST have a 2048-bit
  modulus and a public exponent (e) of 65,537.

SUBJ_PUBKEY_EXPONENT_SZ
draft-ietf-sidr-rpki-algs-05, 3. Asymmetric Key Pair Formats
  The RSA key pairs used to compute the signatures MUST have a 2048-bit
  modulus and a public exponent (e) of 65,537.
This value is stored in 3 bytes in ASN encoding.

SUBJ_PUBKEY_MAX_SZ
draft-ietf-sidr-rpki-algs-05, 3. Asymmetric Key Pair Formats
  The RSA key pairs used to compute the signatures MUST have a 2048-bit
  modulus and a public exponent (e) of 65,537.
This is the size required to hold to resulting ASN structure.

SUBJ_PUBKEY_MODULUS_SZ
draft-ietf-sidr-rpki-algs-05, 3. Asymmetric Key Pair Formats
  The RSA key pairs used to compute the signatures MUST have a 2048-bit
  modulus and a public exponent (e) of 65,537.
The ASN encoding of this value is actually one byte longer to contain a leading
zero byte.

*/
#endif /* GLOBALS_H_ */
