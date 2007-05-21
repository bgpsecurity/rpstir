/* $Id$ */
/* Dec  6 1996 411U  */
/* Dec  6 1996 GARDINER added C++ conditionals */
/* Mar  8 1994   2U  */
/* Mar  8 1994 GARDINER Started on SPARC */
/* sfcsid[] = "@(#)md2.h 411p" */
/*
 ***********************************************************************
 ** md2.h -- Header file for implementation of MD2                    **
 ** RSA Data Security, Inc. MD2 Message Digest Algorithm              **
 ** Created: 10/1/88 RLR                                              **
 ** Revised: 12/27/90 SRD,BSK,JT Reference C version                  **
 ***********************************************************************
 */

/*
 ***********************************************************************
 ** Copyright (C) 1990, RSA Data Security, Inc. All rights reserved.  **
 **                                                                   **
 ** License to copy and use this software is granted for              **
 ** non-commercial Internet privacy-enhanced mail provided that it    **
 ** is identified as the "RSA Data Security, Inc. MD2 Message Digest  **
 ** Algorithm" in all material mentioning or referencing this         **
 ** software or this function.                                        **
 **                                                                   **
 ** RSA Data Security, Inc. makes no representations concerning       **
 ** either the merchantability of this software or the suitability    **
 ** of this software for any particular purpose.  It is provided "as  **
 ** is" without express or implied warranty of any kind.              **
 **                                                                   **
 ** These notices must be retained in any copies of any part of this  **
 ** documentation and/or software.                                    **
 ***********************************************************************
 */

/* Data structure for MD2 (Message Digest) computation */
typedef struct {
  /* buffer for forming md into.  Actual digest is buf[0]...buf[15] */
  unsigned char buf[48];
  unsigned char mac[16];                              /* mac register */
  unsigned char i;              /* number of bytes handled, modulo 16 */
  unsigned char lastMac;                      /* last mac value saved */
} MD2_CTX;

#ifdef __cplusplus
extern "C"
    {
#endif
    void MD2Init (MD2_CTX *);
    void MD2Update (MD2_CTX *, unsigned char *, unsigned);
    void MD2Final (MD2_CTX *);
#ifdef __cplusplus
    };
#endif
