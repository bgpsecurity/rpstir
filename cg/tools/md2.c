/* $Id$ */
/* Mar  8 1994   2U  */
/* Mar  8 1994 GARDINER Started on SPARC */
/* */
char md2_sfcsid[] = "@(#)md2.c   2P";
/*
 ***********************************************************************
 ** md2.c                                                             **
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

#include "md2.h"

/*
 ***********************************************************************
 **  Message digest routines:                                         **
 **  To form the message digest for a message M                       **
 **    (1) Initialize a context buffer mdContext using MD2Init        **
 **    (2) Call MD2Update on mdContext and M                          **
 **    (3) Call MD2Final on mdContext                                 **
 **  The message digest is now in mdContext->buf[0...15]              **
 ***********************************************************************
 */

/*
 ***********************************************************************
 ** The table given below is a permutation of 0...255 constructed     **
 **  from the digits of pi.  It is a "random" nonlinear byte          **
 **  substitution operation.                                          **
 ***********************************************************************
 */
static unsigned char PI_SUBST[256] = {
   41, 46, 67,201,162,216,124,  1, 61, 54, 84,161,236,240,  6, 19,
   98,167,  5,243,192,199,115,140,152,147, 43,217,188, 76,130,202,
   30,155, 87, 60,253,212,224, 22,103, 66,111, 24,138, 23,229, 18,
  190, 78,196,214,218,158,222, 73,160,251,245,142,187, 47,238,122,
  169,104,121,145, 21,178,  7, 63,148,194, 16,137, 11, 34, 95, 33,
  128,127, 93,154, 90,144, 50, 39, 53, 62,204,231,191,247,151,  3,
  255, 25, 48,179, 72,165,181,209,215, 94,146, 42,172, 86,170,198,
   79,184, 56,210,150,164,125,182,118,252,107,226,156,116,  4,241,
   69,157,112, 89,100,113,135, 32,134, 91,207,101,230, 45,168,  2,
   27, 96, 37,173,174,176,185,246, 28, 70, 97,105, 52, 64,126, 15,
   85, 71,163, 35,221, 81,175, 58,195, 92,249,206,186,197,234, 38,
   44, 83, 13,110,133, 40,132,  9,211,223,205,244, 65,129, 77, 82,
  106,220, 55,200,108,193,171,250, 36,225,123,  8, 12,189,177, 74,
  120,136,149,139,227, 99,232,109,233,203,213,254, 59,  0, 29, 57,
  242,239,183, 14,102, 88,208,228,166,119,114,248,235,117, 75, 10,
   49, 68, 80,180,143,237, 31, 26,219,153,141, 51,159, 17,131, 20,
};

/* The routine MD2Init initializes the message digest context buffer;
   mdContext. All fields are set to zero.
 */
void MD2Init (mdContext)
MD2_CTX *mdContext;
{
  int i;

  for (i = 0; i < 16; i++)
    mdContext->buf[i] = mdContext->mac[i] = 0;
  mdContext->i = 0;
  mdContext->lastMac = 0;
}

/* The routine MD2Update updates the message digest context to
   account for the presence of each of the characters M[0..inLen-1]
   in the message pointed to by inBuf whose digest is being computed.
 */
void MD2Update (mdContext, inBuf, inLen)
MD2_CTX *mdContext;
unsigned char *inBuf;
unsigned int inLen;
{
  unsigned char mdi, t, j, ix;

  /* put mdContext->i into local variable for efficiency */
  mdi = mdContext->i;

  while (inLen--) {
    /* Add new character to buffer */
    mdContext->buf[16+mdi] = *inBuf;
    mdContext->buf[32+mdi] = *inBuf ^ mdContext->buf[mdi];

    /* Update MAC */
    mdContext->lastMac =
      (mdContext->mac[mdi] ^=
       PI_SUBST[0xFF & (*inBuf++ ^ mdContext->lastMac)]);

    /* Increment mdi */
    mdi++;
    /* Encrypt if necessary */
    if (mdi == 16) {
      t = 0;
      for (j = 0; j < 18; j++) {
        for (ix = 0; ix < 48; ix++)
          t = mdContext->buf[ix] = mdContext->buf[ix] ^ PI_SUBST[t];
        t = t + j;
      }
      mdi = 0;
    }
    /* New digest is in mdContext->buf[0]..mdContext->buf[15] */
  }
  mdContext->i = mdi;
}

/* The routine MD2Final terminates the message digest computation and
   ends with the desired message digest being in mdContext->buf[0...15].
 */
void MD2Final (mdContext)
MD2_CTX *mdContext;
{
  int i;
  unsigned char padLen;

  padLen = (unsigned char) 16 - mdContext->i;

  /* pad out to multiple of 16 */
  for (i = 0; i < (int)padLen; i++)
    MD2Update (mdContext, &padLen, 1);

  /* extend with MAC.
     Note that even though mac is updated with each char, the
       mac added in is what it was at the end of the padding operation
  */
  MD2Update (mdContext, mdContext->mac, 16);
}
