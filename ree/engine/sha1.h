/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE—RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

/* $Id$ */

#ifndef SHA1_H
#define SHA1_H
typedef unsigned int uint32;

#define SIZE_OF_SHA1 20 /* SHA1 message digest is 20 bytes long */

#if PROTOTYPES    /* If we should use function prototypes.*/

STATUS BSAFE_CALL BSAFE_SHA1(
   BSAFE_CTX BSAFE_PTR,   /*  ctx */
   UWORD,                 /*  opcode */
   ULONG,                 /*  part_in_size */
   BYTE BSAFE_PTR,        /*  part_in */
   ULONG BSAFE_PTR,       /*  part_out_size */
   BYTE BSAFE_PTR,        /*  part_out */
   UWORD                  /*  unused_bits */
);
int  sha1_hash ( /* to hash a non-prepared (non-padded) input */
   unsigned char *,       /*  input */
   unsigned long,         /*  input_len */
   unsigned short,        /*  unused_bits */
   unsigned char *,       /*  output */
   unsigned long *        /*  output_len */
);
void sha1_init_h();                 /* to initialize the hash accumulator */
void sha1_hash_block(uint32);                /* to hash one 16 word block */
void SHA1_memcpy(char *, char *, unsigned int);
void SHA1_memset(char *, int, unsigned int);

#else  /* no PROTOTYPES */

int sha1_hash (
  unsigned char   *input,
  unsigned long   input_len,
  unsigned short  unused_bits,
  unsigned char   *output,
  unsigned long   *output_len,
  int             mode);
void sha1_init_h();
void SHA1_memset(
  char         *output,
  int          value,
  unsigned int len);
void SHA1_memcpy (
  char         *output,
  char         *input,
  unsigned int len);
void sha1_hash_block (uint32 buff[16]);
#endif /* PROTOTYPES */

#endif /* _SHA1_H */
