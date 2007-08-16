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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

/* $Id$ */

#include <string.h>
#include "enforce.h"
#include "sha1.h"

char *sha1cname = "SHA1C";
#define PROGRAM_NAME sha1cname

#ifdef VAX
#define VAX 1	/* if you have VAX word order */
#else
#define VAX 0
#endif

#ifdef SHA1_DEBUG
#define SHA1_DEBUG 1 /* prints intermediate values for comparison with
                        SHA test data */
#else
#define SHA1_DEBUG 0
#endif

/* function "S" as defined in SHA */
#define S(n,X)  ((X << n)|(X >> (32-n)))

/* function "K" for constants as defined in SHA */
#define K(t)    (t <= 19 ? 0x5a827999 : \
                (t <= 39 ? 0x6ed9eba1 : \
                (t <= 59 ? 0x8f1bbcdc : \
                           0xca62c1d6)))

/* function "f" as defined in SHA */
#define F(t,x,y,z)    (t <= 19 ? ((x&y)|(~x&z)): \
                      (t <= 39 ? (x^y^z): \
                      (t <= 59 ? ((x&y)|(x&z)|(y&z)): \
                                 (x^y^z) )))

/* the hash acumulator register */
static uint32 h[5];
void bytes2ulongs(uint32 *ulp, unsigned char *ucp, int nlongs);

/* hash a non-prepared (non-padded) input */
int sha1_hash (
  unsigned char   *input,
  unsigned long   input_len,
  unsigned short  unused_bits,
  unsigned char   *output,
  unsigned long   *output_len,
  int             mode)   /* 1= first, 2 = last, 3 = only, 0= middle */
{
    uint32        val;
    uint32        lbuff[16]; /* local buffer processed by sha1_hash_block */
    unsigned char tbuff[64]; /* temp buffer for doing last chunk */
    uint32        j, k;
    uint32        tbits;     /* total bits in message */
    uint32        bitsleft;  /* bits left to be processed */
    uint32        bufsiz;    /* number of bytes in padded string */
    uint32        *ulp;
    int		  i;

    /* The limit of (2^32)-1 bits of input is imposed. */
    if (input_len > 0x7FFFFFFF) return -1;

    if (mode & HASH_FIRST) sha1_init_h(); /* initialize the output register block */

    /* bufsiz is the number of 8 bit bytes in the padded buffer.
     * padding consists of adding room for 1 bit of data and
     * 64 bits of length and rounding up to the next 512 bit block.
     * (note the numbers 65 and 512 below).  There are 8 bits in a byte
     * (size is the count of bytes)
     * This is ugly but it works.
     */
    tbits = (input_len << 3) - unused_bits;
    bufsiz = ((tbits + 65) + (512 - ((tbits + 65) % 512))) >> 3;

    for (i = 0, bitsleft = tbits; bufsiz > 0;
         bitsleft -= (bitsleft >= 512) ? 512 : bitsleft,
         bufsiz -= 64, i++, input += 64)
        {
#if SHA1_DEBUG
       printf("Block # %d\n", i+1);
#endif

        memset(lbuff, 0, sizeof(lbuff)); /* clear the buffer first */

        if (bitsleft >= 512) bytes2ulongs(lbuff, input, 16);
//          copynbytes((uchar *)lbuff, (uchar *)input, 64);
        else
            {
            memset(tbuff, 0, sizeof(tbuff));
            if ((mode & HASH_LAST) && bitsleft > 0)
                {
                j = bitsleft >> 3; /* # of whole bytes left */
                copynbytes((uchar *)tbuff, input, j);
                if (unused_bits)
                    tbuff[j] = ((input[j] & (0xff << unused_bits)) |
                                (0x01 << (unused_bits - 1)));
                else tbuff[j] = 0x80;
    
                 /* If there are 2 32-bit (ie. 512 - 64) room left, stick in 
                  * the number of bits in the message in the last 32-bit field.
                  * Since we impose the limit to 2^32-1 bits, the second 32-bit
                  * field from the last is always Zero.
                  */
                if (bitsleft < 448)
                    {
                    tbuff[60] = (tbits >> 24) & 0xff;
                    tbuff[61] = (tbits >> 16) & 0xff;
                    tbuff[62] = (tbits >>  8) & 0xff;
                    tbuff[63] = tbits & 0xff;
                    }
                bytes2ulongs(lbuff, tbuff, 16);
                }
            else
                {
                 /* This entire 64-byte buffer is all zero except:
                  * 1. 0x80 in the first byte, if the total number of bits in
                  *    message is multiple of 512-bit.
                  * 2. the number of total bits in the last 32-bit field.
                  */
                if ((tbits % 512) == 0)
                    lbuff[0] = 0x80;
    
                lbuff[60] = (tbits >> 24) & 0xff;
                lbuff[61] = (tbits >> 16) & 0xff;
                lbuff[62] = (tbits >>  8) & 0xff;
                lbuff[63] = tbits & 0xff;
                }
            }

        sha1_hash_block((uint32 *)lbuff);
        } /* end of for loop */

    if ((mode & HASH_LAST))
	{
        for (j = 0; j < (sizeof(h) / sizeof(uint32)); j++, 
            output += sizeof(uint32))
    	    {
    	    for (val = h[j], i = sizeof(uint32) ; --i >= 0;
                output[i] = val & 0xFF, val >>= 8);
    	    }
        *output_len = SIZE_OF_SHA1;
	}
    else *output_len = 0;
    return(0);
}

void bytes2ulongs(uint32 *ulp, unsigned char *ucp, int nlongs)
    {
    int j, k;

    for (j = 0; j < nlongs; j++, ulp++)
        {
        for (k = 0; k < 4; k++)
            {
            *ulp <<= 8;
            *ulp += *ucp++;
            }
        }
    }

/* initialize the hash accumulator */
void sha1_init_h()
{
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
    h[4] = 0xc3d2e1f0;
}

/* hash one 16 word block */
void sha1_hash_block (
  uint32 buff[16])
{
    register int    t;
    register unsigned A,B,C,D,E,TEMP;
    unsigned         W[80];

    memset(W, 0, sizeof(W));
    memcpy(W, buff, 64);
    for(t = 16; t <= 79; t++)
       W[t] = S(1, (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])); /* SHA-1 uses S:
                                                              left-shift */

    A = h[0]; B = h[1]; C = h[2]; D = h[3]; E = h[4];

#if SHA1_DEBUG
    	printf("t = %2d,  0x%08lx, 0x%08lx, 0x%08lx, 0x%08lx,0x%08lx\n",
               t, A,B,C,D,E);
#endif
    for(t = 0; t <= 79; t++)
    {
	TEMP = S(5,A) + F(t,B,C,D) + E + W[t] + K(t);
        E = D; D = C; C = S(30,B); B = A; A = TEMP;
#if SHA1_DEBUG
    	printf("t = %2d,  0x%08lx, 0x%08lx, 0x%08lx, 0x%08lx,0x%08lx\n",
               t, A,B,C,D,E);
#endif
    }

    h[0] = h[0] + A;
    h[1] = h[1] + B;
    h[2] = h[2] + C;
    h[3] = h[3] + D;
    h[4] = h[4] + E;
}

