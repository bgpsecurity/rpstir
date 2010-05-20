/* $Id$ */
char prencode_sfcsid[] = "@(#)prencode.c 378P";
/*
 * FILE:        prencode.c
 * AUTHORs:     John Linn (Linn@decwrl.dec.com),
 *              John Lowry (jlowry@bbn.com)
 *
 * DESCRIPTION: 6 bit encode/decode routines
 *
 ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 1991-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
 *
 * $Revision: 1.2 $
 * $Source: /nfs/flippet/u1/Mosaic/Dev/rcs/lib/asn1utils/prencode.c,v $
 * $State: Exp $
 *
 *
 */

#ifndef lint
const char prencode_rcsid[]="$Header: /nfs/flippet/u1/Mosaic/Dev/rcs/lib/asn1utils/prencode.c,v 1.2 1993/09/02 13:56:37 dpn Exp $";
#endif

/* prencode.c: routines to do printable encoding per PTF RFC */

#define NASCII  TRUE    /* Native character set is ASCII. Allows */
                        /* a simple yet fast decoding operation  */

#define ENCNULL '='             /* used when a number of characters is */
                                /* to be encoded which requires a      */
                                /* non-integral number of encoding     */
                                /* quanta                              */

static char ia5subset[65] =       /* 64 universally-representable chars */
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void convto8p();
int  convto6b();


int sixBitEncode(src,dest, size)
char *src, *dest;
int size;
{
    register int i, j;
    register char *s, *d;

    s = src; d = dest;

    for(i = j = 0; i < size; i+= 3, j += 4){
	convto8p(s, d, ((i+3) < size) ? 3 : size - i);
	s+=3; d+=4;
    }

    return(j);
}

/* convto8p: convert up to 6 arbitrary bytes to an 8-byte printable */
/* encoded form. nenc represents the number of actual bytes to encode */

void convto8p(src, dest, nenc)
char    src[], dest[];
int     nenc;
{
        unsigned        ua[3];
        int    c;
        char    *cp;

        cp = src;

        ua [0] = *cp++ << 8;
        ua [0] |= 0xff & *cp++;
        ua [1] = *cp++ << 8;
        ua [1] |= 0xff & *cp++;
        ua [2] = *cp++ << 8;
        ua [2] |= 0xff & *cp;

        cp = dest;

        *cp++ = (nenc > 0) ? ia5subset [0x3f & ua [0] >> 10] : ENCNULL;
        *cp++ = (nenc > 0) ? ia5subset [0x3f & ua [0] >> 4] : ENCNULL;
        c = ((0xf & ua [0]) << 2) | (0x3 & (ua [1] >> 14));
        *cp++ = (nenc > 1) ? ia5subset [c] : ENCNULL;
        *cp++ = (nenc > 2) ? ia5subset [0x3f & ua [1] >> 8] : ENCNULL;
        *cp++ = (nenc > 3) ? ia5subset [0x3f & ua [1] >> 2] : ENCNULL;
        c = ((0x3 & ua [1]) << 4) | (0xf & (ua [2] >> 12));
        *cp++ = (nenc > 3) ? ia5subset [c] : ENCNULL;
        *cp++ = (nenc > 4) ? ia5subset [0x3f & ua [2] >> 6] : ENCNULL;
        *cp = (nenc > 5) ? ia5subset [0x3f & ua [2]] : ENCNULL;
}

int sixBitDecode(src, dest, size)
char *src, *dest;
int size;
{
    register char *s, *d;
    register int tmp1, tmp2;

    s = src; d = dest; tmp1 = 0;

    while((tmp2 = convto6b(s, d)) >= 3){
	if(tmp2 > 3) tmp2 = 3;
        s+=4; d+=3; tmp1 += tmp2;
	if((int)(s - src) >= size) break; /* sanity check */
    }
    if((tmp2 > 0) && (tmp2 < 3))
	tmp1 += tmp2;
    return(tmp1);
}



/* convto6b: convert an 8-byte printable encoding into up to 6 arbitrary */
/* bytes: return result is number of actual bytes decoded */

int    convto6b(src,dest)      /* convert 8 printables to 6 8-bit bytes */
char    src[], dest[];
{
        int     i, rv;
        char    ca[8];
        char    *cp;
        char    c;

        cp = src;
        rv = 6;         /* unless ENCNULL detected, 6 bytes returned */
        for (i = 0; i < 8; i++)
        {
                c = *cp++;
                if (c == ENCNULL)
                {
                        switch (i)      /* where did first ENCNULL appear? */
                        {
                        case 0: rv = 0; break;  /* all padding (bad case) */
                        case 1: rv = 0; break;  /* 1 data, 7 pad (bad case) */
                        case 2: rv = 1; break;  /* 2 data, 6 pad */
                        case 3: rv = 2; break;  /* 3 data, 5 pad */
                        case 4: rv = 3; break;  /* 4 data, 4 pad */
                        case 5: rv = 4; break;  /* 5 data, 3 pad (bad case) */
                        case 6: rv = 4; break;  /* 6 data, 2 pad */
                        case 7: rv = 5; break;  /* 7 data, 1 pad */
                        }
                        break;          /* once ENCNULL seen, parsing done */
                }
#ifdef  NASCII
                if (c >= 'A' && c <= 'Z')
                        ca[i] = 0x3f & ((char) c - 'A');
                else if (c >= 'a' && c <= 'z')
                        ca[i] = (char) 0x3f & ((c - 'a') + 26);
                else if (c >= '0' && c <= '9')
                        ca[i] = (char) 0x3f & ((c - '0') + 26 + 26);
                else if (c == '+')
                        ca[i] = (char) 0x3f & (26 + 26 + 10);
                else if (c == '/')
                        ca[i] = (char) 0x3f & (26 + 26 + 10 + 1);
                else
                { /*
                    printf ("Can't find bit value for character %c (hex %x)\n",
                        c, (unsigned) c);
		  */
                }
#else
                for (j = 0; j < sizeof (ia5subset); j++)
                {
                    if (c == ia5subset[j]) break;
                }
                if (j == sizeof (ia5subset))
                {
		/*
                    printf ("Can't find bit value for character %c (hex %x)\n",
                        c, (unsigned) c);
		*/
                }
                ca[i] = j;
#endif
        }

        cp = dest;
        *cp++ = (0xfc & (ca[0] << 2)) | (0x3 & (ca[1] >> 4));
        *cp++ = (0xf0 & (ca[1] << 4)) | (0xf & (ca[2] >> 2));
        *cp++ = (0xc0 & (ca[2] << 6)) | (0x3f & ca[3]);
        *cp++ = (0xfc & (ca[4] << 2)) | (0x3 & (ca[5] >> 4));
        *cp++ = (0xf0 & (ca[5] << 4)) | (0xf & (ca[6] >> 2));
        *cp = (0xc0 & (ca[6] << 6)) | (0x3f & ca[7]);

        return (rv);
}

int SIXBIT(x)
int x;
{
    float m;

    m = (float)4/(float)3;
    return(  (int)( ((float)x * m) + (float)8)  );
}
