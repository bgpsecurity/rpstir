/* $Id$ */
/*****************************************************************************
File:     casn_real.c
Contents: Functions for AsnReal objects
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

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
 * Copyright (C) Raytheon BBN Technologies Corp. 2005-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/
char casn_real_sfcsid[] = "@(#)casn_real.c 860P";

#include <stdio.h>
#include "casn.h"

extern int _casn_obj_err(struct casn *, int);
extern struct casn *_go_up(struct casn *);
#if (sparc || SPARC || INTEL || PA_RISC)
/* bits in double for Sparc:
 low addr                                                       high addr
 SXXXXXXX XXXXMMMM MMMMMMMM MMMMMMMM MMMMMMMM MMMMMMMM MMMMMMMM MMMMMMMM
    0x7FF    1 = MSBit
   bits in double for Intel machine -- just reversed byte order:
 MMMMMMMM MMMMMMMM MMMMMMMM MMMMMMMM MMMMMMMM MMMMMMMM XXXXMMMM SXXXXXXX
*/
#define DBL_EXPONENT_BITS 11        // # of bits in exponent
#define DBL_EXPONENT_BYTES ((DBL_EXPONENT_BITS + 7) >> 3)
                                    // # of bytes in exponent
#define DBL_XMSBYTE_INDEX  0        // index of MSByte in exponent
#define DBL_XMSBYTE_MASK   0x7F     // mask for exponent bits in MSByte
#define DBL_XLSBYTE_INDEX  1        // index of LSByte in exponent
#define DBL_XLSBYTE_MASK   0xF0     // mask for exponent bits in LSByte
#define DBL_EXPONENT_ZERO  0x3FF    // value of exponent when 0
#define DBL_MANTISSA_BITS 52        // # of bits in mantissa
#define DBL_BINIMAL_SIZE  52        // # of bits to right of 'binimal' point
#define DBL_MANTISSA_BYTES ((DBL_MANTISSA_BITS + 7) >> 3)
				    // # of bytes in mantissa
#define DBL_MMSBYTE_INDEX  1        // index of MSByte in mantissa
#define DBL_MMSBYTE_MASK   0x0F     // mask for mantissa bits in MSByte
#define DBL_MMSBIT_EXP     4        // offset of mantissa MSBit in MSbyte
		    // this is needed if MSBit is omitted, as in Sparc
#define DBL_MLSBYTE_INDEX  7        // index of MSByte in mantissa
#define DBL_MLSBYTE_MASK   0xFF     // mask for mantissa bits in MSByte
#define DBL_PRINTF_FFORMAT "%18lf"  // printf format for 'e' format
#define DBL_PRINTF_EFORMAT "%-18.18E" //  "       "     '  'f'   "
#endif

static int shift_buf(uchar *, int, int);
static void swap_box(uchar *);

union dbl_box
    {
    double dbl_val;
    uchar cval[sizeof(double)];
    };
union end_box
    {
    short short_val;
    uchar cval[sizeof (short)];
    };

int read_casn_double(struct casn *casnp, double *val)
    {
    /**
    Procedure:
    1. IF beyond end of an OF, return error
       IF field not filled in, return error
       IF it's an infinity, return appropriate value
       IF it's in decimal format
    	    Convert it to double
       ELSE
            Get the sign, base and shift factor
            Calculate exponent size, and exponent
    2.      Convert the exponent to a 2s exponent
            Calculate mantissa length
            Adjust the exponent for effect of moving binimal point to r.h. end
            Shift the mantissa to the left so that its MSbit is to right of
                machine's MSbit
            Shift mantissa left till mantissa's MSbit is in right place,
                adjusting exponent
            IF that left a null byte at the end, trim that off
    3.      Adjust the exponent for the MSBit
            Put mantissa into machine's mantissa
            Adjust exponent for machine's 'zero'
            Put exponent into machine's exponent
            Set the sign
    4. Copy double value into return
       Return 1
    **/
    unsigned int exp_size, base_exp, max, mantissa_bits, ff;
    int i, j, sign, exponent, mantissa_lth;
    uchar *c, tc, locbuf[128], mask;
    union dbl_box box;
    union end_box bigend;
                                                             /* step 1 */
    bigend.short_val = 1;
    i = 0;
    if (casnp->level > 0 && (_go_up(casnp)->flags & ASN_OF_FLAG) &&
	(casnp->flags & ASN_LAST_FLAG)) i = ASN_OF_BOUNDS_ERR;
    else if (!casnp->startp) i = ASN_MANDATORY_ERR;
    if (i) return _casn_obj_err(casnp, i);
    if (!(max = (unsigned int)casnp->lth))
        {
        *val = 0;
        return 0;
        }
    if (casnp->lth >= sizeof(locbuf)) return _casn_obj_err(casnp, ASN_GEN_ERR);
    memcpy(locbuf, casnp->startp, casnp->lth);
    tc = *locbuf;
    box.dbl_val = 0;
    if (tc == ASN_PLUS_INFINITY || tc == ASN_MINUS_INFINITY)
        {
        if (tc == ASN_MINUS_INFINITY) *val = -1;
        else *val = 1;
        return -ASN_BOUNDS_ERR;
        }
    if (!(tc & 0xC0))
        {
        if (!tc || tc > ((ISO6093NR3 - 8) / 2)) 
            return _casn_obj_err(casnp, ASN_CODING_ERR);
        locbuf[casnp->lth] = 0;
        *val = 0;
        for (c = &locbuf[1]; *c && *c != ','; c++);  // convert comma as decimal
        if (*c) *c = '.';                            // mark to period
        sscanf((char *)&locbuf[1], (tc == ((ISO6093NR3 - 8) / 2))? "%le": "%lf",
            &box.dbl_val);
        }
    else
        {
        sign = (tc & 0x40);
        base_exp = (tc & 0x30) >> 4;
        ff = (tc & 0xC) >> 2;
        i = 1;
        if ((exp_size = (tc & 3) + 1) > 2) exp_size = locbuf[i++];
        for (exponent = (!(locbuf[i] & 0x80))? 0: -1; exp_size--;
            exponent = (exponent << 8) + locbuf[i++]);
    						        /* step 2 */
        if (base_exp) exponent *= (base_exp + 2);
        mantissa_lth = (max - i);
        mantissa_bits = mantissa_lth << 3;
        exponent += mantissa_bits + DBL_MMSBIT_EXP;
        mask = (1 << DBL_MMSBIT_EXP);       // machine's MSbit
            // shift mantissa to left for convenience
        if (locbuf[i] < mask)  // can shift all the way
            {
            if (i + mantissa_lth >= sizeof(locbuf))
                return _casn_obj_err(casnp, ASN_GEN_ERR);
            memcpy(locbuf, &locbuf[i], mantissa_lth);
            for (c = &locbuf[mantissa_lth]; --i >= 0; *c++ = 0);
            exponent -= 8;
                // how much left shift will bring mantissa's MSbit to proper point?
            for (j = 0; !(*locbuf & mask); j--, mask >>= 1);
            }
        else        // have to stop a byte short
            {
            if (i < 2) return _casn_obj_err(casnp, ASN_GEN_ERR);
            memcpy((c = &locbuf[1]), &locbuf[i], mantissa_lth++);
            *locbuf = 0;
            for (c = &locbuf[mantissa_lth]; --i >= 0; *c++ = 0);
                // how much left shift will bring mantissa's MSbit to proper point?
            for (j = -(DBL_MMSBIT_EXP) - 1, mask = 0x80; !(locbuf[1] & mask);
                j--, mask >>= 1);
            }
            // do the shift
        exponent += shift_buf(locbuf, mantissa_lth + 1, j);
        if (!locbuf[mantissa_lth - 1]) mantissa_lth--;
    						        /* step 3 */
            // delete MS bit
        *locbuf &= DBL_MMSBYTE_MASK;
        memcpy(&box.cval[DBL_MMSBYTE_INDEX], locbuf, mantissa_lth);
        exponent += DBL_EXPONENT_ZERO;  // set to machine's zero
        exponent += ff;
        for (i = DBL_XLSBYTE_MASK; !(i & 1); i >>= 1, exponent <<= 1);
        for (box.cval[(i = DBL_XLSBYTE_INDEX)] |=
            (exponent & DBL_XLSBYTE_MASK); i > DBL_XMSBYTE_INDEX; )
            box.cval[--i] = (exponent >>= 8) & 0xFF;
        box.cval[i] &= DBL_XMSBYTE_MASK;
        if (*bigend.cval)  swap_box(box.cval);
        if (sign) box.dbl_val = -box.dbl_val;
        }
    *val = box.dbl_val;
    return 1;
    }

int write_casn_double(struct casn *casnp, double val, int type)
    {
    /**
    Procedure:
    1. IF invalid base, return error
       IF an infinity is requested, return result of special write
       IF decimal format asked for, return what dec_write returns
            Set the first byte according to the base requested
            Print the value into the rest of the buffer
            Write that character string into the object
       ELSE
    	    IF value is zero, return result of special write
            Get the exponent
    2.      Mask off unwanted parts of the mantissa
            Set the missing bit, if any
    3.      IF there are null bytes at the end, trim them off
            Adjust the exponent for moving binimal point to right hand end
            Encode the first octet
            Encode the exponent
    4.      Copy the mantissa to a local buffer, starting after where the exponent
            will go
    5. Write the local buffer into the object
    **/
    int shift, j, mantissa_lth, exp_lth, sign = (val < 0);
    long i, exponent;
    uchar tc, mask, *uc, *mantissap;
    char locbuf[40], *c, *Ep, *ptp;
    union dbl_box box;
    union end_box bigend;
    memset(locbuf, 0, sizeof(locbuf));
    bigend.short_val = 1;
    box.dbl_val = val;
							/* step 1 */
    if (type != -1 && type != 1 && type != 2 && type != 10)
        return _casn_obj_err(casnp, ASN_UNDEF_VALUE);
							// step 2
    if ((type & 1))
        {
        *locbuf = (type > 0)? ASN_PLUS_INFINITY: ASN_MINUS_INFINITY;
        i = 1;
        }
    else if (type == 10)
        {
        *locbuf = 3;
        if (snprintf((char *)&locbuf[1], sizeof(locbuf) - 1,
            DBL_PRINTF_EFORMAT, box.dbl_val) > sizeof(locbuf) - 1)
           return _casn_obj_err(casnp, ASN_BOUNDS_ERR);
        for (c = &locbuf[1]; *c ; c++);  // go to end
        while (*(--c) == ' ') *c = 0;   // trim off trailing spaces
        for (c = &locbuf[1]; *c == '0'; c++); // trim off leading zeroes
        if (c > &locbuf[1]) strncpy(&locbuf[1], c, strlen(c) + 1);
	for (Ep = &locbuf[1]; *Ep && *Ep != 'E'; Ep++);  // go to E
        sscanf(&Ep[1], "%ld", &exponent);
        for (Ep--; Ep[-1] == '0'; Ep--);  // trim off trailing zeroes in mantissa
        if (*Ep != '0') Ep++;
        *Ep= 0;    // Ep now at terminal null
            // find decimal pt
        for (ptp = &locbuf[1]; *ptp && *ptp != '.'; ptp++);
        if (*ptp && ptp[1]) // have a decimal pt and someting beyond
            {
            strncpy(ptp, &ptp[1], strlen(ptp));
            Ep[-1] = '.';
            exponent -= strlen(ptp) - 1;  //adjust for shift of decimal pt
            }
        if (exponent == 0) strncpy(Ep, "E+0", 4);
        else
            {     // append nulls since sprintf will not
            for (ptp = Ep; ptp < &Ep[6]; *ptp++ = 0);
            snprintf(Ep, 6, "E%ld", exponent);
            }
        i = strlen((char *)locbuf);
        }
    else if (!box.dbl_val) i = 0;   // special case base 2
							    // step 3
    else                    // general case 2
        {
        if (*bigend.cval) swap_box(box.cval);
        for (exponent = (box.cval[(i = DBL_XMSBYTE_INDEX)] &
    	    DBL_XMSBYTE_MASK), i++; i < DBL_XLSBYTE_INDEX;
    	    exponent = (exponent << 8) + box.cval[i++]);
        exponent = (exponent << 8) + (box.cval[i] & DBL_XLSBYTE_MASK);
        for (tc = DBL_XLSBYTE_MASK; !(tc & 1); tc >>= 1, exponent >>= 1);
        exponent -= DBL_EXPONENT_ZERO;
        mantissap = &box.cval[DBL_MMSBYTE_INDEX];
        *mantissap &= DBL_MMSBYTE_MASK;
        mask = DBL_MLSBYTE_MASK;
        box.cval[DBL_MMSBYTE_INDEX] &= mask;
        if (!(DBL_MMSBYTE_MASK & (1 << DBL_MMSBIT_EXP)))
    	    *mantissap |= (1 << DBL_MMSBIT_EXP);
    							    // step 4
               /* bits of shift */
        for (uc = &box.cval[DBL_MLSBYTE_INDEX], shift = 0; !*uc; uc--, shift += 8);
                // how much will we shift?
        if ((mantissa_lth = (int)(uc - mantissap + 1)) < 0)
            return _casn_obj_err(casnp, ASN_GEN_ERR);
        for (mask = 1, j = 0; !(*uc & mask); j++, mask <<= 1);
        shift += shift_buf(mantissap, mantissa_lth, j);
            // if MSbyte is empty, shift left 1 byte
        if (!*mantissap) memcpy(mantissap, &mantissap[1], mantissa_lth--);
        if (mantissa_lth < 0) return _casn_obj_err(casnp, ASN_GEN_ERR);
                                                                // step 5
        exponent += shift - DBL_BINIMAL_SIZE;
        j = exponent & 0x7FFF;
        for (exp_lth = 0; j > 0x7F; j >>= 8, exp_lth++);
        if (!exp_lth) exp_lth++;
        locbuf[0] = ((!sign)? 0x80: 0xC0) | (exp_lth - 1);
        for (j = exp_lth; j; j--)
            {
            locbuf[j] = (exponent & 0xFF);
            exponent >>= 8;
            }
                                                                // step 6
        memcpy(&locbuf[exp_lth + 1], mantissap, mantissa_lth);
        i = 1 + exp_lth + mantissa_lth;
        }
                            			       	    // step 7
    return write_casn(casnp, (uchar *)locbuf, (long)i);
    }

int shift_buf(uchar *buf, int size, int amt)
    {
    uchar *c, *e;
    ushort wd = 0;

    if (amt < 0)    // shift left
        {
        for (c = buf, e = &c[size - 1]; c < e; c++)
    	    {
	    wd = *c;
	    wd <<= 8;
	    wd |= c[1];
	    wd <<= -amt;
	    *c = (wd >> 8) & 0xFF;
    	    }
	wd = *c;
	wd <<= 8;
	wd <<= -amt;
	*c = (wd >> 8) & 0xFF;
        }
    else if (amt)   // shift right
        {
        for (c = &buf[size - 1]; c > buf; c--)
    	    {
	    wd = c[-1];
	    wd <<= 8;
	    wd |= *c;
	    wd >>= amt;
	    *c = (wd & 0xFF);
    	    }
	wd = (*c & 0xFF);
	wd >>= amt;
	*c = (wd & 0xFF);
        }
    return amt;
    }

static void swap_box(uchar *buf)
    {
    uchar *ap, *bp, c;
    for (ap = buf, bp = &buf[sizeof(double)]; ap < --bp; ap++)
        {
        c = *ap;
        *ap = *bp;
        *bp = c;
        }
    }
