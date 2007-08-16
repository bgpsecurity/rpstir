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

#ifndef _enforce_h
#include "enforce.h"
#endif

char asn_sfcsid[] = "@(#)asn.c 772E";

int validate_alg (), validate_int (), validate_name (),
    validate_rdn ();

ulong get_num(uchar *, int);

void put_asn_lth();

uchar asn_typ();

adj_asn_lth(struct asn *asnp, int diff)
    {
/**
Function: Shifts the data pointed to by all struct asns after this one to the
right (diff > 0) or left (diff < 0), increases/decreases the lth field of this
struct asn and all higher ones by diff.
Inputs: Ptr to struct asn for field to be changed
        Number of bytes to change. <0 means shorten, >0 means lengthen
Returns: New value of diff.  (it may have changed if length of a length field
        before the starting point changed.)
Procedure:
1. Calculate true difference, taking into account that length field may change.
2. Find end of stream
   Shift all subsequent bytes to adjust to new length
   Adjust all the stringps in subsequent struct asns
3. Change length of this struct asn and all its 'parents'
**/
    int lev, new_lth_lth, tmp;
    uchar *b, *c, *e;
    struct asn *tasnp;
                                                    /* step 1 */
    tmp = calc_asn_lth_lth(asnp->lth) - calc_asn_lth_lth(asnp->lth + diff);
    diff += tmp;
                                                    /* step 2 */
    for (tasnp = asnp; tasnp->stringp; tasnp++);
    tasnp--;
    e = &asn_start(tasnp)[tasnp->lth];
    c = asn_start(asnp);
    b = c;
    if (diff < 0) b -= diff;
    if (diff) e += move_over(b, (e - b), diff);
    while (tasnp > asnp) (tasnp--)->stringp += diff;
                                                    /* step 3 */
    put_asn_lth(c, asnp->lth += diff);
    while (asnp->level)
        {          /* go up one level */
        for (lev = asnp->level; asnp->level >= lev; asnp--);
        c = asn_start(asnp);
        if ((tmp = (new_lth_lth = calc_asn_lth_lth(asnp->lth + diff)) -
            calc_asn_lth_lth(asnp->lth)))
            {
            e += move_over(c, (e - c), tmp);
            c += tmp;
            for (tasnp = &asnp[1]; tasnp->stringp; (tasnp++)->stringp += tmp);
            }
        else tmp = 0;
        put_asn_lth(c, asnp->lth + diff);
        asnp->lth += diff;
        diff += tmp;
        }
    return diff;
    }

/*
 * asn_setup()
 * Determines type, length and start of data in an ASN.1-encoded item.
 * Returns pointer to start of value.
 */
uchar *asn_setup(asnp)
struct asn *asnp;
{
    uchar *from = asnp->stringp, typ;
    int ansr;
    ulong lth;

    typ = asn_typ (&from);
    if (((lth = *from++) & ASN_INDEF))
        {
        if ((ansr = (lth &= (uchar)~ASN_INDEF)))
            {
            for (lth = 0; ansr--; lth = (lth << 8) + *from++);
            }
        }
    asnp->lth = lth;
#ifdef SUN
    asnp->pad = 0;
#endif
    return from;
}

/*
 * asn_typ()
 * Determines first byte of type in ASN.1 string starting at '*s'.
 * Returns that type; sets ptr to start of length field.
 */
uchar asn_typ(s)
    uchar **s;
{
    uchar typ, *from = *s;

    if (((typ = *from++) & ASN_XT_TAG) == ASN_XT_TAG)
    {
        while ((*from & ASN_INDEF)) from++;
        from++;
    }
    *s = from;
    return typ;
}

/*
 * asn_start()
 * Returns pointer to start of value.
 */
uchar *asn_start(struct asn *asnp)
{
    uchar *from = asnp->stringp;
    int ansr;
    ulong lth;

    asn_typ (&from);
    if (((lth = *from++) & ASN_INDEF) && (ansr = (lth &= (uchar)~ASN_INDEF)))
        from += ansr;
    return from;
}

int calc_asn_lth_lth(lth)
    int lth;
    {
    int fwd;
    if (lth < 128) return 0;
    for (fwd = 0; lth; fwd++, lth >>= 8);
    return fwd;
    }

decode_asn (asnpp,easnp,from,nbytes,level)
    struct asn **asnpp, *easnp;
    uchar *from;
    ulong nbytes;
    ushort level;
{
    struct asn *curr_asnp;
    int ansr, did;
    uchar *c;
                                                                    /* step 1 */
    for (did = 0, curr_asnp = *asnpp; !nbytes || nbytes > did; curr_asnp++)
    {
        if (curr_asnp >= easnp) return -1;
        *asnpp = curr_asnp;
	c = from;
	asn_typ(&c);
	if (*c == ASN_INDEF) return -1;
        curr_asnp->stringp = from;
        from = asn_setup (curr_asnp);
        did += from - curr_asnp->stringp;
        curr_asnp->level = level;
        if ((nbytes && nbytes < did) ||
            (*curr_asnp->stringp == ASN_INTEGER && validate_int(curr_asnp)) ||
            (*curr_asnp->stringp == ASN_NULL && curr_asnp->lth))
            return -1;
                                                                    /* step 2 */
        if ((*curr_asnp->stringp & ASN_CONSTRUCTED))
        {
            if (curr_asnp->stringp[1])
            {
                (*asnpp)++;
                if ((ansr = decode_asn(asnpp,easnp,from,(ulong)curr_asnp->lth,
                                       level + 1)) < 0) return ansr;
                from += ansr;
		(*asnpp)[1].level = 0;  /* for end of test_set */
		(*asnpp)[1].stringp = (uchar *)0;
                if (nbytes && did + ansr > nbytes ||
	 	    (*curr_asnp->stringp == ASN_SET && test_set(curr_asnp) < 0))
                    {
                    *asnpp = curr_asnp;
                    return -1;
                    }
            }
            else ansr = 0;
            curr_asnp = *asnpp;
        }
        else if (*curr_asnp->stringp == ASN_NULL) ansr = 0;
                                                                    /* step 3 */
        else from += (ansr = curr_asnp->lth);
        if ((did += ansr) > nbytes && nbytes) return -1;
                                                                    /* step 4 */
        if (!nbytes && !*from && !from[1]) break;
    }
    if (!level)
    {
        (++(*asnpp))->stringp = (uchar *)0;
        (*asnpp)->level = (*asnpp)->lth = 0;
#ifdef SUN
	(*asnpp)->pad = 0;
#endif
    }
                                                                    /* step 5 */
    return did;
}

/*
 * fasn_start()
 * Returns pointer to start of value.
 */
uchar *fasn_start(struct fasn *fasnp)
{
    struct asn asn;
    asn.stringp = GET_FILE_ASN_REF(fasnp);
    asn.lth = fasnp->lth;
    asn.level = fasnp->level;
    return asn_start(&asn);
}

void fix_date(struct asn *asnp)
    {
/**
Name: fix_date()
Function: Fixes date to conform to DER.  Assumes decode_asn has been run
Input: Ptr to struct asn for date
Returns: 1 if OK, -1 if error
Procedure:
1. Get the time as a ulong
   Put it into spare_time as GenTime
2. IF it might have a decimal of seconds
        Find where it starts and how long it is
3. Adjust the length of the array of struct asns
   Put the new string there
   IF there's a decimal, append that plus terminal Z
**/
    ulong val = get_asn_time(asnp);
    uchar *b, *c, *e, spare_time[24];
    int lth, dec_lth = 0;
    struct asn asn;
                                                        /* step 1 */
    lth = put_asn_gentime(spare_time, val);
    asn.stringp = spare_time;
    asn_setup(&asn);
                                                        /* step 2 */
    if (*asnp->stringp == ASN_GENTIME)
        {
        for (c = asn_start(asnp), e = &c[asnp->lth]; c < e && *c != '.' &&
            *c != ','; c++);
        if (*c == ',') *c = '.';
        if (*c == '.')
        if (*c == '.')
            {
            for (b = &c[1]; b < e && *b >= '0' && *b <= '9'; b++);
            while(b[-1] == '0') b--;
            if (*b == '.') b--;
            dec_lth = b - c;
            }
        }
                                                        /* step 3 */
    adj_asn_lth(asnp, asn.lth + dec_lth -
        ((*asnp->stringp == ASN_UTCTIME)? 2: 0) - asnp->lth);
    b = asn_start(&asn);
    if (*asnp->stringp == ASN_UTCTIME)
        {
        b += 2;
        asn.lth -= 2;
        }
    e += copynbytes((e = asn_start(asnp)), b, asn.lth);
    if (dec_lth)
        {
        e += copynbytes(e, c, dec_lth);
        *e++ = 'Z';
        }
    }


/* get_asn_num()
 * Translates an ASN.1-encoded INTEGER to a signed long.
 */
long get_asn_num(asnp)
    struct asn *asnp;
{
    long val;
    uchar *c = asn_start(asnp);
    ushort lth;
    int minus;

    val = (*c & 0x80)? -1: 0;
    for (lth = asnp->lth; lth--; val = (val << 8) + *c++);
    return val;
}


static ushort mos[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304,
    334, 365, 366};                     /* last is for leap year */

/*
 * get_asn_time()
 * Function: Converts ASN.1-encoded time to a number of seconds from midnight
 * Dec. 31, 1969
 * Inputs: Pointer to ASN structure
 *
 * Translates an ASN.1-encoded time to a number of seconds since midnight
 * Dec. 31, 1969 (GMT).
 */
ulong get_asn_time (asnp)
    struct asn *asnp;
{
    long val;
    int yr, mo, da;
    uchar *b,
        *c = asn_start(asnp),
        *e = &c[asnp->lth];

    if (*asnp->stringp != ASN_GENTIME && *asnp->stringp != ASN_UTCTIME)
        return -1;
    for (b = c; *b >= '0' && *b <= '9' && b < e; b++);
    if (b < e && ((*asnp->stringp == ASN_UTCTIME && b < &c[UTCSE]) ||
                  (*asnp->stringp == ASN_GENTIME && b < &c[GENTSE]) ||
                  (*b != 'Z' && *b != '+' && *b != '-' &&
                  (*asnp->stringp == ASN_UTCTIME || (*b != '.' && *b != ','))) ||
                  (*b == 'Z' && e != &b[UTCSFXHR]) ||
                  ((*b == '-' || *b == '+') && e != &b[UTCSFXMI + UTCMISIZ])))
        return -1;
    if(*asnp->stringp == ASN_UTCTIME)
    {
        if ((yr = get_num (&c[UTCYR],UTCYRSIZ) - UTCBASE) < 0) yr += 100;
    }
    else if ((yr = get_num (&c[GENTYR],GENTYRSIZ) - (GENTBASE)) < 0)
        return -1;
    else c += (GENTYRSIZ - UTCYRSIZ);
    if ((mo = get_num (&c[UTCMO],UTCMOSIZ)) < 1 || mo > 12)
        return -1;
    val = (yr * 365) + mos[mo - 1] + ((yr + (UTCBASE % 4)) / 4) -
        ((!((yr + UTCBASE) % 4) && mo < 3)? 1: 0);
    if ((da = get_num (&c[UTCDA],UTCDASIZ)) < 1 ||
        da > mos[mo] - mos[mo - 1] +
        ((!((yr + UTCBASE) % 4) && mo == 2)? 1: 0)) return -1;
    val += da - 1;
    if ((yr = get_num (&c[UTCHR],UTCHRSIZ)) > 23) return -1;
                                        /* hour */
    val = (val * 24) + yr;
    if ((yr = get_num (&c[UTCMI],UTCMISIZ)) > 59 || mo > 59) return -1;
                                        /* min */
    if (b > &c[UTCSE]) mo = get_num (&c[UTCSE],UTCSESIZ);
                                        /* seconds */
    else mo = 0;
    val = (val * 3600) + (yr * 60) + mo;
    if (*asnp->stringp == ASN_GENTIME && (*b == '.' || *b == ','))
        for (b++; b < e && *b >= '0' && *b <= '9'; b++);
    if (*b == '+' || *b == '-')
    {
        if ((yr = get_num (&b[UTCSFXHR],UTCHRSIZ)) > 23 ||
            (mo = get_num (&b[UTCSFXMI],UTCMISIZ)) > 59)
            return -1;
        yr = (yr * 60) + mo;            /* diff in minutes */
        if (*b == '+') yr = -yr;
        val += (60 * yr);               /* adjust by diff of seconds */
    }
    return val;
}

int get_int_lth(asnp)
    struct asn *asnp;
{            /* assumes a positive integer of more than 1 byte */
    uchar *c = asn_start(asnp);
    if (!*c) return asnp->lth - 1;
    return asnp->lth;
}

ulong get_num (uchar *c, int lth)
    {
    ulong val;

    for (val = 0; lth--; val = (val * 10) + *c++ - '0');
    return val;
    }

int move_over(start, lth, diff)
    uchar *start;
    int lth, diff;
    {
    register uchar *b, *c;
    uchar *e;
    if (diff > 0)
        for (c = &start[lth], b = &c[diff]; c > start; *(--b) = *(--c));
    else
        {
        for (b = start, c = &b[diff], e = &b[lth]; b < e; *c++ = *b++);
        while (c < e) *c++ = 0;   /* makes debugging easier */
        }
    return diff;
    }

mo_diff (asnt1p,asnt2p)
    struct asn *asnt1p, *asnt2p;
{
/**
Function: Calculates the number of months between date 1 and date 2, rounding
up or down according to the days in each date.
**/
    uchar *t1, *t2;
    int yr, mo, da, diff, last;

    t1 = asn_start(asnt1p);
    if (*asnt1p->stringp == ASN_GENTIME) t1 += 2;
    t2 = asn_start(asnt2p);
    if (*asnt2p->stringp == ASN_GENTIME) t2 += 2;
    if ((diff = get_num(&t2[UTCYR],UTCYRSIZ) -
         (yr = get_num(&t1[UTCYR],UTCYRSIZ))) < 0) diff += 100;
    diff = (diff * 12) + get_num (&t2[UTCMO],UTCMOSIZ) -
        (mo = get_num(&t1[UTCMO],UTCMOSIZ));
    if (get_num(&t2[UTCDA],UTCDASIZ) < get_num(&t1[UTCDA],UTCDASIZ))
	diff -= (diff >= 0)? 1: -1;
    return diff;
}

/*
 * Converts the binary number 'val' to a right-justified
 * ASCII decimal number of 'lth' bytes, starting at 'to'.
 * Returns 0 if no overflow.
 */
put_num (to,val,lth)
    uchar *to;
    ulong val;
    int lth;
{
    uchar *c;

    for (c = &to[lth]; c > to; )
    {
        *(--c) = (val % 10) + '0';
        val /= 10;
    }
    return val;
}

/*
 * put_asn_gentime()
 * Translates a number of seconds to an ASN.1-encoded string in
 * GeneralizedTime GMT format.
 * Returns count of ASN.1 bytes created.
 */
put_asn_gentime(to, time)
    uchar *to;
    ulong time;
{
    int ansr = put_asn_time(&to[2], time);

    to[1] = ansr;
    if (to[4] >= '7')
	{
        to[2] = '1';
	to[3] = '9';
	}
    else
	{
        to[2] = '2';
	to[3] = '0';
	}
    *to = ASN_GENTIME;
    return ansr + 2;
}

void put_asn_lth(start, lth)
    uchar *start;
    int lth;
    {
    uchar *c;
    if (lth < 128) start[-1] = lth;
    else
	{
        for (c = start; lth; *(--c) = lth & 0xFF, lth >>= 8);
	c[-1] = (ASN_INDEF + (start - c));
	}
    }

/*
 * put_asn_num()
 * Translates a ulong number to an ASN.1-encoded string of specified types
 * 'typ1', 'typ2'.
 * Returns count of ASN.1 bytes created.
 */
put_asn_num(to, from, typ1, typ2)
    uchar *to, typ1, typ2;
    ulong from;
{
    uchar *c, *e, *b = to;

    for (c = (uchar *)&from, e = &c[sizeof (ulong)]; c < e; c++)
    {
        if ((from & 0x80000000))
        {
            if (*c != (uchar)0xFF || (!(c[1] & (uchar)0x80))) break;
        }
        else if (*c) break;
    }
    if (c >= e) c--;
    *b++ = typ1;
    if ((typ1 & 0x1F) == 0x1F) *b++ = typ2;
    *b++ = 0;
    if ((*c & 0x80) && !(from & 0x80000000)) *b++ = 0;
    while (c < e) *b++ = *c++;
    b += set_asn_lth (to,b);
    return (b - to);
}

/*
 * put_asn_time()
 * Translates a number of seconds to an ASN.1-encoded string in UTCTime GMT
 * format.
 * Returns count of ASN.1 bytes created.
 */
put_asn_time(to, time)
    uchar *to;
    ulong time;
{
    ushort *mop;
    long da, min, sec;
    uchar *c = &to[2];

    *to = ASN_UTCTIME;
    to[1] = 0;
    sec = (time % 60);
    time /= 60;
    min = (time % 60);
    time /= 60;
    da = (time % 24);
    if (put_num (&c[UTCSE],(ulong)sec,UTCSESIZ) < 0 ||
        put_num (&c[UTCMI],(ulong)min,UTCMISIZ) < 0 ||
        put_num (&c[UTCHR],(ulong)da,UTCHRSIZ) < 0) return -1;
    time /= 24;                         /* day number */
    time += (((UTCBASE - 1) % 4) * 365);/* days since leap year before base
                                           year*/
    da = time  % 1461;                  /* da # in quadrenniad */
    time /= 1461;                       /* quadrenniads since prior leap yr */
    sec = ((time * 4) + ((da == 1460)? 3 : (da / 365)) - ((UTCBASE - 1) % 4));
                                        /* yrs since base yr */
    if (da == 1460) da = 365;
    else da %= 365;
    for (mop = mos; da >= *mop; mop++);
    if (mop > &mos[12]) mop--;
    if ((sec % 4) == (UTCBASE % 4))     /* leap year */
    {
        if (da == 59) mop--;            /* Feb 29  */
        else if (da > 59 && (da -= 1) < mop[-1]) mop--;
    }
    if (put_num(&c[UTCDA],(ulong)(da + 1 - mop[-1]),UTCDASIZ) < 0 ||
        put_num(&c[UTCMO],(ulong)(mop - mos),UTCMOSIZ) < 0 ||
        put_num(&c[UTCYR],(ulong)(sec + UTCBASE),UTCYRSIZ) < 0) return -1;
    c += UTCSE + UTCSESIZ;
    *c++ = 'Z';
    c += set_asn_lth(to,c);
    return (c - to);
}

/* $b(*g"set_asn_lth.txt"b)
 */
set_asn_lth(s,e)
    uchar *s, *e;
    {
    uchar *c;
    ulong lth;
    int fwd, bwd;

    bwd = 0;
                                                                    /* step 1 */
    asn_typ(&s);
    if (*s++ & ASN_INDEF)           /* shrink to 1-digit length */
        {
        bwd = (int)(s[-1] & (~ASN_INDEF & 0xFF));
        copynbytes (s,&s[bwd],((e -= bwd) - s));
        }
                                                                    /* step 2 */
    lth = e - s;
    if (!(fwd = calc_asn_lth_lth(lth))) s[-1] = lth;
    else                    /* expand for correct size of lth field */
        {
        for (c = e, e += fwd; c > s; *(--e) = *(--c));
	put_asn_lth(e, lth);
        for (c = (uchar *)&lth, c += sizeof (ulong); e > s; *(--e) = *(--c));
        }
    return (fwd - bwd);
    }

/*
 * skip_asn()
 * Skip forward from the asn structure pointed to by 'asnp' for 'count' such
 * structures of that same level.  If count is negative, go backwards,
 * but do not go beyond base.
 */
struct asn *skip_asn(asnp, base, count)
    struct asn *asnp, *base;
    int count;
{
    int dir, level = asnp->level;

    if (count > 0) dir = 1;
    else if (count < 0) dir = -1;
    else return asnp;
    for (asnp += dir; asnp->level >= level && asnp > base; asnp += dir)
    {
        if (asnp->level == level && !(count -= dir)) break;
    }
    return asnp;
}

struct fasn *skip_fasn(struct fasn *tfasnp1, struct fasn *tfasnp2, int num)
    {
    return (struct fasn *)skip_asn((struct asn *)tfasnp1, (struct asn *)tfasnp2,
        num);
    }

int test_set(struct asn *easnp)
    {
/**
Function: Tests members of a SET to be sure they conform to DER
Input: Ptr to struct asn for SET
Returns: 1 if OK, -1 if not
Procedure:
1. Starting with the first and second members of the SET
   WHILE the later member is still in the set
	IF the later member should be earlier, return -1
	Advance to next members
2. Return 1
**/
    struct asn *lasnp;
    uchar *b, *c, *e, *esetp;
							    /* step 1 */
    esetp = &asn_start(easnp)[easnp->lth];
    easnp++;
    for (lasnp = skip_asn(easnp, easnp, 1); lasnp->stringp &&
        lasnp->stringp < esetp;
        lasnp = skip_asn((easnp = lasnp), lasnp, 1))
	{
	for (b = lasnp->stringp, c = easnp->stringp, e = &c[FULL_LENGTH(easnp)];
	    c < e && *b == *c; b++, c++);
	if (*b < *c) return -1;
	}
							    /* step 2 */
    return 1;
    }

/*
 * validate_int()
 * Validates an ASN.1-encoded integer string.
 * Returns 0 if no error, else BAD_ASN1.
 */
validate_int (struct asn *asnp)
    {
    uchar *c;

    c = asn_start(asnp);
    if (*asnp->stringp != ASN_INTEGER ||
        (asnp->lth > 1 &&
        ((!*c && !(c[1] & 0x80)) || (*c == 0xFF && (c[1] & 0x80)))))
        return BAD_ASN1;
    return NO_ERR;
    }


