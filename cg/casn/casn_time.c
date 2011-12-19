/* $Id$ */
/*****************************************************************************
File:     casn_time.c
Contents: Functions to handle ASN.1 time objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

char casn_time_sfcsid[] = "@(#)casn_time.c 851P";
#include "casn.h"
#include <stdio.h>

#define UTCBASE 70
#define UTCYR 0
#define UTCYRSIZ 2
#define UTCMO (UTCYR + UTCYRSIZ) // 2
#define UTCMOSIZ 2
#define UTCDA  (UTCMO + UTCMOSIZ) //4
#define UTCDASIZ 2
#define UTCHR  (UTCDA + UTCDASIZ) // 6
#define UTCHRSIZ 2
#define UTCMI  (UTCHR + UTCHRSIZ) // 8
#define UTCMISIZ 2
#define UTCSE (UTCMI + UTCMISIZ) // 10
#define UTCSESIZ 2
#define UTCSFXHR 1
#define UTCSFXMI (UTCSFXHR + UTCHRSIZ)  // 3
#define UTCT_SIZE 16
#define GENBASE (1900 + UTCBASE)
#define GENYR 0
#define GENYRSIZ 4
#define GENMO 4
#define GENMOSIZ UTCMOSIZ
#define GENDA 6
#define GENDASIZ UTCDASIZ
#define GENHR 8
#define GENHRSIZ UTCHRSIZ
#define GENMI 10
#define GENMISIZ UTCMISIZ
#define GENSE 12
#define GENSESIZ UTCSESIZ
#define GENSFXHR 1
#define GENSFXMI 3

extern int _casn_obj_err(struct casn *, int),
        _check_filled(struct casn *casnp),
        _fill_upward(struct casn *, int);
extern void *_free_it(void *);

static ushort _mos[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304,
    334, 365, 366};    /* last is for leap year */

static ulong get_num (const char *c, int lth)
    {
/*
Function: Converts lth decimal digits, starting at c, to a number
*/
    long val;
    for (val = 0; lth--; val = (val * 10) + *c++ - '0');
    return val;
    }

int diff_casn_time(struct casn *casnp1, struct casn *casnp2)
    {
    int diff;
    ulong t1, t2;

    if ((casnp1->type != ASN_UTCTIME && casnp1->type != ASN_GENTIME) ||
        (casnp2->type != ASN_UTCTIME && casnp2->type != ASN_GENTIME) ||
        read_casn_time(casnp1, &t1) <= 0 || read_casn_time(casnp2, &t2) <= 0)
	return -2;
    diff = t1 - t2;
    if (diff > 1) diff = 1;
    if (diff < -1) diff = -1;
    return diff;
    }

int _utctime_to_ulong(ulong *valp, char *fromp, int lth)
    {
    int yr, mo, da;
    ulong val;
    char *b, *ep;

    for (b = fromp, ep = &fromp[lth]; b < ep && *b >= '0' && *b <= '9'; b++);
    if (b < ep && (b < &fromp[UTCSE] ||
        (*b != 'Z' && *b != '+' && *b != '-') ||
        (*b == 'Z' && ep != &b[UTCSFXHR]) ||
        (*b < '0' && ep != &b[UTCSFXMI + UTCMISIZ])))
        return -1;
    if ((yr = (int)get_num (&fromp[UTCYR],UTCYRSIZ) - UTCBASE) < 0) yr += 100;
    if ((mo = (int)get_num (&fromp[UTCMO],UTCMOSIZ)) < 1 || mo > 12)
        return -1;
    val = (yr * 365) + _mos[mo - 1] + ((yr + (UTCBASE % 4)) / 4) -
        ((!((yr + UTCBASE) % 4) && mo < 3)? 1: 0);
    if ((da = (int)get_num (&fromp[UTCDA],UTCDASIZ)) < 1 ||
        da > _mos[mo] - _mos[mo - 1] +
        ((!((yr + UTCBASE) % 4) && mo == 2)? 1: 0)) return -1;
    val += da - 1;
    if (&fromp[UTCHR] >= ep ||                                   /* hour */
        (yr = (int)get_num (&fromp[UTCHR],UTCHRSIZ)) > 23) return -1;
    val = (val * 24) + yr;
    if (&fromp[UTCMI] >= ep ||                                   /* min */
        (yr = (int)get_num(&fromp[UTCMI], UTCMISIZ)) > 59) return -1;
    if (b <= &fromp[UTCSE]) mo = 0;                             /* seconds */
    else if ((mo = (int)get_num(&fromp[UTCSE], UTCSESIZ)) > 59) return -1;
    val = (val * 3600) + (yr * 60) + mo;
    if (*b == '+' || *b == '-')
        {
        if ((yr = (int)get_num (&b[UTCSFXHR],UTCHRSIZ)) > 23 ||
            (mo = (int)get_num (&b[UTCSFXMI],UTCMISIZ)) > 59)
            return -1;
        if ((yr = (yr * 60) + mo) > 780) return -1;  /* diff in minutes */
        if (*b == '+') yr = -yr;
        val += (60 * yr);           /* adjust by diff of seconds */
        }
    *valp = val;
    return 1;
    }

int _gentime_to_ulong(ulong *valp, char *fromp, int lth)
    {
    int yr, mo, da;
    long long val = 0;
    char *b, *ep;

    for (b = fromp, ep = &fromp[lth]; b < ep && *b >= '0' && *b <= '9'; b++);
    if (b < ep && (b < &fromp[GENSE] ||
        (*b != 'Z' && *b != '+' && *b != '-') ||
        (*b == 'Z' && ep != &b[GENSFXHR]) ||
        (*b < '0' && ep != &b[GENSFXMI + GENMISIZ])))
        return -1;
    if ((yr = (int)get_num (&fromp[GENYR],GENYRSIZ) - GENBASE) < 0) yr += 100;
    if ((mo = (int)get_num (&fromp[GENMO],GENMOSIZ)) < 1 || mo > 12)
        return -1;
    val = (yr * 365) + _mos[mo - 1] + ((yr + (GENBASE % 4)) / 4) -
        ((!((yr + GENBASE) % 4) && mo < 3)? 1: 0);
    if ((da = (int)get_num (&fromp[GENDA],GENDASIZ)) < 1 ||
        da > _mos[mo] - _mos[mo - 1] +
        ((!((yr + GENBASE) % 4) && mo == 2)? 1: 0)) return -1;
    val += da - 1;
    if (&fromp[GENHR] >= ep ||                                   /* hour */
        (yr = (int)get_num (&fromp[GENHR],GENHRSIZ)) > 23) return -1;
    val = (val * 24) + yr;
    if (&fromp[GENMI] >= ep ||                                   /* min */
        (yr = (int)get_num(&fromp[GENMI], GENMISIZ)) > 59) return -1;
    if (b <= &fromp[GENSE]) mo = 0;                             /* seconds */
    else if ((mo = (int)get_num(&fromp[GENSE], GENSESIZ)) > 59) return -1;
    val = (val * 3600) + (yr * 60) + mo;
    if (val > 0xFFFFFFFF) return -1;
    if (*b == '+' || *b == '-')
        {
        if ((yr = (int)get_num (&b[GENSFXHR],GENHRSIZ)) > 23 ||
            (mo = (int)get_num (&b[GENSFXMI],GENMISIZ)) > 59)
            return -1;
        if ((yr = (yr * 60) + mo) > 780) return -1;  /* diff in minutes */
        if (*b == '+') yr = -yr;
        val += (60 * yr);           /* adjust by diff of seconds */
        }
    *valp = val;
    return 1;
    }


int read_casn_time(struct casn *casnp, ulong *valp)
    {
/*
Function: Converts contents of decoded UTC or GEN time to a number of seconds
from midnight Dec. 31, 1969
Inputs: Pointer to ASN structure
	Pointer to ulong for count
Returns: IF error, -1, ELSE length of time field
*/
    int ansr;  

    if ((ansr = _check_filled(casnp)) < 0 || (casnp->type != ASN_UTCTIME &&
        casnp->type != ASN_GENTIME)) return -1;
    if (!ansr) return 0;
    ansr = casnp->lth;
    uchar timebuf[32];
    if (casnp->type == ASN_GENTIME) memcpy(timebuf, casnp->startp, ansr);
    else 
	{
        timebuf[0] = '1';
        timebuf[1] = '9';
        memcpy(&timebuf[2], casnp->startp, ansr);
        ansr += 2;
        }
    timebuf[ansr] = 0;
    if (_gentime_to_ulong(valp, (char *)timebuf, ansr) < 0)
        return _casn_obj_err(casnp, ASN_TIME_ERR);
    return casnp->lth;
    }

static ulong put_num (char *to, ulong val, int lth)
    {
    char *c;
    for (c = &to[lth]; c > to; )
        {
        *(--c) = (char)(val % 10) + '0';
        val /= 10;
        }
    return val;
    }

int write_casn_time(struct casn *casnp, ulong time) 
    {
    ushort *mop;
    long da, min, sec, leap;
    char *c, *to;
    int err = 0;

    if (casnp->type != ASN_UTCTIME && casnp->type != ASN_GENTIME) return -1;
    _free_it(casnp->startp);
    casnp->startp = (uchar *)calloc(1, 20);
    c = to = (char *)casnp->startp;
    if (casnp->type == ASN_GENTIME) c += 2;
    sec = (time % 60);
    time /= 60;
    min = (time % 60);
    time /= 60;
    da = (time % 24);
    put_num (&c[UTCSE],(ulong)sec,UTCSESIZ);
    put_num (&c[UTCMI],(ulong)min,UTCMISIZ);
    put_num (&c[UTCHR],(ulong)da,UTCHRSIZ);
    time /= 24;             /* day number */
    time += (((UTCBASE - 1) % 4) * 365); /* days since leap year before base year */
    da = time  % 1461; /* da # in quadrenniad */
    time /= 1461;                        /* quadrenniads since prior leap yr */
    leap = ((time * 4) + ((da == 1460)? 3 : (da / 365)) - ((UTCBASE - 1) % 4));
                                    /* yrs since base yr */
    if (da == 1460) da = 365;
    else da %= 365;
    for (mop = _mos; da >= *mop; mop++);
    if (mop > &_mos[12]) mop--;
    if ((leap % 4) == (UTCBASE % 4))  /* leap year */
        {
        if (da == 59) mop--;  /* Feb 29  */
        else if (da > 59 && (da -= 1) < mop[-1]) mop--;
        }
    put_num (&c[UTCDA],(ulong)(da + 1 - mop[-1]),UTCDASIZ);
    put_num (&c[UTCMO],(ulong)(mop - _mos),UTCMOSIZ);
    put_num (&c[UTCYR],(ulong)(leap + UTCBASE),UTCYRSIZ);
    c += UTCSE + UTCSESIZ;
    *c++ = 'Z';
    if (casnp->type == ASN_GENTIME)
	{
	if (leap >= 30)
          {
          *to = '2';
          to[1] = (leap < 130)? '0': '1';
          }
	else
	    {
	    *to = '1';
	    to[1] = '9';
	    }
	}
    casnp->lth = (c - to);
    if ((err = _fill_upward(casnp, ASN_FILLED_FLAG)) < 0)
        return _casn_obj_err(casnp, -err);
    return casnp->lth;
    }
    
