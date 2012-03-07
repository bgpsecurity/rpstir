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
#include <stdint.h>

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
#define UTCT_SIZE 17
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
    int64_t t1, t2;

    if (read_casn_time(casnp1, &t1) <= 0 || read_casn_time(casnp2, &t2) <= 0)
	return -2;
    if (t1 > t2) return 1;
    if (t1 < t2) return -1;
    return 0;
    }

int _gentime_to_ulong(int64_t *valp, char *fromp, int lth)
    {
    int yr, mo, da, hr, mi, se;
    int64_t val = 0;
    char *b, *ep;

    for (b = fromp, ep = &fromp[lth]; b < ep && *b >= '0' && *b <= '9'; b++);
    if (b < ep && (b < &fromp[GENSE] ||
        (*b != 'Z' && *b != '+' && *b != '-') ||
        (*b == 'Z' && ep != &b[GENSFXHR]) ||
        (*b < '0' && ep != &b[GENSFXMI + GENMISIZ])))
        return -1;
    if ((yr = (int)get_num (&fromp[GENYR],GENYRSIZ) - GENBASE) < 0)
      return -1;
    if ((mo = (int)get_num (&fromp[GENMO],GENMOSIZ)) < 1 || mo > 12)
        return -1;
     // calculate number of days until start of the month
    val = (yr * 365) + _mos[mo - 1] + ((yr + (UTCBASE % 4)) / 4);
    if (!((yr + UTCBASE) % 4) && mo < 3) val--;
    if (val < 0) return -1;   // went around the end?
    int modays = _mos[mo] - _mos[mo - 1];
    int leap = 1;  
         // not leap year if not divisible by 4 OR 
         // at even century that is not divisible by 4
    if ((((yr + UTCBASE)) % 4) > 0 || ((yr / 100) % 4) > 0) leap = 0;
    if (mo == 2 && leap) modays++; 
    if ((da = (int)get_num (&fromp[GENDA],GENDASIZ)) < 1 ||
       da > modays)  return -1;
      // add in this month's days
    val += da - 1;
    if (&fromp[GENHR] >= ep ||                                   /* hour */
        (hr = (int)get_num (&fromp[GENHR],GENHRSIZ)) > 23) return -1;
    val = (val * 24) + hr;
    if (val < 0) return -1;   
    if (&fromp[GENMI] >= ep ||                                   /* min */
        (mi = (int)get_num(&fromp[GENMI], GENMISIZ)) > 59) return -1;
    if (b <= &fromp[GENSE]) se = 0;                             /* seconds */
    else if ((se = (int)get_num(&fromp[GENSE], GENSESIZ)) > 59) return -1;
    val = (val * 3600) + (mi * 60) + se;
    if (val < 0) return -1;   
    if (*b == '+' || *b == '-')
        {
        int xtra = 0;
        if ((hr = (int)get_num (&b[GENSFXHR],GENHRSIZ)) > 23 ||
            (mi = (int)get_num (&b[GENSFXMI],GENMISIZ)) > 59)
            return -1;
        xtra = (hr * 60) + mi;  /* diff in minutes */
        if (*b == '-') xtra = -xtra;
#define HIXTRA (14 * 60)  // easternmost time zone in minutes
#define LOXTRA (-12 *60)  // westernmost time zone in minutes
        if (xtra > HIXTRA || xtra < LOXTRA) 
          return -1;
        val -= (60 * xtra);  /* adjust to GMT by diff of seconds */
        }
    if (val < 0) return -1;
    *valp = val;
    return GENSE + GENSESIZ + 1 ;
    }

int _utctime_to_ulong(int64_t *valp, char *fromp, int lth)
    {
    int yr;
    char *b, *ep;

    for (b = fromp, ep = &fromp[lth]; b < ep && *b >= '0' && *b <= '9'; b++);
    if (lth > UTCT_SIZE || 
        (b < ep && b < &fromp[UTCSE]) ||
        (*b != 'Z' && *b != '+' && *b != '-') ||
        (*b == 'Z' && ep != &b[UTCSFXHR]) ||
        (*b < '0' && ep != &b[UTCSFXMI + UTCMISIZ]))
        return -1;
    char genfrom[32];
    memset(genfrom, 0, 32);

    if ((size_t)lth + 2 > sizeof(genfrom))
        return -1;
     
    yr = (int)get_num (&fromp[UTCYR],UTCYRSIZ);
    if (yr < 70) strcpy(genfrom, "20");
    else strcpy(genfrom, "19");
    memcpy(&genfrom[2], fromp, lth);
    int ansr = _gentime_to_ulong(valp, genfrom, lth += 2);
    if (ansr <= 0) return ansr;
    return ansr - 2;
    }



int read_casn_time(struct casn *casnp, int64_t *valp)
    {
/*
Function: Converts contents of decoded UTC or GEN time to a number of seconds
from midnight Dec. 31, 1969
Inputs: Pointer to ASN structure
	Pointer to ulong for count
Returns: IF error, -1, ELSE length of time field
*/
    int ansr;  

    if (casnp->type == ASN_CHOICE)
      {
      if (vsize_casn(&casnp[1])) casnp = &casnp[1];
      else if (vsize_casn(&casnp[2])) casnp = &casnp[2];
      else return _casn_obj_err(casnp, ASN_TIME_ERR);
      }
    if ((ansr = _check_filled(casnp)) < 0 || (casnp->type != ASN_UTCTIME &&
        casnp->type != ASN_GENTIME)) return -1;
    if (!ansr) return 0;
    ansr = casnp->lth;
    uchar timebuf[32];
    if (casnp->type == ASN_GENTIME)
        {
        if ((size_t)ansr + 1 > sizeof(timebuf))
            return _casn_obj_err(casnp, ASN_TIME_ERR);
        memcpy(timebuf, casnp->startp, ansr);
        }
    else 
	{
        if ((size_t)ansr + 2 + 1 > sizeof(timebuf))
            return _casn_obj_err(casnp, ASN_TIME_ERR);
        memcpy(&timebuf[2], casnp->startp, ansr);
        if (timebuf[2] >= '7') strncpy((char *)timebuf, "19", 2);
        else strncpy((char *)timebuf, "20", 2);
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

int write_casn_time(struct casn *casnp, int64_t time) 
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
       // is it UTCTIME beyond the upper limit?
    if (casnp->type == ASN_UTCTIME && leap >= 100)
      return -1; 
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
    
