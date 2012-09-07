/*
 * $Id$ 
 */
/*****************************************************************************
File:     casn_time.c
Contents: Functions to handle ASN.1 time objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

The BER encodings of time are defined by X.680-0207 and ISO 8601
UTCTime: YYMMDDHHMM{suffix} or YYMMDDHHMMSS{suffix}
GeneralizedTime: YYYYMMDDHHMMSS[.fff...]{suffix}
{suffix} can be one of
1. Z
2. +hhmm
3. -hhmm

The DER encodings of time are defined by X.690-0207, which further
restrict the BER encodings to provide a canonical form.  For example,
"Z" is required, and trailing zeros in fractional seconds are
forbidden.

In the code below, UTCTime's two-digit year is interpreted as
described by RFC 5280, Section 4.1.2.5.1.

4.1.2.5.1. UTCTime

   The universal time type, UTCTime, is a standard ASN.1 type intended
   for representation of dates and time.  UTCTime specifies the year
   through the two low-order digits and time is specified to the
   precision of one minute or one second.  UTCTime includes either Z
   (for Zulu, or Greenwich Mean Time) or a time differential.

   For the purposes of this profile, UTCTime values MUST be expressed in
   Greenwich Mean Time (Zulu) and MUST include seconds (i.e., times are
   YYMMDDHHMMSSZ), even where the number of seconds is zero.  Conforming
   systems MUST interpret the year field (YY) as follows:

      Where YY is greater than or equal to 50, the year SHALL be
      interpreted as 19YY; and

      Where YY is less than 50, the year SHALL be interpreted as 20YY.

WARNING: The code does not currently handle fractional seconds in
GeneralizedTime, nor minutes-only UTCTime.  Thus, it is not a general
ASN.1 UTCTime or GeneralizedTime implementation, but rather follows
the restrictions prescribed by RFC 5280 sections 4.1.2.5.1 and
4.1.2.5.2.

KNOWN BUGS: There are problems with leap year adjustments starting the
year 2100.  In addition, it is not clear that [read/write]_casn_time
handle time zones correctly.
*****************************************************************************/

char casn_time_sfcsid[] = "@(#)casn_time.c 851P";
#include "casn.h"
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <limits.h>

#define UTCBASE 70              // base year 1970 (unix epoch)
#define UTCYR 0                 // 0 (UTC year position)
#define UTCYRSIZ 2              // 2-digit year
#define UTCMO (UTCYR + UTCYRSIZ)        // 2 (UTC month position)
#define UTCMOSIZ 2              // 2-digit month
#define UTCDA  (UTCMO + UTCMOSIZ)       // 4 (UTC day position)
#define UTCDASIZ 2              // 2-digit day
#define UTCHR  (UTCDA + UTCDASIZ)       // 6 (UTC hour position)
#define UTCHRSIZ 2              // 2-digit hour
#define UTCMI  (UTCHR + UTCHRSIZ)       // 8 (UTC minute position)
#define UTCMISIZ 2              // 2-digit minute
#define UTCSE (UTCMI + UTCMISIZ)        // 10 (UTC seconds position)
#define UTCSESIZ 2              // 2-digit seconds
#define UTCSFXHR 1              // suffix hour position (after +/-)
#define UTCSFXMI (UTCSFXHR + UTCHRSIZ)  // 3 (suffix minute position)
#define UTCT_SIZE 17            // 12 (YYMMDDHHMMSS) + 1 (Z/+/-) + 4 (hhmm)
#define GENBASE (1900 + UTCBASE)        // base year 1970 (unix epoch)
#define GENYR 0                 // GeneralizedTime year position
#define GENYRSIZ 4              // 4-digit year
#define GENMO 4                 // GeneralizedTime month position
#define GENMOSIZ UTCMOSIZ       // 2-digit month
#define GENDA 6                 // GeneralizedTime day position
#define GENDASIZ UTCDASIZ       // 2-digit day
#define GENHR 8                 // GeneralizedTime hour position
#define GENHRSIZ UTCHRSIZ       // 2-digit hour
#define GENMI 10                // GeneralizedTime minute position
#define GENMISIZ UTCMISIZ       // 2-digit minute
#define GENSE 12                // GeneralizedTime seconds position
#define GENSESIZ UTCSESIZ       // 2-digit seconds
#define GENSFXHR 1              // suffix hour position (after +/-)
#define GENSFXMI 3              // suffix minute position

extern int _casn_obj_err(
    struct casn *,
    int),
    _check_filled(
    struct casn *casnp),
    _fill_upward(
    struct casn *,
    int);
extern void *_free_it(
    void *);

static ushort _mos[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304,
    334, 365, 366
};                              /* last is for leap year */

/**
 * Converts lth decimal digits, starting at c, to a number
 *
 * return non-negative integer, or negative on failure
 */
static int get_num(
    const char *c,
    int lth)
{
    intmax_t val = 0;
    int i;
    for (i = 0; i < lth; ++i)
    {
        if (c[i] >= '0' && c[i] <= '9')
        {
            val = val * 10 + (c[i] - '0');
        }
        else
        {
            return -1;
        }

        if (val > INT_MAX || val < 0)
        {
            return -1;
        }
    }
    return (int)val;
}

/** Returns true (nonzero) if year is a leap year.
 *
 * \remark http://en.wikipedia.org/wiki/Gregorian_calendar
 * 
 * Every year that is exactly divisible by four is a leap year, except
 * for years that are exactly divisible by 100; the centurial years
 * that are exactly divisible by 400 are still leap years. For
 * example, the year 1900 is not a leap year; the year 2000 is a leap
 * year.
 */
static int is_leapyear(
    int year)
{
    if (year % 400 == 0)
        return 1;
    else if (year % 100 == 0)
        return 0;
    else if (year % 4 == 0)
        return 1;
    else
        return 0;
}

/**
 * Convert struct tm to 64-bit signed integer.
 *
 * Mostly analogous to mktime(), with 64 bit output (unlike time_t
 * which may be 32 or 64 depending on the system).  The mktime64_gmt()
 * function shall convert the broken-down time, expressed as GMT, in
 * the structure pointed to by timeptr, into a time since the Epoch
 * value. The original values of the tm_wday and tm_yday components of
 * the structure are ignored, and the original values of the other
 * components are not restricted to the ranges described in <time.h>.
 *
 * Unlike POSIX mktime(), timeptr is NOT modified upon successful
 * completion.  Nor is the output corrected for timezone and seasonal
 * time adjustments.  Therefore, the input is assumed to be GMT,
 * e.g. the output of the gmtime() function.
 *
 * \return The specified time since the Epoch encoded as a value of
 * type int64_t.  If the time since the Epoch cannot be represented,
 * the function shall return the value (int64_t)-1.  In particular,
 * times before January 1, 1970 GMT cannot be represented and will
 * return -1.
 *
 * \remark Note that leap-seconds will cause ambiguities; "Unix time"
 * is neither a linear representation of time nor a true
 * representation of UTC, as it cannot unambiguously represent UTC
 * leap seconds (e.g. December 31, 1998 23:59:60).
 */
static int64_t mktime64_gmt(
    const struct tm *timeptr)
{
    int64_t t = 0;
    int64_t tm_sec,
        tm_min,
        tm_hour,
        tm_mday,
        tm_mon,
        tm_year,
        tm_yday;

    // Minimally check pointer and bounds.
    if (!timeptr || timeptr->tm_year < 70)
        return (int64_t) - 1;

    // Cast timeptr members to 64-bit integers.
    tm_sec = timeptr->tm_sec;
    tm_min = timeptr->tm_min;
    tm_hour = timeptr->tm_hour;
    tm_mday = timeptr->tm_mday;
    tm_mon = timeptr->tm_mon;
    tm_year = timeptr->tm_year;

    // Compute tm_yday based on tm_mday, tm_mday, and tm_myear
    if (tm_mon < 0 || tm_mon > 11)
        return (int64_t) - 1;
    tm_yday = _mos[tm_mon] + (tm_mday - 1);
    // Must add leap day if March or later and it's a leap year.
    if (is_leapyear(tm_year + 1900) && tm_mon >= 2)
        tm_yday++;

    /*
     * Compute seconds since epoch.  Equation reference: Base Definitions
     * volume of IEEE Std 1003.1-2001, Section 4.14, Seconds Since the Epoch.
     * http://pubs.opengroup.org/onlinepubs/007904875/basedefs/xbd_chap04.html#tag_04_14
     * Note: since all timeptr members were converted from int to int64_t, there is no
     * danger of overflow on systems where int is 32-bit. 
     */
    t = tm_sec + tm_min * 60 + tm_hour * 3600 + tm_yday * 86400 +
        (tm_year - 70) * 31536000 + ((tm_year - 69) / 4) * 86400 -
        ((tm_year - 1) / 100) * 86400 + ((tm_year + 299) / 400) * 86400;

    // As required by POSIX, we did not check bounds on timeptr members,
    // so we must now check for a negative result.
    if (t < 0)
        return (int64_t) - 1;

    return t;
}

int diff_casn_time(
    struct casn *casnp1,
    struct casn *casnp2)
{
    int64_t t1,
        t2;

    if (read_casn_time(casnp1, &t1) <= 0 || read_casn_time(casnp2, &t2) <= 0)
        return -2;
    if (t1 > t2)
        return 1;
    if (t1 < t2)
        return -1;
    return 0;
}

int _gentime_to_ulong(
    int64_t * valp,
    char *fromp,
    int lth)
{
    int yr,
        mo,
        da,
        hr,
        mi,
        se;
    int64_t val = 0;
    char *b,
       *ep;

    for (b = fromp, ep = &fromp[lth]; b < ep && *b >= '0' && *b <= '9'; b++);
    if (b < ep && (b < &fromp[GENSE] ||
                   (*b != 'Z' && *b != '+' && *b != '-') ||
                   (*b == 'Z' && ep != &b[GENSFXHR]) ||
                   (*b < '0' && ep != &b[GENSFXMI + GENMISIZ])))
        return -1;
    if ((yr = (int)get_num(&fromp[GENYR], GENYRSIZ) - GENBASE) < 0)
        return -1;
    if ((mo = (int)get_num(&fromp[GENMO], GENMOSIZ)) < 1 || mo > 12)
        return -1;
    // calculate number of days until start of the month
    val = (yr * 365) + _mos[mo - 1] + ((yr + (UTCBASE % 4)) / 4);
    if (!((yr + UTCBASE) % 4) && mo < 3)
        val--;
    if (val < 0)
        return -1;              // went around the end?
    int modays = _mos[mo] - _mos[mo - 1];
    int leap = 1;
    // not leap year if not divisible by 4 OR 
    // at even century that is not divisible by 4
    if ((((yr + UTCBASE)) % 4) > 0 || ((yr / 100) % 4) > 0)
        leap = 0;
    if (mo == 2 && leap)
        modays++;
    if ((da = (int)get_num(&fromp[GENDA], GENDASIZ)) < 1 || da > modays)
        return -1;
    // add in this month's days
    val += da - 1;
    if (&fromp[GENHR] >= ep ||  /* hour */
        (hr = (int)get_num(&fromp[GENHR], GENHRSIZ)) > 23 || hr < 0)
        return -1;
    val = (val * 24) + hr;
    if (val < 0)
        return -1;
    if (&fromp[GENMI] >= ep ||  /* min */
        (mi = (int)get_num(&fromp[GENMI], GENMISIZ)) > 59 || mi < 0)
        return -1;
    if (b <= &fromp[GENSE])
        se = 0;                 /* seconds */
    else if ((se = (int)get_num(&fromp[GENSE], GENSESIZ)) > 59 || se < 0)
        return -1;
    val = (val * 3600) + (mi * 60) + se;
    if (val < 0)
        return -1;
    if (*b == '+' || *b == '-')
    {
        int xtra = 0;
        if ((hr = (int)get_num(&b[GENSFXHR], GENHRSIZ)) > 23 || hr < 0 ||
            (mi = (int)get_num(&b[GENSFXMI], GENMISIZ)) > 59 || mi < 0)
            return -1;
        xtra = (hr * 60) + mi;  /* diff in minutes */
        if (*b == '-')
            xtra = -xtra;
#define HIXTRA (14 * 60)        // easternmost time zone in minutes
#define LOXTRA (-12 *60)        // westernmost time zone in minutes
        if (xtra > HIXTRA || xtra < LOXTRA)
            return -1;
        val -= (60 * xtra);     /* adjust to GMT by diff of seconds */
    }
    if (val < 0)
        return -1;
    *valp = val;
    return GENSE + GENSESIZ + 1;
}

int _utctime_to_ulong(
    int64_t * valp,
    char *fromp,
    int lth)
{
    int yr;
    char *b,
       *ep;

    for (b = fromp, ep = &fromp[lth]; b < ep && *b >= '0' && *b <= '9'; b++);
    if (lth > UTCT_SIZE ||
        (b < ep && b < &fromp[UTCSE]) ||
        (*b != 'Z' && *b != '+' && *b != '-') ||
        (*b == 'Z' && ep != &b[UTCSFXHR]) ||
        (*b < '0' && ep != &b[UTCSFXMI + UTCMISIZ]))
        return -1;
    char genfrom[32];
    memset(genfrom, 0, 32);

    if ((size_t) lth + 2 > sizeof(genfrom))
        return -1;

    yr = (int)get_num(&fromp[UTCYR], UTCYRSIZ);
    if (yr < 0)
        return -1;
    if (yr < 50)                // rfc5280#section-4.1.2.5.1
        strcpy(genfrom, "20");
    else
        strcpy(genfrom, "19");
    memcpy(&genfrom[2], fromp, lth);
    int ansr = _gentime_to_ulong(valp, genfrom, lth + 2);
    if (ansr <= 0)
        return ansr;
    return ansr - 2;
}



int read_casn_time(
    struct casn *casnp,
    int64_t * valp)
{
    /*
     * Function: Converts contents of decoded UTC or GEN time to a number of
     * seconds from midnight Dec. 31, 1969 Inputs: Pointer to ASN structure
     * Pointer to ulong for count Returns: IF error, -1, ELSE length of time
     * field 
     */
    int ansr;

    if (casnp->type == ASN_CHOICE)
    {
        if (vsize_casn(&casnp[1]))
            casnp = &casnp[1];
        else if (vsize_casn(&casnp[2]))
            casnp = &casnp[2];
        else
            return _casn_obj_err(casnp, ASN_TIME_ERR);
    }
    if ((ansr = _check_filled(casnp)) < 0 || (casnp->type != ASN_UTCTIME &&
                                              casnp->type != ASN_GENTIME))
        return -1;
    if (!ansr)
        return 0;
    ansr = casnp->lth;
    uchar timebuf[32];
    if (casnp->type == ASN_GENTIME)
    {
        if ((size_t) ansr + 1 > sizeof(timebuf))
            return _casn_obj_err(casnp, ASN_TIME_ERR);
        memcpy(timebuf, casnp->startp, ansr);
    }
    else
    {
        if ((size_t) ansr + 2 + 1 > sizeof(timebuf))
            return _casn_obj_err(casnp, ASN_TIME_ERR);
        memcpy(&timebuf[2], casnp->startp, ansr);
        if (timebuf[2] >= '5')  // rfc5280#section-4.1.2.5.1
            strncpy((char *)timebuf, "19", 2);
        else
            strncpy((char *)timebuf, "20", 2);
        ansr += 2;
    }
    timebuf[ansr] = 0;
    if (_gentime_to_ulong(valp, (char *)timebuf, ansr) < 0)
        return _casn_obj_err(casnp, ASN_TIME_ERR);
    return casnp->lth;
}

static ulong put_num(
    char *to,
    ulong val,
    int lth)
{
    char *c;
    for (c = &to[lth]; c > to;)
    {
        *(--c) = (char)(val % 10) + '0';
        val /= 10;
    }
    return val;
}

int write_casn_time(
    struct casn *casnp,
    int64_t time)
{
    ushort *mop;
    long da,
        min,
        sec,
        years_since_base;
    char *c,
       *to;
    int err = 0;

    if (casnp->type != ASN_UTCTIME && casnp->type != ASN_GENTIME)
        return -1;
    _free_it(casnp->startp);
    casnp->startp = (uchar *) calloc(1, 20);
    c = to = (char *)casnp->startp;
    if (casnp->type == ASN_GENTIME)
        c += 2;
    sec = (time % 60);
    time /= 60;
    min = (time % 60);
    time /= 60;
    da = (time % 24);
    put_num(&c[UTCSE], (ulong) sec, UTCSESIZ);
    put_num(&c[UTCMI], (ulong) min, UTCMISIZ);
    put_num(&c[UTCHR], (ulong) da, UTCHRSIZ);
    time /= 24;                 /* day number */
    time += (((UTCBASE - 1) % 4) * 365);        /* days since leap year before 
                                                 * base year */
    da = time % 1461;           /* da # in quadrenniad */
    time /= 1461;               /* quadrenniads since prior leap yr */
    years_since_base =
        ((time * 4) + ((da == 1460) ? 3 : (da / 365)) - ((UTCBASE - 1) % 4));
    /*
     * yrs since base yr 
     */
    if (da == 1460)
        da = 365;
    else
        da %= 365;
    for (mop = _mos; da >= *mop; mop++);
    if (mop > &_mos[12])
        mop--;
    if ((years_since_base % 4) == (UTCBASE % 4))        /* leap year */
    {
        if (da == 59)
            mop--;              /* Feb 29 */
        else if (da > 59 && (da -= 1) < mop[-1])
            mop--;
    }
    put_num(&c[UTCDA], (ulong) (da + 1 - mop[-1]), UTCDASIZ);
    put_num(&c[UTCMO], (ulong) (mop - _mos), UTCMOSIZ);
    // is it UTCTIME beyond the upper limit?
    if (casnp->type == ASN_UTCTIME && years_since_base >= (2050 - 1970))
        return -1;
    put_num(&c[UTCYR], (ulong) (years_since_base + UTCBASE), UTCYRSIZ);
    c += UTCSE + UTCSESIZ;
    *c++ = 'Z';
    if (casnp->type == ASN_GENTIME)
    {
        if (years_since_base >= 30)
        {
            // FIXME: this is broken for dates beyond 2199
            *to = '2';
            to[1] = (years_since_base < 130) ? '0' : '1';
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

int adjustTime(
    struct casn *timep,
    long basetime,
    char *deltap)
{
    // if they passed in a NULL for deltap, just use basetime
    if (deltap != NULL)
    {
        char *unitp = &deltap[strlen(deltap) - 1];
        if (*unitp == 'Z')
        {
            // absolute time
            if (strlen(deltap) == 15)   /* generalized time? */
                /*
                 * this fn doesn't handle generalizedtime, strip century 
                 */
                deltap += (15 - 13);
            else if (strlen(deltap) != 13)      /* utc time? */
                return -1;      /* bad format */
            if (write_casn(timep, (uchar *) deltap, 13) < 0)
                return -1;      /* bad format */
        }
        else if (strchr("YMWDhms", *unitp) != 0)
        {
            // relative time
            ulong val;
            sscanf(deltap, "%ld", &val);
            if (*unitp == 's'); // val is right
            else if (*unitp == 'm')
                val *= 60;
            else if (*unitp == 'h')
                val *= 3600;
            else if (*unitp == 'D')
                val *= (3600 * 24);
            else if (*unitp == 'W')
                val *= (3600 * 24 * 7);
            else if (*unitp == 'M')
                val *= (3600 * 24 * 30);
            else if (*unitp == 'Y')
                val *= (3600 * 24 * 365);
            basetime += val;
            write_casn_time(timep, (ulong) basetime);
        }
        else
            return -1;          // unknown delta unit, bad call
    }
    return 0;
}
