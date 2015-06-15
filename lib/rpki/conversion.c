#include "util/inet.h"
#include "rpwork.h"

void cvt_asn(
    struct iprange *torangep,
    struct IPAddressOrRangeA *asnp)
{
    struct casn *locasn,
       *hicasn;
    if (vsize_casn(&asnp->addressPrefix))
        locasn = hicasn = &asnp->addressPrefix;
    else
    {
        locasn = &asnp->addressRange.min;
        hicasn = &asnp->addressRange.max;
    }
    uchar locbuf[20];
    int siz = read_casn(locasn, locbuf) - 1;
    memset(torangep->lolim, 0, sizeof(torangep->lolim));
    memcpy(torangep->lolim, &locbuf[1], siz);
    siz = read_casn(hicasn, locbuf) - 1;
    memset(torangep->hilim, -1, sizeof(torangep->hilim));
    memcpy(torangep->hilim, &locbuf[1], siz);
    // fill in unused bits in last byte with ones
    if (locbuf[0])
        torangep->hilim[siz - 1] |= ((1 << locbuf[0]) - 1);
}

void cvt_asnum(
    struct iprange *certrangep,
    struct ASNumberOrRangeA *asNumberOrRangep)
{
    uchar locbuf[20];
    int lth;
    memset(certrangep->lolim, 0, sizeof(certrangep->lolim));
    memset(certrangep->hilim, 0, sizeof(certrangep->hilim));
    if (size_casn(&asNumberOrRangep->num) > 0)
    {
        lth = read_casn(&asNumberOrRangep->num, locbuf);
        memcpy(&certrangep->lolim[4 - lth], locbuf, lth);
        memcpy(&certrangep->hilim[4 - lth], locbuf, lth);
    }
    else
    {
        lth = read_casn(&asNumberOrRangep->range.min, locbuf);
        memcpy(&certrangep->lolim[4 - lth], locbuf, lth);
        lth = read_casn(&asNumberOrRangep->range.max, locbuf);
        memcpy(&certrangep->hilim[4 - lth], locbuf, lth);
    }
}

void decrement_iprange(
    uchar * lim,
    int lth)
{
    uchar *eucp = &lim[lth],
        *ucp;
    for (ucp = &eucp[-1]; ucp >= lim && *ucp == 0; *ucp-- = 0xFF);
    // uc now at last non-zero
    if (ucp >= lim)
        (*ucp)--;
}

void increment_iprange(
    uchar * lim,
    int lth)
{
    uchar *eucp = &lim[lth],
        *ucp;
    for (ucp = &eucp[-1]; ucp >= lim && *ucp == 0xff; *ucp-- = 0);
    if (ucp >= lim)
        (*ucp)++;
}

int diff_ipaddr(
    struct iprange *lop,
    struct iprange *hip)
{
    int lth = (lop->typ == ASNUM || lop->typ == IPv4) ? 4 : 6;
    return memcmp(lop->lolim, hip->lolim, lth);
}

int overlap(
    struct iprange *lop,
    struct iprange *hip)
{
    if (lop->typ != hip->typ)
        return 0;
    if (lop->typ > 0)
    {
        int lth = lop->typ == IPv4 ? 4 : 16;
        if ((memcmp(lop->lolim, hip->lolim, lth) > 0 && // lolo within hi
             memcmp(lop->lolim, hip->hilim, lth) < 0) || (memcmp(lop->hilim, hip->lolim, lth) > 0 &&    // lohi 
                                                                                                        // within 
                                                                                                        // hi
                                                          memcmp(lop->hilim, hip->hilim, lth) < 0) || (memcmp(hip->lolim, lop->lolim, lth) > 0 &&       // hilo 
                                                                                                                                                        // within 
                                                                                                                                                        // lo
                                                                                                       memcmp(hip->lolim, lop->hilim, lth) < 0) || (memcmp(hip->hilim, lop->lolim, lth) > 0 &&  // hihi 
                                                                                                                                                                                                // within 
                                                                                                                                                                                                // lo
                                                                                                                                                    memcmp
                                                                                                                                                    (hip->
                                                                                                                                                     hilim,
                                                                                                                                                     lop->
                                                                                                                                                     hilim,
                                                                                                                                                     lth)
                                                                                                                                                    <
                                                                                                                                                    0))
            return -1;
    }
    return 0;
}

int txt2loc(
    int typ,
    char *skibuf,
    struct iprange *iprangep)
{
    int ansr;
    char *c,
       *d = strchr(skibuf, (int)'-');
    ulong ASnum;
    iprangep->typ = typ;
    memset(iprangep->lolim, 0, 16);
    memset(iprangep->hilim, 0xFF, 16);
    if (d && *d)
    {
        for (c = &d[-1]; *c == ' ' || *c == '\t'; *c-- = 0);
        for (d++; *d == ' ' || *d == '\t'; d++);
    }
    else
        d = (char *)0;
    if (typ == ASNUM)
    {
        for (c = skibuf; *c == '-' || (*c >= '0' && *c <= '9'); c++);
        if (*c > ' ')
            return -2;
        sscanf(skibuf, "%ld", &ASnum);
        uchar *top;
        for (top = &iprangep->lolim[3]; top >= iprangep->lolim; top--)
        {
            *top = (uchar) (ASnum & 0xFF);
            ASnum >>= 8;
        }
        if (!d)
            memcpy(iprangep->hilim, iprangep->lolim, 4);
        else
        {
            sscanf(d, "%ld", &ASnum);
            for (top = &iprangep->hilim[3]; top >= iprangep->hilim; top--)
            {
                *top = (uchar) (ASnum & 0xFF);
                ASnum >>= 8;
            }
        }
    }
    else if (typ == IPv4)
    {
        if ((ansr = cvtv4((uchar) 0, skibuf, iprangep->lolim)) < 0 ||
            (ansr =
             cvtv4((uchar) 0xff, (d) ? d : skibuf, iprangep->hilim)) < 0)
            return ansr;
    }
    else if (typ == IPv6)
    {
        if ((ansr = cvtv6((uchar) 0, skibuf, iprangep->lolim)) < 0 ||
            (ansr =
             cvtv6((uchar) 0xff, (d) ? d : skibuf, iprangep->hilim)) < 0)
            return ansr;
    }
    else
        return -1;
    return 0;
}
