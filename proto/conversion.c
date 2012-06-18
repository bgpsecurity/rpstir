
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

static int cvtv4(
    uchar fill,
    char *ip,
    uchar * buf)
{
    uchar *uc,
       *ue = &buf[4];
    char *c;
    int fld,
        lth;
    for (c = ip; *c > ' ' && ((*c >= '0' && *c <= '9') ||
                              *c == '.' || *c == '/'); c++)
    {
        if (*c == '/')
        {
            sscanf(&c[1], "%d", &lth);
            lth = ((lth + 7) >> 3);     // number of bytes
        }
    }
    if (*c > ' ')
        return -2;
    memset(buf, fill, 4);
    for (c = ip, uc = buf; *c && *c != '/';)
    {
        if (*c == '.')
            c++;
        sscanf(c, "%d", &fld);
        if (uc >= ue || fld > 255)
            return -1;
        if ((uc - buf) < lth)
            *uc++ = (uchar) fld;
        while (*c && *c != '.' && *c != '/')
            c++;
    }
    if (*c)
    {
        uchar mask;
        c++;
        sscanf(c, "%d", &fld);  // fld has total number of bits
        if (fld >= 32)
            return (fld > 32) ? -1 : 0;
        if (uc < &buf[fld >> 3])
            return -1;
        uc = &buf[(fld >> 3)];  // points to char having bit beyond last
        fld %= 8;               // number of used bits in last byte
        fld = 8 - fld;          // number of unused 
        mask = ~(0xFF << fld);  // mask for last byte
        if (fill)
        {
            if ((mask & *uc) && mask != *uc)
                return -1;
            *uc |= mask;
        }
        else
        {
            if ((mask & *uc))
                return -1;
            *uc &= ~(mask);
        }
    }
    return 0;
}

static int cvtv6(
    uchar fill,
    char *ip,
    uchar * buf)
{
    uchar *up,
       *ue;
    char *c;
    int fld,
        elided;
    for (c = ip; *c > ' ' && ((*c >= '0' && *c <= '9') ||
                              ((*c | 0x20) >= 'a' && (*c | 0x20) <= 'f')
                              || *c == ':' || *c == '/'); c++);
    if (*c > ' ')
        return -2;
    memset(buf, fill, 16);
    for (up = buf, ue = &buf[16]; up < ue; *up++ = fill);
    if (*ip == ':' && ip[1] == ':')
        elided = 7;
    else
        for (c = ip, elided = 8; *c && *c != '/'; c++)
        {
            if (*c == ':')
                elided--;
        }
    if (elided < 0)
        return -1;
    for (c = ip, up = buf; *c > ' ' && *c != '/';)
    {
        if (*c == ':')
        {
            if (c[1] == ':')
            {
                while (elided--)
                {
                    *up++ = 0;
                    *up++ = 0;
                }
                c += 2;
            }
            else
                c++;
        }
        if (*c == '/')
            break;
        sscanf(c, "%x", &fld);
        if (up >= ue || fld > 0xFFFF)
            return -1;
        *up++ = (uchar) ((fld >> 8) & 0xFF);
        *up++ = (uchar) (fld & 0xFF);
        while (*c && *c != ':' && *c != '/')
            c++;
    }
    if (*c)
    {
        uchar mask = 0;
        fld = 0;
        if (*c == '/')
        {
            c++;
            sscanf(c, "%d", &fld);      // fld has total number of bits
            if (fld >= 128)
                return (fld > 128) ? -1 : 0;
            if (up < &buf[fld >> 3])
                return -1;
            up = &buf[(fld >> 3)];      // points to first possibly partial
                                        // byte 
            fld %= 8;           // number of used bits in that byte 
            fld = 8 - fld;      // number of unused bits
            mask = ~(0xFF << fld);      // mask for last byte
        }
        else
            up = &buf[14];
        if (fill)
        {
            if ((mask & *up) && mask != *up)
                return -1;
            *up++ |= mask;
            if ((mask & *up) && mask != *up)
                return -1;
            while (up < ue)
                *up++ |= 0xFF;
            // if up is at the high byte in a short
        }
        else
        {
            if ((mask >> 8) && *up)
                return -1;
            *up++ &= ((~(mask) >> 8) & 0xFF);
            if ((mask & 0xFF) && *up)
                return -1;
            *up &= (~(mask) & 0xFF);
        }
        for (up++; up < ue; *up++ = fill);
    }
    return 0;
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
