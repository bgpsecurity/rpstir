#include "util/inet.h"
#include "rpwork.h"

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
