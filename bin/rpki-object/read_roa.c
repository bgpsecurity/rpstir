
#include "rpki/cms/roa_utils.h"

char *msgs[] = {
    "Finished OK\n",
    "Error in family %s\n",
    "Can't open %s\n",          // 2
    "%s is not a roa\n",
    "Invalid or missing AS#\n", // 4
    "Error in family %d\n",
};

static void fatal(
    int err,
    char *param)
{
    if (err)
        fprintf(stderr, msgs[err], param);
    exit(0);
}

static int roa2prefix(
    char **prefixpp,
    struct ROAIPAddress *roaipp,
    int family)
{
    int lth = vsize_casn(&roaipp->self);
    if (lth <= 0)
        return -1;
    int bsize = (lth * 5) + 30; // on the safe side
    char *buf = (char *)calloc(1, bsize);
    uchar *abuf;
    int asize = readvsize_casn(&roaipp->address, &abuf);
    uchar *e,
       *u;
    char *c;
    int i;
    for (u = &abuf[1], e = &abuf[asize], c = buf; u < e; u++)
    {
        if (family == 1)
            c += sprintf(c, "%d.", (int)*u);
        else if (!*u && !u[1])
        {
            *c++ = ':';
            u++;
        }
        else
        {
            i = (*u++ << 8);
            i += *u;
            c += sprintf(c, "%02x:", i);
        }
    }
    c--;                        // cut of final '.' or ':'
    i = (asize - 1) * 8;        // total bits
    i -= abuf[0];               // used bits
    c += sprintf(c, "/%d", i);
    while (*c)
        c++;
    if (vsize_casn(&roaipp->maxLength) > 0)
    {
        read_casn_num(&roaipp->maxLength, (long *)&i);
        c += sprintf(c, "^%d", i);
        while (*c)
            c++;
    }
    *c++ = '\n';
    *c = 0;
    free(abuf);
    *prefixpp = buf;
    return (c - buf);
}

static int read_family(
    char **fampp,
    struct ROAIPAddressFamily *roafamp)
{
    uchar ub[8];
    read_casn(&roafamp->addressFamily, ub);
    int bsize = 100;
    char *a,
       *c,
       *buf = (char *)calloc(1, bsize);
    strcpy(buf, "IPv4\n");
    if (ub[1] == 2)
        buf[3] = '6';
    c = &buf[5];
    int i,
        num = num_items(&roafamp->addresses.self);
    for (i = 0; i < num; i++)
    {
        struct ROAIPAddress *roaipp =
            (struct ROAIPAddress *)member_casn(&roafamp->addresses.self,
                                               i);
        if (!roaipp)
            fatal(1, buf);
        int lth = roa2prefix(&a, roaipp, (int)ub[1]);
        if (lth <= 0)
            fprintf(stderr, "Error in address[%d] in IPv%c\n", i, buf[3]);
        else
        {
            if (&c[lth + 8] >= &buf[bsize])
            {
                int clth = (c - buf);
                buf = (char *)realloc(buf, bsize += lth);
                c = &buf[clth];
            }
            strcat(strcpy(c, "    "), a);
            c += 4 + lth;
            free(a);
        }
    }
    *fampp = buf;
    return strlen(buf);
}

int main(
    int argc,
    char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr,
                "Parameters are: ROA file name and optional output file name\n");
        exit(0);
    }
    FILE *str = stdout;
    if (argc == 3 && (str = fopen(argv[2], "w")) == 0)
        fatal(2, argv[2]);
    struct ROA roa;
    ROA(&roa, (ushort) 0);
    if (get_casn_file(&roa.self, argv[1], 0) < 0)
        fatal(2, argv[1]);
    struct RouteOriginAttestation *roaip;
    roaip = &roa.content.signedData.encapContentInfo.eContent.roa;

    if (vsize_casn(&roaip->self) <= 0)
        fatal(3, argv[1]);
    long asnum;
    if (read_casn_num(&roaip->asID, &asnum) < 0 || asnum <= 0)
        fatal(4, (char *)0);
    fprintf(str, "AS# %ld\n", asnum);
    struct ROAIPAddrBlocks *roablockp = &roaip->ipAddrBlocks;
    int i,
        num = num_items(&roablockp->self);
    for (i = 0; i < num; i++)
    {
        int ansr;
        struct ROAIPAddressFamily *roafamp =
            (struct ROAIPAddressFamily *)member_casn(&roablockp->self, i);
        char *a;
        if ((ansr = read_family(&a, roafamp)) < 0)
            fatal(5, (char *)i);
        fprintf(str, "%s", a);
        free(a);
    }
    return 0;
}
