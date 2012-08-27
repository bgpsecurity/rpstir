/*
 * $Id: make_roa.c 453 20078-07-25 15:30:40Z gardiner $ 
 */


#include "rpki/cms/roa_utils.h"
#include "rpki-asn1/manifest.h"
#include "cryptlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

char *msgs[] = {
    "Created %s\n",
    "Can't open %s\n",          // 1
    "Invalid prefix %s\n",
    "Missing %s\n",             // 3
    "%s covers AS number and v4 and v6 files\n",
    "Error in %s when signng\n",        // 5
    "Error writing %s\n",
    "Invalid parameter %s\n",   // 7
};

static int fatal(
    int msg,
    char *paramp)
{
    fprintf(stderr, msgs[msg], paramp);
    exit(msg);
}

static int prefix2roa(
    struct ROAIPAddress *roaIPAddrp,
    char *prefixp,
    int family)
{
    char *c;
    int pad = 0,
        siz;
    for (c = prefixp, siz = family; *c >= ' ' && *c != '/'; c++)
    {
        if (family == 1)
        {
            if (*c == '.')
                siz += 1;
        }
        else if (*c == ':')
        {
            if (c[1] != ':')
                siz += 2;
            else if (pad)
                fatal(2, prefixp);
            else
                pad = 1;
        }
    }
    if (pad)
        pad = 16 - siz;
    uchar *buf = (uchar *) calloc(1, siz + pad + 2);
    uchar *b;
    int i;
    for (c = prefixp, b = &buf[1]; *c >= ' ' && *c != '/'; c++)
    {
        if (family == 1)
        {
            sscanf(c, "%d", &i);
            *b++ = i;
        }
        else if (*c == ':')
        {
            int j;
            for (j = 0; j < pad; *b++ = 0, j++);
        }
        else
        {
            sscanf(c, "%x", &i);
            *b++ = (uchar) (i >> 8);
            *b++ = (uchar) (i & 0xFF);
        }
        while (*c > ' ' && *c != '.' && *c != ':' && *c != '/')
            c++;
        if (*c == '/')
            break;
    }
    if (*c == '/')
    {
        c++;
        sscanf(c, "%d", &i);
        while (*c >= '0' && *c <= '9')
            c++;
        siz += pad;
    }
    int lim = (i + 7) / 8;
    if (siz < lim)
        fatal(2, prefixp);
    else if (siz > lim)
    {
        b--;
        if (*b)
            fatal(2, prefixp);
        siz--;
    }
    i = (8 * siz) - i;          // i = number of bits that don't count
    uchar x,
        y;
    for (x = 1, y = 0; x && y < i; x <<= 1, y++)
    {
        if (b[-1] & x)
            fatal(2, prefixp);
    }
    buf[0] = i;
    write_casn(&roaIPAddrp->address, buf, siz + 1);
    if (*c == '^')
    {
        sscanf(++c, "%d", &i);
        write_casn_num(&roaIPAddrp->maxLength, (long)i);
    }
    return siz;
}

static void do_family(
    struct ROAIPAddrBlocks *roaBlockp,
    int famnum,
    int x,
    FILE * str)
{
    struct ROAIPAddressFamily *roafamp =
        (struct ROAIPAddressFamily *)inject_casn(&roaBlockp->self, x);
    uchar family[2];
    char *c,
        nbuf[256];
    family[0] = 0;
    family[1] = famnum;
    write_casn(&roafamp->addressFamily, family, 2);

    int numaddr;
    for (numaddr = 0; fgets(nbuf, sizeof(nbuf), str); numaddr++)
    {
        if (nbuf[0] > ' ')
            return;
        for (c = nbuf; *c == ' '; c++);
        struct ROAIPAddress *roaIPaddrp =
            (struct ROAIPAddress *)inject_casn(&roafamp->addresses.self,
                                               numaddr);
        prefix2roa(roaIPaddrp, c, famnum);
    }
}

int main(
    int argc,
    char **argv)
{
    struct ROA roa;

    if (argc < 2)
    {
        fprintf(stderr, "Need EITHER a parameter file name\n");
        fprintf(stderr, "OR -c certificateFile -k keyfile -o outputfile\n");
        fprintf(stderr, "    -r read_roa_outputfile or\n");
        return 0;
    }
    char *b,
       *c,
       *e,
       *buf = (char *)0;
    char *certfile,
       *keyfile,
       *outfile,
       *readroafile,
       *vfile;
    char **pp,
      **tp;
    certfile = keyfile = outfile = readroafile = vfile = (char *)0;
    if (argc == 2 && argv[1][0] != '-') // parameter file
    {
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0)
            fatal(1, argv[1]);
        int lth = lseek(fd, 0, SEEK_END);
        lseek(fd, 0, SEEK_SET);
        buf = (char *)calloc(1, lth + 1);
        read(fd, buf, lth);
        int numargs;
        for (e = buf; *e; e++)
            if (*e <= ' ')
                *e = 0;
        for (b = buf; b < e && *b == 0; b++);   // go to first parameter
        for (numargs = 0; b < e; numargs++)
        {
            while (b < e && *b != 0)
                b++;
            while (b < e && *b == 0)
                b++;
        }
        pp = (char **)calloc(1, (numargs + 1) * sizeof(char *));
        for (b = buf; b < e && *b == 0; b++);   // go to first parameter
        for (tp = pp; numargs-- > 0; tp++)
        {
            while (b < e && *b == 0)
                b++;
            *tp = b;
            while (b < e && *b > 0)
                b++;
        }
    }
    else
        pp = &argv[1];          // parameters as argvs
    for (; *pp; pp++)
    {
        c = *pp;
        if (*c != '-')
            fatal(7, c);
        b = *(++pp);
        if (*(++c) == 'c')
            certfile = b;
        else if (*c == 'k')
            keyfile = b;
        else if (*c == 'o')
            outfile = b;
        else if (*c == 'r')
            readroafile = b;
        else if (*c == 'v')
            vfile = b;
        else
            fatal(7, &c[-1]);
    }
    if (!certfile)
        fatal(3, "certificate file");
    if (!outfile)
        fatal(3, "output file");
    if (!keyfile)
        fatal(3, "key file");
    if (!readroafile)
        fatal(4, "readroafile");
    FILE *str = fopen(readroafile, "r");
    if (!str)
        fatal(1, readroafile);
    char nbuf[256];
    long asnum = -1;
    while (fgets(nbuf, 128, str))
    {
        if (!strncmp(nbuf, "AS#", 2))
        {
            for (c = &nbuf[3]; *c == ' '; c++);
            sscanf(c, "%ld", &asnum);
            break;
        }
    }
    fseek(str, 0, SEEK_SET);
    ROA(&roa, (ushort) 0);
    write_objid(&roa.contentType, id_signedData);
    struct SignedData *sgdp = &roa.content.signedData;
    write_casn_num((struct casn *)&sgdp->version, 3);
    struct AlgorithmIdentifier *algidp =
        (struct AlgorithmIdentifier *)inject_casn(&sgdp->digestAlgorithms.self,
                                                  0);
    write_objid(&algidp->algorithm, id_sha256);
    write_casn(&algidp->parameters.sha256, (uchar *) "", 0);
    write_objid(&sgdp->encapContentInfo.eContentType,
                id_routeOriginAttestation);
    struct RouteOriginAttestation *roap = &sgdp->encapContentInfo.eContent.roa;
    write_casn_num(&roap->asID, asnum);
    int x = 0;
    while ((c = fgets(nbuf, sizeof(nbuf), str)) && strncmp(nbuf, "IPv4", 4));
    if (c)
        do_family(&roap->ipAddrBlocks, 1, x++, str);
    fseek(str, 0, SEEK_SET);
    while ((c = fgets(nbuf, sizeof(nbuf), str)) && strncmp(nbuf, "IPv6", 4));
    if (c)
        do_family(&roap->ipAddrBlocks, 2, x, str);
    struct Certificate *certp =
        (struct Certificate *)inject_casn(&sgdp->certificates.self, 0);
    if (get_casn_file(&certp->self, certfile, 0) < 0)
        fatal(2, certfile);
    if ((c = signCMS(&roa, keyfile, 0)))
        fatal(5, c);
    if (put_casn_file(&roa.self, outfile, 0) < 0)
        fatal(6, outfile);
    if (vfile)
    {
        int lth = dump_size(&roa.self);
        char *dbuf = (char *)calloc(1, lth + 8);
        dump_casn(&roa.self, dbuf);
        FILE *vstr = fopen(vfile, "w");
        fputs(dbuf, vstr);
        fclose(vstr);
        free(dbuf);
    }
    if (buf)
        free(buf);
    fatal(0, outfile);
    return 0;
}
