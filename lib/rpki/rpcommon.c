/*
 * $Id: rpwork.h 888 2009-11-17 17:59:35Z gardiner $ 
 */

#include "rpwork.h"
#include <time.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <util/logutils.h>

struct done_certs done_certs;

extern char nextskibuf[SKIBUFSIZ];
extern struct Certificate myrootcert;
extern char myrootfullname[PATH_MAX];
extern char errbuf[160];
extern struct ipranges certranges,
    ruleranges,
    lessranges,
    fromranges;

extern char *Xcrldp,
   *Xcp,
   *Xrpdir;


/**
 * @param from Path to file that references to.
 * @param to Path extracted from the file from.
 * @return If to is an absolute path, return a copy of to. Otherwise return a
 *         normalized path to the file to as seen from the directory of from.
 *         For example, if from is "path/to/foo" and to is "../bar", the return
 *         value might be "path/to/../bar". On error, return NULL. Regardless
 *         of the value of from and to, the return value should be passed to
 *         free().
 */
static char *translate_file(
    const char *from,
    const char *to)
{
    if (from == NULL || to == NULL)
    {
        return NULL;
    }

    if (to[0] == '\0')
    {
        return NULL;
    }

    if (to[0] == '/')
    {
        // to is an absolute path
        return strdup(to);
    }

    char * from_for_dirname = strdup(from);
    if (from_for_dirname == NULL)
    {
        return NULL;
    }

    char * from_dirname = dirname(from_for_dirname);

    size_t relative_path_len = strlen(from_dirname) + 1 + strlen(to) + 1;
    char * relative_path = malloc(relative_path_len);
    if (relative_path == NULL)
    {
        free(from_for_dirname);
        return NULL;
    }

    snprintf(relative_path, relative_path_len, "%s/%s", from_dirname, to);

    free(from_for_dirname);

    char * absolute_path = realpath(relative_path, NULL);

    free(relative_path);

    if (absolute_path == NULL)
    {
        return NULL;
    }

    return absolute_path;
}

static char *free_old_key_field(
    char *f)
{
    if (f)
        free(f);
    return NULL;
}

static int check_keyring(
    struct keyring *keyring,
    char *cc,
    const char *file_being_parsed)
{
    char *b;
    keyring->filename = free_old_key_field(keyring->filename);
    keyring->label = free_old_key_field(keyring->label);
    keyring->password = free_old_key_field(keyring->password);
    if ((cc = nextword(cc)))
    {
        size_t filename_raw_len = strcspn(cc, " ");
        if (filename_raw_len <= 0)
        {
            return -1;
        }

        char * filename_raw = strndup(cc, filename_raw_len);
        if (filename_raw == NULL)
        {
            return -1;
        }

        keyring->filename = translate_file(file_being_parsed, filename_raw);

        free(filename_raw);
        filename_raw = NULL;

        if (keyring->filename == NULL)
        {
            return -1;
        }

        for (b = cc; *b > ' '; b++);
        if (*b)
        {
            if ((cc = nextword(cc)))
            {
                if ((b = strchr(cc, (int)' ')))
                {
                    keyring->label = (char *)calloc(1, (b - cc) + 2);
                    if (keyring->label)
                    {
                        strncpy(keyring->label, cc, (b - cc));
                        if ((cc = nextword(cc)))
                        {
                            for (b = cc; *b > ' '; b++);
                            keyring->password =
                                (char *)calloc(1, (b - cc) + 2);
                            strncpy(keyring->password, cc, (b - cc));
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return -1;
}

char *nextword(
    char *cc)
{
    while (*cc > ' ')
        cc++;
    while (*cc && (*cc == ' ' || *cc == '\t'))
        cc++;
    return cc;
}

static int trueOrFalse(
    char *c)
{
    if (!strcmp(c, "TRUE") || !strcmp(c, "FALSE"))
        return 1;
    return 0;
}

static int next_cmd(
    char *outbufp,
    int siz,
    FILE * SKI)
{
    /*
     * Function: Gets next command in control file, eliminating superfluous white
     *         space
     * Inputs: Ptr to destination buffer
     *         Length of destination
     *         Ptr to FILE of commands
     * Output: Buf filled with clean line
     * Returns: 1 if success
     *          0 if no more lines in file
     *         -1 if error
     * Procedure:
     * 1. DO
     *      Read in next line
     *      IF none, return 0
     *      Check for overflow or initial white space 
     *    WHILE line is just a comment
     * 2. Starting at input and output buffers
     *    DO
     *      Copy a word to output up to the limit of output 
     *      Skip over white space in input
     *      IF the output buffer is full but there's more input
     *        Return error
     *      Put one space in output   
     *    WHILE there is more input
     *    Overwrite the last space with line end codes 
     *    Return success  
     */
    char locbuf[2 * SKIBUFSIZ],
       *eip = &locbuf[sizeof(locbuf) - 1],      // last allowed char
        *eop = &outbufp[siz - 3];       // last allowed char
    do                          // step1
    {
        *eip = 'x';             // a test character
        if (!fgets(locbuf, sizeof(locbuf), SKI))
            return 0;
        if (*eip != 'x' || locbuf[0] <= ' ')
            return ERR_SCM_BADSKIFILE;
    }
    while (*locbuf == ';');
    // step 2
    char *op = outbufp,
        *ip = locbuf;
    do
    {
        while (*ip > ' ' && op < eop)
            *op++ = *ip++;
        while (*ip && *ip <= ' ')
            ip++;
        if (*ip > ' ' && op >= eop)     // No room for more
            return -1;
        *op++ = ' ';
    }
    while (*ip);
    op[-1] = '\n';              // <= &outbuf[siz-2] 
    *op = 0;                    // <= &outbuf[siz-1]
    return 1;
}

static int check_cp(
    char *cpp)
{
    if ((*cpp == 'C' || *cpp == 'D' || *cpp == 'R') && cpp[1] <= ' ')
    {

        Xcp = (char *)calloc(1, 2);
        *Xcp = *cpp;
    }
    else
    {
        char *c;
        for (c = cpp; *c > ' ' && (*c == '.' || (*c >= '0' && *c <= '9'));
             c++);
        if (*c == ' ')
            *c = 0;
        if (*c > ' ')
            return -1;
        struct casn oid;
        tagged_constructor(&oid, 0, ASN_OBJ_ID, ASN_OBJ_ID);
        int ansr = write_objid(&oid, cpp);
        clear_casn(&oid);
        if (ansr > 0)
        {
            Xcp = (char *)calloc(1, strlen(cpp) + 2);
            strcpy(Xcp, cpp);
        }
        else
            return -1;
    }
    return 1;
}

int check_date(
    char *datep,
    struct casn *casnp,
    int64_t * datenump)
{
    char *c;
    for (c = datep; *c >= '0' && *c <= '9'; c++);
    if (*c != 'Z' || c != &datep[14])
        return -1;
    if (strncmp(datep, "2000", 4) < 0)
        return -1;
    ulong tag;
    if (strncmp(datep, "2050", 4) >= 0)
        tag = (ulong) ASN_GENTIME;
    else
        tag = (ulong) ASN_UTCTIME;
    tagged_constructor(casnp, 0, tag, tag);
    if ((tag == (ulong) ASN_UTCTIME &&
         (write_casn(casnp, (uchar *) & datep[2], 13) < 0 ||
          read_casn_time(casnp, datenump)) < 0) ||
        (tag == (ulong) ASN_GENTIME &&
         (write_casn(casnp, (uchar *) datep, 15) < 0 ||
          read_casn_time(casnp, datenump) < 0)))
        return -1;
    return 1;
}

int check_dates(
    char *datesp)
{
    int64_t fromDate,
        toDate;
    time_t now = time((time_t *) 0);
    char *enddatep = nextword(datesp);
    if (!enddatep || datesp[14] != 'Z' || datesp[15] != ' ' ||
        enddatep[14] != 'Z' || enddatep[15] > ' ' ||
        strncmp(datesp, enddatep, 14) >= 0)
        return -1;
    if (check_date(datesp, &Xvaliddates.lodate, &fromDate) < 0 ||
        check_date(enddatep, &Xvaliddates.hidate, &toDate) < 0 ||
        fromDate >= toDate || toDate < now)
        return -1;
    return 1;
}

struct Extension *find_extn(
    struct Certificate *certp,
    char *oid,
    int add)
{
    struct Extensions *extsp = &certp->toBeSigned.extensions;
    struct Extension *extp;
    int num = num_items(&extsp->self);
    if (!num && !add)
        return (struct Extension *)0;
    for (extp = (struct Extension *)member_casn(&extsp->self, 0);
         extp && diff_objid(&extp->extnID, oid);
         extp = (struct Extension *)next_of(&extp->self));
    if (!extp && add)
    {
        extp = (struct Extension *)inject_casn(&extsp->self, num);
    }
    return extp;
}

void free_ipranges(
    struct ipranges *iprangesp)
{
    int i;
    struct iprange *iprangep = iprangesp->iprangep;
    if (!iprangep)
        return;
    for (i = 0; i < iprangesp->numranges; i++, iprangep++)
    {
        if (iprangep->text)
        {
            free(iprangep->text);
            iprangep->text = (char *)0;
        }
    }
    free(iprangesp->iprangep);
    iprangesp->iprangep = (struct iprange *)0;
}

void clear_ipranges(
    struct ipranges *iprangesp)
{
    free_ipranges(iprangesp);
    iprangesp->iprangep = (struct iprange *)0;
    iprangesp->numranges = 0;
}

static void internal_error(
    char *msg)
{
    fprintf(stderr, "%s", msg);
    exit(0);
}

struct iprange *eject_range(
    struct ipranges *iprangesp,
    int num)
{
    int typ;
    if (num < 0 || num >= iprangesp->numranges)
        internal_error("Ejecting out of range\n");
    iprangesp->numranges--;
    struct iprange *newrangep =
        (struct iprange *)calloc(iprangesp->numranges, sizeof(struct iprange));
    int i;
    for (i = 0; i < num; i++)
    {
        newrangep[i].typ = iprangesp->iprangep[i].typ;
        memcpy(newrangep[i].lolim, iprangesp->iprangep[i].lolim, 18);
        memcpy(newrangep[i].hilim, iprangesp->iprangep[i].hilim, 18);
        newrangep[i].text = iprangesp->iprangep[i].text;
        iprangesp->iprangep[i].text = (char *)0;
    }
    typ = iprangesp->iprangep[i].typ;
    for (; i < iprangesp->numranges; i++)
    {
        newrangep[i].typ = iprangesp->iprangep[i + 1].typ;
        memcpy(newrangep[i].lolim, iprangesp->iprangep[i + 1].lolim, 18);
        memcpy(newrangep[i].hilim, iprangesp->iprangep[i + 1].hilim, 18);
        newrangep[i].text = iprangesp->iprangep[i + 1].text;
        iprangesp->iprangep[i].text = (char *)0;
    }
    free_ipranges(iprangesp);
    if (iprangesp->numranges)
    {
        iprangesp->iprangep = newrangep;
        if (iprangesp->iprangep[num].typ != typ)
            return NULL;
    }
    return &iprangesp->iprangep[num];
}

struct iprange *inject_range(
    struct ipranges *iprangesp,
    int num)
{
    if (num < 0 || num > iprangesp->numranges)
        internal_error("Injecting out of range\n");
    struct iprange *newrangep =
        (struct iprange *)calloc(iprangesp->numranges + 1,
                                 sizeof(struct iprange));
    int i;
    for (i = 0; i < num; i++)
    {
        newrangep[i].typ = iprangesp->iprangep[i].typ;
        memcpy(newrangep[i].lolim, iprangesp->iprangep[i].lolim, 18);
        memcpy(newrangep[i].hilim, iprangesp->iprangep[i].hilim, 18);
        newrangep[i].text = iprangesp->iprangep[i].text;
        iprangesp->iprangep[i].text = (char *)0;
    }
    memset(newrangep[i].lolim, 0, sizeof(newrangep));
    memset(newrangep[i].hilim, 0, sizeof(newrangep));
    newrangep[i].text = 0;
    for (; i < iprangesp->numranges; i++)
    {
        newrangep[i + 1].typ = iprangesp->iprangep[i].typ;
        memcpy(newrangep[i + 1].lolim, iprangesp->iprangep[i].lolim, 18);
        memcpy(newrangep[i + 1].hilim, iprangesp->iprangep[i].hilim, 18);
        newrangep[i + 1].text = iprangesp->iprangep[i].text;
        iprangesp->iprangep[i].text = (char *)0;
    }
    free_ipranges(iprangesp);
    iprangesp->numranges++;
    iprangesp->iprangep = newrangep;
    return &iprangesp->iprangep[num];
}

struct iprange *next_range(
    struct ipranges *iprangesp,
    struct iprange *iprangep)
{
    if (iprangep - iprangesp->iprangep + 1 >= iprangesp->numranges)
        return NULL;
    if (iprangep[1].typ != iprangep->typ)
        return (struct iprange *)0;
    return ++iprangep;
}

int sort_resources(
    struct iprange *iprangesp,
    int numranges)
{
    struct iprange *rp0,
       *rp1,
        spare;
    int did,
        i;
    for (did = 0, i = 1; i < numranges;)
    {
        rp0 = &iprangesp[i - 1];
        rp1 = &iprangesp[i];
        if (diff_ipaddr(rp0, rp1) > 0)  // swap them
        {
            memcpy(&spare, rp0, sizeof(struct iprange));
            memcpy(rp0, rp1, sizeof(struct iprange));
            memcpy(rp1, &spare, sizeof(struct iprange));
            i = 1;              // go back to start
            did++;
        }
        else
            i++;
    }
    return did;
}

int touches(
    struct iprange *lop,
    struct iprange *hip,
    int lth)
{
    struct iprange mid;
    memcpy(mid.lolim, lop->hilim, lth);
    increment_iprange(mid.lolim, lth);
    return memcmp(mid.lolim, hip->lolim, lth);
}

static struct AddressesOrRangesInIPAddressChoiceA *find_IP(
    int typ,
    struct Extension *extp)
{
    uchar fambuf[4];
    int loctyp;
    if (typ == IPv4)
        loctyp = 1;
    else if (typ == IPv6)
        loctyp = 2;
    else
        return (struct AddressesOrRangesInIPAddressChoiceA *)0;
    struct IpAddrBlock *ipAddrBlock = &extp->extnValue.ipAddressBlock;
    struct IPAddressFamilyA *ipFamp;
    for (ipFamp =
         (struct IPAddressFamilyA *)member_casn(&ipAddrBlock->self, 0); ipFamp;
         ipFamp = (struct IPAddressFamilyA *)next_of(&ipFamp->self))
    {
        read_casn(&ipFamp->addressFamily, fambuf);
        if (fambuf[1] == loctyp)        // OK the cert has some
            return &ipFamp->ipAddressChoice.addressesOrRanges;
    }
    return (struct AddressesOrRangesInIPAddressChoiceA *)0;
}

void mk_certranges(
    struct ipranges *rangep,
    struct Certificate *certp)
{
    if (rangep->numranges > 0 || rangep->iprangep)
        clear_ipranges(rangep);
    int num = 0;
    struct IPAddressOrRangeA *ipAddrOrRangep;
    struct iprange *certrangep;
    struct AddressesOrRangesInIPAddressChoiceA *ipAddrOrRangesp;
    struct Extension *extp = find_extn(certp, id_pe_ipAddrBlock, 0);
    if (extp)
    {
        if ((ipAddrOrRangesp = find_IP(IPv4, extp)))
        {
            for (ipAddrOrRangep =
                 (struct IPAddressOrRangeA *)member_casn(&ipAddrOrRangesp->
                                                         self, 0);
                 ipAddrOrRangep;
                 ipAddrOrRangep =
                 (struct IPAddressOrRangeA *)next_of(&ipAddrOrRangep->self))
            {
                certrangep = inject_range(rangep, num++);
                certrangep->typ = IPv4;
                cvt_asn(certrangep, ipAddrOrRangep);
            }
        }
        if ((ipAddrOrRangesp = find_IP(IPv6, extp)))
        {
            for (ipAddrOrRangep =
                 (struct IPAddressOrRangeA *)member_casn(&ipAddrOrRangesp->
                                                         self, 0);
                 ipAddrOrRangep;
                 ipAddrOrRangep =
                 (struct IPAddressOrRangeA *)next_of(&ipAddrOrRangep->self))
            {
                certrangep = inject_range(rangep, num++);
                certrangep->typ = IPv6;
                cvt_asn(certrangep, ipAddrOrRangep);
            }
        }
    }
    if ((extp = find_extn(certp, id_pe_autonomousSysNum, 0)))
    {
        struct AsNumbersOrRangesInASIdentifierChoiceA *asNumbersOrRangesp =
            &extp->extnValue.autonomousSysNum.asnum.asNumbersOrRanges;
        struct ASNumberOrRangeA *asNumOrRangep;
        for (asNumOrRangep =
             (struct ASNumberOrRangeA *)member_casn(&asNumbersOrRangesp->self,
                                                    0); asNumOrRangep;
             asNumOrRangep =
             (struct ASNumberOrRangeA *)next_of(&asNumOrRangep->self))
        {
            certrangep = inject_range(rangep, num++);
            certrangep->typ = ASNUM;
            cvt_asnum(certrangep, asNumOrRangep);
        }
    }
    certrangep = inject_range(rangep, num++);
    certrangep->typ = 0;
}

static int getIPBlock(
    FILE * SKI,
    int typ,
    char *skibuf,
    int siz)
{
    int ansr;
    while ((ansr = next_cmd(skibuf, siz, SKI)) > 0)
    {
        if (*skibuf <= ' ')
            continue;
        if ((typ == IPv4 && *skibuf == 'I') ||
            (typ == IPv6 && !strncmp(skibuf, "AS", 2)) ||
            (typ == ASNUM && *skibuf == 'S'))
            break;
        char *cc = nextword(skibuf);
        if (cc && *cc > ' ' && *cc != '-')
            return ERR_SCM_BADSKIBLOCK;
        struct iprange *iprangep =
            inject_range(&ruleranges, ruleranges.numranges);
        if (txt2loc(typ, skibuf, iprangep) < 0)
            return ERR_SCM_BADIPRANGE;
        else
        {
            int j = strlen(skibuf);
            iprangep->text = calloc(1, j);
            strncpy(iprangep->text, skibuf, j - 1);
            if (iprangep > &ruleranges.iprangep[0] &&
                iprangep->typ == iprangep[-1].typ &&
                (j =
                 touches(&iprangep[-1], iprangep,
                         (iprangep->typ == IPv4) ? 4 : 16)) >= 0)
            {
                snprintf(errbuf, sizeof(errbuf),
                         (!j) ? "Ranges touch " : "Ranges out of order ");
                return ERR_SCM_BADSKIBLOCK;
            }
        }
    }
    if (ansr < 0)
        return ansr;
    if (!ansr)
        *skibuf = 0;
    if (typ == ASNUM && ansr && !strncmp(skibuf, "SKI", 3))
        strcpy(nextskibuf, skibuf);
    return ansr;
}

int getSKIBlock(
    FILE * SKI,
    char *skibuf,
    int siz)
{
    int ansr = ERR_SCM_BADSKIBLOCK;
    int val;
    if ((val = next_cmd(skibuf, siz, SKI)) < 0)
        snprintf(errbuf, sizeof(errbuf), "Invalid IPv4 ");
    else if (!val)
        snprintf(errbuf, sizeof(errbuf), "Missing IPv4 ");
    else if (strcmp(skibuf, "IPv4\n"))
        snprintf(errbuf, sizeof(errbuf), "Invalid IPv4 ");
    else if (getIPBlock(SKI, IPv4, skibuf, siz) < 0)
    {
        if (!*errbuf)
            snprintf(errbuf, sizeof(errbuf), "Bad/disordered IPv4 group ");
    }
    else if (strcmp(skibuf, "IPv6\n"))
        snprintf(errbuf, sizeof(errbuf), "Missing/invalid IPv6 ");
    else if (getIPBlock(SKI, IPv6, skibuf, siz) < 0)
        snprintf(errbuf, sizeof(errbuf), "Bad/disordered IPv6 group ");
    else if (strcmp(skibuf, "AS#\n"))
        snprintf(errbuf, sizeof(errbuf), "Missing/invalid AS# ");
    else if (getIPBlock(SKI, ASNUM, skibuf, siz) < 0)
        snprintf(errbuf, sizeof(errbuf), "Bad/disordered AS# group ");
    else if (ruleranges.numranges == 0)
        snprintf(errbuf, sizeof(errbuf), "Empty SKI block ");
    else
    {
        ansr = 1;
    }
    return ansr;
}

static int parse_privatekey(
    struct keyring *keyring,
    char *skibuf,
    const char *file_being_parsed)
{
    char *cc;
    if (strncmp(skibuf, "PRIVATEKEYMETHOD", 16))
    {
        snprintf(errbuf, sizeof(errbuf), "No private key method.");
        return ERR_SCM_BADSKIFILE;
    }
    for (cc = &skibuf[16]; *cc && *cc <= ' '; cc++);
    if (strncmp(cc, "Keyring", 7) || check_keyring(keyring, cc, file_being_parsed) < 0)
    {
        snprintf(errbuf, sizeof(errbuf), "Invalid private key method.");
        return ERR_SCM_BADSKIFILE;
    }
    return 0;
}

static int parse_topcert(
    char *skibuf,
    int siz,
    FILE * SKI,
    const char * SKI_filename)
{
    int ansr = 0,
        val = next_cmd(skibuf, siz, SKI);
    char *c = NULL;
    if (val <= 0 || strncmp(skibuf, "TOPLEVELCERTIFICATE ", 20))
    {
        ansr = ERR_SCM_NORPCERT;
        if (val < 0)
            snprintf(errbuf, sizeof(errbuf), "Error in top level certificate");
        else
            snprintf(errbuf, sizeof(errbuf), "No top level certificate.");
    }
    else
    {                           // get root cert
        if ((c = strchr(skibuf, (int)'\n')))
            *c = 0;
        for (c = &skibuf[20]; *c == ' '; c++);
        c = translate_file(SKI_filename, c);
        if (!c)
        {
            snprintf(errbuf, sizeof(errbuf),
                     "Error translating root cert file name");
            ansr = ERR_SCM_NORPCERT;
        }
        else if (strlen(c) >= sizeof(myrootfullname) - 2)
        {
            ansr = ERR_SCM_NORPCERT;
            snprintf(errbuf, sizeof(errbuf),
                     "Top level certificate name too long");
        }
        else
        {
            strcpy(myrootfullname, c);
            if (get_casn_file(&myrootcert.self, myrootfullname, 0) < 0)
            {
                snprintf(errbuf, sizeof(errbuf),
                         "Invalid top level certificate: %s.", myrootfullname);
                ansr = ERR_SCM_NORPCERT;
            }
            else
            {
                char * slash_in_top_cert = strrchr(c, (int)'/');
                if (!slash_in_top_cert)
                    ansr = ERR_SCM_NORPCERT;
                else
                {
                    *slash_in_top_cert = 0;
                    Xrpdir = (char *)calloc(1, strlen(c) + 4);
                    strcpy(Xrpdir, c);
                }
            }
        }
        free(c);
    }
    return ansr;
}

static int parse_control_section(
    char *skibuf,
    int siz,
    FILE * SKI,
    int *locflagsp)
{
    int ansr = 0,
        val = 0;
    char *c = skibuf,
        *cc;
    while (c && !ansr && !strncmp(skibuf, "CONTROL ", 8))
    {
        if ((c = strchr(skibuf, (int)'\n')))
            *c = 0;
        cc = nextword(skibuf);
        if (!strncmp(cc, "treegrowth", 10) && cc[10] == ' ')
        {
            cc = nextword(cc);
            if (!trueOrFalse(cc))
                ansr = -1;
            else if (*cc == 'T')
                *locflagsp |= TREEGROWTH;
        }
        else if (!strncmp(cc, "resource_nounion", 16) && cc[16] == ' ')
        {
            cc = nextword(cc);
            if (!trueOrFalse(cc))
                ansr = -1;
            else if (*cc == 'T')
                *locflagsp |= RESOURCE_NOUNION;
        }
        else if (!strncmp(cc, "intersection_always", 19) && cc[19] == ' ')
        {
            cc = nextword(cc);
            if (!trueOrFalse(cc))
                ansr = -1;
            else if (*cc == 'T')
                *locflagsp |= INTERSECTION_ALWAYS;
        }
        else
        {
            ansr = ERR_SCM_BADSKIFILE;
            snprintf(errbuf, sizeof(errbuf), "Invalid control message: %s.\n",
                     cc);
        }
        if (!ansr)
        {
            if ((val = next_cmd(skibuf, siz, SKI)) <= 0)
            {
                c = NULL;
                snprintf(errbuf, sizeof(errbuf), "Error in control section");
            }
        }
    }
    if (ansr == -1)
    {
        snprintf(errbuf, sizeof(errbuf), "No/not TRUE or FALSE in %s.",
                 skibuf);
        ansr = ERR_SCM_BADSKIFILE;
    }
    return ansr;
}

static int parse_validity_dates(
    char *cc)
{
    cc = nextword(cc);
    if (!*cc || (*cc != 'C' && *cc != 'R' && check_dates(cc) < 0))
        return ERR_SCM_BADSKIFILE;
    return 0;
}

static int parse_Xcrldp(
    char *cc)
{
    int ansr = 0;
    cc = nextword(cc);
    if (!*cc || (*cc == 'R' && cc[1] <= ' ' &&
                 !find_extn(&myrootcert, id_cRLDistributionPoints, 0)))
        ansr = ERR_SCM_BADSKIFILE;
    else if (strchr(cc, (int)','))
        ansr = ERR_SCM_BADSKIFILE;
    else
    {
        Xcrldp = (char *)calloc(1, strlen(cc) + 2);
        strcpy(Xcrldp, cc);
    }
    return ansr;
}

static int parse_Xcp(
    char *cc,
    char *skibuf)
{
    int ansr = 0;
    struct Extension *extp;
    cc = nextword(cc);
    if (!*cc ||
        (*cc == 'R' &&
         ((!(extp = find_extn(&myrootcert, id_certificatePolicies, 0))) ||
          num_items(&extp->extnValue.certificatePolicies.self) > 1)))
        ansr = ERR_SCM_BADSKIFILE;
    else if (nextword(cc))
    {
        ansr = ERR_SCM_BADSKIFILE;
        snprintf(errbuf, sizeof(errbuf), "Invalid Xcp entry: %s.", skibuf);
    }
    else if (check_cp(cc) < 0)
        ansr = ERR_SCM_BADSKIFILE;
    return ansr;
}

static int parse_tag_section(
    char *skibuf,
    int siz,
    FILE * SKI)
{
    int ansr = 0,
        val = 0;
    char *c,
       *cc;
    while (!ansr && !strncmp(skibuf, "TAG", 3))
    {
        if ((c = strchr(skibuf, (int)'\n')))
            *c = 0;
        cc = nextword(skibuf);
        if (skibuf[3] != ' ')
        {
            snprintf(errbuf, sizeof(errbuf), "Invalid line: %s.", skibuf);
            ansr = ERR_SCM_BADSKIFILE;
            break;
        }
        if (!strncmp(cc, "Xvalidity_dates ", 16))
            ansr = parse_validity_dates(cc);
        else if (!strncmp(cc, "Xcrldp ", 7))
            ansr = parse_Xcrldp(cc);
        else if (!strncmp(cc, "Xcp ", 4))
            ansr = parse_Xcp(cc, skibuf);
        else if (!strncmp(cc, "Xaia ", 5))
        {
            cc = nextword(cc);
            Xaia = (char *)calloc(1, strlen(cc) + 1);
            strncpy(Xaia, cc, strlen(cc) + 1);
        }
        else
        {
            ansr = ERR_SCM_BADSKIFILE;
            snprintf(errbuf, sizeof(errbuf), "Invalid TAG entry: %s.", cc);
        }
        if (!ansr)
        {
            if ((val = next_cmd(skibuf, siz, SKI)) <= 0)
            {
                ansr = ERR_SCM_BADSKIFILE;
                snprintf(errbuf, sizeof(errbuf), "Error in TAG entries");
            }
        }
    }
    return ansr;
}

int parse_SKI_blocks(
    struct keyring *keyring,
    FILE * SKI,
    const char * SKI_filename,
    char *skibuf,
    int siz,
    int *locflagsp)
{
    /*
     * Procedure: 1. Get nformation on the top level certificate Get first SKI 
     * line from the control file 2. IF no error, process the control section
     * IF no error, process the tag section 3. IF no error AND the next is
     * part of the control section, note error
     * 
     * FOR each item in done_certs Flag the target cert in the database as
     * having a para Sign the paracertificate Put it into database with para
     * flag Free all and return error 
     */
    Certificate(&myrootcert, (ushort) 0);
    char *c,
       *cc;
    // step 1
    int ansr = 0;
    int val = 0;
    if ((ansr = next_cmd(skibuf, siz, SKI)) <= 0)
    {
        ansr = ERR_SCM_BADSKIFILE;
        snprintf(errbuf, sizeof(errbuf), "No private key material");
    }
    else
        ansr = parse_privatekey(keyring, skibuf, SKI_filename);

    if (!ansr)
        ansr = parse_topcert(skibuf, siz, SKI, SKI_filename);
    if (!ansr && (val = next_cmd(skibuf, siz, SKI)) <= 0)
    {
        if (val < 0)
            snprintf(errbuf, sizeof(errbuf), "Error in control section");
        else
            snprintf(errbuf, sizeof(errbuf), "No control section.");
        ansr = ERR_SCM_BADSKIFILE;
    }
    // step 2
    else if (!ansr)
        ansr = parse_control_section(skibuf, siz, SKI, locflagsp);
    if (!ansr)
        ansr = parse_tag_section(skibuf, siz, SKI);
    // step 3
    if (!ansr)
    {
        if (!*errbuf && !strncmp(skibuf, "CONTROL ", 8))
        {
            snprintf(errbuf, sizeof(errbuf),
                     "CONTROL message out of order: %s", skibuf);
            ansr = ERR_SCM_BADSKIFILE;
        }
        else if (!ansr)
        {
            if (strncmp(skibuf, "SKI ", 4))
            {
                ansr = ERR_SCM_BADSKIFILE;
                snprintf(errbuf, sizeof(errbuf), "No SKI entry in file.");
            }
            else if (!(cc = nextword(skibuf)) || *cc < ' ')
            {
                ansr = ERR_SCM_BADSKIFILE;
                snprintf(errbuf, sizeof(errbuf), "Incomplete SKI entry.");
            }
        }
    }
    if (ansr < 0)
    {
        if ((c = strchr(skibuf, (int)'\n')))
            *c = 0;
        if (skibuf && *skibuf)
            log_msg(LOG_DEBUG, "Error at this line of control file: %s.",
                    skibuf);
    }
    return ansr;
}
