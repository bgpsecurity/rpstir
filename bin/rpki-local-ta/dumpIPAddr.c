// For testing LTA perforation/expansion.

#include <casn/casn.h>
#include <rpki-object/certificate.h>
#include <stdio.h>
#include "util/logging.h"

#define MSG_OK "Finished checking %s OK"
#define MSG_USAGE "Usage: certfilename(s)"
#define MSG_FILE "Bad file %s"
#define MSG_SN "Invalid serial number"
#define MSG_EXT "No %s extension"
#define MSG_OPEN "Can't open %s"
#define MSG_IN "Error in %s"

void printAddress(
    struct IPAddressA *addressPrefixp,
    int tot,
    char *fill)
{
    uchar buf[36];
    char text[36];
    int lth = read_casn(addressPrefixp, buf);
    if (buf[0])
    {
        uchar mask = 0xff;
        mask >>= (8 - buf[0]);
        if (*fill == '0')
            buf[lth - 1] &= ~mask;
        else
            buf[lth - 1] |= mask;
    };
    int i,
        j;
    memset(text, 0, 36);
    for (i = 1, j = 0; i < lth; i++, j++)
        sprintf(&text[2 * j], "%02x", buf[i]);
    while (j < tot)
        sprintf(&text[2 * j++], "%s", fill);
    for (i = 0, tot <<= 1; i < tot;)
    {
        printf("%c", text[i++]);
        printf("%c", text[i++]);
        printf("%c", text[i++]);
        printf("%c", text[i++]);
        if (i < tot - 1)
            printf(":");
    }
    if (*fill == '0')
        printf(" - ");
    else
        printf("\n");
}

void printRange(
    struct IPAddressRangeA *addressRangep,
    int tot)
{
    printAddress(&addressRangep->min, tot, "00");
    printAddress(&addressRangep->max, tot, "ff");
}

int main(
    int argc,
    char **argv)
{
    int lth;
    if (argc < 2)
        FATAL(MSG_USAGE);
    char **p;
    for (p = &argv[1]; p < &argv[argc]; p++)
    {
        struct Extensions extensions;
        Extensions(&extensions, (ushort) 0);
        if ((lth = get_casn_file(&extensions.self, *p, 0)) < 0)
            FATAL(MSG_OPEN, *p);
        struct Extension *extp;
        if (!(extp = find_extension(&extensions, id_pe_ipAddrBlock, 0)))
            FATAL(MSG_EXT, "IPAddress");
        printf("File %s\n", *p);
        struct IpAddrBlock *ipaddrblockp = &extp->extnValue.ipAddressBlock;
        struct IPAddressFamilyA *ipaddrfamap =
            (struct IPAddressFamilyA *)member_casn(&ipaddrblockp->self, 0);
        uchar fam[2];
        read_casn(&ipaddrfamap->addressFamily, fam);
        printf("%s\n", (fam[1] == 1 ? "v4" : "v6"));
        struct IPAddressChoiceA *ipaddrchoiceap =
            &ipaddrfamap->ipAddressChoice;
        struct AddressesOrRangesInIPAddressChoiceA *addrsOrRangesp =
            &ipaddrchoiceap->addressesOrRanges;
        struct IPAddressOrRangeA *ipaddrorrangeap;
        for (ipaddrorrangeap =
             (struct IPAddressOrRangeA *)member_casn(&addrsOrRangesp->self, 0);
             ipaddrorrangeap;
             ipaddrorrangeap =
             (struct IPAddressOrRangeA *)next_of(&ipaddrorrangeap->self))
        {
            if (vsize_casn(&ipaddrorrangeap->addressPrefix) > 0)
            {
                printAddress(&ipaddrorrangeap->addressPrefix, 4, "00");
                printAddress(&ipaddrorrangeap->addressPrefix, 4, "ff");
            }
            else
                printRange(&ipaddrorrangeap->addressRange, 4);
        }
        ipaddrfamap = (struct IPAddressFamilyA *)next_of(&ipaddrfamap->self);
        read_casn(&ipaddrfamap->addressFamily, fam);
        printf("%s\n", (fam[1] == 1 ? "v4" : "v6"));
        ipaddrchoiceap = &ipaddrfamap->ipAddressChoice;
        addrsOrRangesp = &ipaddrchoiceap->addressesOrRanges;
        for (ipaddrorrangeap =
             (struct IPAddressOrRangeA *)member_casn(&addrsOrRangesp->self, 0);
             ipaddrorrangeap;
             ipaddrorrangeap =
             (struct IPAddressOrRangeA *)next_of(&ipaddrorrangeap->self))
        {
            if (vsize_casn(&ipaddrorrangeap->addressPrefix) > 0)
            {
                printAddress(&ipaddrorrangeap->addressPrefix, 10, "00");
                printAddress(&ipaddrorrangeap->addressPrefix, 10, "ff");
            }
            else
                printRange(&ipaddrorrangeap->addressRange, 10);
        }
        clear_casn(&extensions.self);
    }
    DONE(MSG_OK, argv[1]);
    return 0;
}
