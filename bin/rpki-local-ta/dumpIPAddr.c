// For testing LTA perforation/expansion.

#include <casn/casn.h>
#include <rpki-object/certificate.h>
#include <stdio.h>

char *msgs[] = {
    "Finished checking %s OK\n",
    "Usage: certfilename(s)\n",
    "Bad file %s\n",            // 2
    "Invalid serial number\n",
    "No %s extension\n",        // 4
    "Can't open %s\n",
    "Error in %s\n",            // 6
};

void fatal(
    int num,
    char *note)
{
    printf(msgs[num], note);
    if (num)
        exit(-1);
}

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
        fatal(1, (char *)0);
    char **p;
    for (p = &argv[1]; p < &argv[argc]; p++)
    {
        struct Extensions extensions;
        Extensions(&extensions, (ushort) 0);
        if ((lth = get_casn_file(&extensions.self, *p, 0)) < 0)
            fatal(5, *p);
        struct Extension *extp;
        if (!(extp = find_extension(&extensions, id_pe_ipAddrBlock, 0)))
            fatal(4, "IPAddress");
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
    fatal(0, argv[1]);
    return 0;
}
