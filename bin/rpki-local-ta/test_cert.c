// For testing LTA perforation/expansion.

#include <casn/casn.h>
#include <rpki-asn1/certificate.h>
#include <rpki/rpwork.h>
#include <stdio.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Bad file %s\n",
    "Invalid serial number\n",  // 2
    "No %s extension\n",
    "Can't open or error in %s\n",      // 4
    "Error in %s\n",
    "Usage: TBtestedFile, answersfile\n",
};

int fatal(
    int num,
    char *note)
{
    printf(msgs[num], note);
    exit(-1);
}

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    int lth;
    Certificate(&cert, (ushort) 0);
    if (argc == 0 || argc < 3)
        fatal(6, (char *)0);
    lth = get_casn_file(&cert.self, argv[1], 0);
    struct casn *casnp = &cert.toBeSigned.serialNumber;
    if ((lth = vsize_casn(casnp)) < 6)
        fatal(2, (char *)0);
    struct Extension *extp;
    if (!(extp = find_extn(&cert.toBeSigned.extensions, id_pe_ipAddrBlock, 0)))
        fatal(3, "IPAddress");
    struct Extensions extensions;
    Extensions(&extensions, (ushort) 0);
    if ((lth = get_casn_file(&extensions.self, argv[2], 0)) < 0)
        fatal(4, argv[2]);
    struct Extension *sbextp = (struct Extension *)member_casn(&extensions.self, 0);    // ip 
                                                                                        // Addresses
    uchar *sb = (uchar *) calloc(1, size_casn(&sbextp->self));
    read_casn(&sbextp->self, sb);
    uchar *b = (uchar *) calloc(1, size_casn(&extp->self));
    read_casn(&extp->self, b);
    if (diff_casn(&sbextp->self, &extp->self))
        fatal(5, "IP Addresses");
    sbextp = (struct Extension *)next_of(&sbextp->self);
    if (!(extp = find_extn(&cert.toBeSigned.extensions,
                           id_pe_autonomousSysNum, 0)))
        fatal(3, "AS number");
    if (diff_casn(&sbextp->self, &extp->self))
        fatal(5, "AS numbers");
    fatal(0, argv[1]);
    return 0;
}
