// For testing LTA perforation/expansion.

#include <casn/casn.h>
#include <rpki-object/certificate.h>
#include <stdio.h>
#include "util/logging.h"

#define MSG_OK "Finished %s OK"
#define MSG_FILE "Bad file %s"
#define MSG_SN "Invalid serial number"
#define MSG_EXT "No %s extension"
#define MSG_OPEN "Can't open or error in %s"
#define MSG_IN "Error in %s"
#define MSG_USAGE "Usage: TBtestedFile, answersfile"

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    int lth;
    Certificate(&cert, (ushort) 0);
    if (argc == 0 || argc < 3)
        FATAL(MSG_USAGE);
    lth = get_casn_file(&cert.self, argv[1], 0);
    struct casn *casnp = &cert.toBeSigned.serialNumber;
    if ((lth = vsize_casn(casnp)) < 6)
        FATAL(MSG_SN);
    struct Extension *extp;
    if (!(extp = find_extension(&cert.toBeSigned.extensions, id_pe_ipAddrBlock, 0)))
        FATAL(MSG_EXT, "IPAddress");
    struct Extensions extensions;
    Extensions(&extensions, (ushort) 0);
    if ((lth = get_casn_file(&extensions.self, argv[2], 0)) < 0)
        FATAL(MSG_OPEN, argv[2]);
    struct Extension *sbextp = (struct Extension *)member_casn(&extensions.self, 0);    // ip
                                                                                        // Addresses
    uchar *sb = (uchar *) calloc(1, size_casn(&sbextp->self));
    read_casn(&sbextp->self, sb);
    uchar *b = (uchar *) calloc(1, size_casn(&extp->self));
    read_casn(&extp->self, b);
    if (diff_casn(&sbextp->self, &extp->self))
        FATAL(MSG_IN, "IP Addresses");
    sbextp = (struct Extension *)next_of(&sbextp->self);
    if (!(extp = find_extension(&cert.toBeSigned.extensions,
                                id_pe_autonomousSysNum, 0)))
        FATAL(MSG_EXT, "AS number");
    if (diff_casn(&sbextp->self, &extp->self))
        FATAL(MSG_IN, "AS numbers");
    DONE(MSG_OK, argv[1]);
    return 0;
}
