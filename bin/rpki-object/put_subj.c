
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <casn/casn.h>
#include <rpki-asn1/certificate.h>
#include <stdio.h>
#include "util/logging.h"

#define MSG_OK "Finished %s OK"
#define MSG_USAGE "Usage: filename subjname"
#define MSG_OPEN "Can't open %s"
#define MSG_READING "Error reading %n"
#define MSG_WRITING "Error writing %s"

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    Certificate(&cert, (ushort) 0);
    if (argc < 3)
        FATAL(MSG_USAGE);
    if (get_casn_file(&cert.self, argv[1], 0) <= 0)
        FATAL(MSG_OPEN, argv[1]);
    struct RelativeDistinguishedName *rdnp =
        (struct RelativeDistinguishedName *)member_casn(&cert.toBeSigned.
                                                        subject.rDNSequence.
                                                        self, 0);
    struct AttributeValueAssertion *avap =
        (struct AttributeValueAssertion *)member_casn(&rdnp->self, 0);
    if (write_casn
        (&avap->value.commonName.printableString, (uchar *) argv[2],
         strlen(argv[2])) < 0)
        FATAL(MSG_WRITING, "name");
    if (put_casn_file(&cert.self, argv[1], 0) < 0)
        FATAL(MSG_WRITING, argv[1]);
    DONE(MSG_OK, argv[1]);
    return 0;
}
