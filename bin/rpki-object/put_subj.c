
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <casn/casn.h>
#include <rpki-asn1/certificate.h>
#include <stdio.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Usage: filename subjname\n",
    "Can't open %s\n",
    "Error reading %n\n",
    "Error writing %s\n",
};

void fatal(
    int num,
    char *note)
{
    printf(msgs[num], note);
    if (num)
        exit(num);
}

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    Certificate(&cert, (ushort) 0);
    if (argc < 3)
        fatal(1, (char *)0);
    if (get_casn_file(&cert.self, argv[1], 0) <= 0)
        fatal(1, argv[1]);
    struct RelativeDistinguishedName *rdnp =
        (struct RelativeDistinguishedName *)member_casn(&cert.toBeSigned.
                                                        subject.rDNSequence.
                                                        self, 0);
    struct AttributeValueAssertion *avap =
        (struct AttributeValueAssertion *)member_casn(&rdnp->self, 0);
    if (write_casn
        (&avap->value.commonName.printableString, (uchar *) argv[2],
         strlen(argv[2])) < 0)
        fatal(3, "name");
    if (put_casn_file(&cert.self, argv[1], 0) < 0)
        fatal(3, argv[1]);
    fatal(0, argv[1]);
    return 0;
}
