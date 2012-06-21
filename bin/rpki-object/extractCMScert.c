#include <stdio.h>
#include <rpki-asn1/roa.h>

int main(
    int argc,
    char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: CMSfile [certfile] deefault stdout\n");
        return 1;
    }
    if (argc > 3)
    {
        fprintf(stderr, "Too many parameters\n");
        return 1;
    }
    struct ROA roa;
    ROA(&roa, (ushort) 0);
    int ansr = get_casn_file(&roa.self, argv[1], 0);
    if (ansr <= 0)
    {
        fprintf(stderr, "Error reading file %s\n", argv[1]);
        return 1;
    }
    struct Certificate *certp =
        (struct Certificate *)member_casn(&roa.content.signedData.certificates.
                                          self, 0);
    if (!certp)
    {
        fprintf(stderr, "Error getting certificate\n");
        return 1;
    }
    if ((argc > 2 && put_casn_file(&certp->self, argv[2], 0) < 0) ||
        (argc == 2 && put_casn_file(&certp->self, 0, 1) < 0))
    {
        fprintf(stderr, "Error writing file\n");
        return 1;
    }
    return 0;
}
