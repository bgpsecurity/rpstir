// For testing LTA perforation/expansion.

#include <casn/casn.h>
#include <rpki-asn1/certificate.h>
#include <stdio.h>

char *msgs[] = {
    "Finished checking %s OK\n",
    "Usage: casename, certfilename(s)\n",
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
    int i = 0;
    printf(msgs[num], note);
    if (num > 1)
        i = -1;
    if (i)
        exit(i);
}

struct Extension *find_extn(
    struct Extensions *extsp,
    char *oidp)
{
    struct Extension *extp;
    int num = num_items(&extsp->self);
    if (!num)
        return NULL;
    for (extp = (struct Extension *)member_casn(&extsp->self, 0);
         extp && diff_objid(&extp->extnID, oidp);
         extp = (struct Extension *)next_of(&extp->self));
    return extp;
}

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    int lth;
    Certificate(&cert, (ushort) 0);
    if (argc == 0 || argc < 3)
        fatal(1, (char *)0);
    char **p;
    for (p = &argv[2]; p < &argv[argc]; p++)
    {
        struct Extensions extensions;
        Extensions(&extensions, (ushort) 0);
        char filename[80];
        strcpy(filename, *p);
        char *c = strrchr(filename, (int)'.');
        strcat(strcpy(++c, argv[1]), ".tst");
        if (get_casn_file(&extensions.self, filename, 0) < 0)
            fatal(5, filename);
        if ((lth = get_casn_file(&cert.self, *p, 0)) < 0)
            fatal(5, *p);
        struct Extension *extp;
        if (!
            (extp = find_extn(&cert.toBeSigned.extensions, id_pe_ipAddrBlock)))
            fatal(4, "IPAddress");
        struct Extension *nextp =
            (struct Extension *)member_casn(&extensions.self, 0);
        if (diff_casn(&nextp->self, &extp->self))
            fatal(6, *p);
        if (!(extp = find_extn(&cert.toBeSigned.extensions,
                               id_pe_autonomousSysNum)))
            fatal(4, "AS number");
        nextp = (struct Extension *)member_casn(&extensions.self, 1);
        if (diff_casn(&nextp->self, &extp->self))
            fatal(6, *p);
        clear_casn(&extensions.self);
    }
    fatal(0, argv[1]);
    return 0;
}
