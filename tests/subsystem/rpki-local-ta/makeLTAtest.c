// For testing LTA perforation/expansion.

#include <casn/casn.h>
#include <rpki-object/certificate.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

char *msgs[] = {
    "Finished making %s OK\n",
    "Usage: casename, certfilename(s)\n",
    "Bad file %s\n",
    "Invalid serial number\n",  // 2
    "No %s extension\n",
    "Can't open or error in %s\n",      // 4
    "Error in %s\n",
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
        fatal(1, (char *)0);
    char **p;
    for (p = &argv[2]; p < &argv[argc]; p++)
    {
        lth = get_casn_file(&cert.self, *p, 0);
        struct Extensions extensions;
        Extensions(&extensions, (ushort) 0);
        struct Extension *extp;
        if (!
            (extp = find_extension(&cert.toBeSigned.extensions, id_pe_ipAddrBlock, 0)))
            fatal(4, "IPAddress");
        struct Extension *nextp =
            (struct Extension *)inject_casn(&extensions.self, 0);
        copy_casn(&nextp->self, &extp->self);
        if (!(extp = find_extension(&cert.toBeSigned.extensions,
                                    id_pe_autonomousSysNum, 0)))
            fatal(4, "AS number");
        nextp = (struct Extension *)inject_casn(&extensions.self, 1);
        copy_casn(&nextp->self, &extp->self);
        char filename[80];
        strcpy(filename, *p);
        char *c = strrchr(filename, (int)'.');
        strcat(strcpy(++c, argv[1]), ".tst");
        put_casn_file(&extensions.self, filename, 0);
        strcat(filename, ".raw");
        lth = dump_size(&extensions.self);
        c = (char *)calloc(1, lth + 2);
        dump_casn(&extensions.self, c);
        int fd = open(filename, (O_CREAT | O_RDWR | O_CREAT), 0755);
        write(fd, c, lth);
        close(fd);
        clear_casn(&extensions.self);
    }
    fatal(0, argv[1]);
    return 0;
}
