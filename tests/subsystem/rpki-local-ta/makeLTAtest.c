// For testing LTA perforation/expansion.

#include <casn/casn.h>
#include <rpki-object/certificate.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "util/logging.h"

#define MSG_OK "Finished making %s OK"
#define MSG_USAGE "Usage: casename, certfilename(s)"
#define MSG_BAD_FILE "Bad file %s"
#define MSG_INVAL_SN "Invalid serial number"
#define MSG_NO_EXT "No %s extension"
#define MSG_OPEN "Can't open or error in %s"
#define MSG_IN "Error in %s"

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    int lth;
    Certificate(&cert, (ushort) 0);
    if (argc == 0 || argc < 3)
        FATAL(MSG_USAGE);
    char **p;
    for (p = &argv[2]; p < &argv[argc]; p++)
    {
        lth = get_casn_file(&cert.self, *p, 0);
        struct Extensions extensions;
        Extensions(&extensions, (ushort) 0);
        struct Extension *extp;
        if (!
            (extp = find_extension(&cert.toBeSigned.extensions, id_pe_ipAddrBlock, 0)))
            FATAL(MSG_NO_EXT, "IPAddress");
        struct Extension *nextp =
            (struct Extension *)inject_casn(&extensions.self, 0);
        copy_casn(&nextp->self, &extp->self);
        if (!(extp = find_extension(&cert.toBeSigned.extensions,
                                    id_pe_autonomousSysNum, 0)))
            FATAL(MSG_NO_EXT, "AS number");
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
    DONE(MSG_OK, argv[1]);
    return 0;
}
