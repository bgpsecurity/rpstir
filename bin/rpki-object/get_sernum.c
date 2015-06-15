
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <casn/casn.h>
#include <rpki-asn1/certificate.h>
#include <stdio.h>
#include "util/logging.h"

#define MSG_OK "Finished %s OK"
#define MSG_USAGE "Usage: file of names"
#define MSG_OPEN "Can't open %s"
#define MSG_READ "Error reading %s"

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    long certnum;
    Certificate(&cert, (ushort) 0);
    if (argc == 0 || argc < 2)
        FATAL(MSG_USAGE);
    FILE *fp = fopen(argv[1], "r");
    if (!fp)
        FATAL(MSG_OPEN, argv[1]);
    char linebuf[128];
    while (fgets(linebuf, 128, fp))
    {
        char *c;
        for (c = linebuf; *c > ' '; c++);
        *c = 0;
        if (get_casn_file(&cert.self, linebuf, 0) < 0)
            FATAL(MSG_READ, linebuf);
        read_casn_num(&cert.toBeSigned.serialNumber, &certnum);
        printf("%ld %s\n", certnum, linebuf);
    }
    DONE(MSG_OK, argv[1]);
    return 0;
}
