
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <casn/casn.h>
#include <rpki-asn1/certificate.h>
#include <stdio.h>
#include "util/logging.h"

#define MSG_OK "Finished %s OK"
#define MSG_USAGE "Usage: filename serialNum"
#define MSG_OPEN "Can't open %s"
#define MSG_READING "Error reading %s"
#define MSG_WRITING "Error writing %s"

int main(
    int argc,
    char **argv)
{
    struct Certificate cert;
    int certnum;
    Certificate(&cert, (ushort) 0);
    if (argc < 3)
        FATAL(MSG_USAGE);
    if (get_casn_file(&cert.self, argv[1], 0) <= 0)
        FATAL(MSG_OPEN, argv[1]);
    if (sscanf(argv[2], "%d", &certnum) != 1)
        FATAL(MSG_READING, "serial number");
    if (write_casn_num(&cert.toBeSigned.serialNumber, certnum) < 0)
        FATAL(MSG_WRITING, "serial number");
    if (put_casn_file(&cert.self, argv[1], 0) < 0)
        FATAL(MSG_WRITING, argv[1]);
    DONE(MSG_OK, argv[1]);
    return 0;
}
