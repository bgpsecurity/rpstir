
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <casn.h>
#include <certificate.h>
#include <stdio.h>

char *msgs[] = {
    "Finished %s OK\n",
    "Usage: file of names\n",
    "Can't open %s\n",
    "Error reading %n\n",
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
    long certnum;
    Certificate(&cert, (ushort) 0);
    if (argc == 0 || argc < 2)
        fatal(1, (char *)0);
    FILE *fp = fopen(argv[1], "r");
    if (!fp)
        fatal(2, argv[1]);
    char linebuf[128];
    while (fgets(linebuf, 128, fp))
    {
        char *c;
        for (c = linebuf; *c > ' '; c++);
        *c = 0;
        if (get_casn_file(&cert.self, linebuf, 0) < 0)
            fatal(3, linebuf);
        read_casn_num(&cert.toBeSigned.serialNumber, &certnum);
        printf("%ld %s\n", certnum, linebuf);
    }
    fatal(0, argv[1]);
    return 0;
}
