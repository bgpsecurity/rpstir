/*
 * $Id: six2hex.c 453 2007-07-25 15:30:40Z mreynolds $ 
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

unsigned char binbuf[1024];
char obuf[2048];

extern int sixBitDecode(
    char *,
    char *,
    int);

int main(
    int argc,
    char *argv[])
{
    int inlth,
        lth;
    unsigned char *a,
       *e;
    char *c;

    if (argc < 2)
    {
        printf("Usage: sixbit string\n");
        return 0;
    }
    for (c = argv[1]; *c > ' '; c++);
    *c = 0;
    inlth = c - argv[1];
    lth = sixBitDecode(argv[1], (char *)binbuf, strlen(argv[1]));
    for (a = binbuf, c = obuf, e = &binbuf[lth]; a < e; a++, c += 2)
        sprintf(c, "%02X", *a);
    int outlth = (inlth * 3) / 2;
    fprintf(stderr, "inlth %d, outlth %d\n", inlth, outlth);
    obuf[outlth] = 0;
    printf("%s\n", obuf);
    return (0);
}
