/*
 * Jan 20 1997 416U 
 */
/*
 * Jan 20 1997 GARDINER fixed for bigger input lines 
 */
/*
 * Jul 10 1996 378U 
 */
/*
 * Jul 10 1996 GARDINER changed for Solaris 2 
 */
/*
 * Apr 11 1995 166U 
 */
/*
 * Apr 11 1995 GARDINER tidied for gcc 
 */
/*
 * Apr 11 1995 165U 
 */
/*
 * Apr 11 1995 GARDINER enlarged input buffer 
 */
/*
 * Oct 27 1994 98U 
 */
/*
 * Oct 27 1994 GARDINER fixed for input > 2048 bytes 
 */
/*
 * Mar 8 1994 1U 
 */
/*
 * Mar 8 1994 GARDINER Started on SPARC 
 */
/*
 * Mar 8 1994 
 */
/*
 * $Id$ 
 */
char six_to_bin_sfcsid[] = "@(#)six_to_bin.c 416P";
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

unsigned char ibuf[1024];
char *msgs[] = {
    "Finished OK\n",
    "Can't find string\n",
    "No search string\n",
};

void fatal(
    int);

int sixBitDecode(
    char *,
    char *,
    int);

int main(
    argc,
    argv)
     int argc;
     char *argv[];
{
    int lth,
        str_lth;
    unsigned char *a,
       *c,
       *obuf,
       *binbuf;
    if (argc < 2)
        fatal(2);
    str_lth = strlen(argv[1]);
    while ((c = (unsigned char *)fgets((char *)ibuf, sizeof(ibuf), stdin)) &&
           strncmp(argv[1], (char *)ibuf, str_lth));
    if (!c)
        fatal(1);
    a = obuf = (unsigned char *)calloc((lth = 1024), 1);
    do
    {
        for (c = &ibuf[str_lth]; *c && *c <= ' '; c++);
        if (&a[strlen((char *)c)] >= &obuf[lth])
        {
            str_lth = a - obuf;
            obuf = (unsigned char *)realloc(obuf, (lth += 1024));
            a = &obuf[str_lth];
        }
        for (; *c > ' '; *a++ = *c++);
        str_lth = 0;
        c = (unsigned char *)fgets((char *)ibuf, sizeof(ibuf), stdin);
    }
    while (c && *c);
    lth = a - obuf;
    binbuf = (unsigned char *)calloc(((lth + 3) / 4), 3);
    lth = sixBitDecode((char *)obuf, (char *)binbuf, lth);
    write(1, binbuf, lth);
    fatal(0);
    return (0);
}

void fatal(
    int err)
{
    fprintf(stderr, msgs[err]);
    exit(err);
}
