/*****************************************************************************
File:     dump.c
Contents: Main function of the dump utility
System:   IOS development.
Created:  Mar 8, 1994
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/
/*
 * DUMP
 */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "casn/asn.h"
#include "util/logging.h"

#define BSIZE 512

#define MSG_OK "Dump finished OK"
#define MSG_INVAL "Invalid parameters"
#define MSG_OPEN "Can't open file"
#define MSG_READ "Can't read file"
#define MSG_MEM "Error getting memory"
#define MSG_ASN1 "ASN.1 error at offset 0x%x"
#define MSG_DUMP "Error dumping ASN.1"
#define MSG_PIPE "Can't start in pipe with indefinite-length-encoded item"
#define MSG_LEN "File is shorter than first item's length implies"

int
asn1dump(
    unsigned char *,
    int,
    FILE *);

uchar *
asn_set(
    struct asn *asnp);

static void
dump_asn1(
    int,
    long);

char ibuf[BSIZE];
char obuf[80] = "     0  ";
char *fname;
char hex[] = "0123456789ABCDEF";

char *
hexit(
    char *,
    unsigned char);

long
getd(
    char **b,
    int lev);

int aflag;

int
is_numeric(
    );

int main(
    int argc,
    char **argv)
{
    char *b;
    char *c;
    char **p;
    char *d;
    char *e;
    char *ee;
    int did;
    int fd = 0;
    int offset;
    int lth;
    int count;
    int little;
    long start;
    long pos;
    long left;
    union {
        short x;
        char y[2];
    } end_test;

    (void)argc;

    end_test.x = 1;
    little = (end_test.y[0] > 0);
    for (c = obuf; c < &obuf[66]; *c++ = ' ');
    *c++ = '\n';
    for (p = &argv[1], pos = left = 0; *p; p++)
    {
        b = &(c = *p)[1];
        if (*c == '-')
        {
            if (*b == 'a' || *b == 'A')
            {
                if (aflag)
                    FATAL(MSG_INVAL);
                aflag = (*b == 'a') ? 1 : -1;
            }
            else if (*b == 'l')
                little = 1;
            else if (*b == 'b')
                little = 0;
            else
                pos = -getd(&b, 0);
        }
        else if (*c == '+')
            pos = getd(&b, 0);
        else if (is_numeric(c))
            left = getd(&c, 0);
        else
            fname = c;
    }
    if (fname && (fd = open(fname, O_RDONLY)) < 0)
        FATAL(MSG_OPEN);
    if (aflag)
        dump_asn1(fd, pos);
    if (pos < 0)
        start = lseek(fd, 0L, 2);
    else
        start = 0;
    lseek(fd, ((start + pos) & ~(BSIZE - 1)), 0);
    c = &ibuf[((pos += start) & (BSIZE - 1))];
    if (!left)
        left = 1000000000;
    left += (c - ibuf);
    did = 16 - (offset = pos & 0xF);
    for (; left; c = ibuf)
    {
        for (lth = 0;
             (count =
              read(fd, &ibuf[lth],
                   (int)((left > BSIZE - lth) ? BSIZE - lth : left)));
             lth += count);
        if (!lth)
            break;
        if (c > ibuf)
        {
            lth -= (c - ibuf);
            left -= (c - ibuf);
        }
        if (lth > left)
            lth = left;
        for (e = &c[lth]; c < e && left;)       /* each input block */
        {
            if (!little)
                for (; lth > 0;)        /* each output line */
                {
                    for (*(b = &obuf[5]) = '0', start = pos; start;
                         start >>= 4)
                        *b-- = hex[start & 0xF];
                    b = &obuf[8];
                    d = &obuf[50];
                    if (offset)
                    {
                        b += (2 * offset + (offset / 2));
                        d += offset;
                        if (offset & 1)
                        {
                            b = hexit(b, *c);
                            *d++ = *c++;
                            *b++ = ' ';
                        }
                        offset = 0;
                    }
                    for (ee = &c[lth]; d < &obuf[66] && c < ee;)
                    {
                        b = hexit(b, *c);
                        *d++ = *c++;
                        if (c >= ee)
                            break;
                        b = hexit(b, *c);
                        *d++ = *c++;
                        *b++ = ' ';
                    }
                    while (b < &obuf[50])
                        *b++ = ' ';
                    for (b = &obuf[50]; b < d; b++)
                        if (*b < ' ' || (unsigned char)*b > '~')
                            *b = '.';
                    while (d < &obuf[66])
                        *d++ = ' ';
                    write(1, obuf, 67);
                    pos += did;
                    lth -= did;
                    left -= did;
                    did = (left > 16) ? 16 : left;
                }
            else
                for (; lth > 0;)        /* each output line */
                {
                    for (*(b = &obuf[47]) = '0', start = pos; start;
                         start >>= 4)
                        *b-- = hex[start & 0xF];
                    b = &obuf[38];
                    d = &obuf[50];
                    if (offset)
                    {
                        b -= (2 * offset + (offset / 2));
                        d += offset;
                        if (offset & 1)
                        {
                            b--;
                            b = &hexit(b, *c)[-4];
                            *d++ = *c++;
                        }
                        offset = 0;
                    }
                    for (ee = &c[lth]; d < &obuf[66] && c < ee;)
                    {
                        *b-- = ' ';
                        b = &hexit(b, *c)[-4];
                        *d++ = *c++;
                        if (c >= ee)
                            break;
                        b = &hexit(b, *c)[-4];
                        *d++ = *c++;
                    }
                    if (b > obuf)
                        b[1] = ' ';
                    while (b >= obuf)
                        *b-- = ' ';
                    for (b = &obuf[50]; b < d; b++)
                        if (*b < ' ' || (unsigned char)*b > '~')
                            *b = '.';
                    while (d < &obuf[66])
                        *d++ = ' ';
                    write(1, obuf, 67);
                    pos += did;
                    lth -= did;
                    left -= did;
                    did = (left > 16) ? 16 : left;
                }
        }
    }
    DONE(MSG_OK);
    return 0;
}


long getd(
    char **b,
    int lev)
{
    long val = 0;
    int base = 16;
    char *c = *b;
    char wk;
    if (*c == '0')
    {
        if (*(++c) != 'x' && *c != 'X')
            base = 8;
        else
            c++;
    }
    else
        base = 10;
    for (val = 0; *c;)
    {
        if (*c == '+' || *c == '-')
        {
            if (lev)
                break;
            if (*c++ == '+')
                val += getd(&c, lev + 1);
            else
                val -= getd(&c, lev + 1);
        }
        else if (base == 16)
        {
            wk = *c++;
            if (wk >= 'a' && wk <= 'f')
                wk &= ~0x20;
            if (wk > 'F')
                break;
            if (wk > '9')
                wk -= 7;
            val = (val << 4) + wk - '0';
        }
        else if (*c - '0' > base)
            break;
        else
            val = (val * base) + *c++ - '0';
    }
    *b = c;
    return val;
}



char *hexit(
    char *b,
    unsigned char c)
{
    *b++ = hex[c >> 4];
    *b++ = hex[c & 0xF];
    return b;
}

int is_numeric(
    char *c)
{
    getd(&c, 0);
    if (!*c)
        return 1;
    return 0;
}

void dump_asn1(
    int fd,
    long pos)
{
    int lth;
    int size;
    struct asn asn;
    uchar *area;
    uchar *c;
    struct stat tstat;
    if (pos < 0)
        FATAL(MSG_INVAL);
    if (fd)
    {
        if (fstat(fd, &tstat))
            FATAL(MSG_READ);
        lseek(fd, pos, 0);
    }
    for (lth = 0; lth < 8; lth += size)
    {
        if ((size = read(fd, &ibuf[lth], 8 - lth)) < 0)
            FATAL(MSG_READ);
        else if (!size)
        {
            if (!lth)
                DONE(MSG_OK);
            break;
        }
    }
    asn.stringp = (uchar *) ibuf;
    c = asn_set(&asn);
    if (asn.lth)
    {
        size = (c - (uchar *) ibuf) + asn.lth;
        if (fd && pos + size > tstat.st_size)
            FATAL(MSG_LEN);
    }
    else if (!fd)
        FATAL(MSG_PIPE);
    else
        size = tstat.st_size - pos;
    if (!(area = (uchar *) calloc((size + 2), 1)))
        FATAL(MSG_MEM);
    memcpy(area, ibuf, lth);
    for (c = &area[lth], lth = 0; c < &area[size] &&
         (lth = read(fd, c, (size - (c - area)))) > 0; c += lth);
    if (c < &area[size])
        FATAL(MSG_LEN);
    if (asn1dump(area, size, stdout) < 0)
        FATAL(MSG_DUMP);
    DONE(MSG_OK);
}
