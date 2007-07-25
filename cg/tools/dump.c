/* $Id$ */
/* May 23 2006 840U  */
/* May 23 2006 GARDINER additions for APKI */
/* May 24 2001 577U  */
/* May 24 2001 GARDINER made main an int */
/* Apr 10 2000 528U  */
/* Apr 10 2000 GARDINER made getd() not change input string */
/* Nov 18 1996 395U  */
/* Nov 18 1996 GARDINER added -b and -l switches */
/* Aug 30 1996 388U  */
/* Aug 30 1996 GARDINER made self-adjusting for little-endian */
/* Jul 10 1996 378U  */
/* Jul 10 1996 GARDINER changed for Solaris 2 */
/* Jan  3 1996 318U  */
/* Jan  3 1996 GARDINER combined name table with rr */
/* Oct 13 1995 290U  */
/* Oct 13 1995 GARDINER fixed bug from bcopy in dump_asn1() */
/* Aug 30 1994  50U  */
/* Aug 30 1994 GARDINER initialize EOF pos variable */
/* Apr 21 1994  20U  */
/* Apr 21 1994 GARDINER allow indefinite length encoding */
/* Apr  6 1994  11U  */
/* Apr  6 1994 GARDINER fixed error messages; allow indef to start */
/* Mar  8 1994   1U  */
/* Mar  8 1994 GARDINER Started on SPARC */
/* Mar  8 1994      */
/*****************************************************************************
File:     dump.c
Contents: Main function of the dump utility
System:   IOS development.
Created:  Mar 8, 1994
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

 ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 1994-2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/
/* DUMP */
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "asn.h"

#define BSIZE 512

char dump_sfcsid[] = "@(#)dump.c 840P";

extern int asn1dump(unsigned char *, int, FILE *);

static void dump_asn1(int, long);
void fatal(int, char *);

char ibuf[BSIZE],
    obuf[80] = "     0  ",
    *fname,
    *err_msgs[] =
	{
	"Dump finished OK\n",
	"Invalid parameters\n",		/* 1 */
	"Can't open file\n",		/* 2 */
	"Can't read file\n",		/* 3 */
	"Error getting memory\n",	/* 4 */
	"ASN.1 error at offset 0x%x\n",	  /* 5 */
	"Error dumping ASN.1\n",	/* 6 */
	"Can't start in pipe with indefinite-length-encoded item\n", /* 7 */
	"File is shorter than first item's length implies\n",       /* 8 */
	},
    hex[] = "0123456789ABCDEF",
    *hexit(char *, unsigned char);

long getd ();
int aflag, is_numeric();

int main (int argc, char **argv)
{
char *b, *c, **p;
char *d, *e, *ee;
int did, fd = 0, offset, lth, count, little;
long start, pos, left;
union
    {
    short x;
    char y[2];
    } end_test;
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
            if (aflag) fatal(1, c);
            aflag = (*b == 'a')? 1: -1;
            }
	else if (*b == 'l') little = 1;
	else if (*b == 'b') little = 0;
	else pos = -getd (&b,0);
	}
    else if (*c == '+') pos = getd (&b,0);
    else if (is_numeric(c)) left = getd (&c,0);
    else fname = c;
    }
if (fname && (fd = open(fname, O_RDONLY)) < 0) fatal(2, (char *)0);
if (aflag) dump_asn1(fd, pos);
if (pos < 0) start = lseek (fd,0L,2);
else start = 0;
lseek (fd,((start + pos) & ~(BSIZE - 1)),0);
c = &ibuf[((pos += start) & (BSIZE - 1))];
if (!left) left = 1000000000;
left += (c - ibuf);
did = 16 - (offset = pos & 0xF);
for ( ; left; c = ibuf)
    {
    for (lth = 0; (count = read(fd, &ibuf[lth], (int)((left > BSIZE - lth)?
	BSIZE - lth: left))); lth += count);
    if (!lth) break;
    if (c > ibuf)
        {
        lth -= (c - ibuf);
	left -= (c - ibuf);
	}
    if (lth > left) lth = left;
    for (e = &c[lth]; c < e && left; )          /* each input block */
        {
        if (!little) for (; lth > 0; )          /* each output line */
            {
            for (*(b = &obuf[5]) = '0', start = pos; start; start >>= 4)
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
            for (ee = &c[lth]; d < &obuf[66] && c < ee; )
                {
                b = hexit(b, *c);
                *d++ = *c++;
                if (c >= ee) break;
                b = hexit(b, *c);
                *d++ = *c++;
                *b++ = ' ';
                }
            while (b < &obuf[50]) *b++ = ' ';
            for (b = &obuf[50]; b < d; b++) if (*b < ' ' ||
                (unsigned char)*b > '~') *b = '.';
            while (d < &obuf[66]) *d++ = ' ';
            write (1,obuf,67);
            pos += did;
            lth -= did;
            left -= did;
            did = (left > 16)? 16: left;
            }
        else for (; lth > 0; )          /* each output line */
            {
            for (*(b = &obuf[47]) = '0', start = pos; start; start >>= 4)
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
            for (ee = &c[lth]; d < &obuf[66] && c < ee; )
                {
		*b-- = ' ';
                b = &hexit(b, *c)[-4];
                *d++ = *c++;
                if (c >= ee) break;
                b = &hexit(b, *c)[-4];
                *d++ = *c++;
                }
	    if (b > obuf) b[1] = ' ';
            while (b >= obuf) *b-- = ' ';
            for (b = &obuf[50]; b < d; b++) if (*b < ' ' ||
                (unsigned char)*b > '~') *b = '.';
            while (d < &obuf[66]) *d++ = ' ';
            write (1,obuf,67);
            pos += did;
            lth -= did;
            left -= did;
            did = (left > 16)? 16: left;
            }
        }
    }    
fatal(0, (char *)0);
return 0;
}


void fatal (int err, char *param)
{
fprintf(stderr, err_msgs[err], param);
exit (err);
}


long getd (char **b, int lev)
{
long val = 0;
int base = 16;
char *c = *b, wk;
if (*c == '0')
    {
    if (*(++c) != 'x' && *c != 'X') base = 8;
    else c++;
    }
else base = 10;
for (val = 0; *c; )
    {
    if (*c == '+' || *c == '-')
        {
	if (lev) break;
	if (*c++ == '+') val += getd (&c,lev + 1);
	else val -= getd (&c,lev + 1);
	}
    else if (base == 16)
        {
	wk = *c++;
        if (wk >= 'a' && wk <= 'f') wk &= ~0x20;
	if (wk > 'F') break;
        if (wk > '9') wk -= 7;
	val = (val << 4) + wk - '0';
	}
    else if (*c - '0' > base) break;
    else val = (val * base) + *c++ - '0';
    }
*b = c;
return val;
}



char *hexit(char *b, unsigned char c)
{
*b++ = hex[c >> 4];
*b++ = hex[c & 0xF];
return b;
}

int is_numeric(char *c)
{
getd(&c, 0);
if (!*c) return 1;
return 0;
}

void dump_asn1(int fd, long pos)
{
int lth, size;
struct asn asn;
uchar *area, *c, *asn_set();
struct stat tstat;
if (pos < 0) fatal(1, (char *)0);
if (fd)
    {
    if (fstat(fd, &tstat)) fatal(3, (char *)0);
    lseek (fd, pos, 0);
    }
for(lth = 0; lth < 8; lth += size)
    {
    if ((size = read(fd, &ibuf[lth], 8 - lth)) < 0) fatal(3, (char *)0);
    else if (!size)
        {
        if (!lth) fatal(0, (char *)0);
	break;
	}
    }
asn.stringp = (uchar *)ibuf;
c = asn_set(&asn);
if (asn.lth)
    {
    size = (c - (uchar *)ibuf) + asn.lth;
    if (fd && pos + size > tstat.st_size) fatal(8, (char *)0);
    }
else if (!fd) fatal(7, (char *)0);
else size = tstat.st_size - pos;
if (!(area = (uchar *)calloc((size + 2), 1))) fatal(4, (char *)0);
memcpy(area, ibuf, lth);
for (c = &area[lth], lth = 0; c < &area[size] &&
    (lth = read(fd, c, (size - (c - area)))) > 0; c += lth);
if (c < &area[size]) fatal(8, (char *)0);
if (asn1dump(area, size, stdout) < 0) fatal(6, (char *)0);
fatal(0, (char *)0);
}
