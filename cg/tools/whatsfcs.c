/* $Id$ */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#define	BSIZE	512
#define	SCRSIZE	23
#define MONTH 5
#define DATE 9
#define ALT 26
#define DIR 47
char whatsfcs_sfcsid[] = "@(#)whatsfcs.c 843P";
char buf[3*BSIZE],
    namebuf[82],
    fmt[] = "%d %d %d:%d:%d",
    *write_line ();
int linenum, wdcmp(char *, char *);
struct mo
    {
    char *name;
    int size;
    } mos[] =
	{
	    {"Jan", 31},
	    {"Feb", 29},
	    {"Mar", 31},
	    {"Apr", 30},
	    {"May", 31},
	    {"Jun", 30},
	    {"Jul", 31},
	    {"Aug", 31},
	    {"Sep", 30},
	    {"Oct", 31},
	    {"Nov", 30},
	    {"Dec", 31},
        { 0, 0},
	};


int main (argc,argv)
int argc;
char *argv[];
{
register int fd, lth;
register char *b, *c, *d;
char *e1, *e2, *fname, **p, *mname, *a, starter;
int nreads, da, yr, hr, min, sec;
long offset = 0;
struct mo *mo_ptr;
if (argc < 2)
    {
    printf ("No file name\n");
    exit (0);
    }
for (p = &argv[1]; *p; p++)
    {
    if ((fd = open (fname = *p,0)) < 0)
	{
	printf ("Can't open %s\n",fname);
	continue;
	}
    for (c = fname; *c++; );
    for (e2 = buf; (lth = read(fd,e2,BSIZE)) > 0 && (e2 = &e2[lth]) <
	&buf[2*BSIZE];);
    if (lth < 0)
	{
	printf("Can't read %s\n", fname);
	continue;
	}
    e1 = &buf[BSIZE];
    if (!lth) e1 = e2;
    nreads = 1;
    offset += e2 - buf;
    write (1,fname,strlen (fname));
    b = &buf[MONTH];
    for (mo_ptr = mos; mo_ptr->name && wdcmp (mo_ptr->name,b); mo_ptr++);
    if (mo_ptr->name &&
        sscanf (&buf[DATE],fmt,&da,&yr,&hr,&min,&sec) == 5 &&
        da && da <= mo_ptr->size && yr > 1980 && yr < 2000 && hr >= 0 &&
        hr < 24 && min >= 0 && min < 60 && sec >= 0 && sec < 60)
        {
        sprintf (namebuf," of %s\n  from %s",b,&buf[DIR]);
        if (buf[ALT])
            {
            write_line ();
            sprintf (namebuf,"  changed on %s",&buf[ALT]);
            }
        }
    else *namebuf = 0;
    strcat (namebuf," has:");
    mname = write_line ();
    for (c = buf; e2 > buf;)
	{
	while (c < e1 && *c != '@') c++;
	if (*c == '@' && *(++c) == '(' && *(++c) == '#' && *(++c) == ')' && c <
	    e2)
    	    {
            if ((starter = c[-4]) != '"' && starter != '\'') starter = '\n';
            c++;
            for (d = c; *d && *d != starter; d++);
            if (&mname[(d - c)] >= &namebuf[80]) mname = write_line ();
            d = mname;
            while (*c > ' ' && *c != starter) *d++ = *c++;
            if (*c == ' ')
                {
                while (*c == ' ') *d++ = *c++;
                if (*c >= '0' && *c <= '9' && d <= &mname[15])
                    {    /* right justify batch number */
                    for (a = c; *a >= '0' && *a <= '9'; a++);
                    for (d = &mname[15]; a < &c[3]; *d++ = ' ', a++);
                    while (*c && d <= &mname[19] && *c != starter) *d++ = *c++;
                    }
                else while (*c >= ' ' && *c <= '~' && *c != starter)
                    *d++ = *c++;
                }
            if (d > mname)
    	        {
                mname += ((d - mname + 19) / 20) * 20;
                for (*mname = 0; d < mname; *d++ = ' ');
		}
    	    }
	if (c >= e1)
    	    {
    	    for (b = buf; c < e2; *b++ = *c++);
    	    c = buf;
    	    for (e2 = b; (lth = read (fd,e2,BSIZE)) && (e2 = &e2[lth]) <
    	        &buf[2*BSIZE];);
    	    e1 = &buf[BSIZE];
    	    if (!lth) e1 = e2;
            nreads++;
            offset += e2 - b;
	    }
	}
    if (*namebuf > ' ') write_line ();
    write_line ();
    close (fd);
    }
exit (0);
}


int wdcmp (char *s1, char *s2)
{
while (*s1 && *s1 == *s2++) s1++;
if (!*s1) return 0;
return 1;
}


char *write_line ()
{
char *c;
namebuf[79] = 0;
for (c = namebuf; *c; c++);
*c++ = '\n';
*c = 0;
write (1,namebuf,c - namebuf);
if (isatty (1) && ++linenum >= SCRSIZE)
    {
    write (1,"Continue or quit (<c>/q)? ",26);
    fgets (namebuf, sizeof(namebuf), stdin);
    if ((*namebuf | 0x20) == 'q') exit (0);
    linenum = 0;
    }
for (c = namebuf; c < &namebuf[79]; *c++ = ' ');
*c = 0;
return namebuf;
}
