/* $Id$ */
/* Oct  1 2001 591U  */
/* Oct  1 2001 GARDINER added stuff for "biw" and "ocw" */
/* May 24 2001 577U  */
/* May 24 2001 GARDINER made main an int; fixed warning in hash_asn */
/* Apr 18 2000 529U  */
/* Apr 18 2000 GARDINER allowed "--" to indicate comment start */
/* Feb  4 1999 501U  */
/* Feb  4 1999 GARDINER added 'sth' feature */
/* Nov 22 1996 402U  */
/* Nov 22 1996 GARDINER tidied */
/* Nov 20 1996 399U  */
/* Nov 20 1996 GARDINER added -d switch */
/* Jul 30 1996 380U  */
/* Jul 30 1996 GARDINER fixed for big/little-endian */
/* Jul 10 1996 378U  */
/* Jul 10 1996 GARDINER changed for Solaris 2 */
/* Jan  3 1996 318U  */
/* Jan  3 1996 GARDINER taught dot notation; combined name table with asn_dump */
/* Jan  6 1995 123U  */
/* Jan  6 1995 GARDINER re-fixed lmarg */
/* Jan  6 1995 122U  */
/* Jan  6 1995 GARDINER re-fixed bug about lmarg */
/* Dec 29 1994 121U  */
/* Dec 29 1994 GARDINER loosened constraints on left margin */
/* Sep  2 1994  56U  */
/* Sep  2 1994 GARDINER fixed bug ending level */
/* Sep  1 1994  54U  */
/* Sep  1 1994 GARDINER fixed bug relating to last item at a level */
/* Aug 30 1994  51U  */
/* Aug 30 1994 GARDINER fixed test for lmarg in do_it; cleaned up flow code */
/* Aug 30 1994  50U  */
/* Aug 30 1994 GARDINER made lmarg a function of level */
/* Mar  8 1994   1U  */
/* Mar  8 1994 GARDINER Started on SPARC */
/* Mar  8 1994      */
/* RR */

#include <sys/types.h>
#include <fcntl.h>

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <stdio.h>
#include "asn.h"
#include "md2.h"

char rr_sfcsid[] = "@(#)rr.c 591p";

void dump_asn(), fatal(int, char *), hash_asn(), putasn(uchar),
    putout(uchar);

char buf[512], *hash_start,
    *msgs[] =
        {
	"RR finished OK. Wrote %d bytes\n", 	/* 0 */
	"Invalid parameter %s\n",		/* 1 */
	"Can't get memory\n",			/* 2 */
	"Extra '}'\n",				/* 3 */
	"Can't open %s\n",			/* 4 */
	"Area %s overflowed\n",			/* 5 */
	},
    *cvt_obj_id(char *, char *),
    *do_it (char *, int, int), *getbuf (char *);

struct varfld
    {
    ushort offset,      /* offset of field in vararea */
        lth;            /* length of variable-length field.  If field
                           is not present, lth is zero */
    }varfld;

int bytes, dflag, req, linenum, adj_asn(int), set_asn_lth(uchar *, uchar *),
    wdcmp(char *, char *), write_out(char *, int),
    write_varfld(struct varfld *);

struct name_tab
    {
    char *name;
    unsigned chunk, limit;
    char *area;    /* pointer to a general name area */
    unsigned size,  /* size    of the area */
        next;       /* offset to next free part of area */
    } genarea = {"genarea", 1024, 0x4000},  /* for varareas */
      out_area = {"out_area", 1024, 0x20000}, /* for all output, to avoid
		having to do lseek() with -r option */
      asn_area = {"asn_area", 1024, 0x20000};

extern struct typnames typnames[];  /* in asn.c */

int main(int argc, char **argv)
{
/* $b(+
1. Scan argvs to see if -r flag is set
   IF standard input and output have been redirected, run with them
   Scan argvs and at any file name
	Append .raw and open that as standard input
	Append .req and open that as standard output
	Convert the input file
	Close both standard input and output
2. Exit with OK message	$b) */
char *c, **p;
int fd;
for (p = &argv[1]; p < &argv[argc]; p++)
    {
    if (*(c = *p) == '-')
        {
	if (*(++c) == 'r') req = 1;
	else if (*c == 'd') dflag = 1;
	else fatal (1,*p);
	}
    }
if (!isatty (0) && !isatty (1))
    {
    do_it(buf, 0, 0);
    write(1, out_area.area, out_area.next);
    out_area.next = 0;
    }
for (p = &argv[1]; p < &argv[argc]; p++)
    {
    if (*(c = *p) == '-');
    else
	{
	strcat (strcpy (buf,*p),".raw");
	if ((fd = open (buf,O_RDONLY)) < 0 || dup2 (fd,0) < 0) fatal (4,buf);
	strcat (strcpy (buf,*p),".req");
	if ((fd = open (buf,(O_WRONLY | O_CREAT | O_TRUNC),0777)) < 0 ||
	    dup2 (fd,1) < 0) fatal (4,buf);
	*buf = 0;
	do_it(buf, 0, 0);
	write(1, out_area.area, out_area.next);
	out_area.next = 0;
	}
    }
fatal (0,(char *)bytes);
return 0;
}

char *do_it(char *c, int min, int level)
{
/* $b(+
Function: Converts text PM-request/response to true form

Inputs: Standard input is an input file

Outputs: Standard output is result

1. IF not at top level, skip to first blank
   Starting with no left margin, WHILE forever
	Skip white space
  	IF at line end
	    Get another line
	    Go to first non-blank
	    IF no left margin, set it to greater of this or min
	    IF at EOF OR line starts before left margin
		IF translating dot notation, put it out
		IF had a start for this line, set the length
		IF not at top level, return current pointer
		Break out of WHILE
2.	IF not in a comment 
	    IF no left margin, set it to this
	    IF char is numeric,
		IF string is decimal or hex, output data to appropriate place
		ELSE (dot notation) append to dot_buf
	    ELSE IF char is quote, put data in appropriate place
            ELSE IF char is '{'
     	        IF this is the first one, get space
    		Set the offset in varfld
            ELSE IF char is '}'
                Set the length in varfld
         	Write varfld to output
	    ELSE IF char is '/' OR '-', note half in comment
            ELSE IF md2 hash is called for, do that
	    ELSE IF starting a hash here, mark that
            ELSE
                IF not at a reserved word, skip it
                ELSE
                    IF had an ASN.1 item started, set its length
                    IF there's a tag, print it
                    ELSE convert the next word from hex
                    Put out zero length
                    IF it's constructed
                        Call this function for the next level
                        Set the length of this item
                        IF should be at a higher level, return current pointer
                        IF at end of line, break out of WHILE
                        Continue in WHILE
3.	ELSE IF half in a comment
                IF char is second half, note fully in comment
		ELSE IF char is non-whitespace,
                    Note not in comment
		    Back up one char to repeat
	ELSE IF fully in comment
            IF char is firts exit char, note half out of comment
	    ELSE IF char is non-whitespace, note fully out of comment
        ELSE IF half out of comment
            IF char is final exit char, note out of comment
            ELSE IF char is non-whitespace, note fully in comment
	IF at a non-null, go to next char
4. IF have anything in asn_area, put that out
   IF have any vararea, write it to output
   IF -r switch is set, put length in proper field
$b) */

char *b, *lmarg, quote, *cvt_out (), dot_buf[80], *edot;
int val, start = -1;
char comment[4]; /* contains up to 3 chars, 2 entry & 1 exit */
ushort lth;
struct typnames *tpnmp = (struct typnames *)0;
*(edot = dot_buf) = 0;
memset(comment, 0, sizeof(comment));
if (level) while (*c > ' ') c++;
for (lmarg = (char *)0; 1; ) 			            /* step 1 */
    {
    while (*c && *c <= ' ') c++;
    if (!*c)
        {
	if (comment[0] && comment[0] == comment[1]) memset(comment, 0, 3);
	for (c = getbuf (buf); c && *c && *c <= ' '; c++);
	if (!lmarg) lmarg = (c > &buf[min])? c: &buf[min];
	if (!c || c < lmarg || (c == lmarg && start >= 0))
	    {
	    if (edot > dot_buf)
		{
                cvt_obj_id(dot_buf, edot);
		*(edot = dot_buf) = 0;
		}
	    if (start >= 0 && c <= lmarg) start = adj_asn (start);
	    if (c < lmarg)
		{
    	        if (level) return c;
    	        break;
    	        }
	    }
	}
    if (!comment[0])                                       /* step 2 */
        {
        if (*c >= '0' && *c <= '9')
	    {
	    for (b = c; *b >= '0' && *b <= '9'; b++);
            if (*b != '.') c = cvt_out (c);
	    else while (*c > ' ') *edot++ = *c++;
	    }
        else if (*c == '"' || *c == '\'')
	    for (quote = *c++; *c != quote; putout (*c++));
        else if (*c == '{')
            {
            if (!genarea.area)
	        {
                if (!(genarea.area = calloc((genarea.size = genarea.chunk), 1)))
    		    fatal (2, (char *)0);
                if (bytes & 1) bytes += write_out("",1);
		}
	    if (genarea.next & 1) genarea.next++;
	    varfld.offset = genarea.next;
            }
        else if (*c == '}')
            {
	    if (level) return c;
	    if (asn_area.next) dump_asn ();
	    varfld.lth = genarea.next - varfld.offset;
            bytes += write_varfld(&varfld);
            }
        else if (*c == '/' || *c == '-') comment[0] = *c;
	else if (!wdcmp ("md2",c))
	    {
	    hash_asn ();
	    c += 3;
	    }
	else if (!wdcmp("sth", c))
	    {
            hash_start = &asn_area.area[asn_area.next];
	    c += 3;
	    }
	else if (*c)
	    {
	    if (!lmarg) lmarg = c;
	    for (tpnmp = typnames; tpnmp->name && wdcmp(tpnmp->name, c); tpnmp++);
	    if (!tpnmp->name) while (*c > ' ') c++;
	    else
	        {
		if (start >= 0) start = adj_asn (start);
		start = asn_area.next;
		if (tpnmp->typ)
		    {
		    putasn (tpnmp->typ);
		    if ((tpnmp->typ & 0xC0))
		        {
			for (b = &c[3]; *c && *c++ != '+';);
		        if (*c == '0' && (*(++c) | 0x20) == 'x')
			    {
			    c++;
			    val = *c - '0' - ((*c > '9')? 7: 0) -
			        ((*c >= 'a')? 0x20: 0);
			    val <<= 4;
			    *c++ = '0';
			    val |= *c - '0' - ((*c > '9')? 7: 0) -
			        ((*c >= 'a')? 0x20: 0);
			    *c++ = 'x';
			    }
			else for (val = 0; *c >= '0' && *c <= '9'; val =
			    (val * 10) + *c++ - '0');
		        asn_area.area[asn_area.next -1] |= (char)val;
			for (c = cvt_out(&c[-2]); c > b; *(--c) = ' ');
			}
		    }
		else
		    {
		    for (b = c; *b > ' '; b++);
		    while (*b && *b <= ' ') b++;
		    for (b = cvt_out (b); b > c; *(--b) = ' ');
		    }
		putasn ((char)0);
		if ((asn_area.area[start] & ASN_CONSTRUCTED))
		    {
		    if (asn_area.area[start] == (ASN_CONSTRUCTED | ASN_BITSTRING) ||
			asn_area.area[start] == (ASN_CONSTRUCTED | ASN_OCTETSTRING))
			asn_area.area[start] &= ~(ASN_CONSTRUCTED);
		    c = do_it(++c, &lmarg[1] - buf, level + 1);
		    start = adj_asn (start);
		    if (c < lmarg && level) return c;
		    if (!c) break;
		    continue;
		    }
		else while (*c > ' ') c++;
		}
	    }
	}
    else if (!comment[1])                              /* step 3 */
        {
	if ((comment[0] == '/' && (*c == '*' || *c == '/')) ||
            (comment[0] == '-' && *c == '-'))  comment[1] = *c;
	else comment[0] = 0;
	}
    else if (!comment[2] && comment[1] != '/' && *c == comment[1])
        comment[2] = *c;
    else if (*c == comment[0]) memset(comment, 0, 3);
    else comment[2] = 0;
    if (*c) c++;
    }
if (edot > dot_buf) cvt_obj_id(dot_buf, edot);
if (asn_area.next) dump_asn ();				/* step 4 */
if (genarea.area)
    {
    if (genarea.next & 1) genarea.next++;
    bytes += write_out(genarea.area,genarea.next);
    }
if (req)
    {
    lth = bytes - 4;
    out_area.area[3] = (char )(lth & 0xFF);
    out_area.area[2] = (char )((lth >> 8) & 0xFF);
    }
return c;
}

int adj_asn(int start)
{
putasn ((char)0);
putasn ((char)0);
 asn_area.next += set_asn_lth ((uchar *)&asn_area.area[start],
			       (uchar *)&asn_area.area[asn_area.next -= 2]);
return -1;
}

char *cvt_obj_id(char *from, char *to)
{
uchar *b, locbuf[20], *e = &locbuf[sizeof(locbuf)];
long val, tmp;                                      /* do first field */
for (val = 0; from < to && *from != '.'; val = (val * 10) + *from++ - '0');
val *= 40;
for (from++, tmp = 0; from < to && *from != '.'; tmp = (tmp * 10) + *from++
    - '0');
val += tmp;
for (b = e, tmp = val; val; val >>= 7)
    *(--b) = (uchar)(val & 0x7F) | ((tmp != val)? 0x80: 0);
while (b < e) putout(*b++);
for (from++; from < to; from++)                       /* now do next fields */
    {
    for (val = 0; from < to && *from != '.'; val = (val * 10) + *from++ - '0');
    if (!val) *(b = &e[-1]) = 0;
    else for (b = e, tmp = val; val; val >>= 7)
	*(--b) = (uchar)(val & 0x7F) | ((tmp != val)? 0x80: 0);
    while (b < e) putout(*b++);
    }
return from;
}

char *cvt_out (char *c)
{
/* $b(+
Function: Converts string pointed to by c and puts it in right place

IF string is hex
    FOR each byte pair
        Convert byte pairs to a byte
    	Write the byte to output
    IF there's an odd byte, error
ELSE
    Convert as a decimal number
    Write it as one byte to output
$b) */
uchar val;
char *b;
if (*c == '0' && (c[1] | 0x20) == 'x')
    {
    for (c += 2, b = c; (*b >= '0' && *b <= '9') || ((*b | 0x20) >= 'a' &&
        (*b | 0x20) <= 'f'); b++);
    if ((((int)(c - b)) & 1))
        {
        if (*c > '9') val = (*c++ | 0x20) - 0x27 - '0';
    	else val = *c++ - '0';
        putout (val);
	}
    while (c < b)
        {
        if (*c > '9') val = (*c++ | 0x20) - 0x27 - '0';
	else val = *c++ - '0';
        val <<= 4;
        if (*c > '9') val += (*c++ | 0x20) - 0x27 - '0';
        else val += *c++ - '0';
        putout (val);
        }
    }
else 
    {
    for (val = 0; *c >= '0' && *c <= '9'; val = (val * 10) + *c++ - '0');
    putout (val);
    }
return c;
}

void dump_asn()
{
/**
Function: Transfers the contents of asn_area to output.  Note the setting of
asn_area.next to zero to force putout to go elsewhere
**/
char *c, *e;
for (c = asn_area.area, e = &c[asn_area.next], asn_area.next = 0; c < e;
    putout (*c++));
}

void fatal(int err, char *param)
{
fprintf (stderr,msgs[err],param);
exit (err);
}

char *getbuf(char *to)
{
char *b, *c, *e;
int col;
//if (!gets (to)) return (char *)0;
if (!fgets(to, 512, stdin)) return (char *)0;
linenum++;
for (b = to; *b; b++);
e = b;
if (!dflag)
    {
    for (b = to; b < e; )
        {
        if (*b == '\t')
            {
    	    col = b - to;
    	    col = 7 - (col & 0x7);
    	    for (c = e, e = &c[col]; c > b; c[col] = *c, c--);
    	    for (c += col + 1; b < c; *b++ = ' ');
    	    }
         else b++;
	}
    }
else
    {
    e[-16] = 0;
    if (*to <= ' ') for (b = to; *b && *b <= ' '; b++);
    else b = to;
    while (*b > ' ') b++;
    while (*b && *b <= ' ') b++;
    *to = '0';
    to[1] = 'x';
    strcpy(&to[2], b);
    for (b = &to[2]; *b; )
	{
	if (*b <= ' ') strcpy(b, &b[1]);
	else b++;
	}
    }
return to;
}

void hash_asn()
{
MD2_CTX md;
uchar *c, *e, typ, *asn_typ_lth();
struct asn asnb;
MD2Init(&md);
if (!hash_start) asnb.stringp = (uchar *)&asn_area.area[2];
 else asnb.stringp = (uchar *)hash_start;
c = asn_typ_lth(&asnb, &typ, 1);
MD2Update(&md, asnb.stringp, asnb.lth + (c - asnb.stringp));
MD2Final(&md);
for (c = md.buf, e = &c[16]; c < e; putout (*c++));
}

int numconv(char *c)
{
int val = 0;
if (*c == '0' && (*(++c) | 0x20) == 'x')
    {
    for (c++; (*c >= '0' && *c <= '9') || ((*c | 0x20) >= 'a' && (*c | 0x20)
      	<= 'f'); val = (val << 4) + (*c++ | 0x20) - 0x27 - '0');
    }
return val;
}

void putasn(uchar val)
{
if (!asn_area.area && !(asn_area.area = calloc ((asn_area.size =
    asn_area.chunk), 1))) fatal(2, (char *)0);
if (asn_area.next >= asn_area.size)
    {
    if (!(asn_area.area = realloc (asn_area.area,(asn_area.size +=
	    asn_area.chunk)))) fatal(2, (char *)0);
	if (asn_area.size >= asn_area.limit) fatal (5,asn_area.name);
	}
asn_area.area[asn_area.next++] = val;
}

void putout (uchar val)
{
if (asn_area.next) putasn (val);
else if (!genarea.area) bytes += write_out((char *)&val,1);
else
    {
    if (genarea.next >= genarea.size)
        {
	if (!(genarea.area = realloc (genarea.area,(genarea.size +=
	    genarea.chunk)))) fatal(2, (char *)0);
	if (genarea.size >= genarea.limit) fatal(3, (char *)0);
	}
    genarea.area[genarea.next++] = val;
    }
}

int wdcmp(char *s1, char *s2)  /* s1 is target */
{
for (; *s1 > '+' && *s1 == *s2; s1++, s2++);
if (*s1 > '+' || (*s1 != '+' && *s2 > '+')) return -1;
return 0;
}

int write_out(char *c, int lth)
{
char *b, *e;
if (!out_area.area && !(out_area.area = calloc(out_area.chunk, 1)))
    fatal(2, (char *)0);
while (out_area.next + lth > out_area.size)
    {
    if ((out_area.size += out_area.chunk) > out_area.limit)
	fatal(5, out_area.name);
    if (!(out_area.area = realloc(out_area.area, out_area.size +=
 	out_area.chunk))) fatal(2, (char *)0);
    }
for(b = &out_area.area[out_area.next], e = &b[lth]; b < e; *b++ = *c++);
out_area.next = b - out_area.area;
return lth;
}

int write_varfld(struct varfld *varfldp)
{
char c = (char)((varfldp->offset >> 8) & 0xFF);
write_out(&c, 1);
c = (char)(varfldp->offset & 0xFF);
write_out(&c, 1);
c = (char)((varfldp->lth >> 8) & 0xFF);
write_out(&c, 1);
c = (char)(varfldp->lth & 0xFF);
write_out(&c, 1);
return sizeof(struct varfld);
}
