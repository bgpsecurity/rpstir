/* $Id: compare.c 453 2008-07-25 15:30:40Z cgardiner $ */

/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles iW. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
/* COMPARE */
// #include "includes.h"
#include "sfcs.h"

#define A_LEN 3000
#define FSIZE   1000    /* size of na, oa & o_tab increments */
#define HASH    16384
#define FLAG    0x4000 /* in na, tentative xlink; in oa, printed; in hasht,
xlinked pair */
#define BLANK   FLAG-1
char sfcsid[] = "@(#)compare.c 845P";

char n_buf[BSIZE], o_buf[BSIZE], namebuf[BSIZE],
    delchar = 'D',
    *n_file = 0,
    *o_file = 0,
    *c_file = "diffile",
    c_hdr[D_HDR+2],
    *replies[] =
        {
        "*       lines deleted,       inserted,       moved\n", /* 0 */
        "*!  INVALID ARGUMENTS. CANCELED!",             /* 1*/
        "*!  ERROR %d OPENING NEW FILE %s. CANCELED!",  /* 2 */
        "*!  ERROR %d OPENING OLD FILE %s. CANCELED!",  /* 3 */
        "*!  CAN'T OPEN OUTPUT FILE. CANCELED!",        /* 4 */
        "*!  ERROR %d READING LINE %d OF NEW FILE. ABORTED!",/* 5 */
        "*!  ERROR %d READING LINE %d OF OLD FILE. ABORTED!",/* 6 */
        "*!  ERROR WRITING OUTPUT FILE. ABORTED!",      /* 7 */
        "*!  NEW FILE LINE %d TOO LONG. ABORTED!",      /* 8 */
        "*!  OLD FILE LINE %d TOO LONG. ABORTED!",      /* 9 */
        "*!  THESE FILES HAVE NOTHING IN COMMON!",      /* 10 */
        "*!  NEW FILE TOO BIG. ABORTED!",               /* 11 */
        "*!  OLD FILE TOO BIG. ABORTED!",               /* 12 */
        "*!  NEW FILE OUT OF SEQUENCE. ABORTED!",       /* 13 */
        "*!  OLD FILE OUT OF SEQUENCE. ABORTED!",       /* 14 */
        "*!  CAN'T GET ENOUGH MEMORY. ABORTED!",        /* 15 */
        "*!  ERROR CREATING TEMP FILE. ABORTED!",       /* 16 */
        "*!  ABORTED BY USER!",                         /* 17 */
        "* These files are identical\n",                /* 18 */
        "*!  NEW FILE IS EMPTY. ABORTED!",              /* 19 */
        "*!  OLD FILE IS EMPTY. ABORTED!",              /* 20 */
        "*!  ERROR SEEKING LINE %d IN OLD FILE\n",      /* 21 */
        },
    *mktemp();
FILE *in_str, *out_str, *err_str,  /* pointers to stdin, stdout & stderr or
                        replacements */
    *n_str, *o_str,     /* new & old file stream pointers */
    *try_open ();

int shellst,            /* flag = 0 if started by update */
    clr_sfcsid = 0,     /* flag = 1 if batch # to be disregarded */
    white = 0,          /* 1= any white space string = 1 space */
    mflag,
    io_errno,           /* capture of errno */
    badline,            /*   "     " line # */
    oa_size, na_size,   /* # of items in oa (& o_tab) and na */
    collate(), difis(), forward(short *, short *), getline(FILE *, char *), oseek(),
        textdiff();

short *lennp, *lenop,    /* pointers to last entries in na & oa */
    delcount, inscount, movcount, textmode, lastmod, error,
    hasht[HASH],        /* hash table. -1=unused, -2= a new line, -3= collision
        or false match */
    *na = 0, *oa = 0,   /* arrays for new file and old file pointers.
        in oa and na, -16383 to 0 = unlinked; 1 to 16382= xlinked;
        16383=blank line. In na, >= 16384 means tentative link.
                          In oa, >= 16384 means printed */
    *ex_tend (), hash_it(), *solve ();

long *o_tab;            /* table of position #'s of lines in old file */

void id_test(), linkup(), numconv(), onintr(), re_solve(), reply(),
    scan_link(), write_diff(), writeline();

/* $d3i1(q( main (argc,argv)  $i1)q) */
int main (argc,argv)
int argc;
char *argv[];
{
/*
1. Get parameters and put them in proper places
2. IF no error
2.      DO
            Get memory for tables
            IF not started by a shell, get next filename
            Open the files
            IF comparing, compare the two files
            ELSE collate them
3.          Write reply message
4.          Close input files and diffile, if opened
            Free memory for tables
        WHILE not started by a shell
6. Exit */
register char *b, *c, **p;
register int i = 0, j = 0;
struct stat tstat;
int cf_flag;
in_str = fdopen(0,"r");
err_str = fdopen(2,"w");
out_str = fdopen(1,"w");
signal (SIGINT,onintr);
shellst = argv[0][0] & 0x20;
for (p = &argv[1]; *p && !error; p++)
    {
    if (*(b = *p) == '-')
        {
        if (*(++b) == '@') clr_sfcsid = 1;
        else if ((*b | 0x20) == 'w') white = 1;
        else if (*b == 'm') mflag = 1;
        else if (*b == 'b') textmode = 1;
        else error = 1;
        }
    else
        {
        if (!n_file) n_file = b;
        else         o_file = b;
        }
    }
if (shellst && !n_file) error = 2;
if (error) reply ();
else
    {
    if (!shellst && !o_file) o_file = "selfile";
    do                                                  /* step 2 */
        {
        lastmod = error = 0;
        n_str = o_str = NULL;
        cf_flag = 1;
        delchar = 'D';
        if (!(o_tab = (long *) calloc (oa_size = A_LEN,sizeof (long))) ||
            !(oa = (short *)calloc (A_LEN,sizeof (short))) ||
            !(na = (short *)calloc (na_size = A_LEN,sizeof (short))))
            error = 15;
        if (!shellst)
            {
            if (fgets (n_file = namebuf,BSIZE,in_str) == NULL) exit (0);
            for (b = n_file; *b != '\n'; b++);
            *b = 0;
            }
        else
            {
            if (!o_file)
                {
                strcpy (o_file = o_buf,n_file);
                strcat (o_file,BACKUP);
                }
            else if (!stat (o_file,&tstat) && (tstat.st_mode & S_IFDIR))
	        {
		strcpy (o_buf,o_file);
		strcat (o_buf,"/");
                for (c = n_file; *c; c++);
                while (c > n_file && c[-1] != '/') c--;
                strcat ((o_file = o_buf),c);
                }
            }
        if (*(b = n_file) == '+' || *b == '`')
            {
            cf_flag = 0;
            if (*b++ == '+') delchar = ' ';
            }
        if (shellst) j = 1;
        if (error);
        else if ((n_str = try_open (b     )) == NULL) error = 2;
        else if ((o_str = try_open (o_file)) == NULL) error = 3;
        else if ((!shellst && (j = creat (c_file,0777)) < 0) ||
            (out_str = fdopen (j,"w")) == NULL) error = 4;
        c_hdr[D_HDR] = 0;
        if (!error)
            {
            if (cf_flag) i = difis ();
            else i = collate ();
            }
        else io_errno = errno;
        if (n_str != NULL) fclose (n_str);                      /* step 4 */
        if (o_str != NULL) fclose (o_str);
        if (out_str != NULL) fclose (out_str);
        if (o_tab) free (o_tab);
        if (oa) free (oa);
        if (na) free (na);
        reply (i);
        }
    while (!shellst);
    }
exit (0);
}
/* $di1(q( difis ()  $i1)q) */
int difis ()
{
/*
1. Clear hasht to -1's
2. Read thru old file putting -hashcode in oa[i], the line # in old_file[i],
        and setting hasht[hashcode] thus:
        IF line is blank, put special hashcode in oa
        ELSE IF line not too long
            IF hash entry was -1 (has not occurred yet), set it to line #
            ELSE set it to -3 (multiple occurrence)
3. Read thru new file putting hashcode in na[i] and setting hasht entries thus:
        IF line is blank, put special hashcode in na
        ELSE IF line not too long
            SWITCH on hashentry
            CASE -1: Set hashentry to -2 (new line inserted)
            CASE -2: Leave as is
            CASE >0 AND no FLAG (single old occurrence)
                IF text in new line matches old
                    Flag hashentry linked
                    Cross-link oa and na entries
                ELSE set hashentry to -3 (false match)
            CASE FLAG set (2nd occurrence in new after it was linked)
                Unlink first occurrence
                Set hashentyr to -3
4. Scan na in ascending order to pick up context going forward from cross-
        linked points.
        IF na entry is unlinked
            Find the next preceding non-blank na entry
            IF that entry is cross-linked
                Scan the oa table forward from the entry pointed to by that na
                    entry UNTIL a non-blank entry is found
                WHILE the current na entry is unlinked
                    IF the na entry is the same as the oa entry
                        Link then (tentatively if non-blank)
                        WHILE next na entry is blank AND oa isn't, keep going
                        WHILE next oa  "    "   "     "  na   "      "    "
5. Scan na in descending to pick up backwards context from cross-linked points
        in the same way
6. Count insertions and deletions
   IF files are different OR started by a shell, write difference file */
short i,j,      /* local counters */
    *k, hashcode, length, oa_max;
int ftellmode;     /* special item for VMS */
register short *nap, *oap, *tap;
for (tap = hasht; tap < &hasht[HASH]; *tap++ = -1);             /* step 1 */
for (tap = oa, oap = &oa[oa_size]; tap < oap; *tap++ = 0);
for (tap = na, nap = &na[na_size]; tap < nap; *tap++ = 0);
for (tap = (short *)o_tab, oap = (short *)&o_tab[oa_size]; tap < oap; *tap++ = 0);
ftellmode = 0;
for (oap = &oa[j = 1]; !error; oap++, j++)                      /* step 2 */
    {
    if (j >= oa_size && !(oap = ex_tend (&oa,&oa_size,oap))) return 0;
    if (ftellmode) o_tab[j] = ftell (o_str);
    if ((length = getline (o_str,o_buf)) <= 0) break;
    if (j == 1) ftellmode = ftell (o_str);
    if (!ftellmode) o_tab[j] = ftell (o_str);
    if (length == 1) *oap = BLANK;
    else if (length < BSIZE)
        {
        *oap = -(hashcode = hash_it (o_buf));
        if (*(k = &hasht[hashcode]) == -1) *k = j;
        else *k = -3;
        }
    }
if (j == 1) error = 20;
if (++j >= oa_size && !(oap = ex_tend (&oa,&oa_size,oap))) return 0;
if (error) return j;
else                                                 /* step 3 */
    {
    oa_max = j;
    lenop = oap;
    for (nap = &na[j = 1]; (length = getline (n_str,n_buf)) > 0 &&
        !error; j++, nap++)
        {
        if (j >= na_size && !(nap = ex_tend (&na,&na_size,nap))) return 0;
        if (length == 1) *nap = BLANK;
        else if (length < BSIZE)
            {
            *nap = -(hashcode = hash_it (n_buf));
            if (*(k = &hasht[hashcode]) == -1) *k = -2;
            else if (*k > 0 && *k < FLAG)
                {
                if (!textdiff (&oa[*k],j))
                    {
                    linkup (nap,&oa[*k],1);
                    *k |= FLAG;
                    }
                else *k = -3;
                }
            else if (*k >= FLAG)
                {
                *k &= ~FLAG;
                i = oa[*k];
                na[i] = (oa[*k] = -hashcode) & ~FLAG;
                *k = -3;
                }
            if (*k == -3)  *nap &= ~FLAG;
            }
        }
    if (j == 1) error = 19;
    }
if (error) return j;
else
    {
    if (++j >= na_size && !(nap = ex_tend (&na,&na_size,nap))) return 0;
    else
        {
        lennp = nap;
        linkup (lennp--,lenop--,1);
        scan_link (1);                                  /* step 4 */
        scan_link (-1);
        for (nap = &na[1]; nap <= lennp; nap++)
            {
            if (*nap <= 0) nap = solve (nap,(long)0);
            }
        scan_link (1);
        scan_link (-1);
        }
    }
delcount = inscount = movcount = 0;
if (!error)
    {
    i = 0;
    for (oap = &oa[j = 1]; oap <= lenop; oap++, j++)
        {
        if (*oap <= 0 || *oap == BLANK) delcount ++;
        else if (*oap != j) movcount++;
        }
    for (nap = &na[1]; nap <= lennp; nap++)
        {
        if (*nap <= 0 || *nap == BLANK) inscount++;
        if (*nap > FLAG) i++;
        }
    if (inscount + delcount + movcount + i > 0 || shellst) write_diff ();
    if (!error && inscount >= lennp - na) error = 10;
    }
if (error == 8 || error == 9) return j;
return 0;
}
/* $di1(q( hash_it (w_buf)  $i1)q) */
short hash_it (w_buf)
char *w_buf;
{
/* Returns the hashcode for the string in w_buf */
register short hashcode;
register char *c;
register int col;
for (hashcode = 0, col = 0, c = w_buf; *c;)
    {
    if (*c <= ' ')
        {
        if (white) while (*c && *c <= ' ') c++;
        else if (*c != '\t' || (col & 7) == 7) c++;
        hashcode += 0x20 << 7;
        }
    else hashcode += (*c++ << 7);
    col++;
    if (*c && *c <= ' ')
        {
        if (white) while (*c && *c <= ' ') c++;
        else if (*c != '\t' || (col & 7) == 7) c++;
        hashcode += 0x20;
        }
    else if (*c) hashcode += *c++;
    col++;
    hashcode &= 0x3fff;
    }
return hashcode;
}
/* $d3i1(q( ex_tend (xa,xa_size,xap)  $i1)q) */
short *ex_tend (xa,xa_size,xap)
short **xa, *xap;
int *xa_size;
{
short *ptr;
int rec = xap - *xa;
if (*xa == oa && !(o_tab = (long *) realloc ((char *)o_tab,(oa_size + FSIZE) *
    sizeof (int)))) error = 15;
else if (!(ptr = (short *) realloc ((char *)*xa,(*xa_size += FSIZE) * sizeof
    (short)))) error = 15;
else
    {
    *xa = ptr;
    return &ptr[rec];
    }
return 0;
}
/* $di1(q( collate ()  $i1)q) */
int collate ()
{
register int n_lth, o_lth, com_pare;
long *optr;
int ftellmode;
char new_buf[BSIZE];
na = &hasht[HASH/2];
lennp = &na[1];
lenop = &oa[1];
delcount = inscount = movcount = 0;
n_lth = getline (n_str,n_buf);
o_lth = getline (o_str,o_buf);
optr = &o_tab[1];
*optr++ = 0;
ftellmode = ftell (o_str);
while (!error && (n_lth || o_lth))
    {
    if ((com_pare = strcmp (n_buf,o_buf)) == 0)
        {
        *lennp = lenop - oa;
        writeline (n_buf,lennp,' ');
        }
    else if (com_pare < 0)
        {
        writeline (n_buf,lennp,'I');
        inscount++;
        }
    else if (*o_buf != '\n')
        {
        writeline (o_buf,lenop,'D');
        delcount++;
        }
    if (com_pare <= 0 && n_lth)
        {
        if (!(n_lth = getline (n_str,new_buf)))
            {
            *n_buf = 0x7F;
            n_buf[1] = 0;
            }
        else if (!error)
            {
            if (strcmp (new_buf,n_buf) <= 0) error = 13;
            else
                {
                lennp++;
                strcpy (n_buf,new_buf);
                }
            }
        }
    if (!error && com_pare >= 0 && o_lth)
        {
        if (ftellmode) *optr++ = ftell (o_str);
        if (!(o_lth = getline (o_str,o_buf)))
            {
            *o_buf = 0x7F;
            o_buf[1] = 0;
            }
        else if (!error)
            {
            lenop++;
            if (!ftellmode) *optr++ = ftell (o_str);
            }
        }
    }
if (error == 8) return (lennp - na);
if (error == 9) return (lenop - oa);
return 0;
}
/* $di1(q( write_diff()  $i1)q) */
void write_diff()
{
/*
1.  Starting at beginning of new file
    Scan thru new file
1a.     IF a new line is tentatively cross-linked
            IF text does not match
                Unlink the two lines
                IF the old line is before the current old line
                    Make that old line the current old line so as not to miss
                        any deletes
            ELSE make link definite
        IF current na entry is unlinked AND shows a collision (< -16383)
            Try to resolve the collision
        IF a line is an insert, write it as such
        ELSE
2.          DO
                WHILE old line is a delete OR is marked printed OR
                    (flag is off AND new line points beyond old line) OR
		    (showing moves AND old line points before new line)
                    IF old line is a delete
                        Search the inserted new lines starting just after the
                            current one to find if one has the same hashcode
                            as this old line
                        IF one does
                            Link the lines (tentatively if not blank)
                            Decrement old line to repeat this line at the WHILE
                        ELSE print old line as a delete
                    ELSE IF showing moves,
		        IF no flag, write old line as retarded
		        ELSE write old line as advanced
                    ELSE IF old line is not marked printed, turn flag on
                        (force exit)
                    Go to next old line
2a              IF new line is linked to old line
                    Flag new line to print as unchanged
                    Advance old line
2b              ELSE IF new line is linked to a line after old line
                    IF # of linked new lines from new line to the line that
                        points to old line >
                       # of linked old lines from old line  "  "   "    "
                        points to new line
                        Turn flag off (This is a 'retarded' situation
                            requiring a repeat of the WHILE clause above)
                        IF not showing moves, write line as retarded
                    ELSE
                        Set flag for new line to print as a forward move
                        If showing moves, mark old line to which new line
			    points as printed
2c              ELSE flag new line to print as a backward move
            UNTIL flag is on
            Print new line as flagged
3.      Search oa for any lines not yet printed & print them */
register int i, j;
register short *oap, *nap, *tap;
int ftellmode = 0;
long nptr;
char flag_ch = ' ';
movcount = 0;
fseek (n_str,0L,0);
for (oap = &oa[j = 1], nap = &na[i = 1]; nap <= lennp && !error; i++, nap++)
    {                                                   /* step 1 */
    if (ftellmode) nptr = ftell (n_str);
    if (getline (n_str,n_buf) > 0)
        {
        if (i == 1) ftellmode = ftell (n_str);
        if (!ftellmode) nptr = ftell (n_str);
        if (*nap > FLAG)                        /* step 1a */
            {
            if (textdiff (tap = &oa[*nap &= ~FLAG],i))
                {
                *nap = (*tap = -(hash_it (o_buf))) & ~FLAG;
                inscount++;
                delcount++;
                if (tap != oap)
                    {
                    if (tap < oap) j = (oap = tap) - oa;
                    oseek (oap);
                    }
                }
            }
        else (*nap &= ~FLAG);
        if (*nap < -FLAG) re_solve (nap,oap,nptr);
        if (*nap <= 0 || *nap == BLANK) writeline (n_buf,nap,(flag_ch = 'I'));
                                                /* insert */
        else                                    /* step 2 */
            {
            do
                {
                for (; *oap <= 0 || *oap >= BLANK || (!flag_ch && *nap > j) ||
		    (mflag && *oap < i); j++, oap++)
                    {
                    if (*oap <= 0 || *oap == BLANK)
                        {
                        for (tap = &nap[1]; *tap <= 0 && (*tap | FLAG) != *oap;
                            tap++);
                        if ((*tap | FLAG) == *oap)
                            {
                            linkup (tap,oap,0);
                            oap--;
                            j--;
                            }
                        else if (!textmode) writeline (o_buf,oap,'D');/*delete*/
                        }
                    else if (mflag)
		        {
			writeline (o_buf,oap,(flag_ch)? 'A': 'R');
    			*oap |= FLAG;
			}
                    else if (!(*oap & FLAG)) flag_ch = ' ';
                    }
                if (*nap == j)                          /* step 2a */
                    {
                    flag_ch = ' ';
                    j++;
                    *oap++ |= FLAG;
                    }
                else if (*nap > j)                      /* step 2b */
                    {
                    if (!forward (nap,oap)) flag_ch = 0;
                    else
                        {
                        flag_ch = 'F';
                        if (!mflag) oa[*nap] |= FLAG;
                        }
                    }
                else flag_ch = 'B';                 /* step 2c */
                }
            while (!flag_ch);
            writeline (n_buf,nap,flag_ch);
            }
        }
    }
if (!error && !textmode)                                /* step 3 */
    {
    for (oap = &oa[j = 1]; oap <= lenop && !error; j++, oap++)
        {
        if (*oap <= 0 || *oap == BLANK) writeline (o_buf,oap,'D');
        else if (mflag && !(*oap & FLAG))
	    {
	    writeline (o_buf,oap,(flag_ch)? 'A': 'R');
    	    *oap |= FLAG;
	    }
        }
    }
}
/* $d3i1(q( forward (nap,oap) $i1)q) */
int forward (nap,oap)
short *nap, *oap;
{
short *tap,
    i = nap - na,
    j = oap - oa,
    num = 0;
for (tap = nap; tap <= lennp && (*tap & ~FLAG) != j; tap++)
    if (*tap > 0) num++;
for (tap = oap; tap <= lenop && *tap != i; tap++)
    if (*tap > 0) num--;
if (num <= 0) return 1;
return 0;
}
/* $di1(q( writeline (w_buf,ptr,code)  $i1)q) */
void writeline (w_buf,ptr,code)
char *w_buf, code;      /* code = D, I, F, B or space */
short *ptr;
{ /*
Function: Converts line numbers to ASCII in c_hdr and writes out line in w_buf
1. IF deletion
        Read record from old file
        Mark line printed in oa
        Put old line # in c_hdr
2. ELSE
        Put new line # in c_hdr
3.      IF not an insert, put old line # in c_hdr, too
4. Change initial groups of 8 spaces to tabs (Removed for Apollo)
   IF in text mode AND ((line is changed AND not blank) OR line is where
        some text was deleted/moved away) append '$|' to line
   Write the line */
register char *c;
short *tap;
for (c = c_hdr; c < &c_hdr[D_HDR]; *c++ = ' ');
*c_hdr = code;
if (code == 'D' || code == 'A' || code == 'R')          /* step 1 */
    {
    oseek (ptr);
    if (code == 'D')
        {
        *ptr = FLAG;
        *c_hdr = delchar;
        }
    numconv (&c_hdr[D_OLINE],ptr - oa);
    if (code != 'D') numconv(&c_hdr[D_NLINE], *ptr);
    }
else                                                    /* step 2 */
    {
    numconv (&c_hdr[D_NLINE],ptr - na);
    if (code != 'I')                                    /* step 3 */
        {
        if (code == 'F' || code == 'B') movcount++;
        numconv (&c_hdr[D_OLINE],*ptr);
        }
    }
if (!error)                                             /* step 4 */
    {
    if (!textmode) fputs (c_hdr,out_str);
/*    for (c = w_buf; *c == ' '; c++);      Removed for Apollo
    if ((i = c - w_buf >> 3))
        {
        c = &w_buf[i << 3];
        for (b = w_buf; i--; *b++ = '\t');
        while (*c) *b++ = *c++;
        *b = 0;
        }                                */
    if (textmode)
        {
        for (c = w_buf; *c == ' ' || *c == '\t'; c++);
        if (*c_hdr == ' ' && *(tap = ptr) > 0 && *ptr < BLANK)
            {
            for (tap = &oa[*ptr]; tap > oa && *tap == BLANK; tap--);
            }
        if ((*c_hdr > ' ' && *c != '\n') || (*tap <= 0 && !lastmod))
            {
            while (*c != '\n') c++;
            strcpy (c," $|\n");
            lastmod = 1;
            }
        else lastmod = 0;
        }
    fputs (w_buf,out_str);
    }
}
/* $di1(q( numconv (start,num)  $i1)q) */
void numconv (start,num)
char *start;
register int num;
{
register char *c;
c = &start[5];
*c-- = ' ';
if (num)
    {
    while (num)
        {
        *c-- = (num % 10) + '0';
        num /= 10;
        }
    }
else *c-- = '0';
while (c >= start) *c-- = ' ';
}
/* $d3i1(q( getline (str,buf)  $i1)q) */
int getline (str,buf)
FILE *str;
char *buf;
{
register char *c;
*buf = 0;
if (fgets (buf,BSIZE,str) == NULL)
    {
    if (ferror (str))
        {
        if (str == o_str) error = 6;
        else error = 5;
        io_errno = errno;
        return -1;
        }
    else return 0;
    }
for (c = buf; *c; c++);
if (c[-1] != '\n')
    {
    if (str == o_str) error = 9;
    else error = 8;
    }
for (c--; c >= buf && *(--c) <= ' ';);
*(++c) = '\n';
*(++c) = 0;
if (clr_sfcsid) id_test (buf);
return (c - buf);
}
/* $d3i1(q( oseek (ptr)  $i1)q) */
int oseek (ptr)
short *ptr;
{
/* Puts o_record[oa - ptr] in o_buf */
register int line = ptr - oa;
if (ptr > lenop || fseek (o_str,o_tab[line],0) ||
    getline (o_str,o_buf) <= 0)
    {
    error = 21;
    badline = line;
    return -1;
    }
return 0;
}
/* $di1(q( re_solve (nap,oap,nptr)  $i1)q) */
void re_solve (nap,oap,nptr)
short *nap, *oap;       /* pointers to starting new/oldlines in na/oa */
long nptr;       /* location in new file where newline starts */
{
/* Tries to resolve hashcode collisions in two steps:  First it looks at the
unmatched old lines at or beyond the current one to see if one matches the
current new line.  Failing that, it tries to find 2 consecutive oldlines (not
counting blanks) which match the starting newline and the next newline (also
omitting blank lines).
1. WHILE current oldline is a delete AND its hashcode differs from that of
        the current newline, try next oldline
   IF this oldline has the same hashcode AND the text matches the newline
        Link old and new
2. ELSE try solve () */
while (*oap <= 0 && *oap != (*nap | FLAG)) oap++;       /* step 1 */
if (*oap == (*nap | FLAG))
    {
    if (!textdiff (oap,nap - na))
        {
        linkup (nap,oap,1);
        return;
        }
    }
nap = solve (nap,nptr);     /* set nap to keep lint happy */
}
/* $di1(q( solve (nap,nptr)  $i1)q) */
short *solve (nap,nptr)
short *nap;
long nptr;
{
/* $b(+
Function: Searches for a pair of consecutive old lines that are unlinked
and have the same hashcodes as nap and the next line
1. Find next non-blank na entry
   IF that next entry is also unlinked
2.      FOR all old lines
            IF current oa entry matches current na entry AND
                next non-blank oa entry matches next na entry
                IF no nptr, link both lines tentatively
                ELSE
                    IF text matches for both line pairs, link them
                    Reposition in new file
                BREAK out of FOR
$b) */
short *oap, *nxnap, *nxoap;
int diff;
for (nxnap = &nap[1]; *nxnap == BLANK; nxnap++);        /* step 1 */
if (*nxnap <= 0)
    {
    for (oap = oa; oap <= lenop; oap++)                 /* step 2 */
        {
        if (*oap == (*nap | FLAG))
            {
            for (nxoap = &oap[1]; *nxoap == BLANK; nxoap++);
            if (*nxnap <= 0 && *nxoap == (*nxnap | FLAG))
                {
                diff = 0;
                if (nptr)
                    {
                    if (!(diff = textdiff (oap,nap - na)))
                        {
                        do                                  /* step 6 */
                            {
                            getline (n_str,n_buf);
                            }
                        while (*n_buf == '\n' && !error);
                        diff = textdiff (nxoap,nxnap - na);
                        if (fseek (n_str,nptr,0) || getline (n_str,n_buf) <= 0)
                            {
                            error = 5;
                            io_errno = errno;
                            }
                        }
                    }
                if (!diff)
                    {
                    linkup (nap,oap,(nptr > 0));
                    linkup (nxnap,nxoap,(nptr > 0));
                    return nxnap;
                    }
                }
            }
        }
    }
return nap;
}
/* $d3i1(q( linkup (nap,oap,firm)  $i1)q) */
void linkup (nap,oap,firm)
short *nap, *oap;
int firm;       /* 0 = tentative, 1= firm */
{
short hashcode = *nap;
*nap = oap - oa;
*oap = nap - na;
if (hashcode != BLANK && !firm) *nap |= FLAG;
inscount--;
delcount--;
}
/* $d3i1(q( scan_link (nap,oap)  $i1)q) */
void scan_link (dir)
int dir;    /* 1 = forward, -1 = backward */
{
short *nap, *oap, *tap;
for (nap = (dir > 0)? &na[1]: lennp; nap <= lennp && nap > na; nap += dir)
    {
    if (*nap <= 0 || *nap == BLANK)
        {
        for (tap = &nap[-dir]; *tap == BLANK; tap -= dir);
        if (*tap > 0 || tap == na)
            {
            for (oap = &oa[(*tap & ~FLAG) + dir]; *oap == BLANK &&
                *nap != BLANK; oap += dir);
            while ((*nap <= 0 && *oap == (*nap | FLAG)) || (*nap == BLANK &&
                *oap == BLANK) || (!*nap && !*oap))
                {
                linkup (nap,oap,0);
                nap += dir;
                oap += dir;
                while (*oap == BLANK && *nap != BLANK) oap += dir;
                while (*nap == BLANK && *oap != BLANK) nap += dir;
                }
            }
        }
    }
}
/* $d3i1(q( textdiff (ptr,nline)  $i1)q) */
int textdiff (ptr,nline)
short *ptr;
short nline;
{
/* Compares the line in n_buf with the old line indicated by ptr. Handles tabs
1. Get old line
2. WHILE not at end of either line
        WHILE both lines match with non-white chars, go to next char in each
        While both lines have white space
            IF disregarding white space, skip over it
            ELSE
                WHILE spaces or chars match, go to next char in each line
                WHILE new line has tabs, process them
                WHILE old line  "   "     "        "
                WHILE old col is less then new and old line has white space
                    IF old char is space, advance 1 col
                    ELSE IF old char is tab, process that
                WHILE new col is less than old and new line has white space
                    Do similar thing to new line
        IF chars do not match, return 1
3. IF either line is not at end, return 1
   Return 0 */
register char *nc, *oc;
register int ncol, ocol;
oseek (ptr);
for (nc = n_buf, oc = o_buf, ncol = ocol = 0; *nc != '\n' && *oc != '\n';)
    {
    for (; *nc == *oc && *nc != '\n' && *nc != ' ' && *nc != '\t' &&
        *oc != '\n' && *oc != ' ' && *oc != '\t'; nc++, oc++, ncol++, ocol++);
    while ((*nc == ' ' || *nc == '\t') && (*oc == ' ' || *oc == '\t'))
        {
        if (white)
            {
            while (*nc == '\t' || *nc == ' ') nc++;
            while (*oc == '\t' || *oc == ' ') oc++;
            }
        else
            {
            for (; *nc >= ' ' && *nc == *oc; nc++, oc++, ncol++, ocol++);
            while (*nc == '\t')
                {
                ncol = (ncol & ~7) + 8;
                nc++;
                }
            while (*oc == '\t')
                {
                ocol = (ocol & ~7) + 8;
                oc++;
                }
            while (ocol < ncol && (*oc == ' ' || *oc == '\t'))
                {
                if (*oc == ' ') ocol++;
                else if (*oc == '\t') ocol = (ocol & ~7) + 8;
                oc++;
                }
            while (ncol < ocol && (*nc == ' ' || *nc == '\t'))
                {
                if (*nc == ' ') ncol++;
                else if (*nc == '\t') ncol = (ncol & ~7) + 8;
                nc++;
                }
            }
        }
    if (*nc != *oc || ncol != ocol) return -1;
    }
return 0;
}
/* $d3i1(q( id_test (buf)  $i1)q) */
void id_test (buf)
char *buf;
{
register char *b, *c;
for (c = buf; *c && *c != '@'; c++);
if (*c++ == '@' && *c++ == '(' && *c++ == '#' && *c++ == ')')
    {
    for (b = c; *c && *c != '\n' && *c != '"' && *c != '\''; c++);
    while ((*b++ = *c++));
    }
}
/* $di1(q( reply ()  $i1)q) */
void reply (linenum)
int linenum;
{
if (error == 2 && n_file) sprintf (n_buf,replies[2],io_errno,n_file);
else if (error == 3 && o_file) sprintf (n_buf,replies[3],io_errno,o_file);
else if (error == 5 || error == 6) sprintf (n_buf,replies[error],
    io_errno,linenum);
else if (error == 8 || error == 9) sprintf (n_buf,replies[error],linenum);
else if (error == 21) sprintf (n_buf,replies[21],badline);
else strcpy (n_buf,replies[error]);
if (!error)
    {
    if (inscount + delcount + movcount == 0) fputs (replies[18],err_str);
    else
        {
        if (delchar == ' ') delcount = 0;
        numconv (&n_buf[2],delcount);
        numconv (&n_buf[23],inscount);
        numconv (&n_buf[38],movcount);
        fputs (n_buf,err_str);
        }
    }
else fputs (strcat (n_buf," ********\n"),err_str);
fflush (err_str);
}
/* $d3i1(q( try_open (fname)  $i1)q) */
FILE *try_open (fname)
char *fname;
{
register FILE *str;
char buf[100];
while (!(str = fopen (fname,"r")) && shellst)
    {
    fprintf (err_str,"Open of %s failed. Correct name? ",fname);
    fflush (err_str);
    fgets (buf, sizeof(buf), stdin);
    if (!*buf) return NULL;
    fname = buf;
    }
return str;
}
/* $d3i1(q( onintr ()  $i1)q) */
void onintr ()
{
signal (SIGINT,onintr);
if (!error) error = 17;
}
/* $g"zz.c" */
