/* Jun 11 2008 865U  */
/* Jun 11 2008 GARDINER added oidtable stuff; added some snprintf etc. stuff */
/* May 23 2006 840U  */
/* May 23 2006 GARDINER additions for KTJL */
/* May 24 2001 577U  */
/* May 24 2001 GARDINER added UTF8String */
/* Apr 10 2000 528U  */
/* Apr 10 2000 GARDINER fixed for big offsets */
/* Jan  8 1997 415U  */
/* Jan  8 1997 GARDINER corrected improvement of last batch */
/* Jan  3 1997 414U  */
/* Jan  3 1997 GARDINER made dot notation all be on one line */
/* Jan  3 1997    made indef length message be on same line */
/* Nov 22 1996 401U  */
/* Nov 22 1996 GARDINER added copyright notice header */
/* Nov 22 1996 400U  */
/* Nov 22 1996 GARDINER fixed for ObjId starting with 2. */
/* Nov 19 1996 396U  */
/* Nov 19 1996 GARDINER made it continue even if error; made enumerated hex */
/* Feb 22 1996 338U  */
/* Feb 22 1996 GARDINER fixed formatting */
/* Feb 20 1996 335U  */
/* Feb 20 1996 GARDINER removed reference to rr_dump.h */
/* Jan  3 1996 318U  */
/* Jan  3 1996 GARDINER taught dot notation; combined name table with rr */
/* Oct 27 1994  98U  */
/* Oct 27 1994 GARDINER added #defines; tidied up output format */
/* Aug 30 1994  50U  */
/* Aug 30 1994 GARDINER check for unprintables in t61 etc.; fix level bug */
/* Apr 22 1994  21U  */
/* Apr 22 1994 GARDINER added 'indefinite length' comment in output */
/* Mar  8 1994   3U  */
/* Mar  8 1994 GARDINER starting on SPARC */
/*****************************************************************************
File:     asn_dump.c
Contents: Function to do the -a option of the dump utility
System:   IOS development.
Created:  Mar 8, 1994
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 1995 BBN Systems and Technologies, A Division of Bolt Beranek and
   Newman Inc.
150 CambridgePark Drive
Cambridge, Ma. 02140
617-873-4000
*****************************************************************************/
char asn_dump_sfcsid[] = "@(#)asn_dump.c 865p";
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "asn.h"

extern void fatal(int, char *);
extern int aflag;

static int putform (FILE *, unsigned char *, struct asn *, int, int);

extern struct typnames typnames[];

static void load_oidtable(char *);
static char *find_label(char *oidp, int *diffp);

struct oidtable
  {
  char *oid;
  char *label;
  } *oidtable;
int oidtable_size;

int asn1dump(unsigned char *buf, int buflen, FILE *outf)
{
struct asn *asnbase, *asnp;
struct typnames *tpnmp;
int ansr, j, k, row, make_asn_table();
unsigned char typ, tag, *b, *ctmp, *asn_set();
char *indef_msg = " /* indefinite length */\n";

char *c;
if ((c = getenv("OIDTABLE")))
  {
  load_oidtable(c);
  }
ansr = make_asn_table(&asnbase, buf, buflen);
for (asnp = asnbase, row = 1, typ = ASN_CONSTRUCTED; asnp->stringp; asnp++)
    {
    if (asnp > asnbase &&
        ((asnp->level & ~(ASN_INDEF_FLAG)) <=
        (asnp[-1].level & ~(ASN_INDEF_FLAG)) ||
        ((asnp[-1].level & ASN_INDEF_FLAG) && !(typ & 0xC0))))
        {
        if ((asnp[-1].level & ASN_INDEF_FLAG)) fprintf(outf, indef_msg);
        else fprintf(outf,"\n");
        for(k = (asnp->level & ~(ASN_INDEF_FLAG)); k--; fprintf(outf,"    "));
        }
    typ = *asnp->stringp;
    ctmp = asn_set(asnp);
    for (tpnmp = typnames; tpnmp->typ && tpnmp->typ != typ; tpnmp++)
        {
	if (!(tpnmp->typ & 0x1F) && tpnmp->typ == (typ & ~0x3F)) break;
	}
    if (typ < ASN_APPL_SPEC) fprintf(outf, "%s ", tpnmp->name);
    switch(typ)
        {
    case ASN_BOOLEAN:	  /* boolean */
    case ASN_INTEGER:
    case ASN_BITSTRING:
    case 7:	/* object descriptor */
    case 8: 	/* external */
    case ASN_REAL:
    case ASN_ENUMERATED:
        row = putform(outf, ctmp, asnp, 3, row);
        break;

    case ASN_OBJ_ID:
        row = putform(outf, ctmp, asnp, 2, row);
        break;

    case ASN_OCTETSTRING:
    case ASN_NUMERIC_STRING:
    case ASN_UTF8_STRING:
    case ASN_PRINTABLE_STRING:
    case ASN_T61_STRING:
    case ASN_IA5_STRING:
    case ASN_VIDEOTEX_STRING:
    case ASN_GRAPHIC_STRING:
    case ASN_VISIBLE_STRING:
    case ASN_GENERAL_STRING:
    case ASN_UNIVERSAL_STRING:
    case ASN_BMP_STRING:
    case ASN_UTCTIME:
    case ASN_GENTIME:
        row = putform(outf, ctmp, asnp, 1, row);
        break;

    case ASN_NULL:
    case ASN_SEQUENCE:
    case ASN_SET:
        break;

    default:
        b = asnp->stringp;
        tag = *b++;
        fprintf(outf,((typ & 0xC0)? "%s+0x": "%s 0x"),tpnmp->name);
        tag &= 0x3F;
	fprintf(outf, "%02X", tag);
	if ((tag & 0x1F) == 0x1F)
	    {
    	    fprintf(outf, "%02X", (int)*b);
	    while ((*b & 0x80)) fprintf(outf, "%02X", (int)*(++b));
	    }
        if (!typ || ((typ & 0xC0) && (typ & ASN_CONSTRUCTED)) ||
            (b - asnp->stringp + 2 + (asnp->level * 4) + (2 * asnp->lth)) >= 80)
	    {
	    if (!(asnp->level & ASN_INDEF_FLAG)) fprintf(outf, "\n");
	    else fprintf(outf, indef_msg);
	    for (j = 1 + (asnp->level & ~(ASN_INDEF_FLAG)); j--;
                fprintf(outf, "    "));
	    }
	else fprintf(outf, " ");
	if (!(typ & ASN_CONSTRUCTED)) row = putform(outf, ctmp, asnp, 1, row);
        break;
        }
    }
fprintf(outf, "\n");
if (ansr < 0) fatal(5, (char *)(-ansr));
return 0;
}

static int putform(FILE *outf, unsigned char *c, struct asn *asnp, int mode,
    int row)
  /* mode 1= ASCII (maybe), 2 = obj_id, 3=hex */
{
int j, k, offset, lth = asnp->lth, width;
unsigned char *b, *e, delim[2], locbuf[256], *d;
long val;
width = 80;
strcpy((char *)delim, "'");
if (mode == 1)
    {
    j = k = 0;
    for (b = c, e = &c[asnp->lth]; b < e && *b >= ' ' && *b <= '~'; b++)
	{
	if (*b == '\'') j++;
	else if (*b == '"') k++;
	else if (aflag  < 0 && *b == '\n') mode = 3;
	}
    if (b < e || (j && k)) mode = 3;
    else if (j) *delim = '"';
    }
else if (mode == 2)
    {
    for (val = 0, b = c, e = &c[asnp->lth]; (*b & 0x80); b++)
        {
        val = (val << 7) + (*b & 0x7F);
        }
    val = (val << 7) + *b++;
    if (val < 80) snprintf((char *)locbuf, sizeof(locbuf), "%ld.%ld", (val / 40), (val % 40));
    else snprintf((char *)locbuf, sizeof(locbuf), "2.%ld", val - 80);
    for (d = locbuf; *d; d++);
    while (b < e)
        {
        for (val = 0; (*b & 0x80); b++)
            {
            val = (val << 7) + (*b & 0x7F);
            }
        val = (val << 7) + *b++;
        snprintf((char *)d, (sizeof(locbuf) - (d - &locbuf[0])), ".%ld", val);
	while (*d) d++;
        }
    if (oidtable)
      {
      int diff;
      char *label;
      if ((label = find_label((char *)locbuf, &diff)))
        {
        if (!diff) sprintf((char *)d, "  /* %s */", label);
        else
          {
          char locpart[16];
          for (c = locbuf; *c > ' '; c++);
          strncpy(locpart, (char *)&c[diff], -diff);
          locpart[-diff] = 0;
          sprintf((char *)d, "  /* %s + %s */", label, locpart);
          }
        }
      }
    if (aflag < 0) fprintf(outf, "(%d) ", (d - locbuf));
    fprintf(outf, (char *)locbuf);
    return row;
    }
for (offset = (asnp->level + 1) * 4; lth; )
    {
    if (mode == 1) fprintf(outf, (char *)delim);
    else fprintf(outf, "0x");
    if ((k = (width - 9 - offset) / mode) < 16) k = 16;
    for (j = 1; k >>= 1; j <<= 1);
    if (j > lth) j = lth;
    if (aflag < 0)
        {
        if (lth <= 4 &&
            (*asnp->stringp == ASN_INTEGER || *asnp->stringp == ASN_ENUMERATED))
            {
            if ((*c & 0x80)) val = -1;
            else val = 0;
            for (e = &c[lth]; c < e; val <<= 8, val += *c++);
            fprintf(outf, "%ld", val);
            break;
            }
        if (mode == 1) k = j + 2;
        else k = 2 * (j + 1);
        fprintf(outf, "(%d) ", k);
        }

    for (e = &(b = c)[j], lth -= j; c < e;
        fprintf(outf, ((mode > 1)? "%02X": "%c"), *c++));
    if (mode == 1) fprintf(outf, (char *)delim);
    else if (aflag >= 0)
        {
	for (fprintf(outf, " /* "); b < e; b++)
	    {
	    if (*b >= ' ' && *b < 0x7F) fprintf(outf, "%c", *b);
	    else fprintf(outf, ".");
	    }
	fprintf(outf, " */");
	}
    if (lth)
        {
        fprintf(outf,"\n");
        e = &c[(80 - offset) / mode];
        for (j = offset; (j -= 4) >= 0; fprintf(outf, "    "));
        }
    }
return row;
}

static int cf_oid(char *curr_oid, char *test_oid)
  {
  char *c, *t;
  for (c = curr_oid, t = test_oid; *c && *t && *c == *t; c++, t++);
  if (!*c && !*t) return 0;  // exact match
  if (!*t) return 1;  // curr is longer than test
  if (!*c)  // curr is shorter than test, so partial match
    {
    // while(*t != '.' && t > test_oid) t--;
    // return (test_oid -t - 1);
    char *x;
    for (x = t; *x; x++);
    return (t - x - 1);
    }
  int cv, tv;
  for (c = curr_oid, t = test_oid; 1; c++, t++)
    {
    sscanf(c, "%d", &cv);
    sscanf(t, "%d", &tv);
    if (cv > tv) return 1;
    if (cv < tv) return -1;
        // matches so far
    while(*c && *c != '.') c++;
    while(*t && *t != '.') t++;
    if (!*c) return (curr_oid - c - 1);
    if (!*t) return 1;
    }
  return -1;  // should never happen
  }

static char *find_label(char *oidp, int *diffp)
  {
  int num;
  struct oidtable *curr_oidp;
  for (num = 0; num < oidtable_size; num++)
    {
    curr_oidp = &oidtable[num];
    if ((*diffp  = cf_oid(curr_oidp->oid, oidp)) <= 0) break;
    }
  if (!(*diffp)) return curr_oidp->label;
  // if (*diffp < -1) return (char *)0;
  for (num++; num < oidtable_size; num++)
    {
    curr_oidp = &oidtable[num];
    if ((*diffp = cf_oid(curr_oidp->oid, oidp)) < -1)
      {
      (*diffp)++;
      return curr_oidp->label;
      }
    }
  return (char *)0;
  }

static void load_oidtable(char *name)
  {
  FILE *str = fopen(name, "r");
  if (!str) return;
  int numoids = 16, oidnum;
  char locbuf[512];
  oidtable = (struct oidtable *)calloc(numoids, sizeof(struct oidtable));
  for (oidnum = 0; fgets(locbuf, 512, str); oidnum++)
    {
    if (oidnum >= numoids - 1) oidtable = (struct oidtable *)realloc(oidtable,
        ((numoids += 16) * sizeof(struct oidtable)));
    char *c, *l;
    for (c = locbuf; *c > ' '; c++);
    for (*c++ = 0; *c && *c <= ' '; c++);
    l = c;
    for (c++; *c > ' '; c++);
    *c = 0;
    struct oidtable *oidp = &oidtable[oidnum];
    oidp->oid = (char *)calloc(1, strlen(locbuf) + 2);
    oidp->label = (char *)calloc(1, strlen(l) + 2);
    strcpy(oidp->oid, locbuf);
    strcpy(oidp->label, l);
    }
  oidtable[oidnum].oid = (char *)0;
  oidtable_size = oidnum;
  }
