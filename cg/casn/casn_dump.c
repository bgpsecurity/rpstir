/* Jun  7 2007 858U  */
/* Jun  7 2007 GARDINER corrected offset after explicit defined-by */
/* Jun  6 2007 857U  */
/* Jun  6 2007 GARDINER corrected dump of DEFINED BY; changed to biw and ocw */
/* Mar 28 2007 849U  */
/* Mar 28 2007 GARDINER fixed signedness errors */
/* Mar 26 2007 848U  */
/* Mar 26 2007 GARDINER corrected for -Wall */
/* May 10 2006 836U  */
/* May 10 2006 GARDINER removed _asn_of; added optional verbose map_string */
/* Jul 14 2004 780U  */
/* Jul 14 2004 GARDINER fixed filling of err_struct.asn_map_string */
/* Jun  8 2004 773U  */
/* Jun  8 2004 GARDINER put test for numm pointer into _clear_error() */
/* May 11 2004 762U  */
/* May 11 2004 GARDINER more fixes for asn_obj tests */
/* Apr  1 2004 752U  */
/* Apr  1 2004 GARDINER added terminal null to dumped string */
/* Mar 30 2004 749U  */
/* Mar 30 2004 GARDINER corrected dump_tag for explicit tagging */
/* Mar 25 2004 743U  */
/* Mar 25 2004 GARDINER started */
/* */
/*****************************************************************************
File:     casn_dump.c
Contents: Functions to dump ASN.1 objects.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Systems and Technologies
10 Moulton St.
Cambridge, Ma. 02138
617-873-3000
*****************************************************************************/

char casn_dump_sfcsid[] = "@(#)casn_dump.c 858P";

#include <stdio.h>
#include "casn.h"

extern struct casn *_skip_casn(struct casn *, int);
extern int _casn_obj_err(struct casn *, int),
    _clear_error(struct casn *),
    _readsize_objid(struct casn *casnp, char *to, int mode);

static char *cat(char *, char *);
static int newline(char *, int);
static long _dumpread(struct casn *casnp, char *to, int offset, int mode),
            _dumpsize(struct casn *casnp, char *to, int offset, int mode);
static void load_oidtable(char *);
static char *find_label(char *oidp, int *diffp);

struct oidtable
  {
  char *oid;
  char *label;
  } *oidtable;
int oidtable_size;

int _dump_tag(int tag, char *to, int offset, ushort flags,
    int mode);

#define ASN_READING 1

static struct typnames typnames[] =
    {
    { ASN_BOOLEAN,          "boo"},
    { ASN_INTEGER ,         "int"},
    { ASN_BITSTRING,        "bit"},
    { ASN_OCTETSTRING,      "oct"},
    { ASN_NULL,             "nul"},
    { ASN_OBJ_ID ,          "oid"},
    { 7,                    "obd"},
    { 8,                    "ext"},
    { ASN_REAL,             "rea"},
    { ASN_ENUMERATED,       "enu"},
    { ASN_UTF8_STRING,      "utf"},     /*  12  */
    { ASN_NUMERIC_STRING,   "num"},     /* 0x12 */
    { ASN_PRINTABLE_STRING, "prt"},     /* 0x13 */
    { ASN_T61_STRING,       "t61"},     /* 0x14 */
    { ASN_VIDEOTEX_STRING,  "vtx"},     /* 0x15 */
    { ASN_IA5_STRING,       "ia5"},     /* 0x16 */
    { ASN_UTCTIME,          "utc"},     /* 0x17 */
    { ASN_GENTIME,          "gen"},     /* 0x18 */
    { ASN_GRAPHIC_STRING,   "grs"},     /* 0x19 */
    { ASN_VISIBLE_STRING,   "vst"},     /* 0x1A */
    { ASN_GENERAL_STRING,   "gns"},     /* 0x1B */
    { ASN_UNIVERSAL_STRING, "unv"},     /* 0x1C */
    { ASN_BMP_STRING,       "bmp"},     /* 0x1E */
    { ASN_SEQUENCE,         "seq"},     /* 0x30 */
    { ASN_SET,              "set"},     /* 0x31 */
    { ASN_APPL_SPEC,        "app"},     /* 0x40 */
    { ASN_CONT_SPEC,        "ctx"},     /* 0x80 */
    { ASN_PRIV_SPEC,        "pri"},     /* 0xC0 */
    { 0,                    "oth"},
    };

extern char char_table[];

int dump_casn(struct casn *casnp, char *to) 
    {
    long ansr;

    if (_clear_error(casnp) < 0) return -1;
    char *c;
    if (!oidtable && (c = getenv("OIDTABLE"))) load_oidtable(c);

    if ((ansr = _dumpsize(casnp, to, 0, 1)) >= 0) to[ansr++] = '\n';
    to[ansr] = 0;
    return ansr;
    }

int dump_size(struct casn *casnp)
    {
    char buf[4];
    long ansr;
    if (_clear_error(casnp) < 0) return -1;
    char *c;
    if (!oidtable && (c = getenv("OIDTABLE"))) load_oidtable(c); 

    if ((ansr = _dumpsize(casnp, buf, 0, 0)) >= 0) ansr++;
    return ansr;
    }

struct casn *_check_choice(struct casn *casnp) 
    {
/**
Function: Goes down through any pointers, choices and defined-bys to find the
proper object to encode

Returns: pointer to proper object

Procedure:
1. WHILE (at a pointer object which points to something) OR
	(at a defined-by) OR
	(at a filled in choice)
	IF it's a pointer, go to what it points to
	ELSE IF it's a choice OR a defined-by
	    Find the chosen member
	    IF none AND it's not optional, return error
	    IF the chosen is also a defined-by (a split definee), return the
                chosen item (it looks like a filled-in choice, but we mustn't
		go farther)
	    Go to the chosen member
	ELSE IF it's a filled-in choice, go to the filled-in member
   Return the answer
**/
    struct casn *tcasnp;

    while (((casnp->flags & ASN_POINTER_FLAG)  && casnp->ptr) ||
        (casnp->flags & ASN_DEFINED_FLAG) ||
        (casnp->type == ASN_CHOICE && (casnp->flags & ASN_FILLED_FLAG)))
        {
        if ((casnp->flags & ASN_POINTER_FLAG)  && casnp->ptr) casnp = casnp->ptr;
        else if (casnp->type >= ASN_CHOICE)
    	    {
            for (tcasnp = &casnp[1]; tcasnp; 
                tcasnp = _skip_casn(tcasnp, 1))
		{
		if (((casnp->flags & ASN_DEFINED_FLAG) &&
                    (tcasnp->flags & ASN_CHOSEN_FLAG)) ||
		    (!(casnp->flags & ASN_DEFINED_FLAG) &&
                    (tcasnp->flags & ASN_FILLED_FLAG))) break;
		}
            if (!tcasnp)
                {
                if (!(casnp->flags & ASN_OPTIONAL_FLAG)) 
                    _casn_obj_err(casnp, ASN_NO_DEF_ERR);
                }
    	    return tcasnp;
    	    }
        }
    return casnp;
    }

long _dumpsize(struct casn *casnp, char *to, int offset, int mode)
    {
/**
Function: 'Dumps' object into area pointed to by 'to' or calculates the size,
depending on 'mode'

Inputs: Pointer to dump area
	amount to indent each new line
	Mode: 0= calculate size, non-zero = do dump
Outputs: Dumped stuff
Returns: Count of bytes (to be) dumped
Procedure:
1. Check for errors and choices
   IF it's a CHOICE or DEFINED BY
	IF tagged AND NOT BOOLEAN AND (it's a true CHOICE OR it's explicitly
            tagged OR the tag is universal
	    IF tag isn't BOOLEAN dump tag
	    IF it's a DEFINED BY AND has no sub-structure
		Dump the contents with indentation
	    ELSE call _dumpsize with indentation
	ELSE call _dumpsize with no indentation
2. Dump the tag
   IF object is explicitly tagged AND NOT a CHOICE
	Dump the tag
	Increment the indentation
3. IF object is constructed AND has subordinate stuff
	DO
    	    FOR each sub-object
    	        IF that's a CHOICE AND NOT a non-anyDEFINED BY
    		    Find the chosen item
    	        Call _dumpsize for the sub-object with indentation
	    IF main object is an OF, go to next one in chain
	WHILE in an OF and have another one
   ELSE call _dumpread to get the contents
**/
    int extra, i, j;
    long ansr = 0;
    char *c, buf[20];
    struct casn *tcasnp;
    						        /* step 1 */
    if (!to) return _casn_obj_err(casnp, ASN_NULL_PTR);
    if (!mode) to = buf;
    c = to;
    if (!(tcasnp = _check_choice(casnp))) 
        return _casn_obj_err(casnp, ASN_NULL_PTR);
    if (!(tcasnp->flags & ASN_FILLED_FLAG))
	{
	if ((casnp->flags & ASN_OPTIONAL_FLAG)) return 0;
	return _casn_obj_err(casnp, ASN_MANDATORY_ERR);
	}
    if (casnp->type >= ASN_CHOICE)
        {
        if (casnp->tag != casnp->type && casnp->tag != ASN_BOOLEAN &&
            (!(casnp->flags & ASN_DEFINED_FLAG) || 
            (casnp->flags & ASN_EXPLICIT_FLAG) ||
            casnp->tag < ASN_APPL_SPEC))
            {   /* a tagged CHOICE is implicitly tagged explicitly
                   and an explicitly tagged DEFINED needs the same,
                   as does a nonANY DEFINED */
            if (casnp->tag != ASN_BOOLEAN)  /* so _dumpsize 7 lines below won't repeat it */
                {
                ansr = _dump_tag(casnp->tag, c, offset, (ushort)0, mode);
                if (mode) c += ansr;
                if (casnp->type > ASN_CHOICE)
                    {
                    if ((casnp->flags & ASN_EXPLICIT_FLAG))
                        {
                        i = _dump_tag(casnp->type & ~(ASN_CHOICE), c, offset, (ushort)0, mode);
                        if (mode) c += i;
                        ansr += i;
                        offset += 4;
                        }
                    if (mode) c[-2] = 'w';
                    }
                }
            if ((casnp->flags & ASN_DEFINED_FLAG) && tcasnp->type == ASN_NOTASN1)
                i = (int)_dumpread(tcasnp, c, offset + 4, mode);
    	    else i = (int)_dumpsize(tcasnp, c, offset + 4, mode);
    	    if (i < 0) return i - ansr;
    	    ansr += i;
    	    if (mode) c += i;
            return ansr;
    	    }
        else return _dumpsize(tcasnp, to, offset, mode);
        }
    						        /* step 2 */
    ansr += (j = _dump_tag(casnp->tag, c, offset,
        (casnp->flags & ASN_INDEF_LTH_FLAG), mode));
    extra = 4;
    if (mode) c += j;
    if (tcasnp->type == ASN_NULL) return ansr;
    if ((tcasnp->flags & ASN_EXPLICIT_FLAG) && tcasnp->type < ASN_CHOICE)
        {
        j = _dump_tag(tcasnp->type, c, offset + extra,
            (tcasnp->flags & ASN_SUB_INDEF_FLAG), mode);
        offset += 4;
        ansr += j;
        if (mode) c += j;
        }
    						        /* step 3 */
    if ((tcasnp->type & ASN_CONSTRUCTED))
        {
        int did, of = tcasnp->flags & ASN_OF_FLAG;
	struct casn *ttcasnp, *of_casnp;
        did = 0;
	of_casnp = &tcasnp[1];
	do
	    {
            for(tcasnp = of_casnp; tcasnp; tcasnp = _skip_casn(tcasnp, 1))
                {
    	        ttcasnp = tcasnp;
    	        if (of && !tcasnp->ptr) break;
                if (tcasnp->tag == ASN_CHOICE && tcasnp->tag == tcasnp->type)
    	            {
                    if (!(ttcasnp = _check_choice(tcasnp)) || 
                        !(ttcasnp->flags & ASN_FILLED_FLAG))
    		        {
                        if (!(tcasnp->flags & ASN_OPTIONAL_FLAG) &&
			    !(ttcasnp->flags & ASN_OPTIONAL_FLAG) &&
                            ttcasnp->type != ASN_NONE)
                            return _casn_obj_err(tcasnp, ASN_MANDATORY_ERR) - ansr;
    		        continue;
    		        }
    	            }
                if (did && ((tcasnp->flags & ASN_FILLED_FLAG) ||
    	            (ttcasnp->flags & ASN_FILLED_FLAG)))
    	            {                               // active item > first
                    ansr += (5 + offset);
    	            if (mode) c += newline(c, offset);
    	            }
                if ((i = (int)_dumpsize(ttcasnp, c, offset + extra, mode)) < 0)
                    return (i - ansr);
    	        did += i;
    	        ansr += i;
                if (mode) c += i;
                }
	    if (of) of_casnp = of_casnp->ptr;
	    }
	while (of && of_casnp);
        *c = 0;
        }
    else ansr += _dumpread(casnp, c, offset + extra, mode);
    return ansr;
    }

long _dumpread(struct casn *casnp, char *to, int offset, int mode)
    {
    char *c = to;
    int  printable;
    long type = (casnp->type == ASN_ANY)? casnp->tag: casnp->type;
    long ansr = 0, i, j,
        count = 80 - offset - 2,  // # of printable spaces less "" or 0x
        lth;

    lth = casnp->lth;
    if(type == ASN_IA5_STRING || type == ASN_OCTETSTRING)
        {
        for(printable = i = 0; i < lth; i++)
            {
            if (char_table[casnp->startp[i]] & 0x10) continue;
            break;
            }
        if (i == lth) printable = 1;
        }
    else if (type == ASN_NUMERIC_STRING || type == ASN_PRINTABLE_STRING ||
        type == ASN_T61_STRING || type == ASN_UTCTIME || type == ASN_GENTIME)
        printable = 1;
    else printable = 0;
    ansr += lth;
    if (printable)
        {                               /* ASCII output */
        for (i = 0; i < lth; )
            {
    	    if (mode) *c++ = '"';
            for (j = count; j-- && i < lth; )
                {
                *c = (char)casnp->startp[i++];
                if (*c == '"')
    		    {
    		    ansr++;
    		    if (mode)
    		        {
                        *c++ = '\\';
        	        *c = '"';
    		        }
    		    }
    	        if (mode) c++;
    	        }
    	    if (mode) *c++ = '"';
    	    ansr += 2;      /* 2 quotes */
            if (i < lth)
    	        {
                ansr += (1 + offset);
    	        if (mode) c += newline(c, offset - 4);
                }
            }
        }
    else if (type == ASN_OBJ_ID)
        {
        ansr = _readsize_objid(casnp, c, mode) - 1; // for extra null
        if (mode) c += ansr;
        if (oidtable)
          {
          char *buf = (char *)calloc(1, ansr + 2);
          _readsize_objid(casnp, buf, 1);
          int diff;
          char *labelp = find_label(buf, &diff);
          if (labelp)
            {
            int xtra = strlen(labelp) + 7;
            if (!diff)
              {
              if (mode) sprintf(c, " /* %s */", labelp);
              }
            else
              {
              if (mode)
                {
                char *locpartp = (char *)calloc(1, -diff + 2);
                strncpy(locpartp, &c[diff], -diff);
                locpartp[-diff] = 0;
                if (mode) sprintf(c, " /* %s + %s */", labelp, locpartp);
                free(locpartp);
                }
              xtra += (3 - diff);
              }
            ansr += xtra;
            if (mode) c += xtra;
            free(buf);
            }
          }
        }
    else    /* output in hex */
        {
        if (count > 64) count = 32;
        else if (count > 32) count = 16;
        else count = 8;
        if (type == ASN_BITSTRING && (casnp->flags & ASN_ENUM_FLAG))
    	    {
    	    uchar mask;
            while(lth > 1 && !(casnp->startp[lth - 1])) lth--;
    	    j = 0;
            if (lth > 1)                         // have a named bit
                {           // find how many null bits at least end of that byte
                for (mask = casnp->startp[lth - 1]; !(mask & 1); j++, mask >>= 1);
    	        }
    	    }
        ansr += lth;  /* double for hex */
        for (i = 0; i < lth; )
            {
    	    if (mode) c = cat(c, "0x");
    	    ansr += 2;
    	    if (!i && type == ASN_BITSTRING && (casnp->flags & ASN_ENUM_FLAG))
    	        {
                if ((*c = (char)((j >> 4) + '0')) > '9') *c += 7;
                if (mode) c++;
                if ((*c = (char)((j & 0xF) + '0')) > '9') *c += 7;
    	        if (mode) c++;
    	        j = count - 1;
    	        i++;
    	        }
    	    else j = count;
            for ( ; j-- && i < lth; i++)
                {
                if ((*c = ((casnp->startp[i]) >> 4) + '0') > '9') *c += 7;
                if (mode) c++;
                if ((*c = ((casnp->startp[i]) & 0xF) + '0') > '9') *c += 7;
    	        if (mode) c++;
                }
            if (i < lth)
    	        {
                ansr += (1 + offset);
    	        if (mode) c += newline(c, offset - 4);
                }
            }
        }
    *c = 0;
    return ansr;
    }

static char *cat(char *s1, char *s2)
    {
    while((*s1 = *s2++)) s1++;
    return s1;
    }

int _dump_tag(int tag, char *to, int offset, ushort flags, int mode)
    {
    char *c = to, *indef_lth_w = " /* indefinite length */";
    struct typnames *tpnp;
    int ansr, lth;
    uchar bb;

    for (tpnp = typnames; tpnp->typ && tpnp->typ < (tag & 0xFF); tpnp++);
    if (tpnp->typ > (tag & 0xFF)) tpnp--;
    ansr = strlen(tpnp->name);
    if (mode) c = cat(c, tpnp->name);
    if (tpnp->typ < ASN_APPL_SPEC)
        {
        ansr++;
        if (mode) *c++ = ' ';
        if (flags)
    	      {
    	    ansr += 5 + offset + strlen(indef_lth_w);
            if (mode)
                {
                c = cat(c, indef_lth_w);
                c += newline(c, offset);
                }
    	      }
        }
    else
        {
        ansr += 3;
        if (mode) c = cat(c, "+0x");
        tag &= ~(ASN_PRIV_SPEC);
	if (tag > 0xFFFFFF) lth = 4;
	else if (tag > 0xFFFF) lth = 3;
	else if (tag > 0xFF) lth = 2;
	else lth = 1; 
        ansr += (2 * lth);
        if (mode) for ( ; lth--; tag >>= 8)
	    {
	    bb = (tag & 0xFF) >> 4;
	    if (bb > 9) bb -= 7;
	    *c++ = bb + '0';
	    bb = (tag & 0xF);
	    if (bb > 9) bb -= 7;
	    *c++ = bb + '0';
            }
        if (flags)       
    	    {
    	    ansr += strlen(indef_lth_w);
            if (mode) c = cat(c, indef_lth_w);
    	    }
        ansr += 5 + offset;
        if ((mode & ASN_READING)) c += newline(c, offset);
        }
    return ansr;
    }
    
static int newline(char *to, int offset)
    {
    char *c = to;
    *c++ = '\n';
    for(offset += 4; offset--; *c++ = ' ');
    return (c - to);
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
