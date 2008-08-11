/* $Id$ */
/*****************************************************************************
File:     asn_gen.c
Contents: Main function of the ASN_GEN program plus various functions
          called by construct(), print_hdr(), pre_proc(), and tabulate().
System:   ASN development.
Created:  11-Jan-1995
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

 ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 1995-2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/

const char asn_gen_rcsid[]="$Header: /nfs/sub-rosa/u1/IOS_Project/ASN/Dev/rcs/cmd/asn_gen/asn_gen.c,v 1.1 1995/01/11 22:43:11 jlowry Exp gardiner $";
char asn_gen_id[] = "@(#)asn_gen.c 828P";

#include "asn_gen.h"
#ifdef WIN32
#include <io.h>
#endif

static void print_define_tables(FILE *);

static void print_if_include(FILE *, char *);
static int putobjid(char *, int, int);

int array, classcount, modflag, genflag,
    ceeflag, dosflag, javaflag,
    did_tables, explicit1 = 3, flags, pre_proc_pass,
    i_namesize, i_pathsize,     /* current sizes of i_names  & i_paths */
    made_change, option,
    state = PRE_GLOBAL,
    vflag;

short subtype;

long curr_line, min, max, tag, type, tablepos, real_start, curr_pos,
    table_start_line, integer_val;

FILE *outstr;

static char linebuf[2048],   /* used by get_token() */
    *nch = linebuf,   /* used by peek_token(), too */
    terminators[] = "\
nnnnnnnnnyyyyynnnnnnnnnnnnnnnnnn\
ynnnnnynyynnynnnnnnnnnnnnnyynynn\
ynnnnnnnnnnnnnnnnnnnnnnnnnnynynn\
nnnnnnnnnnnnnnnnnnnnnnnnnnnyyynn";

char fname[80],
    token[ASN_BSIZE], itemname[ASN_BSIZE], classname[ASN_BSIZE], prevname[ASN_BSIZE], path[16],
    subclass[ASN_BSIZE], defaultname[32], numstring[ASN_BSIZE], defined_by[ASN_BSIZE],
    definer[ASN_BSIZE], tablename[32], inclass[ASN_BSIZE], *source,
    lo_end[ASN_BSIZE], hi_end[ASN_BSIZE], curr_file[80],
    *def_constraintp,
    *sub_val,
    absent_w[] = "ABSENT",
    algid_w[] = "AlgorithmIdentifier",
    all_w[] = "ALL",
    any_w[] = "ANY",
    application_w[] = "APPLICATION",
    array_w[] = "array",
    begin_w[] = "BEGIN",
    bit_w[] = "BIT",
    bmpstring_w[] = "BMPString",
    boolean_w[] = "BOOLEAN",
     /* see comment in asn_gen.h about BUILT_IN_IDS */
    built_ins[] = "TYPE-IDENTIFIER ::= CLASS {\n\
&id OBJECT IDENTIFIER UNIQUE, &Type }\n\
WITH SYNTAX { &Type IDENTIFIED BY &id }\n\
ccitt OBJECT IDENTIFIER ::= {0}\n\
itu-t OBJECT IDENTIFIER ::= {0}\n\
iso OBJECT IDENTIFIER ::= {1}\n\
joint-iso-ccitt OBJECT IDENTIFIER ::= {2}\n\
joint-iso-itu-t OBJECT IDENTIFIER ::= {2}\n\
standard OBJECT IDENTIFIER ::= {0}\n\
member-body OBJECT IDENTIFIER ::= {2}\n\
identified-organization OBJECT IDENTIFIER ::= {3}\n",
    *built_inp = built_ins,
    by_w[] = "BY",
    choice_w[] = "CHOICE",
    class_w[] = "CLASS",
    colon_ch[] = ":",
    component_w[] = "COMPONENT",
    components_w[] = "COMPONENTS",
    constrained_w[] = "CONSTRAINED",
    default_w[] = "DEFAULT",
    defined_w[] = "DEFINED",
    definitions_w[] = "DEFINITIONS",
    either_w[] = "EITHER",
    empty_w[] = "EMPTY",
    encrypted_w[] = "ENCRYPTED",
    end_w[] = "END",
    enumerated_w[] = "ENUMERATED",
    equal_ch[] = "=",
    explicit_w[] = "EXPLICIT",
    exports_w[] = "EXPORTS",
    few_w[] = "few",
    false_w[] = "FALSE",
    from_w[] = "FROM",
    function_w[] = "FUNCTION",
    generalizedtime_w[] = "GeneralizedTime",
    generalstring_w[] = "GeneralString",
    graphicstring_w[] = "GraphicString",
    ia5string_w[] = "IA5String",
    casn_w[] = "casn",
    identifier_w[] = "IDENTIFIER",
    if_include[] = "#ifndef _%s\n#include \"%s\"\n#endif\n",
    implicit_w[] = "IMPLICIT",
    imports_w[] = "IMPORTS",
    in_w[] = "IN",
    instance_w[] = "INSTANCE",
    integer_w[] = "INTEGER",
    many_w[] = "many",
    min_w[] = "MIN",
    max_w[] = "MAX",
    none_w[] = "NONE",
    notasn1_w[] = "NOTASN1",
    null_ptr_w[] = "(AsnObj)null",
    null_w[] = "NULL",
    numericstring_w[] = "NumericString",
    object_w[] = "OBJECT",
    octet_w[] = "OCTET",
    of_w[] = "OF",
    optional_w[] = "OPTIONAL",
    present_w[] = "PRESENT",
    printablestring_w[] = "PrintableString",
    private_w[] = "PRIVATE",
    real_w[] = "REAL",
    relOID_w[] = "RELATIVE_OID",
    self_w[] = "self",
    sequence_w[] = "SEQUENCE",
    set_w[] = "SET",
    signed_w[] = "SIGNED",
    size_w[] = "SIZE",
    string_w[] = "STRING",
    syntax_w[] = "SYNTAX",
    t61string_w[] = "T61String",
    table_w[] = "TABLE",
    tags_w[] = "TAGS",
    teletexstring_w[] = "TeletexString",
    true_w[] = "TRUE",
    type_identifier_w[] = "TYPE_IDENTIFIER",
    union_w[] = "UNION",
    unique_w[] = "UNIQUE",
    universal_w[] = "UNIVERSAL",
    universalstring_w[] = "UniversalString",
    utctime_w[] = "UTCTime",
    utf8string_w[] = "UTF8String",
    videotexstring_w[] = "VideotexString",
    visiblestring_w[] = "VisibleString",
    with_w[] = "WITH",
    *reserved_words[] = { absent_w, any_w, application_w, begin_w, bit_w,
        bmpstring_w, boolean_w, by_w, choice_w, class_w, component_w,
        components_w, constrained_w, default_w, defined_w, definitions_w,
        either_w, empty_w, end_w, enumerated_w, explicit_w, exports_w,
        false_w, from_w,
	generalizedtime_w, generalstring_w, ia5string_w, identifier_w,
        implicit_w, imports_w, in_w, instance_w, integer_w, min_w, max_w,
        none_w, null_w, numericstring_w,
        object_w, octet_w, of_w, optional_w,
        present_w, printablestring_w, private_w,
        real_w, relOID_w,
        sequence_w, set_w, size_w, string_w, syntax_w,
        t61string_w, table_w, tags_w, teletexstring_w, true_w,
        type_identifier_w,
        union_w, unique_w, universal_w, universalstring_w, utctime_w,
        utf8string_w,
        videotexstring_w, visiblestring_w, with_w, 0},
    *msgs[] =
    	{
    	"Asn_gen finished %s OK\n",
	"Invalid parameter: %s\n",	/* 1 */
    	"Can't open %s\n",              /* 2 */
	"Construct has ambiguous DER\n", /* 3 */
	"invalid state %d\n",		/* 4 */
	"no child of %s in table\n",    /* 5 */
	"invalid word: %s\n",  		/* 6 */
	"memory error\n",		/* 7 */
	"Unused error message 8\n",    	/* 8 */
	"overflow in area %s\n",	/* 9 */
	"Unused error message 10\n",     /* 10 */
	"can't find definer/defined path for %s\n", /* 11 */
	"syntax error at %s\n",         /* 12 */
	"nesting detected\n",           /* 13 */
	"unexpected EOF at %s\n",       /* 14 */
	"extra tag definition 0x%lX\n", /* 15 */
	"undefined upper bound %s\n",   /* 16 */
	"duplicate definition of %s\n", /* 17 */
	"ID %s is not defined\n",       /* 18 */
	"no table defined for %s\n",    /* 19 */
	"missing %s\n",                 /* 20 */
	"%s is not on the export list\n", /* 21 */
	"stuck in loop at %s, Check syntax.\n", /* 22 */
	"ambiguous tagging of %s\n",    /* 23 */
	"internal error in %s\n",       /* 24 */
	"multiple definers for %s\n",   /* 25 */
	"too %s parameters in macro\n", /* 26 */
	"undefined macro %s\n",         /* 27 */
	"undefined item %s in syntax\n", /* 28 */
	"not enough columns defined in table\n", /* 29 */
	"undefined class %s\n",         /* 30 */
	"%s not supported for this type\n", /* 31 */
	"%s must not be optional or absent\n",  /* 32 */
	"Can't determine constraint %s\n",  /* 33 */
	"undefined type for %s\n",      /* 34 */
	"no ANY DEFINED BY for %s\n",   /* 35*/
	"token %s is too big\n",        /* 36 */
	"line bigger than buffer: %s\n",    /* 37 */
	"Can't create directory named %s\n",/* 38 */
	"Can't find stream for fd %d\n",    /* 39 */
	"Incomplete table item %s\n",       /* 40 */
	"Couldn't find constraint for %s\n",  /* 41 */
    	},
    *sfcsids[] = {asn_gen_id,
        asn_constr_id, asn_hdr_id,
	asn_java_id,
        asn_pproc_id, asn_read_id, asn_tabulate_id, casn_constr_id,
        casn_hdr_id, 0},
    *i_names, *i_paths,
    *mktemp(char *);


void clear_globals(), print_tables();

struct tag_table tag_table[] =
	{
	{ ASN_ANY,              any_w,       "AsnAny",      "ASN_ANY" },
        { ASN_BOOLEAN,          boolean_w,   "AsnBoolean", "ASN_BOOLEAN"},
	{ ASN_INTEGER,          integer_w,   "AsnInteger", "ASN_INTEGER"},
	{ ASN_BITSTRING,        bit_w,       "AsnBitString", "ASN_BITSTRING"},
	{ ASN_OCTETSTRING,      octet_w,     "AsnOctetString",
                                                            "ASN_OCTETSTRING"},
	{ ASN_NULL,             null_w,      "AsnNull",      "ASN_NULL"},
	{ ASN_OBJ_ID,           object_w,    "AsnObjectIdentifier",
                                                             "ASN_OBJ_ID"},
	{ ASN_REAL,             real_w,       "AsnReal",     "ASN_REAL" },
	{ ASN_ENUMERATED,       enumerated_w, "AsnEnumerated","ASN_ENUMERATED" },
	{ ASN_UTF8_STRING,      utf8string_w, "AsnUTF8String",
                                                          "ASN_UTF8_STRING"},
	{ ASN_RELATIVE_OID,     relOID_w,      "AsnRelativeOID",
                                                          "ASN_RELATIVE_OID"},
	{ ASN_NUMERIC_STRING,   numericstring_w, "AsnNumericString",
                                                          "ASN_NUMERIC_STRING"},
	{ ASN_PRINTABLE_STRING, printablestring_w, "AsnPrintableString",
                                                        "ASN_PRINTABLE_STRING"},
	{ ASN_T61_STRING,       teletexstring_w, "AsnTeletexString",
                                                              "ASN_T61_STRING"},
	{ ASN_T61_STRING,       t61string_w,     "AsnTeletexString",
                                                              "ASN_T61_STRING"},
	{ ASN_VIDEOTEX_STRING,  videotexstring_w, "AsnVideotexString",
    						        "ASN_VIDEOTEX_STRING" },
	{ ASN_IA5_STRING,       ia5string_w,   "AsnIA5String",
                                                              "ASN_IA5_STRING"},
	{ ASN_UTCTIME,          utctime_w,   "AsnUTCTime", "ASN_UTCTIME"},
	{ ASN_GENTIME,          generalizedtime_w,   "AsnGeneralizedTime", "ASN_GENTIME"},
	{ ASN_GRAPHIC_STRING,   graphicstring_w, "AsnGraphicString",
                                                         "ASN_GRAPHIC_STRING"},
	{ ASN_VISIBLE_STRING,   visiblestring_w, "AsnVisibleString",
                                                       "ASN_VISIBLE_STRING"},
	{ ASN_GENERAL_STRING,   generalstring_w, "AsnGeneralString",
                                                       "ASN_GENERAL_STRING"},
	{ ASN_UNIVERSAL_STRING, universalstring_w,"AsnUniversalString",
                                                       "ASN_UNIVERSAL_STRING"},
	{ ASN_BMP_STRING,       bmpstring_w,   "AsnBMPString",
                                                       "ASN_BMP_STRING"},

	{ ASN_SEQUENCE,         sequence_w,  "AsnSequence", "ASN_SEQUENCE"},
	{ ASN_SET,              set_w,       "AsnSet",      "ASN_SET"},
	{ ASN_INSTANCE_OF,      instance_w,  "AsnSequence", "ASN_INSTANCE_OF"},
	{ ASN_CHOICE,           choice_w,    "AsnChoice",   "ASN_CHOICE"},
	{ ASN_CHOICE | ASN_BITSTRING,   choice_w,    "AsnChoice",   "ASN_CHOICE"},
	{ ASN_CHOICE | ASN_OCTETSTRING, choice_w,    "AsnChoice",   "ASN_CHOICE"},
	{ ASN_NONE,             none_w,      "AsnNone",     "ASN_NONE" },
	{ ASN_FUNCTION,         function_w,  "",            "ASN_FUNCTION" },
	{ ASN_NOTASN1,          notasn1_w,   "AsnNotAsn1 ", "ASN_NOTASN1" },
	{ ASN_NOTYPE, "", 0, 0},
	};


struct name_area name_area = { "name_area", sizeof(struct name_table), 50, 4000 , NULL , 0, 0};
struct name_area class_area = { "class_area", sizeof(struct class_table), 10, 1000, NULL , 0, 0};
struct name_area id_area = {"id_area", sizeof(struct id_table), 20, 4000, NULL , 0, 0 };
struct name_area ub_area = { "ub_area", sizeof(struct ub_table), 10, 4000, NULL , 0, 0 };
struct name_area import_area = {"import_area", sizeof(struct import_table), 20, 4000 , NULL , 0, 0};
struct name_area constraint_area = {"constraint_area", 1, 128, 10000 , NULL , 0, 0};
struct name_area macro_area = { "macro_area", sizeof(struct macro_table), 10, 1000 , NULL , 0, 0};
struct name_area module_area = { "module_area", sizeof(struct module_table), 10, 1000 , NULL , 0, 0};

struct alt_subclass *alt_subclassp;

struct fd_to_stream streams;

int main(int argc, char *argv[])
{
FILE *tmpstr;
char *b, *c, **p, locbuf[80], pprocname[80], *sfx;
char sourcebuf[80];
size_t did;
int fd, do_flag, tflag, uflag, lflag;
time_t last, now, start, time(time_t *);
struct name_table *ntbp, *entbp;
struct parent *parentp;
struct ub_table *ubp, *eubp;
struct id_table *idp, *eidp;
struct stat tstat;
if (!getenv("ASN_GEN_LICENSE"))
    {
    fprintf(stderr,
"\nUse of this ASN.1 compiler requires the user's acceptance of the software\n\
license that is bundled with the source distribution.  Any use of this\n\
compiler for other than U. S. Government purposes is subject to the\n\
imposition of license fees.  Contact asn-support@bbn.com.\n\n");
    }
for(p = &argv[1], lflag = tflag = uflag = do_flag = 0,
    source = (char *)0; *p; p++)
    {
    if (*(c = *p) == '-')
	{
	if (*(++c) == 'c')
	    {
            if (!javaflag) ceeflag = 1;
	    else fatal(1, c);
	    }
	else if (*c == 'd') dosflag = 1;
	else if (*c == 'g') genflag = 1;
	else if (*c == 'I' || *c == 'i')
	    {
	    b = c;
	    if (!*(++c)) c = *(++p);
	    if (*b == 'i') add_include_name(c);
	    else
		{
    	        did = strlen (c) + 1;
                if ((!i_paths && !(i_paths = (char*)calloc(did, 1))) ||
                    !(i_paths = recalloc(i_paths, (size_t)i_pathsize,
                    (size_t)(i_pathsize + did)))) fatal(7, (char *)0);
                strcpy(&i_paths[i_pathsize], c);
                i_pathsize += did;
		}
	    }
	else if (*c == 'j')
	    {
            if (!ceeflag) javaflag = 1;
	    else fatal(1, c);
	    }
	else if (*c == 'l')
	    {
	    if (*fname) fatal(1, c);
            lflag = 1;
	    }
	else if (*c == 'o') modflag = 1;
	else if (*c == 't') tflag = 1;
	else if (*c == 'u') uflag = 1;
	else if (*c == 'v') vflag = 1;
	else if (*c == 'V') vflag = 2;
	else if (*c == 'w')
	    {
            for (did = 0; sfcsids[did]; puts(&sfcsids[did++][4]));
	    fatal(0, "");
	    }
	else fatal(1, *p);
	}
    else if (!source) source = *p;
    else if (lflag) fatal(1, *p);
    else cat(fname, *p);
    }
if (!source) fatal(2, "source file");
if (!lflag)
    {
    if (*fname) for (c = fname; *c; c++);
    else
	{
        for (b = c = cat(fname, source); --c >= fname && *c != '.';);
	if (c <= fname) c = b;
	}
    sfx = c;
    if (ceeflag) cat (sfx, ".c");
    else if (javaflag) *c = 0;
    else if (dosflag) cat (sfx, ".cpp");
    else cat(sfx, ".C");
    }
if (!do_flag) do_flag = 3;
if ((fd = open(source, (O_RDONLY | O_BINARY))) < 0) fatal(2, source);
dup2(fd, 0);
close(fd);
fprintf(stderr, "Starting %s\n", source);
start = time(&last);
state = GLOBAL;
pre_proc(-1, (FILE *)0, 0);
cat(pprocname, source);
for (c = pprocname; *c; c++);
for (c--; c >= pprocname && *c != '.'; c--);
if (c < pprocname) for (c = pprocname; *c; c++);
cat(c, ".tmp");
c = source;
do
    {
    made_change = 0;
    if (!(tmpstr = fopen(pprocname, "w"))) fatal(2, pprocname);
    state = PRE_GLOBAL;
    streams.str = fdopen(0, "r");
    strcpy(curr_file, c);
    real_start = curr_line = 0;
    pre_proc(0, tmpstr, 0);
    if (made_change)
	{
	pre_proc_pass++;
        fclose(tmpstr);
	cat(cat(locbuf, pprocname), "~");
	unlink(locbuf);
	link(pprocname, locbuf);
	unlink(pprocname);
	c = locbuf;
	close(fd);
        for(ntbp = (struct name_table *)name_area.area,
            entbp = &ntbp[name_area.next]; ntbp < entbp; ntbp++)
            {        /* so the next pass won't think it's a duplicate def */
	    ntbp->type = -1;
	    }
	fd = open(c, (O_RDONLY | O_BINARY));
        dup2(fd, 0);
        close(fd);
	}
    }
while (made_change);
if (class_area.area) print_define_tables(tmpstr);
fclose(tmpstr);
if (c == locbuf) unlink(locbuf);
streams.str = fopen(pprocname, "r");
strcpy(curr_file, pprocname);
curr_line = 0;
if (uflag) printf("%s\n", pprocname);
#ifndef _DOS
else unlink(pprocname);
#endif
time(&now);
if (tflag) printf("Pre_proc took %d secs.\n", (int)(now - last));
last = now;
tabulate();
clear_globals();
time(&now);
if (tflag) printf("Tabulate took %d secs.\n", (int)(now - last));
last = now;
for(did = 0, ntbp = (struct name_table *)name_area.area,
    entbp = &ntbp[name_area.next]; ntbp < entbp; ntbp++)
    {
    if (ntbp->generation || ntbp->pos < real_start) continue;
    *token = '_';
    cat(&token[1], ntbp->name);
    if (!find_name(token))
	{
        if (!did++) printf("Defined but not used:\n");
        printf("    %s\n", ntbp->name);
	}
    }
for(ubp = (struct ub_table *)ub_area.area, eubp = &ubp[ub_area.next];
    ubp < eubp; ubp++)
    {
    struct name_table *ntbp;
    if (!(ntbp = find_name(ubp->name)) || !ntbp->name)
        printf("    %s\n", ubp->name);
    }
printf("\n");
for(did = 0, ntbp = (struct name_table *)name_area.area; ntbp <
    &((struct name_table *)name_area.area)[name_area.next]; ntbp++)
    {
    if (ntbp->type != 0xFFFFFFFF || *ntbp->name > 'Z' ||
 	(ntbp->flags & (ASN_DEFINED_FLAG | ASN_DEFINER_FLAG | ASN_OF_FLAG |
        ASN_POINTER_FLAG)) || is_ub(ntbp->name) || ntbp->pos < real_start)
        continue;
    if (ntbp->parent.index < 0) continue;
    /* if parents are all imports, skip it */
    for(parentp = &ntbp->parent; parentp; parentp = parentp->next)
	{
	if (((struct name_table *)name_area.area)[parentp->index].pos >=
            real_start) break;
	}
    if (!parentp) continue;
    if (!did++) printf("Undefined items were\007:\n");
    printf("    %s\n", ntbp->name);
    }
if (did) printf("\n");
print_tables();
if ((do_flag & 2))                    /* .C file */
    {
    time(&last);
    curr_line = curr_pos = 0;
    if (javaflag)
	{
        if (!*fname) outstr = stdout;
        else
    	    {
            outstr = (FILE *)0;
    	    if (stat(fname, &tstat)) mkdir(fname, 0777);
    	    else if (!(tstat.st_mode & S_IFDIR)) fatal(38, fname);
    	    }
        fseek(streams.str, 0L, 0);
        jconstruct(fname, i_names, i_namesize);
	}
    else
	{
        if (!*fname) outstr = stdout;
        else
    	    {
            printf("File %s\n", fname);
     	    if (!(outstr = fopen(fname, "w"))) fatal (2, fname);
    	    cat(sfx, ".h");
    	    }
        print_if_include(outstr, fname);
        fprintf(outstr, "\n");
        fseek(streams.str, 0L, 0);
        if (ceeflag) cconstruct();
	else construct();
        if (*fname) fclose(outstr);
	}
    clear_globals();
    time(&now);
    if (tflag) printf("Making C++ source took %d secs.\n", (int)(now - last));
    last = now;
    }
if (!javaflag)
    {
    if ((do_flag & 1))                  /* .h file */
        {
        if (!*fname) outstr = stdout;
        else
            {
	    cat(sfx, ".h");
            printf("File %s\n", fname);
            if (!(outstr = fopen(fname, "w"))) fatal (2, fname);
            for(b = strcpy(locbuf, fname); *b; b++)
                {
                if (*b == '.') *b = '_';
                }
                                                  /* #endif comes later */
	    fprintf(outstr, "#ifndef _%s\n#define _%s\n\n", locbuf, locbuf);
            print_if_include(outstr, (!ceeflag)? "asn_obj.h": "casn.h");
	    for (b = cat(sourcebuf, source); b > sourcebuf && *(--b) != '.'; );
	    cat(b, ".h");
	    for (c = i_names; c < &i_names[i_namesize]; )
	        {
	        if (strcmp(c, sourcebuf)) print_if_include(outstr, c);
	        while (*c++);
	        }
            }
        for(idp = (struct id_table *)id_area.area, eidp = &idp[id_area.next],
            idp += BUILT_IN_IDS; idp < eidp; idp++)
            fprintf(outstr, "#define %s \"%s\"\n", idp->name, idp->val);
        for(ubp = (struct ub_table *)ub_area.area, eubp = &ubp[ub_area.next];
            ubp < eubp; ubp++)
	    {
	    if (ubp->status)
                fprintf(outstr, "#define %s %ld\n", ubp->name, ubp->val);
	    }
        if (id_area.area) fprintf(outstr, "\n");
        if (!ceeflag) fprintf(outstr, "#ifdef __cplusplus\n");
        fseek(streams.str, 0L, 0);
        curr_line = curr_pos = 0;
        if (ceeflag)
	    {
            cdo_hdr();
            fprintf(outstr, "#endif /* %s */\n", locbuf);
	    }
        else
	    {
            do_hdr();
            fprintf(outstr, "#endif /* __cplusplus */\n#endif /* %s */\n",
                locbuf);
	    }
        fclose(outstr);
        time(&now);
        if (tflag) printf("Making header took %d secs.\n", (int)(now - last));
        }
    }
if (tflag) printf("Total time %d secs.\n", (int)(now - start));
close(0);
if (dosflag)
    {
    fclose(streams.str);
    if (!uflag) unlink(pprocname);
    }
fatal(0, source);
return 0;
}

int add_child(char *name, int parent, long offset, long type, int option)
{
/**
Function: Adds 'name' to object name table with 'parent', path defined by
'offset', tag of 'type' and flags of 'option'
Procedure:
1. Add name to table
   Set its tag and flags
   Go to its last filled in parent structure (note: items may have been
	addeas children by find_definer without a known offset)
   IF need another parent structure, make one
   Fill in parent index
   IF offset is >= 0, put count of this subordinate into mymap
**/
struct parent *parentp;
struct name_table *ntbp;
int ansr;
if (parent < 0) return parent;
ansr = add_name(name, type, option);
ntbp = &((struct name_table *)name_area.area)[ansr];
if (ntbp->type == 0xFFFFFFFF) ntbp->type = type;
ntbp->flags |= option;
for(parentp = &ntbp->parent; parentp->index >= 0 && parentp->map_lth > 0 &&
    parentp->next; parentp = parentp->next);
if (parentp->index >= 0 && parentp->map_lth > 0)
    {
    if (!(parentp->next =
        (struct parent *)calloc(sizeof(struct parent), 1)))
	fatal(7, (char *)0);
    parentp = parentp->next;
    }
parentp->index = parent;
if (offset >= 0)
    {
    parentp->map_lth = 1;
    if (!(parentp->mymap = (char*)calloc(16, 1))) fatal(7, (char *)0);
    *parentp->mymap = (char)offset + '0';
    }
return ansr;
}

void add_constraint(char *buf, int lth)
    {
    char *c;

    while (constraint_area.next + lth > constraint_area.size)
        {
        if ((constraint_area.size + constraint_area.chunk) >
            constraint_area.limit) fatal(9, constraint_area.name);
        if ((!constraint_area.area && !(constraint_area.area = (char *)
            calloc(constraint_area.chunk, 1))) ||
            (constraint_area.area && !(constraint_area.area = (char *)
	    recalloc(constraint_area.area, constraint_area.size,
            constraint_area.size + constraint_area.chunk))))
            fatal(7, (char *)0);
        constraint_area.size += constraint_area.chunk;
        }
    c = cat(&constraint_area.area[constraint_area.next], buf);
    constraint_area.next = (c - constraint_area.area);
    }

struct id_table *add_id(char *name)
{
struct id_table *idp, *eidp;
for(idp = (struct id_table *)id_area.area, eidp = &idp[id_area.next];
    idp < eidp && strcmp(idp->name, name); idp++);
if (idp < eidp) fatal(17, name);
idp = (struct id_table *)expand_area(&id_area);
if (!(idp->name = (char*)calloc((strlen(name) + 1), 1))) fatal(7, (char *)0);
cat(idp->name, name);
return idp;
}

int add_include_name(char *fname)
{
char *b, *c;
int lth;
for (c = fname; *c; c++);
lth = c - fname;
while (c > fname && *(--c) != '.');
if (c > fname) lth = c - fname;
if ((!i_names && !(i_names = (char*)calloc((size_t)(lth + 3), 1))) ||
    !(i_names = recalloc(i_names, (size_t)i_namesize + 3,
    (size_t)(i_namesize + lth + 3)))) fatal(7, (char *)0);
strncpy((b = &i_names[i_namesize]), fname, (size_t)lth);
c = &b[lth];
if (!javaflag) c = cat(c,".h");
lth = (c - b) + 1;
for (c = i_names; c < b && strcmp(c, b); )  /* eliminate duplicates */
    {
    while(*c++);
    }
if (c >= b) return (i_namesize += lth);
else return 0;
}

int add_name(char *name, long loctype, int option)
{
struct name_table *ntbp = find_name(name);
if (!ntbp || !ntbp->name)
    {
    ntbp = (struct name_table *)expand_area(&name_area);
    ntbp->name = (char*)calloc(strlen(name) + 1, 1);
    ntbp->pos = ntbp->generation = ntbp->parent.index = -1;
    strcpy(ntbp->name, name);
    ntbp->tag = ntbp->type = ntbp->subtype = -1;
    }
if (ntbp->type == -1) ntbp->type = loctype;
else if (loctype >= ASN_CHOICE && (loctype & ntbp->type) == ntbp->type)
    ntbp->type = loctype;   // OR in the choice
ntbp->flags |= option;
return (ntbp - (struct name_table *)name_area.area);
}

void add_ub(char *name, long val, int active)
{
struct ub_table *ubp, *eubp;
for(ubp = (struct ub_table *)ub_area.area, eubp = &ubp[ub_area.next];
    ubp < eubp && strcmp(ubp->name, name); ubp++);
if (ubp < eubp) fatal(17, name);
ubp = (struct ub_table *)expand_area(&ub_area);
if (!(ubp->name = (char*)calloc(strlen(name) + 1, 1))) fatal(7, (char *)0);
cat(ubp->name, name);
ubp->val = val;
ubp->status = (active < 0)? 1: 0;
}

char *cat (char *s1, char *s2)
{
while ((*s1 = *s2++)) s1++;
return s1;
}

void clear_globals()
{
end_definition();
state = GLOBAL,
explicit1 = 3;
if (def_constraintp)
    {
    free(def_constraintp);
    def_constraintp = (char *)0;
    }
}

void close_file(int fd)
{
struct fd_to_stream *fdstrp;
close(fd);
for (fdstrp = &streams; fdstrp && fdstrp->fd != fd; fdstrp = fdstrp->next);
if (fdstrp)
    {
    fdstrp->str = (FILE *)0;
    fdstrp->fd = -1;
    }
}

void cvt_number(char *to, char *from)
{
char *c;
int base;
long val, val2;
for (c = from; *c && *c != '.'; c++);
if (javaflag || ceeflag)
    {
    if (*c == '.')
        {
        for (c++; *c && *c != '.'; c++);
        if (!*c) syntax(from);
        }
    strcpy(to, from);
    }
else
    {
    if (*c == '.')
	{
	for (val = 0; *from && *from != '.' && *from >= '0' && *from <= '9';
            val = (val * 10) + *from++ - '0');
        val *= 40;
        if (*from != '.') syntax(from);
        for(from++, val2 = 0; *from && *from != '.' && *from >= '0' && *from <= '9';
             val2 = (val2 * 10) + *from++ - '0');
        if (*from && *from != '.') syntax(from);
        c += putobjid((c = to), (val + val2), 0);
        if (*from) from++;
        while(*from)
            {
	    for (val = 0; *from && *from != '.' && *from >= '0' && *from <= '9';
                val = (val * 10) + *from++ - '0');
            c += putobjid(c, val, 0);
	    if (*from)
                {
                if (*from != '.') syntax(from);
                from++;
	        }
	    }
        }
    else if (*from == '0' && (from[1] == 'x' || from[1] == 'X'))
        {
        for (from += 2, c = to; *from; )
	    {
    	    if (*from >= 'a') *from -= 0x20;
            if (*from >= 'A') *from -= 7;
    	    val = *from++ - '0';
    	    if (*from)
    	        {
                if (*from >= 'a') *from -= 0x20;
                if (*from >= 'A') *from -= 7;
	        val = (val << 4) + *from++ - '0';
	        }
    	    c += putoct(c, val);
    	    }
        }
    else
        {
        if (*from != '0') base = 10;
        else base = 8;
        for(val = 0, c = to; *from; val = (val * base) + *from++ - '0');
	c += putoct(c, val);
	}
    }
}

static char assign_table[] = "0114202000100000002222112";
#define NUM_ASSIGN 1
#define CHAR_ASSIGN 2
#define BIT_ASSIGN 4

char *derived_dup(long loctype)
    {
    char *c;

    if (loctype == ASN_SET) c = "AsnArrayOfSets";
    else if (loctype >= sizeof(assign_table) || assign_table[loctype] == '0')
        c = "AsnArray";
    else if ((assign_table[loctype] & CHAR_ASSIGN)) c = "AsnStringArray";
    else if ((assign_table[loctype] & NUM_ASSIGN)) c = "AsnNumericArray";
    else if ((assign_table[loctype] & BIT_ASSIGN)) c = "AsnBitStringArray";
    return c;
    }

void end_definition()
{
*classname = *path = *numstring = 0;
*prevname = 0;
state = GLOBAL;
array = flags = 0;
constraint_area.next = 0;
end_item();
}

void end_item()
{
struct alt_subclass *altscp;
tag = type = subtype = -1;
classcount = min = max = option = 0;
if (sub_val)
    {
    free(sub_val);
    sub_val = (char *)0;
    }
*lo_end = *hi_end = *itemname = *subclass = *defaultname = (char)0;
*defined_by = *tablename = (char)0;
if ((explicit1 & 2)) explicit1 = 3;
else explicit1 = 0;
for (altscp = alt_subclassp; altscp; altscp = altscp->next)
    {
    *(altscp->name) = 0;
    altscp->options = 0;
    }
constraint_area.next = 0;
}

char *expand_area(struct name_area *area)
{
if (area->next + 1 >= area->size)
    {
    if ((area->size + area->chunk) > area->limit) fatal(9, area->name);
    if ((!area->size && !(area->area = (char*)calloc(area->chunk, area->item))) ||
        (area->size && !(area->area = recalloc(area->area,
	 (size_t)(area->size * area->item),
         (size_t)((area->size + area->chunk) * area->item)))))
         fatal(7, (char *)0);
    area->size += area->chunk;
    }
return &area->area[area->next++ * area->item];
}

void fatal(int err, char *param)
{
if (!*classname) cat(classname, "(null}");
warn(err, param);
if (err && !did_tables) print_tables();
exit(err);
}

char *find_child(char *name)
{
struct name_table *ctbp, *ptbp = find_name(name);
struct parent *cparentp;
int curr_parent;
for(ctbp = (struct name_table *)name_area.area, curr_parent = ptbp - ctbp;
    ctbp->name; ctbp++)
    {
    for(cparentp = &ctbp->parent; cparentp && cparentp->index != curr_parent;
        cparentp = cparentp->next);
    if (cparentp) return ctbp->name;
    }
return (char *)0;
}

char *find_class(ulong tag)
{
struct tag_table *tagtbp;
for (tagtbp = tag_table; tagtbp->classname && tagtbp->tag != tag; tagtbp++);
return tagtbp->classname;
}

char *find_define(ulong tag)
{
struct tag_table *tagtbp;
for (tagtbp = tag_table; tagtbp->classname && tagtbp->tag != tag; tagtbp++);
return tagtbp->define;
}

char * find_defined_class(int count)
{
char locname[128];
struct name_table *ntbp;
struct parent *parentp;
cat(locname, classname);
locname[strlen(classname) - 7] = 0;
ntbp = find_parent(locname);
for (parentp = &ntbp->parent; count--; parentp = parentp->next);
if (!parentp)
    {
    if (ntbp->parent.index >= 0)
        ntbp = &((struct name_table *)name_area.area)[ntbp->parent.index];
    fatal(35, ntbp->name);
    }
ntbp = &((struct name_table *)name_area.area)[parentp->index];
return ntbp->name;
}

int find_file(char *name)
{
char *c, buf[120];
int fd;
if ((fd = open(name, (O_RDONLY | O_BINARY))) >= 0) return fd;
for (c = i_paths; c < &i_paths[i_pathsize]; )
    {
    cat(cat(cat(buf, c), "/"), name);
    if ((fd = open(buf, (O_RDONLY | O_BINARY))) >= 0) return fd;
    while (*c++);
    }
return fd;
}

struct id_table *find_id(char *name)
{
struct id_table *idp, *eidp;
for(idp = (struct id_table *)id_area.area, eidp = &idp[id_area.next];
    idp < eidp && strcmp(idp->name, name); idp++);
if (idp && !idp->name) idp = (struct id_table *)0;
return idp;
}

struct name_table *find_name(char *name)
{
struct name_table *ntbp, *entbp;
for(ntbp = (struct name_table *)name_area.area,
    entbp = &((struct name_table *)name_area.area)[name_area.next];
    ntbp < entbp && wdcmp(name, ntbp->name); ntbp++);
return (ntbp < entbp)? ntbp: (struct name_table *)0;
}

struct name_table *find_parent(char *childp)
    {
    struct name_table *ntbp = find_name(childp);
    ntbp = &((struct name_table *)name_area.area)[ntbp->parent.index];
    return ntbp;
    }

int find_parent_index(struct name_table *ntbp, char *name)
    {
    struct parent *parentp;
    int index;
    for (index = 0, parentp = &ntbp->parent; parentp; parentp = parentp->next,
	index++)
	{
        ntbp = &((struct name_table *)name_area.area)[parentp->index];
	if (!strcmp(ntbp->name, name)) return index;
	}
    return -1;
    }

FILE *find_stream(int fd)
    {
    struct fd_to_stream *fdstrp;
    for (fdstrp = &streams; fdstrp && fdstrp->fd != fd; fdstrp = fdstrp->next);
    if (!fdstrp) fatal(39, (char *)fd);
    return fdstrp->str;
    }

ulong find_type(char *string)
{
struct tag_table *tagtbp;
for (tagtbp = tag_table; tagtbp->classname && strcmp(string, tagtbp->string);
    tagtbp++);
return tagtbp->tag;
}

char *find_typestring(ulong tag)
{
struct tag_table *tagtbp;
for (tagtbp = tag_table; tagtbp->classname && tagtbp->tag != tag; tagtbp++);
return tagtbp->string;
}


long find_ub(char *name)
{
struct ub_table *ntbp;
if (!(ntbp = is_ub(name))) fatal(16, name);
return ntbp->val;
}

void get_expected(int fd, ulong loctag, char *name)
{
char *c, *string;
if (loctag == ASN_BITSTRING || (loctag == ASN_OCTETSTRING && *name != 'E'))
    string = string_w;
else if (loctag == ASN_OBJ_ID) string = identifier_w;
else if (loctag == ASN_INSTANCE_OF && *name == 'I') string = of_w;
else return;
for (c = name; *c; c++);
*c++ = ' ';
if (!get_token(fd, c)) syntax(find_typestring(loctag));
if (strcmp(c, string)) fatal(6, c);
}

int get_known(int fd, char *buf, char *val)
{
int ansr;
for (ansr = get_must(fd, buf); (*buf == '\n' || *buf == '\r');
    ansr = get_must(fd, buf));
if (strcmp(buf, val)) syntax(buf);
return ansr;
}

int get_must(int fd, char *buf)
{
int ansr = get_token(fd, buf);
if (!ansr) fatal(14, buf);
return ansr;
}

void get_subtype()
    {
    struct name_table *ntbp;

    if ((ntbp = replace_name(subclass)) &&
        ntbp->type != 0xFFFFFFFF && ntbp->type < ASN_CONSTRUCTED &&
        !(ntbp->flags & ASN_ENUM_FLAG))
        subtype = (short)ntbp->type;
    }

int get_token(int fd, char *buf)
{
/**
Procedure:
0. IF doing built_ins, return what get_built_ins returns
1. Find the start of the next token thus:
   FOR each char in line
	IF no char
	    IF no next line, return 0
	    Reset char ptr
	    IF this is a blank line
		Put \n in buf
		Return 1
	IF char is '--', skip to next '--' OR end of line
	ELSE IF char is white, continue in FOR
2. IF currently at a terminator
	Put that into buf
3. ELSE WHILE not at a terminator
	Copy each character into buf
   Terminate the string
   Return length of string
**/
char *b, *c = buf;
int lth;
struct fd_to_stream *fdstrp;
							/* step 0 */
if (fd < 0)
    {
    while (*built_inp && *built_inp <= ' ') built_inp++;
    if (!*built_inp) return 0;
    *buf = *built_inp++;
    c = &buf[1];
    if (terminators[(int)*buf] != 'y') while (*built_inp > ' ' &&
        terminators[(int)*built_inp] != 'y')
	{
	if (*built_inp == '-') *c++ = '_';
        else *c++ = *built_inp;
	built_inp++;
	}
    *c = 0;
    return (c - buf);
    }
if (!fd) fdstrp = &streams;
else
    {
    for (fdstrp = &streams; fdstrp && fdstrp->fd != fd; fdstrp = fdstrp->next);
    if (!fdstrp)
	{
	for (fdstrp = &streams; fdstrp->str && fdstrp->next;
            fdstrp = fdstrp->next);
	if (!fdstrp->next && fdstrp->str)
	    {
            fdstrp->next =
                (struct fd_to_stream *)calloc(sizeof(struct fd_to_stream), 1);
    	    fdstrp = fdstrp->next;
	    }
	fdstrp->fd = fd;
        fdstrp->str = fdopen(fd, "r");
	}
    }
                                               /* step 1 */
for (b = 0 ; 1; nch++)
    {
    if (!nch || !*nch)
        {
	if (b) strcpy(linebuf, "\n");  /* got non-blank empty line */
	else if (!(b = fgets(linebuf, sizeof(linebuf), fdstrp->str)) && !nch)
            return 0;
	else curr_line++;
	nch = b;
        if (!b || *b == '\n' || *b == '\r')
	    {
    	    *buf++ = '\n';
    	    *buf = 0;
    	    return 1;
	    }
	}
    if (*nch == '-' && nch[1] == '-')
	{
	for (nch += 2; *nch != '\n' && (*nch != '-' || nch[1] != '-'); nch++);
	if (*nch != '\n') nch += 2;
	}
    else if (*nch > ' ') break;
    }
                                                        /* step 2 */
if (terminators[(int)*nch] == 'y') *c++ = *nch++;
else while (terminators[(int)*nch] != 'y') *c++ = *nch++;
*c = 0;
lth = (c - buf);
while(c > buf) if (*(--c) == '-') *c = '_';
return lth;
}

int is_reserved(char *name)
{
char **p;
for(p = reserved_words; *p && **p < *name; p++);
while (*p && **p == *name && wdcmp(name, *p)) p++;
if (*p && **p == *name) return 1;
return 0;
}

struct ub_table *is_ub(char *name)
{
struct ub_table *ntbp, *entbp;
for (ntbp = (struct ub_table *)ub_area.area, entbp = &ntbp[ub_area.next];
    ntbp < entbp && strcmp(ntbp->name, name); ntbp++);
if (ntbp >= entbp) return (struct ub_table *)0;
return ntbp;
}

static int *indexlist, indexsize;

int loop_test(struct name_table *table, struct name_table *ctbp,
    int loops)
{
/**
Function: Looks recursively to see if any item is its own ancestor
Returns: 1 if loop found, ELSE zero
Procedure:
1. IF item is a pointer item, return 0
   FOR each parent of the item
	IF it's in the indexlist, return 1
	IF the indexlist isn't big enough, enlarge it
	Put the parent's index in the list
	IF loop_test for that parent returns 1
	    Print the child name
	    Return 1
2. Return 0
**/
struct parent *cparentp;
int *inxp, *einxp;
if ((ctbp->flags & ASN_POINTER_FLAG)) return 0;
for(cparentp = &ctbp->parent; cparentp; cparentp = cparentp->next)
    {
    if (cparentp->index < 0) continue;
    for (inxp = indexlist, einxp = &inxp[loops]; inxp && inxp < einxp; inxp++)
	{
        if (*inxp == cparentp->index)
	    {
            printf("Nesting detected: %s contains", ctbp->name);
	    for (einxp = &indexlist[loops - 2]; einxp >= inxp;
		printf(" %s\n    which contains", table[*einxp--].name));
	    printf (" %s\n", ctbp->name);
	    return 1;
    	    }
	}
    if (loops >= indexsize)
	{
	if ((!indexsize && !(indexlist = (int *)calloc((size_t)4,
            sizeof(int)))) ||
	    (indexlist && !(indexlist = (int *)recalloc((char *)indexlist,
	    (size_t)(indexsize * sizeof(int)),
            (size_t)((indexsize + 4) * sizeof(int))))))
	    fatal(7, (char *)0);
	indexsize += 4;
	}
    indexlist[loops] = cparentp->index;
    if (loop_test(table, &table[cparentp->index], loops + 1)) return 1;
    }
return 0;
}

void mk_in_name(char *to, char *part1, char *part2)
{
cat(cat(cat(to, part1), "In"), part2);
}

void mk_subclass(char *from)
{
int definee, tmp;
struct name_table *ntbp = find_name(from);
struct parent *parentp;
char *b, *c;
definee = ntbp - (struct name_table *)name_area.area;
if ((b = find_child(from))) c = find_child(b);
ntbp = find_name(b);
b = cat(cat(subclass, c), "Defined");
for (parentp = &ntbp->parent, tmp = 0; parentp &&
    parentp->index != definee; tmp++,
    parentp = parentp->next);
if ((tmp -= 1) > 0) b[-1] += (char)tmp;
*from = 0;
}

char *peek_token(int fd)
{
char buf[256];
int lth;
if (!(lth = get_token(fd, buf)) || !nch) return "";
if (&nch[-lth] >= linebuf) nch -= lth;
else nch = linebuf;
return nch;
}

static void print_define_tables(FILE *str)
{
struct class_table *ctbp, *etbp;
struct table_entry *tbep;
struct table_out *tbop;
for(ctbp = (struct class_table *)class_area.area, etbp = &ctbp[class_area.next];
    ctbp < etbp; ctbp++)
    {
    if (!ctbp->table_out.table_name) continue;
    for (tbop = &ctbp->table_out; tbop; tbop = tbop->next)
	{
        fprintf(str, "\n%s ::= TABLE {\n", tbop->table_name);
        for (tbep = &tbop->table_entry; tbep; tbep = tbep->next)
    	    {
    	    if (!tbep->value || !tbep->id) continue;  /* supported but not used */
    	    if (tbep != &tbop->table_entry) fprintf(str, ",\n");
    	    fprintf(str, "    %s %s %s ", tbep->item, tbep->id, tbep->value);
    	    }
        if (!ctbp->table_out.table_entry.id) fprintf(str, "    any 0xFFFF ANY ");
        fprintf(str, "}\n");
	}
    }
}

static void print_gen(struct name_table *ntbp)
    {
    struct parent *parentp, *childp;
    for(parentp = &ntbp->parent, childp = &ntbp->child; parentp || childp; )
        {
        if (parentp) printf("    Parent %d, mymap is '%s', length %d",
            parentp->index, (parentp->mymap)? parentp->mymap: "(null)",
            parentp->map_lth);
        else printf("                                       ");
        if (childp && childp->index >= 0) printf(", child %d", childp->index);
        printf("\n");
        if (parentp) parentp = parentp->next;
        if (childp) childp = childp->next;
        }
    }

static void print_if_include(FILE *outstr, char *name)
{
char *b, locbuf[80];
for(b = strcpy(locbuf, name); *b; b++)
    {
    if (*b == '.') *b = '_';
    }
fprintf(outstr, if_include, locbuf, name);
}

void print_tables()
{
struct ub_table *ubp, *eubp;
struct id_table *idp, *eidp;
struct macro_table *mtbp, *emtbp;
struct macro_item *mitp;
struct class_table *ctbp, *ectbp;
struct class_item *citp;
struct with_syntax *wsxp;
int did, gen;
struct name_table *ntbp;
struct module_table *modtbp, *emodtbp;
struct table_out *tbop;
struct table_entry *tbep;
char *none = "[none]";
did_tables = 1;
for(did = 0, ntbp = (struct name_table *)name_area.area; vflag && ntbp <
    (struct name_table *)&name_area.area[name_area.next * name_area.item];
    ntbp++, did++)
    {
    if (!did) printf("Start position for non-imports is 0x%lX\n", real_start);
    printf("#%d %s generation %d, at ", did, ntbp->name, ntbp->generation);
    if (ntbp->pos < 0) printf("-1");
    else printf("0x%lX", ntbp->pos);
    printf(", flags 0x%X, type 0x%lX, ", ntbp->flags, ntbp->type);
    if (ntbp->tag != -1) printf("tag 0x%lX, ", ntbp->tag);
    if (ntbp->subtype != -1) printf("subtype %s, ", find_define(ntbp->subtype));
    if (ntbp->max) printf("min %ld, max %ld ", ntbp->min, ntbp->max);
    printf("has:\n");
    print_gen(ntbp);
    }
for(gen = 0, did = 1; genflag && did; gen++)
    {
    printf("generation %d\n", gen);
    for(did = 0, ntbp = (struct name_table *)name_area.area; ntbp <
        (struct name_table *)&name_area.area[name_area.next * name_area.item];
        ntbp++)
        {
	if (ntbp->generation != gen) continue;
	did++;
	printf("#%d %s ", ntbp - (struct name_table *)name_area.area,
            ntbp->name);
        printf("has:\n");
	print_gen(ntbp);
	}
    }
if (vflag > 1)
    {
    if (ub_area.area)
	{
        printf("Defined values:\n");
        for(ubp = (struct ub_table *)ub_area.area, eubp = &ubp[ub_area.next];
            ubp < eubp; ubp++)
            printf("Name: %s, value %ld\n", ubp->name, ubp->val);
	}
    if (id_area.area)
	{
        printf("Defined object identifiers:\n");
        for(idp = (struct id_table *)id_area.area, eidp = &idp[id_area.next];
            idp < eidp; idp++)
            printf("Name: %s, value %s\n", idp->name,
                (idp->val)? idp->val: none);
	}
    if (macro_area.area)
        {
        printf("Macros:\n");
        for(mtbp = (struct macro_table *)macro_area.area,
            emtbp = &mtbp[macro_area.next]; mtbp < emtbp; mtbp++)
            {
            printf("Name: %s takes %d arguments:\n", mtbp->name,
                mtbp->arg_count);
            for (mitp = &mtbp->item; mitp; mitp = mitp->next)
        	{
        	printf("  value: %s", (mitp->prefix)? mitp->prefix: none);
        	if (mitp->index >= 0) printf(", param #%d", mitp->index);
        	printf("\n");
        	}
            }
	}
    if (class_area.area)
	{
        printf("Classes:\n");
        for(ctbp = (struct class_table *)class_area.area,
            ectbp = &ctbp[class_area.next]; ctbp < ectbp; ctbp++)
            {
            printf("Name: %s, instance: %s", ctbp->name,
                (ctbp->instance_name)? ctbp->instance_name: none);
            printf(":\n");
            for (citp = &ctbp->item; citp; citp = citp->next)
        	{
        	printf("  item: %s, predicate: %s\n",
                    (citp->name)? citp->name: none,
                    (citp->predicate)? citp->predicate: none);
        	}
            printf("  Syntax:\n");
            for (wsxp = &ctbp->with_syntax; wsxp; wsxp = wsxp->next)
        	{
        	printf("    subject: %s, verb: %s, object: %s",
                    (wsxp->subject)? wsxp->subject: none,
                    (wsxp->verb)? wsxp->verb: none,
                    (wsxp->object)? wsxp->object: none);
        	if (wsxp->optional) printf(", optional");
        	printf("\n");
        	}
            printf("  Output:\n");
            for (tbop = &ctbp->table_out; tbop && tbop->table_name;
                tbop = tbop->next)
        	{
        	printf("    name: %s:\n", tbop->table_name);
        	for (tbep = &tbop->table_entry; tbep; tbep = tbep->next)
        	    {
        	    printf("      item: %s, id: %s, value: %s\n",
                        (tbep->item)? tbep->item: none,
                        (tbep->id)? tbep->id: none,
                        (tbep->value)? tbep->value: none);
        	    }
        	}
            }
	}
    }
if (modflag && module_area.area) printf("Modules:\n");
for(modtbp = (struct module_table *)module_area.area,
    emodtbp = &modtbp[module_area.next]; modflag && modtbp < emodtbp; modtbp++)
    {
    printf("  File: %s module: %s from %ld to %ld\n", modtbp->fname,
        modtbp->mname, modtbp->start_pos, modtbp->end_pos);
    }
}

static int putobjid(char *to, int val, int lev)
{
char *c = to;
uchar tmp = (val & 0x7F);
if (lev) tmp += 0x80;
if ((val >>= 7)) c += putobjid(to, val, lev + 1);
sprintf(c, "\\%03o", tmp);
return (c - to) + 4;
}

int putoct(char *to, long val)
{
char *c = to;
int tmp = val & 0xFF;
if ((val >>= 8)) c += putoct(c, val);
sprintf(c, "\\%03o", tmp);
return (c - to) + 4;
}

char *recalloc(char *from, size_t oldsize, size_t newsize)
{
char *to;
if ((to = (char*)calloc(newsize, 1)))
    {
    memcpy(to, from, oldsize);
    free(from);
    }
return to;
}

struct name_table *replace_name(char *locname)
{
/**
Function: Replaces locname with a name to which it is equated, e.g. replaces
A with B if A ::= B
Returns: Pointer to name table entry of replacement name
Procedure:
1. IF locname is not in object table, return 0
2. WHILE FALSE flag is set
	Find the (only) child of this parent
	Make that the parent
3. Copy child's name to locname
   Return pointer to table item
**/
struct name_table *ctbp, *ptbp, *table = (struct name_table *)name_area.area;
struct parent *cparentp;
int parent;
if (!(ptbp = find_name(locname)) || !ptbp->name) return (struct name_table *)0;
for ( ; (ptbp->flags & ASN_FALSE_FLAG); ptbp = ctbp)
    {
    parent = ptbp - table;
    for (ctbp = table; ctbp->name; ctbp++)
	{
	for(cparentp = &ctbp->parent; cparentp; cparentp = cparentp->next)
	    {
	    if (cparentp->index == parent) break;
	    }
	if (cparentp) break;
	}
    if (!ctbp->name) syntax(locname);
    }
cat(locname, ptbp->name);
return ptbp;
}

void set_alt_subtype(struct name_table *ctbp, int thisdefined)
{
struct parent *parentp;
struct alt_subclass *altscp;
struct name_table *ptbp;
int tmp;
ulong ttype;
ctbp = &((struct name_table *)name_area.area)[ctbp->parent.index];
for (altscp = alt_subclassp, parentp = &ctbp->parent, tmp = 1;
    tmp < thisdefined && altscp; parentp = parentp->next)
    {
    ptbp = &((struct name_table *)name_area.area)[parentp->index];
    if ((ptbp->flags & ASN_DEFINED_FLAG))
	{
        if (++tmp >= thisdefined) break;
	altscp = altscp->next;
	}
    }
if (!altscp || !altscp->name) fatal(29, (char *)0);
*subclass = 0;
type = -1;
if ((ttype = find_type(altscp->name)) == ASN_NOTYPE)
    cat(subclass, altscp->name);
else type = ttype;
}

int set_name_option(char *to, char *from)
{
int ansr =  (*from == '*')? ASN_POINTER_FLAG: 0;
if (to != from) cat(to, from);
if (*to == '*') *to = '_';
return ansr;
}

void syntax(char *name)
{
if (!*name) name = "no item name";
fatal(12, name);
}

int test_dup(char *objname, long *type)
{
/**
Function: Tests if objname needs a dup function
Returns: Logical OR of
         ASN_OF_FLAG     IF objname is a SET/SEQUENCE OF (class AsnOf)
	 ASN_DUPED_FLAG  IF parent  is a SET/SEQUENCE OF OR
                            objname is exported          (needs _dup() & index)
	 ASN_POINTER_FLAG if _objname exists & is a pointer (needs _point())
Procedure:
1. Find objname in table
   IF it's false OR its type is primitive universal, return 0
   IF table has a '_objname' OR objname starts with '_', set POINTER flag
2. Search objname's parents
        IF a parent has the OF flag or the POINTER flag set
	    Break out of the search
3. IF there is such a parent
        IF the parent had the POINTER flag, set the POINTER bit in answer
	IF the parent had the OF flag, set the DUPED bit in answer
   IF objname has the OF flag set, set the OF bit in answer
   IF objname is exported, set the DUPED flag in the answer -- in case it
        becomes a member of an OF
   Return the answer
**/
struct name_table *ntbp, *ptbp;
struct parent *parentp;
int ansr = 0;
char name[128];
*name = '_';
cat (&name[1], objname);
ntbp = find_name(objname);                    /* step 1 */
if (!ntbp || !ntbp->name || (ntbp->flags & ASN_FALSE_FLAG)) return 0;
if (*objname == '_') ansr |= ASN_POINTER_FLAG;
								/* step 2 */
for (parentp = &ntbp->parent; parentp; parentp = parentp->next)
    {
    if (parentp->index < 0) continue;
    ptbp = (struct name_table*)&name_area.area[parentp->index *
	sizeof(*ptbp)];
    if ((ptbp->flags & ASN_OF_FLAG)) break;
    }
								/* step 3 */
if (parentp)
    {
    if ((ptbp->flags & ASN_OF_FLAG)) ansr |= ASN_DUPED_FLAG;
    }
if ((ntbp->flags & ASN_OF_FLAG)) ansr |= ASN_OF_FLAG;
if ((ntbp->flags & ASN_EXPORT_FLAG)) ansr |= ASN_DUPED_FLAG;
*type = (long)ntbp->type;
return ansr;
}

long tell_pos(FILE *str)
{
return (ftell(str) - ((nch)? strlen(nch): 0));
}

void warn(int err, char *param)
{
if (err) fprintf(stderr, "****** In line %ld of file %s, class %s, \007",
    curr_line, curr_file, classname);
fprintf(stderr, msgs[err], (param)? param: "(null)");
}

int wdcmp(char *s1, char *s2)
{
/**
Function: Compares words delimited by null or white space for match
Returns: 0 if match; 1 if different
**/
for( ; *s1 > ' ' && *s1 == *s2; s1++, s2++);
if (*s1 <= ' ' && *s2 <= ' ') return 0;
return 1;
}
