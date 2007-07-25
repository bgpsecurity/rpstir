/* $Id$ */
/* Apr 25 2005 828U  */
/* Apr 25 2005 GARDINER unified asn_gen for C++, C and Java */
/* Jan 19 2005 824U  */
/* Jan 19 2005 GARDINER changed for relative OIDs */
/* Jul  8 2004 777U  */
/* Jul  8 2004 GARDINER added defconstraintp */
/* Mar 24 2004 741U  */
/* Mar 24 2004 GARDINER added for asn_cgen */
/* Jun 10 2003 621U  */
/* Jun 10 2003 GARDINER more fixes for sub-objid */
/* Jun  4 2003 619U  */
/* Jun  4 2003 GARDINER provided for sub-defined ASN_OBJ_ID */
/* Oct 12 2001 593U  */
/* Oct 12 2001 GARDINER added cvt_num */
/* Jun  8 2001 581U  */
/* Jun  8 2001 GARDINER moved BUILT_IN_OIDS here from asn_gen.c */
/* Jun  1 2001 580U  */
/* Jun  1 2001 GARDINER added status to struct ub_table */
/* Apr 26 2001 575U  */
/* Apr 26 2001 GARDINER added find_stream() */
/* Apr 26 2001 573U  */
/* Apr 26 2001 GARDINER added asn_java_id and null_ptr_w */
/* Sep 11 2000 542U  */
/* Sep 11 2000 GARDINER first stab at multi-pass pre_proc */
/* Apr 21 2000 530U  */
/* Apr 21 2000 GARDINER added struct module_table */
/* Mar 23 2000 524U  */
/* Mar 23 2000 GARDINER changes for nested macros & classes */
/* Mar  9 2000 522U  */
/* Mar  9 2000 GARDINER changed encr_xform from void to int */
/* Feb  2 1999 500U  */
/* Feb  2 1999 GARDINER changed for 2.6 */
/* Nov 11 1998 498U  */
/* Nov 11 1998 GARDINER added integer_val */
/* Nov 10 1997 471U  */
/* Nov 10 1997 GARDINER portability fixes */
/* Oct 29 1997 468U  */
/* Oct 29 1997 GARDINER added typing for portability */
/* Apr 23 1997 431U  */
/* Apr 23 1997 GARDINER added find_defined_subclass */
/* Apr  4 1997 425U  */
/* Apr  4 1997 GARDINER moved some functions out; added some defs */
/* Aug  2 1996 383U  */
/* Aug  2 1996 GARDINER changed name in struct import_table */
/* Aug  2 1996 382U  */
/* Aug  2 1996 GARDINER added sequence_w */
/* Aug  1 1996 381U  */
/* Aug  1 1996 GARDINER changed externs */
/* May 31 1996 374U  */
/* May 31 1996 GARDINER added '_w's */
/* Apr  4 1996 358U  */
/* Apr  4 1996 GARDINER added MIN/MAX */
/* Mar 29 1996 356U  */
/* Mar 29 1996 GARDINER added union_w*/
/* Mar 25 1996 355U  */
/* Mar 25 1996 GARDINER changed for stream get_token */
/* Mar 22 1996 353U  */
/* Mar 22 1996 GARDINER DOS-proofed */
/* Mar 21 1996 351U  */
/* Mar 21 1996 GARDINER removed excess ref to fd */
/* Jan 25 1996 324U  */
/* Jan 25 1996 GARDINER added 1994 */
/* Nov  9 1995 308U  */
/* Nov  9 1995 GARDINER added child member to name table */
/* Sep 26 1995 283U  */
/* Sep 26 1995 GARDINER moved get_derivation to static in asn_hdr.c */
/* Jul 27 1995 252U  */
/* Jul 27 1995 GARDINER added 'source' as global */
/* Jul 17 1995 249U  */
/* Jul 17 1995 GARDINER made is_ub() global */
/* Jul 10 1995 243U  */
/* Jul 10 1995 GARDINER re-arranged for better access to flow code */
/* Jun  2 1995 220U  */
/* Jun  2 1995 GARDINER tidied; started multi-defines */
/* Jan 24 1995 134U  */
/* Jan 24 1995 GARDINER changed syntax of IMPORTS */
/* Jan 23 1995 133U  */
/* Jan 23 1995 GARDINER added PRE_GLOBAL */
/* Jan 17 1995 129U  */
/* Jan 17 1995 GARDINER changed heading & includes */
/* Jan 11 1995 127U  */
/* Jan 11 1995 GARDINER changed prototype for get_size() and get_paren() */
/* Aug  4 1994  44U  */
/* Aug  4 1994 GARDINER changed add_include_name to return an int */
/* May 27 1994  26U  */
/* May 27 1994 GARDINER added tag to name_table struct; use new _type */
/* Apr 27 1994  24U  */
/* Apr 27 1994 GARDINER fixed -Wall complaints */
/* Apr 27 1994  23U  */
/* Apr 27 1994 GARDINER added -w option */
/* Apr 21 1994  20U  */
/* Apr 21 1994 GARDINER added function_w */
/* Apr 13 1994  16U  */
/* Apr 13 1994 GARDINER did imports */
/* Apr 11 1994  15U  */
/* Apr 11 1994 GARDINER added exports */
/* Apr  7 1994  13U  */
/* Apr  7 1994 GARDINER to eliminate gcc warnings */
/* Apr  6 1994  12U  */
/* Apr  6 1994 GARDINER added file headers */
/* Apr  5 1994   9U  */
/* Apr  5 1994 GARDINER changed to deal with '\n' */
/* Mar 31 1994   7U  */
/* Mar 31 1994 GARDINER added classcount */
/* Mar 30 1994 GARDINER added capability for IDs; changed to name_area */
/* Mar 29 1994   6U  */
/* Mar 29 1994 GARDINER started */
/***
 *
 * FILE:        asn_gen.h
 * AUTHOR:     Charles W. Gardiner (gardiner@bbn.com)
 *
 * DESCRIPTION: Header file for the ASN_GEN program.
 *
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
 * Copyright (C) BBN Technologies 1995-2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
 */

/* sfcsid[] = "@(#)asn_gen.h 828P" */
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#ifndef WIN32
#include <unistd.h>
#ifndef DOS
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif
#endif
#include <stdio.h>
#include <asn_obj.h>
#ifdef JAVA
#include <sys/types.h>
#include <sys/stat.h>
#endif

#define GLOBAL 0        /* states used in construct, print_hdr and tabulate */
#define IN_DEFINITION 1
#define SUB_DEFINITION 2
#define IN_ITEM       3
#define SUB_ITEM      4
#define PRE_GLOBAL   -1

#define ASN_BSIZE 128

#define BUILT_IN_IDS 8  /* must match number of OBJECT IDENTIFIERs in built_ins
                         in asn_gen.c */
#ifndef WIN32
#ifndef DOS
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif
#endif

struct tag_table
    {
    ulong tag;
    char *string, *classname, *define;
    };

struct parent
  {
       struct parent *next;
       int index,              /* of parent */
           map_lth;
       char *mymap;            /* via this parent */
  };

struct name_table
    {
    char *name;
    long pos;
    long type, tag;
    short subtype;    /* used for SET/SEQ OF universal primitives to deal with
		    passthroughs */
    int flags, generation;
    long min, max;
    struct parent parent, child;
    };

struct id_table
    {
    char *name,
        *val;
    };

struct ub_table
    {
    char *name;
    long val;
    int status;  /* 0 if imported, else 1 */
    };
struct ub_table *is_ub(char *);

struct module_table
    {
    char *mname;
    char *fname;
    long start_pos;
    long end_pos;
    };

struct name_area
    {
    char *name;
    unsigned item,       /* size of each item in area */
        chunk, 		 /* number of items to add ad each enlargement */
        limit;           /* upper limit of size -- prevent runaway */
    char *area;    /* pointer to a general name area */
    unsigned size,  /* number of items in the area */
        next;       /* index to next first free item in area */
    };

struct alt_subclass
    {
    struct alt_subclass *next;
    char name[ASN_BSIZE];
    short options;
    };

struct import_item
    {
    struct import_item *next;
    char *objname;
    };

struct import_table
    {
    char *name;
    struct import_item item;
    };
struct import_table *add_import_item(struct import_table *, char *);

struct table_entry
    {
    struct table_entry *next;
    char *item, *id, *value;
    };

struct class_item
    {
    struct class_item *next;
    char *name, *predicate;
    };

struct table_out
    {
    struct table_out *next;
    char *table_name;
    struct table_entry table_entry;
    };

struct with_syntax
    {
    struct with_syntax *next;
    char optional, *subject, *verb, *object;
    struct table_out *table_outp;
    };

struct class_table
    {
    char *name, *instance_name;
    struct class_item item;
    struct with_syntax with_syntax;
    struct table_out table_out;
    };
struct class_table *find_class_entry(char *);

struct macro_item
    {
    struct macro_item *next;
    char *prefix;
    int index;      /* number of parameter */
    };

struct macro_table
    {
    char *name;
    int arg_count;
    struct macro_item item;
    };

struct fd_to_stream
    {
    struct fd_to_stream *next;
    int fd;
    FILE *str;
    };

struct chain
    {
    struct chain *next;
    } *add_chain(struct chain *, size_t);

extern char token[], itemname[], classname[], prevname[], path[],
    subclass[], defaultname[], numstring[], defined_by[],
    definer[], tablename[], inclass[], *source,
    lo_end[], hi_end[], curr_file[],
    *def_constraintp,
    *sub_val,
    asn_constr_id[], asn_gen_id[], asn_hdr_id[], asn_java_id[], asn_pproc_id[],
    asn_read_id[], asn_tabulate_id[],
    absent_w[], algid_w[], all_w[], any_w[], application_w[], array_w[],
    begin_w[], by_w[],
    casn_constr_id[], casn_hdr_id[],
    casn_w[], choice_w[], class_w[], colon_ch[], component_w[], components_w[],
    constrained_w[],
    default_w[], defined_w[], definitions_w[],
    either_w[], empty_w[], encrypted_w[], end_w[], enumerated_w[], equal_ch[],
    explicit_w[], exports_w[],
    false_w[], few_w[], from_w[], function_w[],
    identifier_w[], implicit_w[], imports_w[], in_w[], instance_w[],
    integer_w[],
    many_w[], min_w[], max_w[], *msgs[],
    none_w[], null_w[], null_ptr_w[], of_w[], optional_w[],
    real_w[], relOID_w[],
    prefixes[], present_w[], private_w[],
    self_w[], sequence_w[], signed_w[], size_w[], string_w[], syntax_w[],
    table_w[], tags_w[], true_w[],
    type_identifier_w[], union_w[], unique_w[], universal_w[], with_w[],
    *cat(char *, char *),
    *derived_dup(long),
    *expand_area(struct name_area *),
    *find_child(char *),
    *find_class(ulong),
    *find_define(ulong),
    *find_defined_class(int),
    *find_typestring(ulong),
    *get_obj_id(int, char*, char*),
    *peek_token(int),
    **read_table(int *ncolsp, struct name_table *ntbp),
    *recalloc(char *, size_t, size_t);

extern struct tag_table tag_table[];

extern struct name_area class_area, name_area, id_area, import_area, macro_area,
    constraint_area, ub_area, module_area;

extern struct fd_to_stream streams;

extern struct alt_subclass *alt_subclassp;

extern short subtype;

extern int array, classcount, flags, made_change, option, pre_proc_pass,
    state, explicit1,
    add_child(char *, int, long, long, int),
    add_class_def(int),
    add_include_name(char *),
    add_name(char *, long, int),
    encr_xform(int, char *),
    find_file(char *),
    find_parent_index(struct name_table *ntbp, char *name),
    get_known(int, char *, char *),
    get_must(int, char *),
    get_token(int, char *),
    is_reserved(char *),
    is_a_type(char *),
    is_imported(char *),
    loop_test(struct name_table *, struct name_table *, int),
    putoct(char *, long),
    read_definition(int),
    read_global(),
    read_item(int, void(*func)()),
    set_name_option(char *to, char *from),
    test_dup(char *, long *),
    was_imported(char *),
    wdcmp(char *, char *);

extern ulong find_tag(char *), find_type(char *);

extern long curr_line, curr_pos, integer_val, min, max, real_start, tag,
    tablepos, table_start_line, type,
    find_ub(char *), tell_pos(FILE *);

extern void add_class_member(struct class_table *, char *),
    add_constraint(char *, int),
    add_macro(int, char *),
    add_ub(char *, long, int),
    bclr(char *, int),
    class_instance(int, FILE *, struct class_table *, char *),
    close_file(int),
    collect_ids(int, struct class_table *, FILE *),
    collect_id_type(int, struct class_table *, FILE *),
    cconstruct(),
    construct(),
    cdo_hdr(),
    cvt_number(char *, char *),
    do_hdr(),
    do_macro(int, FILE *, struct macro_table *),
    do_subclass(int fd, FILE *str),
    end_definition(),
    end_item(),
    fatal(int, char *),
    fill_name(char **, char *),
    fill_table_entry(int, int),
    free_imports(),
    free_table(char **tablepp, int ncols),
    get_expected(int, ulong, char *),
    get_exports(int, FILE *),
    get_fnames(int),
    get_subtype(),
    jconstruct(),
    mk_in_name(char *, char *, char *),
    mk_subclass(char *),
    pre_proc(int, FILE *, int),
    scan_syntax(int, struct with_syntax *, struct with_syntax *),
    set_alt_subtype(struct name_table *, int),
    set_classname(int nc),
    syntax(char *),
    tabulate(),
    test_paren(int, char *, char *, char **, char *),
    warn(int, char *);

extern struct name_table *find_name(char *),
    *find_parent(char *),
    *replace_name(char *);

extern FILE *outstr, *find_stream();

extern struct id_table *add_id(char *), *find_id(char *);

extern struct macro_table *find_macro(char *);

