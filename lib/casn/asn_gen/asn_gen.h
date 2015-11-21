#ifndef LIB_CASN_ASN_GEN_ASN_GEN_H
#define LIB_CASN_ASN_GEN_ASN_GEN_H

/***
 *
 * FILE:        asn_gen.h
 * AUTHOR:     Charles W. Gardiner (gardiner@bbn.com)
 *
 * DESCRIPTION: Header file for the ASN_GEN program.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <stdbool.h>
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

#include "util/macros.h"

#define GLOBAL 0                /* states used in construct, print_hdr and
                                 * tabulate */
#define IN_DEFINITION 1
#define SUB_DEFINITION 2
#define IN_ITEM       3
#define SUB_ITEM      4
#define PRE_GLOBAL   -1

#define ASN_BSIZE 128

#define BUILT_IN_IDS 8          /* must match number of OBJECT IDENTIFIERs in
                                 * built_ins in asn_gen.c */
#ifndef WIN32
#ifndef DOS
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif
#endif

struct tag_table {
    ulong tag;
    char *string;
    char *classname;
    char *define;
};

struct parent {
    struct parent *next;
    int index;                  /* of parent */
    int map_lth;
    char *mymap;                /* via this parent */
};

struct name_table {
    char *name;
    long pos;
    long type;
    long tag;
    short subtype;              /* used for SET/SEQ OF universal primitives to
                                 * deal with passthroughs */
    int flags;
    int generation;
    long min;
    long max;
    struct parent parent;
    struct parent child;
};

struct id_table {
    char *name;
    char *val;
};

struct ub_table {
    char *name;
    long val;
    int status;                 /* 0 if imported, else 1 */
};
struct ub_table *is_ub(
    char *);

struct module_table {
    char *mname;
    char *fname;
    long start_pos;
    long end_pos;
};

struct name_area {
    char *name;
    unsigned item;              /* size of each item in area */
    unsigned chunk;             /* number of items to add ad each enlargement */
    unsigned limit;             /* upper limit of size -- prevent runaway */
    char *area;                 /* pointer to a general name area */
    unsigned size;              /* number of items in the area */
    unsigned next;              /* index to next first free item in area */
};

struct alt_subclass {
    struct alt_subclass *next;
    char name[ASN_BSIZE];
    short options;
};

struct import_item {
    struct import_item *next;
    char *objname;
};

struct import_table {
    char *name;
    struct import_item item;
};
struct import_table *add_import_item(
    struct import_table *,
    char *);

struct table_entry {
    struct table_entry *next;
    char *item;
    char *id;
    char *value;
};

struct class_item {
    struct class_item *next;
    char *name;
    char *predicate;
};

struct table_out {
    struct table_out *next;
    char *table_name;
    struct table_entry table_entry;
};

struct with_syntax {
    struct with_syntax *next;
    char optional;
    char *subject;
    char *verb;
    char *object;
    struct table_out *table_outp;
};

struct class_table {
    char *name;
    char *instance_name;
    struct class_item item;
    struct with_syntax with_syntax;
    struct table_out table_out;
};
struct class_table *find_class_entry(
    char *);

struct macro_item {
    struct macro_item *next;
    char *prefix;
    int index;                  /* number of parameter */
};

struct macro_table {
    char *name;
    int arg_count;
    struct macro_item item;
};

struct fd_to_stream {
    struct fd_to_stream *next;
    int fd;
    FILE *str;
};

struct chain {
    struct chain *next;
};

struct chain *
add_chain(
    struct chain *,
    size_t);

void
warn(
    const char *format,
    ...)
    WARN_PRINTF(1, 2);

void
done(
    bool is_error,
    const char *format,
    ...)
    WARN_PRINTF(2, 3)
    NO_RETURN;

extern char token[];
extern char itemname[];
extern char classname[];
extern char prevname[];
extern char path[];
extern char subclass[];
extern char defaultname[];
extern char numstring[];
extern char defined_by[];
extern char definer[];
extern char tablename[];
extern char inclass[];
extern char *source;
extern char lo_end[];
extern char hi_end[];
extern char curr_file[];
extern char *def_constraintp;
extern char *sub_val;
extern char asn_java_id[];
extern char absent_w[];
extern char algid_w[];
extern char all_w[];
extern char any_w[];
extern char application_w[];
extern char array_w[];
extern char begin_w[];
extern char by_w[];
extern char casn_w[];
extern char choice_w[];
extern char class_w[];
extern char colon_ch[];
extern char component_w[];
extern char components_w[];
extern char constrained_w[];
extern char default_w[];
extern char defined_w[];
extern char definitions_w[];
extern char either_w[];
extern char empty_w[];
extern char encrypted_w[];
extern char end_w[];
extern char enumerated_w[];
extern char equal_ch[];
extern char explicit_w[];
extern char exports_w[];
extern char false_w[];
extern char few_w[];
extern char from_w[];
extern char function_w[];
extern char identifier_w[];
extern char implicit_w[];
extern char imports_w[];
extern char in_w[];
extern char instance_w[];
extern char integer_w[];
extern char many_w[];
extern char min_w[];
extern char max_w[];
extern char none_w[];
extern char null_w[];
extern char null_ptr_w[];
extern char of_w[];
extern char optional_w[];
extern char real_w[];
extern char relOID_w[];
extern char prefixes[];
extern char present_w[];
extern char private_w[];
extern char self_w[];
extern char sequence_w[];
extern char signed_w[];
extern char size_w[];
extern char string_w[];
extern char syntax_w[];
extern char table_w[];
extern char tags_w[];
extern char true_w[];
extern char type_identifier_w[];
extern char union_w[];
extern char unique_w[];
extern char universal_w[];
extern char with_w[];

char *
cat(
    char *,
    char *);

char *
expand_area(
    struct name_area *);

char *
find_child(
    char *);

char *
find_class(
    ulong);

char *
find_define(
    ulong);

char *
find_defined_class(
    int);

char *
find_typestring(
    ulong);

char *
get_obj_id(
    int,
    char *,
    char *);

char *
peek_token(
    int);

char **
read_table(
    int *ncolsp,
    struct name_table *ntbp);

char *
recalloc(
    char *,
    size_t,
    size_t);

extern struct tag_table tag_table[];

extern struct name_area class_area;
extern struct name_area name_area;
extern struct name_area id_area;
extern struct name_area import_area;
extern struct name_area macro_area;
extern struct name_area constraint_area;
extern struct name_area ub_area;
extern struct name_area module_area;

extern struct fd_to_stream streams;

extern struct alt_subclass *alt_subclassp;

extern short subtype;

extern int array;
extern int classcount;
extern int flags;
extern int made_change;
extern int option;
extern int pre_proc_pass;
extern int state;
extern int explicit1;

int
add_child(
    char *,
    int,
    long,
    long,
    int);

int
add_class_def(
    int);

int
add_include_name(
    char *);

int
add_name(
    char *,
    long,
    int);

int
encr_xform(
    int,
    char *);

int
find_file(
    char *);

int
find_parent_index(
    struct name_table *ntbp,
    char *name);

int
get_known(
    int,
    char *,
    char *);

int
get_must(
    int,
    char *);

int
get_token(
    int,
    char *);

int
is_reserved(
    char *);

int
is_a_type(
    char *);

int
is_imported(
    char *);

int
loop_test(
    struct name_table *,
    struct name_table *,
    int);

int
putoct(
    char *,
    long);

int
read_definition(
    int);

int
read_global(
    );

int
read_item(
    int,
    void (*func)());

int
set_name_option(
    char *to,
    char *from);

int
test_dup(
    char *,
    long *);

int
was_imported(
    char *);

int
wdcmp(
    char *,
    char *);

ulong
find_tag(
    char *);

ulong
find_type(
    char *);

extern long curr_line;
extern long curr_pos;
extern long integer_val;
extern long min;
extern long max;
extern long real_start;
extern long tag;
extern long tablepos;
extern long table_start_line;
extern long type;

long
find_ub(
    char *);

long
tell_pos(
    FILE *);

void
add_class_member(
    struct class_table *,
    char *);

void
add_constraint(
    char *,
    int);

void
add_macro(
    int,
    char *);

void
add_ub(
    char *,
    long,
    int);

void
bclr(
    char *,
    int);

void
class_instance(
    int,
    FILE *,
    struct class_table *,
    char *);

void
close_file(
    int);

void
collect_ids(
    int,
    struct class_table *,
    FILE *);

void
collect_id_type(
    int,
    struct class_table *,
    FILE *);

void
cconstruct(
    );

void
construct(
    );

void
cdo_hdr(
    );

void
cvt_number(
    char *,
    char *);

void
do_hdr(
    );

void
do_macro(
    int,
    FILE *,
    struct macro_table *);

void
do_subclass(
    int fd,
    FILE *str);

void
end_definition(
    );

void
end_item(
    );

void
fill_name(
    char **,
    char *);

void
fill_table_entry(
    int,
    int);

void
free_imports(
    );

void
free_table(
    char **tablepp,
    int ncols);

void
get_expected(
    int,
    ulong,
    char *);

void
get_exports(
    int,
    FILE *);

void
get_fnames(
    int);

void
get_subtype(
    );

void
jconstruct(
    );

void
mk_in_name(
    char *,
    char *,
    char *);

void
mk_subclass(
    char *);

void
pre_proc(
    int,
    FILE *,
    int);

void
scan_syntax(
    int,
    struct with_syntax *,
    struct with_syntax *);

void
set_alt_subtype(
    struct name_table *,
    int);

void
set_classname(
    int nc);

void
syntax(
    char *);

void
tabulate(
    );

void
test_paren(
    int,
    char *,
    char *,
    char **,
    char *);

struct name_table *
find_name(
    char *);

struct name_table *
find_parent(
    char *);

struct name_table *
replace_name(
    char *);

extern FILE *outstr;

FILE *
find_stream(
    );

struct id_table *
add_id(
    char *);

struct id_table *
find_id(
    char *);

struct macro_table *
find_macro(
    char *);

/* verbosity: default 0 (nothing printed to stdout on success)

   From asn_gen.1 man page:
   If '-v' is present, a table of all the defined items is printed on the
   standard output in the form:

       #5 Name xxxx generation 3 flags 0x0 tag 0x30 at 0x234 has:
           Parent 2, mymap is '102', length 3

   where '#5' is the index in the table, 'xxxx'represents the name  of
   the  item, and the generation indicates the level at which the item
   occurs, generation 0 being the highest.
 */
extern int vflag;


#define MSG_OK "Asn_gen finished %s OK\n"
#define MSG_INVAL_PARAM "Invalid parameter: %s\n"
#define MSG_OPEN "Can't open %s\n"
#define MSG_AMBIGUOUS_DER "Construct has ambiguous DER\n"
#define MSG_INVAL_STATE "invalid state %d\n"
#define MSG_NO_CHILD "no child of %s in table\n"
#define MSG_INVAL_WORD "invalid word: %s\n"
#define MSG_MEM "memory error\n"
#define MSG_OVERFLOW "overflow in area %s\n"
#define MSG_NO_PATH "can't find definer/defined path for %s\n"
#define MSG_SYNTAX_ERR "syntax error at %s\n"
#define MSG_NESTING "nesting detected\n"
#define MSG_EOF "unexpected EOF at %s\n"
#define MSG_EXTRA_TAG_DEF "extra tag definition 0x%lX\n"
#define MSG_UNDEF_UPPER "undefined upper bound %s\n"
#define MSG_DUP_DEF "duplicate definition of %s\n"
#define MSG_ID_UNDEF "ID %s is not defined\n"
#define MSG_NO_TABLE "no table defined for %s\n"
#define MSG_MISSING "missing %s\n"
#define MSG_NOT_EXPORT "%s is not on the export list\n"
#define MSG_LOOP "stuck in loop at %s, Check syntax.\n"
#define MSG_AMBIGUOUS_TAG "ambiguous tagging of %s\n"
#define MSG_INTERNAL "internal error in %s\n"
#define MSG_MULTIPLE_DEFINERS "multiple definers for %s\n"
#define MSG_MACRO_PARAMS "too %s parameters in macro\n"
#define MSG_UNDEF_MACRO "undefined macro %s\n"
#define MSG_UNDEF_ITEM "undefined item %s in syntax\n"
#define MSG_FEW_COLS "not enough columns defined in table\n"
#define MSG_UNDEF_CLASS "undefined class %s\n"
#define MSG_NOT_SUPPORTED "%s not supported for this type\n"
#define MSG_MANDATORY "%s must not be optional or absent\n"
#define MSG_DETERMINE_CONSTRAINT "Can't determine constraint %s\n"
#define MSG_UNDEF_TYPE "undefined type for %s\n"
#define MSG_NO_ANY_DEFINED_BY "no ANY DEFINED BY for %s\n"
#define MSG_BIG_TOKEN "token %s is too big\n"
#define MSG_BIG_LINE "line bigger than buffer: %s\n"
#define MSG_CREATE_DIR "Can't create directory named %s\n"
#define MSG_FIND_STREAM "Can't find stream for fd %d\n"
#define MSG_INCOMPLETE_ITEM "Incomplete table item %s\n"
#define MSG_FIND_CONSTRAINT "Couldn't find constraint for %s\n"
#define MSG_RENAME_FILE "Can't rename file: %s\n"

#endif
