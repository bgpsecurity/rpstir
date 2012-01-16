/* $Id$ */
/*****************************************************************************
File:     asn_pproc.c
Contents: Functions to pre-process ASN.1 files as part of the ASN_GEN
          program.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

const char asn_pproc_rcsid[]="$Header: /nfs/sub-rosa/u1/IOS_Project/ASN/Dev/rcs/cmd/asn_gen/asn_pproc.c,v 1.1 1995/01/11 22:43:11 jlowry Exp gardiner $";
char asn_pproc_id[] = "@(#)asn_pproc.c 828P";

#include "asn_gen.h"
#ifdef WIN32
#include <io.h>
#endif

/**
                   Design Notes on the Pre-processor

    For the 1988 version of ASN.1, this module unraveled the nested definitions,
such as:

    XXX ::= SEQUENCE {
	a   SET {
	    b   INTEGER,
	    c   OCTET STRING },
	d   BOOLEAN }

by use of recursive calls to pre_proc().  It also generated the necessary
synthetic names and implemented the ENCRYPTED and SIGNED macros and handled all
imports to produce a single file for the later stages to process.

    For the 1994 additions, the pre-processor was greatly extended to transform
the CLASS notation etc. into the previous TABLE style.  This occurs in several
places.  Consider the built-in definition

    TYPE_IDENTIFIER ::= CLASS {
        &id OBJECT IDENTIFIER UNIQUE,
        &Type }
    WITH SYNTAX { &Type IDENTIFIED BY &id }

When the reserved word CLASS in encountered in the definition state
(function pre_proc_def()), the function add_class_def(), q.v., is called to
process everything up through the final right brace and to set the state to
GLOBAL again.  (The pre-processor and the get_token function were also modified
to do built-in definitions.)

    Next, when a reference to the class is found, e.g.

    ALGORITHM ::= TYPE-IDENTIFIER

by the function find_class_entry() in pre_proc_def(), the function
add_class_member() is called to add this member in such a way that it will
inherit the syntax originally defined.

    When a definition is encountered like

    AlgorithmIdentifier ::= SEQUENCE {
        algorithm   ALGORITHM.&id ( {SupportedAlgorithms} ),
        parameters  ALGORITHM.&Type ( {SupportedAlgorithms } {@algorithm} )
                OPTIONAL }

the function find_class_entry() in pre_proc_item(), the function fill_id_type()
processes the entire item through the final right parenthesis

    At a definition of object identifiers like

    SupportedAlgorithms ALGORITHM ::= {dsa | xxx | rsa-signature }

pre_proc_glob() uses find_class_entry() to detect the class, and fills in the
name.  When the ::= is encountered, pre_proc_glob, noting that the classname is
capitalized, calls collect_ids() to process everything up through the final
right brace.

    At a definition of an instance of the class like:

    dsa ALGORITHM ::= { DSAParameters IDENTIFIED BY id-dsa }

pre_proc_glob(), noting that the classname is NOT capitalized, calls
class_instance() to process everything through the final right brace.

    For "parameterized" items (i.e. macros) like:

    DirectoryString{INTEGER:maxSIZE} ::= CHOICE {
        teletexString   TeletexString(SIZE(1..maxSIZE)),
        printableString PrintableString(SIZE(1..maxSIZE)) }

pre_proc_glob, triggered by the left brace, calls add_macro() to process
everything through the final right brace.  Then when the macro is invoked, as in

    commonName ATTRIBUTE ::=  {
        SUBTYPE OF      name
        WITH SYNTAX     DirectoryString { ub-common-name }
        ID              { id-at-commonName } }

the class_instance() function, noting the left parenthesis in a Type-refernce,
calls do_macro() to perform the substitutions.
**/

struct import_table *imtbp;
               /* pointer to entry for imported file currently being read */

static int num_imports;
static int append_default(int, char *, char *),
    append_token(char *, char *, char *),
    pre_proc_get_token(int, FILE *, char *),
    pre_proc_glob(int, FILE *, char *, char **, char *, int *),
    pre_proc_def(int, FILE *, char *, char **, char *, int *),
    pre_proc_item(int, FILE *, char *, char **, char *, int *, int),
    recurs(int fd, FILE *str, char *newclass, int newstate, int in_sub);

FILE *make_substr(char *);

void empty_substr(FILE *, FILE *, char *, int, char *);

static void glob_type(int, long, int),
    print_signed(FILE *, char *, char *),
    putout(FILE*, char *),
    scan_modules(int), skip_to(int, int, int);

static char table[128], topclass[128],
    tobesigned[] = "    toBeSigned  %sToBeSigned,\n",
    tabledef[] =    /* used in SIGNED SEQUENCE TABLE ... */
"%sAlgorithmIdentifier ::= SEQUENCE {\n\
    algorithm OBJECT IDENTIFIER TABLE %s,\n\
    parameters ANY DEFINED BY algorithm OPTIONAL}\n\n",
    signed_def[] = "%s ::= %s %s",
    thatword[] = "    toBeSigned  %s,\n",
    algsig[] = 
"    algorithm  %sAlgorithmIdentifier,\n\
    signature BIT STRING }\n\n",
    instance_of[] =
"%s ::= INSTANCE OF {\n\
    type_id OBJECT IDENTIFIER TABLE %s,\n\
    value   ANY DEFINED BY type_id }\n\n",
    sub_opener[] = "%s ::= %s {\n";

void pre_proc(int fd, FILE *str, int in_sub)
{
/**
Function: Preprocesses file fd to translate SIGNED macro and produce file str
Inputs: fd is file descriptor for ASN.1 file.  IF this is > zero, we are in
	    an imported file
	str is the stream descriptor for the output
	in_sub is used for recursiveness
Outputs: ASN.1 code written to 'str'
Procedure:
0. Scan for modules
1. Starting with lots of things cleared, DO forever
        IF no token AND no more tokens, break out of DO
        Switch on state
2.    Case GLOBAL
	IF processing global state returns GLOBAL state, return
      Case IN_DEFINITION
	    IF processing the definition returns GLOBAL state
		Clean up a few variables
      Case IN_ITEM
	    IF in a sub-item AND pre-processing the items returns GLOBAL
		state, return
**/
char linebuf[20*ASN_BSIZE], *linend = linebuf, *elinebuf = &linebuf[sizeof(linebuf)];
int signflag,
    active;   /* -1= in main file,
                  0= in imported file but not imported class
		  1= in imported file in an imported class, no details needed
		  2=  "   "        "  "   "    "      " , but details needed */
ulong loctag;
long loctype;
if (!in_sub) *classname = *token = 0;
if (fd >= 0 && !in_sub && !real_start) scan_modules(fd);
if (fd <= 0) active = -1;
else active = 0;
for (signflag = loctag = 0, loctype = -1,
    *linebuf = *itemname = 0; pre_proc_get_token(fd, str, linebuf); )
    {
    switch (state)
    	{
    case PRE_GLOBAL:
	if (*token == ':') syntax(definitions_w);
	if (!strcmp(token, definitions_w)) state = GLOBAL;
	else *token = 0;   /* discard up to DEFINITIONS */
	break;

    case GLOBAL:			 
	state = pre_proc_glob(fd, str, linebuf, &linend, elinebuf, &active);
	break;

    case IN_DEFINITION:                                     /* got ::= */
	if ((state = pre_proc_def(fd, str, linebuf, &linend, elinebuf,
            &active)) == GLOBAL)
	    {
            active = (fd <= 0)? -1: 0;
            loctype = -1;
            *subclass = *classname = 0;
	    if (fd >= 0) fflush(str);
	    if (in_sub) return;
	    }
	else if (state == IN_DEFINITION)
	    {
            if (in_sub) return;
	    syntax(token);
	    }
        *(linend = linebuf) = 0;
	break;

    case IN_ITEM:
    case SUB_ITEM:
	if ((state = pre_proc_item(fd, str, linebuf, &linend, elinebuf,
            &active, in_sub)) == GLOBAL && in_sub) return;
	break;

    default:
	fatal(4, (char *)state);
	}
    }
if (fd < 0) return;
if (linend > linebuf) fprintf(str, "%s\n", linebuf);
if (!fd) free_imports();
}

static int pre_proc_get_token(int fd, FILE *str, char *linebuf)
{
static int loopcount;
if (!*token) loopcount = 0;
else if (loopcount++ > 20)
    {
    putout(str, linebuf);
    fflush(str);
    fatal(22, token);
    }
if (!*token && !get_token(fd, token)) return 0;
return 1;
}

static int pre_proc_glob(int fd, FILE *str, char *linebuf, char **linendpp,
    char *elinebuf, int *activep)
{
/**
1. DO
	IF token is less than space, skip it
	ELSE IF token is left brace, set up the macro
	ELSE IF token if right brace OR left paren, syntax error
        ELSE IF token is '::='
    	    IF not in definitions class
                Set state to IN_DEFINITION
		IF at a defined type, cancel token and linebuf
    	    ELSE IF not in an imported file
    	        Print token with RETURN
    	        Clear class name and token
2.      ELSE IF token is IMPORTS
    	    IF have already started, error
            Get all the file names
            IF at top level
                FOR each file in the import table
    	            Add the name to the i_names list
    	            Open the file for reading
    	            Call pre_proc with that fd (this may add to the import
    		        table)
    	            Close input file
            Put out an extra line end
3.      ELSE IF token is EXPORTS, put export items in export area
        ELSE IF token is BEGIN or END, do nothing
        ELSE IF token is a known tag, call glob_type
        ELSE IF token is a name defined to be a universal type
    	    IF haven't a class name, error
	    Call glob_type
	ELSE IF token is a defined type-identifier
	    IF haven't a class name, error
	    Set the current type index for use by the items
	    IF no table name, fill in the table name with classname
        ELSE IF token is a brace, error
        ELSE IF have no local classname AND token looks like one
    	    Copy token to local class name
        IF classname is upper case, append token to linebuf and clear token
   WHILE state is GLOBAL AND there's a next token
   Return state
**/
char locfile[80], *c, *fname;
int sub_fd;
long tmp, locline;
struct name_table *ntbp;
struct class_table *ctbp = (struct class_table *)0;
struct table_entry *tbep;
struct table_out *tbop;
do                                                          /* step 1 */
    {
    if (*token <= ' ');
    else if (*token == '{')
        {
	add_macro(fd, classname);
        *token = *classname = *(*linendpp = linebuf) = 0;
        }
    else if (*token == '}' || *token == '(') syntax(token);
    else if (*token == ':')
        {
	get_known(fd, &token[1], colon_ch);
	get_known(fd, &token[2], equal_ch);
	token[3] = 0;
	if (ctbp)
	    {
	    if ((*classname & 0x20))
		{
		get_known(fd, token, "{");
		class_instance(fd, str, ctbp, classname);
		}
	    else
		{
                collect_ids(fd, ctbp, str);
		if (!fd && !ctbp->with_syntax.subject && !ctbp->with_syntax.next)
		    {
		    fprintf(str, linebuf);
		    if (strncmp(ctbp->item.predicate,
                        (c = "OBJECT IDENTIFIER"), 17) &&
			strcmp(ctbp->item.predicate, (c = integer_w)))
                        syntax(ctbp->item.predicate);
		    fprintf(str, " ::= %s {\n", c);
		    for (tbep = &ctbp->table_out.table_entry; tbep;
                        tbep = tbep->next)
			{
			fprintf(str, "    %s %s ", (tbep->item)? tbep->item: "",
                            (tbep->id)? tbep->id: "");
			fprintf(str, (tbep->next)? ",\n": "}\n");
			}
		    }
		}
	    *token = *(*linendpp = linebuf) = 0;
    	    ctbp = (struct class_table *)0;
	    }
        else if (strcmp(classname, definitions_w)) state = IN_DEFINITION;
        else
            {
            if (!fd) fprintf(str, "%s ::=\n\n", linebuf);
    	    *token = *classname = *(*linendpp = linebuf) = 0;
	    }
        }
    else if (!strcmp(token, imports_w))                     /* step 2 */
        {
        cat(classname, token);
        if (real_start) syntax(token);
        *token = 0;
        get_fnames(fd);
        if (!fd)
	    {
            for(imtbp = (struct import_table *)import_area.area;
	        imtbp && imtbp->name; imtbp++)
	        {
		if (!strcmp(imtbp->name, source)) continue;
	        if (add_include_name(imtbp->name))
		    {
    	            if ((sub_fd = find_file(imtbp->name)) < 0)
			{
			fname = (char *)calloc(1, strlen(imtbp->name) + 6);
			strcat(strcpy(fname, imtbp->name), ".asn");
			if ((sub_fd = find_file(fname)) < 0)
                            fatal(2, imtbp->name);
			free(imtbp->name);
			imtbp->name = fname;
			}
    	            printf("    Imported file %s\n", imtbp->name);
		    cat(locfile, curr_file);
		    cat(curr_file, imtbp->name);
		    locline = curr_line;
		    curr_line = 0;
		    state = recurs(sub_fd, str, (char *)0, PRE_GLOBAL, 0);
    	            close_file(sub_fd);
		    fflush(str);
		    curr_line = locline;
		    cat(curr_file, locfile);
		    *token = 0;
		    }
	        }
	    imtbp = (struct import_table *)0;
	    num_imports = name_area.next;
	    printf("Main file\n");
	    }
        if (*activep) putout(str, "\n");
        if (!fd) real_start = ftell(str);
        *classname = 0;
        }
    else if (!strcmp(token, exports_w))                     /* step 3 */
        {
        get_exports(fd, str);
        *classname = *token = 0;
        }
    else if (!strcmp(token, begin_w) || !strcmp(token, end_w)) *token = 0;
    else if ((tmp = find_type(token)) != ASN_NOTYPE)
	{
        get_expected(fd, tmp, token);
	glob_type(fd, tmp, *activep);
	*(*linendpp = linebuf) = 0;
	}
    else if ((ntbp = find_name(token)) && ntbp->name && ntbp->type > 0 &&
        ntbp->type < ASN_APPL_SPEC)
        {
        if (!*classname)
	    {
	    cat(classname, token);
            fatal(17, token);
	    }
        ntbp->pos = -2;     /* so it won't appear in unused list */
        glob_type(fd, ntbp->type, *activep);
	*(*linendpp = linebuf) = 0;
        }
    else if (*activep && (ctbp = find_class_entry(token)))
	{
	if (!*classname) fatal(20, "class name");
	if (!(*classname & 0x20) &&
            (ctbp->with_syntax.next || ctbp->with_syntax.subject))
	    {
	    for (tbop = &ctbp->table_out; tbop && tbop->table_name &&
                strcmp(tbop->table_name, classname); tbop = tbop->next);
	    if (!tbop) tbop = (struct table_out *)add_chain((struct chain *)
		&ctbp->table_out, sizeof(struct table_out));
            fill_name(&tbop->table_name, classname);
	    }
	*token = 0;
	}
    else if (!*classname && *token >= 'A')
        {
        cat(classname, token);
        if (strcmp(token, definitions_w) && strcmp(token, implicit_w) &&
	    strcmp(token, explicit_w) && strcmp(token, type_identifier_w) &&
            is_reserved(token)) syntax("invalid class");
        }
    if (fd > 0 && *classname > ' ') *activep = is_imported(classname);
    if (*classname <= 'Z' && *activep && *token && (*linendpp > linebuf ||
        *token > ' ') &&
        (*linendpp = cat(cat(*linendpp, token),
        ((*token == '{')? "\n    ": " "))) >= elinebuf) fatal(37, linebuf);
    *token = 0;
    }
while (state == GLOBAL && pre_proc_get_token(fd, str, linebuf));
return state;
}

static int pre_proc_def(int fd, FILE *str, char *linebuf, char **linendpp,
    char *elinebuf, int *activep)
{
/**
0. IF in later pre_proc pass AND have no real start yet AND the class has a
	name table entry
	IF beyond teh import items OR at an export item, set real_start
1. DO
        IF token is ENCRYPTED, call encrypted transformation
	ELSE IF token is BY OR IN, append next word to token
	ELSE IF token is CLASS, process class up to GLOBAL state
	ELSE IF token is DEFAULT, append it
	ELSE IF token is DEFINED
	    IF next token isn't BY OR no next token, syntax
	    IF in a sub-function, append 'IN topclass' to token
        ELSE IF token is SIGNED
	    IF have no subclass
                Get next token as subclass
		IF that's '{'
		    Get next token as subclass
		    Get the '}
	    IF type of subclass is a universal primitive
		Get the rest of it
	    IF the next token would be TABLE, get it & put next in table name
	    Print the signed stuff
	    Clear token
	    IF class is not imported AND type is SET OR SEQUENCE
		Save globals
		Make a substream, if necessary
		Print the class definition there
		Call pre_proc to do the rest of the definition
		Restore globals
	ELSE IF token is SIZE AND it's an import, skip it
	ELSE IF token is TYPE-IDENTIFIER
            Create a type-table entry
	    Clear the linebuf
	ELSE IF token is a macro, IF active, make the substitutions
2.      ELSE IF token is '{'
	    Set state to IN_ITEM
	    Append the token
	    IF in an import BUT don't need details, skip to '}'
	ELSE IF token is OF
    	    IF linebuf has data, print linebuf
            IF active, put out OF
            IF next token is not a universal type
	        IF active, put out token
	        Clear token
                Set state to GLOBAL
            ELSE IF it's a constructed type
                Make a synthetic name
                IF active
                    Print that with a blank line
		    IF there's further definition
		        Print sub_opener with synthetic name and universal
                            type name
		    ELSE
		        Print sub-definition
		        Call pre_proc to do details
                Clear token
	    ELSE IF it's a primitive without further definition
		Print the token with blank line
    	        Set state to GLOBAL
        ELSE IF have '{' in an imported file
            Print token
            Skip to next '}'
        IF NOT imported
            IF (linebuf has data OR token is '{'
	        IF token is '{', append it to linebuf
                Print the linebuf
        IF state isn't GLOBAL, set state to IN_ITEM
3.      ELSE IF token is open parenthesis, go to end of parentheses
	ELSE IF token is open bracket, bump count
        ELSE IF token is close bracket
    	    IF decrementing count goes < 0, error
        ELSE IF token is numeric
            Add object to ub table
    	    Clear linebuf
	ELSE IF token is a known type
	    Add the class name and save the local type
        ELSE IF token is alphabetic but not a reserved word
    	    IF have subclass OR type, i.e. definition is complete
		Set state to GLOBAL
		IF type is SET/SEQ, error
	    ELSE IF token is lower case, fill in the ID definition
	    ELSE
		Copy token to subclass
		IF classname and subclass are bot lower case,
                    Set state to GLOBAL
4.      IF classname is upper case
    	    IF just switched to GLOBAL state
    	        IF active
		    IF had SIGNED, print signed stuff
		    ELSE
        	        IF in an imported file AND token is capital letter
        	            Add token as an imported item so it will be
        		        included as child of this 'false' item
                            Print 1 or 2 blank lines
    		Keep token, since it starts the next definition
    	    ELSE
                IF active,
    		    Append token to linebuf
    		    IF item is a choice, set active to 2 to force getting
    		        contents of item
		Discard token
        ELSE discard token
   WHILE state is IN_DEFINITION AND there's another token that's (reserved
	OR '{' OR '(' OR ']')
   Return state
**/
int loctype, brackets, parens;
long tmp;
char *c, constrain = 0, is_brace, subfilename[128];
struct class_table *ctbp;
struct id_table *cidp;
struct macro_table *mtbp;
struct name_table *ntbp = find_name(classname);
FILE *substr = 0;
constrain = brackets = parens = 0;
loctype = -1;
*table = *itemname = 0;
if (pre_proc_pass > 0 && !real_start && ntbp)
    {
    if ((ntbp - (struct name_table *)name_area.area) >= num_imports ||
        (ntbp->flags & ASN_EXPORT_FLAG)) real_start = ftell(str);
    }
do
    {
    if (!strcmp(token, encrypted_w))
	{
        loctype = encr_xform(fd, token);
	if (!fd) *linendpp += append_token(*linendpp, token, elinebuf);
	*token = 0;
	}
    else if (!strcmp(token, by_w) || !strcmp(token, in_w))
	{
	token[2] = ' ';
	get_must(fd, &token[3]);
	}
    else if (!strcmp(token, class_w))
	{
        state = add_class_def(fd);
	*classname = *(*linendpp = linebuf) = 0;
	}
    else if (!strcmp(token, defined_w))
	{
	token[7] = ' ';
	get_known(fd, &token[8], by_w);
	token[10] = ' ';
	get_must(fd, &token[11]);
	if (*topclass) cat(cat(cat(cat(&token[strlen(token)], " "), in_w), " "),
	    topclass);
	}
    else if (!strcmp(token, default_w) || !strcmp(token, optional_w))
	{
	fprintf(str, "%s\n\n", linebuf);
        return IN_DEFINITION;
	}
    else if (!strcmp(token, signed_w))
	{
	if (!*subclass)
	    {
	    get_must(fd, subclass);
    	    if (*subclass == '{')
    	        {
    	        get_must(fd, subclass);
    	        get_known(fd, token, "}");
    	        }
	    }
	*token = 0;
	if ((loctype = type = find_type(subclass)) >= 0 && type < ASN_CONSTRUCTED)
	    {
	    for (c = subclass; *c; c++);
            *c++ = ' ';
	    *c = 0;
            get_expected(fd, type, c);
    	    if (!*c) c[-1] = 0;
	    type = ASN_NOTYPE;
	    }
	if (!strncmp(peek_token(fd), table_w, 5))
	    {
	    get_must(fd, token);
	    get_must(fd, table);
	    *token = 0;
	    }
	if (!fd || is_imported(classname))
	    {
	    add_name(classname, ASN_SEQUENCE, 0);
            print_signed(str, classname, subclass);
	    if (*activep > 0) *activep = is_imported(classname);
            if (!fd || *activep)
		{
                if (loctype > ASN_CONSTRUCTED && loctype != ASN_NOTYPE)
                    {
                    cat(token, subclass);
                    if (!substr) substr = make_substr(subfilename);
                    fprintf(substr, signed_def, classname, "", "");
                    state = recurs(fd, substr, (char *)0,  IN_DEFINITION, 1);
                    state = GLOBAL;     /* signed always goes to end */
                    }
		}
	    }
        *(*linendpp = linebuf) = 0;
	}
    else if (!strcmp(token, size_w) && fd) *token = 0;
    else if ((ctbp = find_class_entry(token)))
	{
        for (c = token; *c && *c != '.'; c++);
        if (*c)         /* it is a XXX.&yy in a definition */
            {
            get_known(fd, token, "&");
            get_must(fd, token);
            }
        else add_class_member(ctbp, classname);
	*(*linendpp = linebuf) = *token = *classname = 0;
        loctype = 0;
	}
    else if ((mtbp = find_macro(token)))
	{
	if (*activep) do_macro(fd, str, mtbp);
	else
	    {
	    get_known(fd, token, "{");
	    skip_to(fd, 1, 0);
	    }
	*(*linendpp = linebuf) = *token = 0;
	state = GLOBAL;
	}
    else if (*token == '{')             /* step 2 */
	{
        state = IN_ITEM;
        *linendpp += append_token(*linendpp, token, elinebuf);
	if (fd > 0)        /* in import */
	    {
            skip_to(fd, 1, 0);
	    state = GLOBAL;
	    if (*peek_token(fd) == '(')
		{
	        get_known(fd, token, "(");
	        skip_to(fd, 0, 1);
		}
            *linendpp += append_token(*linendpp, "}", elinebuf);
	    }
        *token = 0;
        }
    else if (!strcmp(token, of_w))
	{
        if (*activep) *linendpp += append_token(*linendpp, token, elinebuf);
        get_must(fd, token);
        if ((tmp = find_type(token)) == ASN_NOTYPE)
	    {
	    if (*activep) *linendpp += append_token(*linendpp, token, elinebuf);
	    else *token = 0;
	    if ((constrain = *peek_token(fd)) != '(')
	        {
	        constrain = 0;
	        state = GLOBAL;
		*token = 0;
		}
	    }
	else if (tmp >= ASN_CONSTRUCTED)  /* SET/SEQ/CHOICE */
	    {
	    cat(cat(cat(itemname, &find_class(tmp)[3]), "In"), classname);
	    if (*activep)
		{
		fprintf(str, "%s %s\n\n", linebuf, itemname);
		*(*linendpp = linebuf) = 0;
                fprintf(str, "%s ::= %s ", itemname, token);
		state = recurs(fd, str, itemname, IN_DEFINITION, 1);
		if (*token == ',') break;
		}
            *itemname = 0;
	    }
        else                     /* have a universal primitive */
	    {
	    get_expected(fd, tmp, token);
	    loctype = tmp;
	    if (!(is_brace = (*peek_token(fd) == '{')))
	        {
	        if (*activep) *linendpp += append_token(*linendpp, token, elinebuf);
	        }
	    else
	        {
	        cat(cat(cat(itemname, &find_class(tmp)[3]), "In"), classname);
	        cat(classname, itemname);
	        if (*activep)
		    {
		    fprintf(str, "%s %s\n\n", linebuf, itemname);
		    *(*linendpp = linebuf) = 0;
		    fprintf(str, sub_opener, itemname, token);
		    get_known(fd, token, "{");
		    state = IN_ITEM;
		    }
		*itemname = 0;
		}
	    *token = 0;
	    }
	if (!fd)
	    {
	    if (*linendpp > linebuf || *token == '{')
		{
	        if (*token == '{' && (*linendpp = cat(*linendpp, "{\n")) >=
		    elinebuf) fatal(37, linebuf);
		*token = 0;
		}
	    }
	fflush(str);
	*table = 0;
	}
                                                             /* step 3 */
    else if (*token == '(')
	{
        test_paren(fd, token, linebuf, linendpp, elinebuf);
	if (constrain == '(')
	    {
            if ((*linendpp = cat(*linendpp, "\n")) >= elinebuf) fatal(37, linebuf);
    	    constrain = 0;
    	    state = GLOBAL;
	    }
	}
    else if (*token == '[') brackets++;
    else if (*token == ']')
	{
	if ((*token == ']' && !brackets--)) syntax(token);
	}
    else if (!parens && !brackets && ((*token >= '0' && *token <= '9') ||
        (*token == '_' && token[1] >= '0' && token[1] <= '9')))
	{
	for (c = (*token == '_')? &token[1]: token, tmp = 0;
            *c >= '0' && *c <= '9'; tmp = (tmp * 10) + *c++ - '0');
	if (*token == '_') tmp = -tmp;
	if (*activep) add_ub(classname, tmp, *activep);
	state = GLOBAL;
	*token = *classname = *(*linendpp = linebuf) = 0;
	}
    else if ((tmp = find_type(token)) != ASN_NOTYPE)
	{
	get_expected(fd, (loctype = tmp), token);
	if (!fd || *activep) add_name(classname, loctype, 0);
	}
    else if ((*token >= 'A' || *token == '*') && !is_reserved(token))
	{
	if (*subclass || loctype >= 0)
	    {
	    state = GLOBAL;
	    if (loctype >= 0 && (loctype & ASN_CONSTRUCTED))
		syntax(find_typestring(loctype));
	    }
	else if ((*token & 0x20) && (cidp = find_id(token)))
	    {
	    c = cidp->val;
	    cidp = add_id(classname);
	    cidp->val = c;
	    end_definition();
	    *token = *(*linendpp = linebuf) = 0;
	    }
	else cat(subclass, (*token == '*')? &token[1]: token);
	}
    if (*classname >= 'A' && *classname <= 'Z')             /* step 4 */
        {
    	if (state == GLOBAL)
	    {
	    if (*activep && !constrain)
		{
            	if (*linendpp > linebuf) fprintf(str, "%s\n\n", linebuf);
    		if (fd > 0 && *token >= 'A' && *token <= 'Z')
    		    add_import_item(imtbp, token);
        	if (*subclass || loctype >= 0) putout(str, "\n");
		}
	    }
	else
	    {
	    if (*activep) *linendpp += append_token(*linendpp, token, elinebuf);
	    *token = 0;
	    }
	}
    else *token = 0;
    }
while (state == IN_DEFINITION && pre_proc_get_token(fd, str, linebuf) &&
    *token != '}' && (*token == '{' || *token == '[' || *token == '(' ||
    *token < ' ' ||
    brackets || is_reserved(token) || (!*subclass && loctype < 0)));
if ((state == IN_DEFINITION || state == IN_ITEM) && *linebuf)
    {
    if (!fd  && pre_proc_pass && state == IN_ITEM &&
            tell_pos(streams.str) < real_start)
        {
        do
            {
            get_must(fd, token);
            *linendpp += append_token(*linendpp, token, elinebuf);
            }
        while(*token != '}');
        *token = 0;
        state = IN_DEFINITION;   /* to make 2nd fprintf happen */
        }
    fprintf(str, "%s\n", linebuf);
    if (state == IN_DEFINITION && !fd && *linebuf != '\n') fprintf(str, "\n");
    }
if (substr) empty_substr(str, substr, linebuf, (elinebuf - linebuf),
    subfilename);
return (state == IN_DEFINITION)? GLOBAL: state;
}

static int pre_proc_item(int fd, FILE *str, char *linebuf, char **linendpp,
    char *elinebuf, int *activep, int in_sub)
{
/**
1. DO
        IF token is ENCRYPTED, call encrypted transformation
        IF token is ',' or '}'
            IF tag is BITSTRING, append BIT STRING to line
    	    IF class is capitalized, append token to line
    	    IF active, print line
    	    IF a peek at next token shows it's '(', print all the paren stuff
    	    IF at end of items, set state to GLOBAL & print another \n
        ELSE IF token is '|'
    	    IF no current type-table entry, error
    	    ELSE
    	        Add itemname to table entry
    	        Clear linebuf
        ELSE IF token is '('
    	    Get the next token
    	    IF that is not a range, put it into linebuf
    	    ELSE
                Back linendpp to start of last word
                IF no item name, insert one ahead of that word
                Make itemInClassname
                IF no substream, make one
                Get the range
                Write the new class definition to the substream
                Append the new class name to linebuf
        ELSE IF token is '{' OR OF, error
            IF type is inappropriate, error
            IF there's no substream, make one
            Save globals, call pre_proc with that substream, restore globals
        ELSE IF token is COMPONENTS
    	    Append next token
    	    Make sure that token is OF
        ELSE IF token is DEFAULT, append it
	ELSE IF token is END, error
        ELSE IF token is FUNCTION, put all up through last ')' into token
        ELSE IF token is INSTANCE
    	    IF next token isn't OF OR no token after that, error
    	    IF present token isn't a known class OR known class has no instance name
    	        Use ANY as the subclass
    	    ELSE use the known class's instance name
        ELSE IF token is SIGNED
    	    Get next token as subclass
    	    IF subclass is universal type OR have no itemname
    	        Make a 'Signed' synthetic name, watching out for initial '*'
    	    ELSE make a synthetic name out of the itemname & classname
    	    Append the name to the linebuf
            IF don't have the name yet, add it to the table
    	    IF haven't a substream, make one
    	    Save globals as locals
    	    Put SIGNED back into token
    	    Call pre_proc
    	    Restore globals from locals
        ELSE IF token is SIZE
    	    Append it to line
    	    Append the parenthetical materil to the line
        ELSE IF token is a universal class
    	    IF it's an INSTANCE OF
    		Get the class
    		IF no substream, make one
    		Write instance material to that
    	    ELSE IF it's sub-defined
    		IF there's no itemname
                    Make synthetic itemname and classname
                    Append the itemname to the line
    		ELSE make a synthetic name from the item & class names
    		Append synthetic classname to the line
    		IF no substream, make one
    		Print the definition there
	ELSE IF token is a class entry, fill that
        ELSE IF token is a known macro, make the substitutions
        ELSE IF no itemname AND token is alpha, copy token to itemname
        IF classname is upper case AND have a token AND it's NOT \n
            Append token to line
    	    IF doing an import of a choice, add name of token to list of
    	        imports, so its definition will be included
        IF state is GLOBAL (reached end of items)
            IF have subfile
                Read it in and out
                Close it
   WHILE state is not GLOBAL AND there's another token
   IF state is not GLOBAL, error
   Return state
**/
FILE *substr = (FILE *)0;
char *b, *c, locclass[128], namebuf[128], subname[128],
    subfilename[20];
int parens, is_of;
long tmp, loctype;
ulong loctag;
struct name_table *ntbp;
struct class_table *ctbp;
struct macro_table *mtbp;
is_of = parens = loctag = 0;
*locclass = *namebuf = *subname = *table = 0;
do
    {
    if (!strcmp(token, encrypted_w)) encr_xform(fd, token);
    else if (*token == ',' || *token == '}')
	{
	if (*classname <= 'Z')
	    *linendpp += append_token(*linendpp, token, elinebuf);
        if (*token == ',' && *peek_token(fd) == '}')
	    {
	    while (**linendpp <= ' ') (*linendpp)--;
            get_known(fd, token, "}");
	    *linendpp += append_token(*linendpp, token, elinebuf);
	    }
	if (*activep) fprintf(str, "    %s\n", linebuf);
	if (*token == '}')
	    {
	    state = GLOBAL;
	    if (*peek_token(fd) == '(')
		{
		get_known(fd, token, "(");
		*linendpp = linebuf;
                test_paren(fd, token, linebuf, linendpp, elinebuf);
		fprintf(str, "%s\n", linebuf);
		}
	    *token = *classname = *(*linendpp = linebuf) = 0;
	    if (in_sub || get_token(fd, token)) fprintf(str, "\n");
	    }
	else *token = 0;
	loctag = 0;
	*(*linendpp = linebuf) = *table = *subclass = *itemname = *namebuf = 0;
	}
    else if (*token == '(' && fd)
	{
	for (parens = 1; parens && get_must(fd, token); )
	    {
	    if (*token == '(') parens++;
	    else if (*token == ')') parens--;
	    }
	if (parens) fatal(20, ")");
	*token = 0;
	}
    else if (*token == '(')
	{
	get_must(fd, &token[2]);
	for (c = &token[2]; *c && *c != '.'; c++);
	if (!(tmp = wdcmp(&token[2], size_w)) || !*c || c[1] != '.')
	    {
            token[1] = ' ';
	    *linendpp += append_token(*linendpp, token, elinebuf);
            if (!tmp)     /* SIZE */
		{
        	get_known(fd, token, "(");
                test_paren(fd, token, linebuf, linendpp, elinebuf);
		}
	    else while (*peek_token(fd) != ')')
		{
		get_must(fd, token);
		*linendpp += append_token(*linendpp, token, elinebuf);
		}
	    }
         else
	    {
//    	      for (*linendpp -= 2; *linendpp > linebuf && **linendpp > ' ';
//                (*linendpp)--);
//    	      if (*linendpp > linebuf) (*linendpp)++;
    	    if (!*itemname)
    	        {
    	        if (loctag <= 0) fatal(20, "item name");
    	        cat(namebuf, *linendpp);
    	        cat(itemname, &find_class(loctag)[3]);
    	        *itemname |= 0x20;
		 *linendpp += append_token(*linendpp, itemname, elinebuf);
//		  cat(*linendpp, namebuf); // temp holding for 5 lines down
    	        }
//    	      mk_in_name(namebuf, itemname, classname);
//    	      *namebuf &= ~(0x20);
//    	      if (!substr) substr = make_substr(subfilename);
//    	      fprintf(substr, range_opener, namebuf, *linendpp, &token[2]);
//	      *linendpp += append_token(*linendpp, namebuf, elinebuf);
	    token[1] = ' ';
	    *linendpp += append_token(*linendpp, token, elinebuf);
	    }
	get_known(fd, token, ")");
	}
    else if (*token == '{' || !strcmp(token, of_w))
	{
        if (loctag != ASN_SEQUENCE && loctag != ASN_SET && loctag != ASN_CHOICE
            && loctag != ASN_INTEGER && loctag != ASN_BITSTRING &&
            loctag != ASN_ENUMERATED) syntax(token);
        if (!substr) substr = make_substr(subfilename);
	state = recurs(fd, substr, namebuf, IN_DEFINITION, 1);
	if (*token == ',' || *token == '}') continue;
	if (!strcmp(token, default_w))
            *linendpp += append_default(fd, *linendpp, elinebuf);
	loctag = 0;
	}
    else if (!strcmp(token, components_w))
	{
	for (b = token; *b; b++);
	*b++ = ' ';
	if (!get_token(fd, b)) fatal(14, linebuf);
	if (strcmp(b, of_w)) syntax(b);
	}
    else if (!strcmp(token, default_w))
        *linendpp += append_default(fd, *linendpp, elinebuf);
    else if (!strcmp(token, end_w)) syntax(token);
    else if (!strcmp(token, function_w))
        {
        for(c = token; *c; c++);
        for (*c++ = ' ', parens = 0; c < &token[ASN_BSIZE] && (parens ||
            (*peek_token(fd) != ',' && *peek_token(fd) != '}')) &&
            get_must(fd, c) ; *c++ = ' ', *c = 0)
    	    {
            if (*c == '(') parens++;
    	    else if (*c == ')' && !(--parens)) break;
    	    while (*c) c++;
     	     }
        }
    else if (!strcmp(token, signed_w))
	{
	get_must(fd, subclass);
	c = namebuf;
	if ((tmp = find_type(subclass)) == ASN_NOTYPE || !*itemname)
	    {
	    if (*subclass != '*') cat(cat(c, "Signed"), subclass);
	    else cat(cat(c++, "*Signed"), &subclass[1]);
	    }
	else mk_in_name(namebuf, itemname, classname);
	*c &= ~0x20;
	*linendpp += append_token(*linendpp, namebuf, elinebuf);
	if ((ntbp = find_name(namebuf)) && ntbp->name)
	    {
	    *token = 0;
            continue; /* had before */
	    }
        add_name(namebuf, -1, 0);
	if (!substr) substr = make_substr(subfilename);
	state = recurs(fd, substr, (*namebuf == '*')? &namebuf[1]: namebuf,
            IN_DEFINITION, 1);
	if (*token == '}' || *token == ',') continue;
	}
    else if (!strcmp(token, size_w))
	{
	*linendpp += append_token(*linendpp, token, elinebuf);
	get_known(fd, token, "(");
        test_paren(fd, token, linebuf, linendpp, elinebuf);
	}
    else if ((tmp = find_type(token)) > 0 && (tmp <
	ASN_APPL_SPEC || tmp == ASN_CHOICE))
	{
	get_expected(fd, (loctag = tmp), token);
        if (loctag == ASN_INSTANCE_OF)
    	    {
    	    get_must(fd, token);
    	    if (!(ctbp = find_class_entry(token))) fatal(30, token);
    	    cat(token, ctbp->name);
    	    for (c = &token[1]; *c; c++)
    	        if (*c >= 'A' && *c <= 'Z') *c |= 0x20;
    	    cat(cat(++c, token), "Table");
    	    if (!substr) substr = make_substr(subfilename);
    	    fprintf(substr, instance_of, token, c);
    	    fill_name(&ctbp->table_out.table_name, c);
    	    }
	else if (loctag == ASN_SET || loctag == ASN_SEQUENCE ||
            loctag == ASN_CHOICE || (*peek_token(fd) == '{' &&
            (loctag == ASN_INTEGER || loctag == ASN_ENUMERATED ||
            loctag == ASN_BITSTRING)))
	    {
	    if (!*itemname)
		{
		mk_in_name(itemname, &find_class(loctag)[3], classname);
		cat(namebuf, itemname);
		*itemname |= 0x20;
		*linendpp += append_token(*linendpp, itemname, elinebuf);
		}
	    else mk_in_name(namebuf, itemname, classname);
	    *namebuf &= ~0x20;
	    *linendpp += append_token(*linendpp, namebuf, elinebuf);
    	    if (!substr) substr = make_substr(subfilename);
	    fprintf(substr, signed_def, namebuf, token,
		(*peek_token(fd) == '{')? " ": "");
            *token = 0;
	    }
	}
    else if ((ctbp = find_class_entry(token))) collect_id_type(fd, ctbp, str);
    else if ((mtbp = find_macro(token)))
	{
	if (!substr) substr = make_substr(subfilename);
	cat(locclass, classname);
	mk_in_name(classname, itemname, locclass);
	*classname &= ~(0x20);
	*linendpp += append_token(*linendpp, classname, elinebuf);
	do_macro(fd, substr, mtbp);
	*token = 0;
	cat(classname, locclass);
	}
    else if (!*itemname && ((*token >= 'a' && *token <= 'z') ||
	(*token >= 'A' && *token <= 'Z')))
	cat(itemname, token);
    if (*classname && *classname <= 'Z' && *token)
	{
	if (*token != '\n')
	    *linendpp += append_token(*linendpp, token, elinebuf);
	*token = 0;
	}
    if (state == GLOBAL)
	{
	if (substr)
	    {
	    if (*linendpp > linebuf) fatal(24, "pre-processor");
	    if (*activep) putout(str, "\n");
	    if (*activep)  empty_substr(str, substr, linebuf,
                (elinebuf - linebuf), subfilename);
	    *linebuf = 0;
	    substr = (FILE *)0;
	    fflush(str);
	    }
	loctype = -1;
	}
    }
while (state != GLOBAL && pre_proc_get_token(fd, str, linebuf));
if (state != GLOBAL) fatal(14, linebuf);
return state;
}

static int append_default(int fd, char *to, char *elinebuf)
{
/**
Function: Translate 'DEFAULT {}' to 'DEFAULT EMPTY'
Procedure:
1. Append 'DEFAULT'
   IF next token is '{'
    	IF next token isn't '}', syntax error
    	Put EMPTY in token
**/
int val;
val = append_token(to, token, elinebuf);
if (!get_token(fd, token)) syntax(classname);
if (*token == '{')
    {
    if (!get_token(fd, token) || *token != '}') syntax(classname);
    cat(token, empty_w);
    }
return val;
}

static int append_token(char *to, char *string, char *elinebuf)
{
char *c;
if (!*string) return 0;
if ((c = cat(cat(to, string), " ")) > elinebuf) fatal(37, string);
return c - to;
}

void empty_substr(FILE *str, FILE *substr, char *buf, int size,
    char *subfilename)
{
fflush(substr);
fseek(substr, 0L, 0);
while (fgets(buf, size, substr)) fputs(buf, str);
fclose(substr);
unlink(subfilename);
}

static void glob_type(int fd, long loctype, int active)
{
struct id_table *cidp;
char *c;
int val;
get_known(fd, token, ":");
get_known(fd, token, ":");
get_known(fd, token, "=");
if (loctype == ASN_OBJ_ID || loctype == ASN_RELATIVE_OID)
    {
    get_known(fd, token, "{");
    get_must(fd, token);
    if (active)
    	{
    	val = (add_id(classname) - (struct id_table *)id_area.area);
		/* get_obj_id may move id_area.area */
    	c = get_obj_id(fd, (*token >= 'A')? token: "", classname);
	cidp = &((struct id_table *)id_area.area)[val];
	cidp->val = c;
    	}
    else skip_to(fd, 1, 0);
    }
else if (loctype == ASN_INTEGER || loctype == ASN_ENUMERATED)
    {
    get_must(fd, token);
    if (*token < '0' || *token > '9') syntax(token);
    for (c = token, val = 0; *c >= '0' && *c <= '9';
        val = (val * 10) + *c++ - '0');
    if (active) add_ub(classname, val, active);
    }
*classname = *token = 0;
}

FILE *make_substr(char *fname)
{
int fd;
FILE *nstr;
strcpy(fname, "asnXXXXXX");
if ((fd = mkstemp(fname)) < 0 ||
    !(nstr = fdopen(fd, "w+"))) fatal(2, fname);
made_change = 1;
return nstr;
}

static void print_signed(FILE *str, char *tname, char *sclass)
{
fprintf(str, sub_opener, tname, sequence_w);
if (type == ASN_NOTYPE) fprintf(str, thatword, sclass);
else fprintf(str, tobesigned, tname);
fprintf(str, algsig, (*table)? tname: "");
if (*table)     fprintf(str, tabledef, tname, table);
strcat(tname, "ToBeSigned");
}

static void putout(FILE* str, char *msg)
{
fputs(msg, str);
if (*msg > ' ') fputs(" ", str);
}

static int recurs(int fd, FILE *str, char *newclass, int newstate, int in_sub)
{
char locclass[128];
int locstate = state;
cat(locclass, classname);
if (in_sub && !*topclass) cat(topclass, classname);
if (newclass) cat(classname, newclass);
state = newstate;
pre_proc(fd, str, in_sub);
fflush(str);
cat(classname, locclass);
if (!strcmp(classname, topclass)) *topclass = 0;
return locstate;
}

static void scan_modules(int fd)
    {
    char *c, locbuf[512];
    int siz;
    struct module_table *modtbp = (struct module_table *)0;
    while ((siz = get_token(fd, locbuf)))
	{
	while(*locbuf <= ' ' && (siz = get_token(fd, locbuf)));
	if (!siz) break;
        modtbp = (struct module_table *)expand_area(&module_area);
        modtbp->fname = (char *)calloc(strlen(curr_file) + 2, 1);
        cat(modtbp->fname, curr_file);
	if (strcmp((c = locbuf), definitions_w))
            get_known(fd, &locbuf[siz + 4], definitions_w);
	else c = "[none]";
	modtbp->mname = (char *)calloc(strlen(c) + 2, 1);
	cat(modtbp->mname, c);
        modtbp->start_pos = tell_pos(streams.str) - strlen(definitions_w);
	while((siz = get_token(fd, locbuf)) && siz < sizeof(locbuf) &&
            strcmp(locbuf, end_w));
	if (siz >= sizeof(locbuf)) fatal(36, locbuf);
	modtbp->end_pos = tell_pos(streams.str);
	if (!siz) break;
	}
    fseek(find_stream(fd), 0L, 0);
    curr_line = curr_pos = 0;
    }




static void skip_to(int fd, int braces, int parens)
{
do
    {
    get_must(fd, token);
    if (*token == '(') parens++;
    else if (*token == ')') parens--;
    else if (*token == '{') braces++;
    else if (*token == '}') braces--;
    }
while (braces || parens);
}

