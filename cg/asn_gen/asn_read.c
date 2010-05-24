/* $Id$ */
/*****************************************************************************
File:     asn_read.c
Contents: Functions to parse ASN.1 as part of the ASN_GEN program.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

 ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 * 
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 1995-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/

const char asn_read_rcsid[]="$Header: /nfs/sub-rosa/u1/IOS_Project/ASN/Dev/rcs/cmd/asn_gen/asn_read.c,v 1.1 1995/01/11 22:43:11 jlowry Exp gardiner $";
char asn_read_id[] = "@(#)asn_read.c 828P";

#include "asn_gen.h"

static void do_components(void(*func)()),
    do_defined(),
    get_min_max(char *, long *, long *, int),
    get_def_paren(char *buf),
    get_paren(char *, long *, long *, int),
    get_size(char *, long *, long *, int);

static struct alt_subclass *append_subclasses(char *);

static long get_tag(char *);

static char *cvt_size(long *, char *, int);

int read_global()
{
/**
Function: Reads file in global state
Inputs: File descriptor
Returns: IF reaches end of file, -1
	 ELSE 0
Procedure:
1. DO
    	IF token is '::='
	    Return IN_DEFINITION  
	ELSE IF token is DEFINITIONS
	    WHILE next token is not '::='
	        IF token is IMPLICIT, clear implicit flag for file
	        ELSE IF token is EXPLICIT, set explicit flag for file
		ELSE IF token is not TAGS, error
	ELSE IF token is EXPORTS OR IMPORTS, throw away everything up to ';'
	ELSE IF haven't a classname, copy token into classname
2. WHILE have another token
   Return -1
**/
do
    {
    if (*token == ':')
        {
	get_known(0, &token[1], colon_ch);
	get_known(0, &token[2], equal_ch);
	token[3] = 0;
        max = min = 0;
        state = IN_DEFINITION;
	return 0;
        }
    else if (!strcmp(token, definitions_w))
        {
        while (get_token(0, token) && *token != ':')
	    {
            if (!strcmp(token, implicit_w)) explicit1 = 0;
    	    else if (!strcmp(token, explicit_w)) explicit1 = 3;
            else if (strcmp(token, tags_w)) syntax(token);
	    }
	get_known(0, &token[1], ":");
	get_known(0, &token[2], "=");
	token[3] = 0;
        }
    else if (!strcmp(token, exports_w) || !strcmp(token, imports_w))
        while(*token != ';') get_must(0, token);
    else if (!*classname && *token >= 'A') strcpy(classname, token);
    }
while (get_token(0, token));
return -1;
}


int read_definition(int parent)
{
/**
Function: General function to read a definition and fill in the appropriate
	    global variables
Inputs: file descriptor for input file
Outputs: Sets flags in option and in flags.
	 Fills in tag, type, min, max, and subclass
	 Sets state as follows:
             IF definition is an upper bound, GLOBAL
             ELSE IF '{' OR '\n' is found, IN_DEFINITION 
Returns: IF end of file is reached, -1
	 ELSE 0
Procedure:
1. DO
	IF token is CHOICE, set type of ASN_CHOICE
	ELSE IF token is DEFINED, do the defined thing to fill in defined_by
	ELSE IF token is EMPTY, do nothing
	ELSE IF token is EXPLICIT, set temporary explicit flag
	ELSE IF token is IMPLICIT, clear temporary explicit flag
	ELSE IF token is OF, set OF bit in options and get the subclass name
	ELSE IF token is SIZE, get sizes
	ELSE IF token is TABLE, set table bit in flags and note file position
	ELSE IF token is '[', get tag
	ELSE IF token is '(', get min-max
	ELSE IF token is ',' AND not at a real definition, reset type
	ELSE IF token is numeric
	    Clear any line end 
            Set state to GLOBAL
	ELSE IF token is a known type name
	    IF type is ENUMERATED, set enumerated flag
	    IF no type so far, use this one
	    ELSE IF OF flag set, set subtype to this type
	    ELSE 'Or' the constructed bit into the present type
	ELSE IF (token begins with a capital letter OR *) AND
            type is not -1, set subclass & options
	IF no next token, return -1
   WHILE state is IN_DEFINITION AND token is not '{' NOR '\n'
   Return 0
**/
long tmp;
do
    {
    if (!strcmp(token, choice_w)) type = ASN_CHOICE;
    else if (!strcmp(token, defined_w))
	{
        do_defined();
	if (type >= ASN_CHOICE) subtype = type;
	else subtype = ASN_CHOICE;
	}
    else if (!strcmp(token, empty_w));
    else if (!strcmp(token, explicit_w)) explicit1 |= 1;
    else if (!strcmp(token, implicit_w)) explicit1 &= ~1;
    else if (!strcmp(token, in_w))
	{
	if (!*definer) syntax(token);
	if (!get_token(0, inclass)) syntax(definer);
	}
    else if (!strcmp(token, of_w)) 
        {
        option |= ASN_OF_FLAG;
        if (!get_token(0, token)) syntax(of_w);
        if ((tmp = find_type(token)) != ASN_NOTYPE)
            get_expected(0, (subtype = (short)tmp), token);
        else if ((*token < 'A' || *token > 'Z') && *token != '*') syntax(token);
	else if (*subclass) syntax(subclass);  /* misspelled SEQ/SET */
        else option |= set_name_option(subclass, token);
        }
    else if (!strcmp(token, size_w)) get_size(token, &min, &max, parent);
    else if (!strcmp(token, table_w)) 
        {
        flags |= ASN_TABLE_FLAG;
        tablepos = tell_pos(streams.str);
	table_start_line = curr_line - 1;  /* adjust for extra \n */
        }
    else if (*token == '[') tag = get_tag(token);
    else if (*token == '(') get_paren(token, &min, &max, parent);
    else if (*token == ',' && (*classname & 0x20)) type = -1;
    else if (*token >= '0' && *token <= '9') 
	{
        while(get_token(0, token) && *token != '\n');
        state = GLOBAL;
	return 0;
	}
    else if ((tmp = find_type(token)) != ASN_NOTYPE)
        {
        get_expected(0, tmp, token);
        if (tmp == ASN_ENUMERATED) flags |= ASN_ENUM_FLAG;
        if (type < 0) type = tmp;
        else if ((option & ASN_OF_FLAG)) subtype = (short)tmp;
        else if (tmp > 0) type |= (tmp & ASN_CONSTRUCTED);
        }
    else if (((*token >= 'A' && *token <= 'Z') || *token == '*') &&
	type == -1) option |= set_name_option(subclass, token);
    if (!get_token(0, token)) return -1;
    }
while (state == IN_DEFINITION && *token != '{' && *token != '\n');
return 0;
}

int read_item(int parent, void(*func)())
{
/**
Function: General function to read an item and fill in appropriate global
variables
Input: File descriptor for input
Outputs: Sets option flags
	 Fills in tag, type, min, max, itemname, subclass, subtype, 
	    defaultname and numstring
Procedure:
1. WHILE token is neither ',' NOR '}'
	IF token is '[', get tag
	ELSE IF token is '('
	    IF enumerated flag set, get material for tag or sub_val
	    ELSE Get min-max
	ELSE IF token is CHOICE, set constructed bit in type
	ELSE IF token is COMPONENTS, do components stuff
        ELSE IF token is DEFAULT, make defaultname and set default flag
	ELSE IF token is DEFINED, do the defined thing to fill in defined_by
	ELSE IF token is EMPTY, do nothing
	ELSE IF token is EXPLICIT, set temporary explicit flag
	ELSE IF token is FUNCTION
	    Set type
            Get all tokens up to comma or right brace
	ELSE IF token is IMPLICIT, clear temporary explicit flag
	ELSE IF token is OF, error
	ELSE IF token is OPTIONAL, set OPTIONAL flag in options
	ELSE IF token is SIZE, get min-max
	ELSE IF token is TABLE
            Get table name to skip it
	    Set table variable
	ELSE IF token is TAGS OR UNIQUE, swallow it
	ELSE IF token is a defined type
	    IF this is a table AND (there's a type OR a subclass already)
		append token to alt_subclasses
	    ELSE IF have a subclass already, syntax error
	    ELSE IF have no type yet, use that
	    ELSE IF explicit tagging, set subtype
	    ELSE
		'Or' the constructed bit into type
        	Get expected sequel to token, if any
	ELSE IF token begins with a number
	    IF TABLE bit is set, convert number 
	    ELSE IF enumerated flag is set
		Put token into itemname prefixed with e
		Set enumerated flag
	ELSE IF in a table AND (token is TRUE OR FALSE)
            Make type boolean
	    Put token in subclass
	ELSE IF name begins with a capital letter
	    IF this is a table item AND (there is already a subclass OR a type)
		Append this to the alt_subclasses
	    ELSE IF there is already a subclass OR a type, syntax error
	    ELSE set the subclass and option from the token
	ELSE IF name begins with a lower-case letter
	    IF this is a table item, increment the array count
            IF no itemname so far, set token in itemname with options
	IF no next token, return -1
2. IF token is '}'
	Peek at the next token
	IF it's '(', set the constrained flag
   Return 0
**/
char *c;
long tmp;
struct name_table *ntbp;
struct id_table *idp = (struct id_table *)0;
int parens;
struct alt_subclass *altscp = (struct alt_subclass *)0;
while (*token != ',' && *token != '}')
    {
    if (*token == '[')
        {
	tmp = get_tag(token);
        if (tag >= 0) tag |= tmp;
        else tag = tmp;
        }
    else if (*token == '(')
        {
        if ((flags & ASN_ENUM_FLAG))
	    {
            if (!get_token(0, token)) syntax(itemname);
	    if (*(c = token) == '_') c++;
	    if (find_name(classname)->type == ASN_OBJ_ID)
		{
		if (*c > '2')
		    {
		    if (!(idp = find_id(c))) syntax(c);
		    strcpy(c, idp->val);
		    idp = (struct id_table *)0;
		    }
		sub_val = (char *)calloc(1, strlen(c) + 1);
		strcpy(sub_val, c);
		}
	    else if (*c >= '0' && *c <= '9')
		{
    	        for (integer_val = 0; *c; integer_val = (integer_val * 10) +
                    *c++ - '0');
		if (*token == '_') integer_val = -integer_val;
		}
	    else
		{
                integer_val = find_ub(token);
		add_child(token, parent, 0, (ulong)-1, 0);
		}
            if (!get_known(0, token, ")")) syntax(itemname);
 	    }
        else get_paren(token, &min, &max, parent);
        }
    else if (!strcmp(token, choice_w))
        {
        if (tag >= 0) tag |= ASN_CONSTRUCTED;
        else if (type >= 0) type |= ASN_CONSTRUCTED;
        else type = ASN_CONSTRUCTED;
        }
    else if (!strcmp(token, components_w)) do_components(func);
    else if (!strcmp(token, default_w))
        {
        option |= (ASN_OPTIONAL_FLAG | ASN_DEFAULT_FLAG);
        get_token(0, token);
        c = defaultname;
        if (*token >= '0' && *token <= '9') *c++ = '0';
        else if (!strcmp(token, empty_w) || !strcmp(token, null_w) ||
            (*token == '"' && token[1] == '"')) cat(token, "{");
        strcpy(c, token);
        }
    else if (!strcmp(token, defined_w))
        {
        do_defined();
        }
    else if (!strcmp(token, empty_w));
    else if (!strcmp(token, explicit_w)) explicit1 |= 1;
    else if (!strcmp(token, function_w))
	{
	type = ASN_FUNCTION;
	for (c = itemname, parens = 0; get_must(0, token) && (parens ||
            (*token != ',' && *token != '}')); )
	    {
	    if (*token == '(') parens++;
	    else if (*token == ')') parens--;
	    c = cat(cat(c, token), " ");
	    }
	break;
	}
    else if (!strcmp(token, implicit_w)) 
        {
        explicit1 &= ~1;
        if (*subclass && tag < ASN_APPL_SPEC && (ntbp = find_name(subclass)) &&
	    ntbp->name) 
	    {
	    if (type < 0) type = ntbp->type;
	    else if (ntbp->type != -1)
                type |= (ntbp->type & ASN_CONSTRUCTED);
	    }
        }
    else if (!strcmp(token, in_w))
	{
	if (!*definer) syntax(token);
	if (!get_token(0, inclass)) syntax(definer);
	}
    else if (!strcmp(token, of_w)) syntax(token);
    else if (!strcmp(token, optional_w))
	{
        option |= ASN_OPTIONAL_FLAG;
	if (altscp)
	    {
            altscp->options = option;
	    option &= ~(ASN_OPTIONAL_FLAG);
	    }
	}
    else if (!strcmp(token, size_w))
	{
        get_size(token, &min, &max, parent);
//        if (type == ASN_UTCTIME || type == ASN_GENTIME) min = max = 0;
	}
    else if (!strcmp(token, table_w)) 
        {
        if (!get_token(0, tablename)) syntax(table_w);
	if (*tablename < 'A' || *tablename > 'Z') syntax(tablename);
        option |= ASN_TABLE_FLAG;
        }
    else if (!strcmp(token, tags_w) || !strcmp(token, unique_w));
    else if ((tmp = (int)find_type(token)) != ASN_NOTYPE)
        {
	if ((flags & ASN_TABLE_FLAG) && (*subclass || type >= 0))
	    altscp = append_subclasses(token);
	else if (*subclass) syntax(token);
        if (type < 0) type = (ulong)tmp;
        else if ((explicit1 & 1)) subtype = (short)tmp;
        else if (tmp > 0) type |= (tmp & ASN_CONSTRUCTED);
        get_expected(0, tmp, token);
        }
    else if ((*token >= '0' && *token <= '9') ||
        (*itemname && (idp = find_id(token))) || is_ub(token))
        {
	if (*token > '9')
	    {
            if (idp) cat(token, idp->val);
	    else
		{
		add_name(token, -1, 0); /* keep it off the 'Defined but not
		                            used' list */
                sprintf(token, "%ld", find_ub(token));
		}
	    }
        if ((flags & ASN_TABLE_FLAG))
	    {
            if (*token >= '0' && *token <= '9') cvt_number(numstring, token);
	    }
        else if ((flags & ASN_ENUM_FLAG))
	    {
            if (!*itemname) cat(cat(itemname, "e"), token);
	    else
		{
		if (*(c = token) == '_') c++;
                for (integer_val = 0; *c; integer_val = (integer_val * 10) +
                    *c++ - '0');
		if (*token == '_') integer_val = -integer_val;
		}
	    }
	idp = (struct id_table *)0;
        }
    else if ((flags & ASN_TABLE_FLAG) && (!strcmp(token, false_w) ||
	!strcmp(token, true_w) || !strcmp(token, either_w)))
	{
        type = ASN_BOOLEAN;
	cat(subclass, token);
	}
    else if ((*token >= 'A' && *token <= 'Z') || *token == '*') 
	{
	if ((flags & ASN_TABLE_FLAG))
	    {
	    if (!strcmp(token, "NONE")) cat(token, "AsnNone");
            if (*subclass || type > 0) altscp = append_subclasses(token);
            else option |= set_name_option(subclass, token);
	    }
	else if ((type > 0 && type < ASN_CHOICE) || *subclass) syntax(token);
        else option |= set_name_option(subclass, token);
	}
    else if (*token >= 'a' && *token <= 'z')
        {
        if ((flags & ASN_TABLE_FLAG)) array++;
        if (*itemname) warn(12, token);
        else cat(itemname, token);
	}
    if (!get_token(0, token)) return -1;
    }
if (*definer && !*inclass) cat(inclass, classname);
if (*token == '}' && *peek_token(0) == '(')
    {
    get_known(0, &token[2], "(");
    get_def_paren(&token[2]);
    }
return 0;
}

static struct alt_subclass *append_subclasses(char *name)
{
struct alt_subclass *altscp;

if (!alt_subclassp)
    {
    if (!(alt_subclassp = altscp =
        (struct alt_subclass *)calloc(sizeof(struct alt_subclass), 1)))
	fatal(7, (char *)0);
    }
else
    {
    for(altscp = alt_subclassp; *(altscp->name) && altscp->next; altscp =
	altscp->next);
    if (*(altscp->name))
	{
        if (!(altscp->next =
            (struct alt_subclass *)calloc(sizeof(struct alt_subclass), 1)))
	    fatal(7, (char *)0);
	altscp = altscp->next;
	}
    }
cat(altscp->name, name);
if (*altscp->name == '*') *altscp->name = '_';
return altscp;
}

static char *cvt_size(long *to, char *from, int parent)
{
char *c, minus, savec;
if (*(c = from) == '_') minus = *c++;
else minus = 0;
if (*c >= '0' && *c <= '9')
    {
    for(*to = 0; *c >= '0' && *c <= '9'; *to = (*to * 10) + *c++ - '0');
    if (minus) *to = -*to;
    }
else
    {
    while (*c > ' ' && *c != '.' && *c != ')') c++;
    savec = *c;
    *c = 0;
    if (!strcmp(from, min_w)) *to = 0x80000001;
    else if (!strcmp(from, max_w)) *to = 0x7FFFFFFF;
    else *to = find_ub(from);
    add_child(from, parent, 0, (ulong)-1, 0);
    *c = savec;
    }
return c;
}

static void do_components(void(*func)())
{
/**
Function: Handles COMPONENTS OF in an item
Procedure:
1. IF no next token OR it's not 'OF' OR no next token OR item is not in table
        OR it's imported, syntax error
   IF no function
	Add token as a child of classname
	Return
   Save current file position
2. Go to where item starts
   Read tokens until '{' is found
3. Call function
   Go back to saved place in file
   Keep reading until ',' or '}'
**/
struct name_table *ntbp;
long pos;
if (tell_pos(streams.str) < real_start) return;
if (!get_token(0, token) ||                /* step 1 */
    strcmp(token, of_w) ||
    !get_token(0, token)) syntax(components_w);
if (!func)
    {
    add_child(token, add_name(classname, (long)0, 0), 0, (long)-1, 0);
    *itemname = 'x';    /* to make the test for no itemname fail */
    return;
    }
if (!(ntbp = find_name(token))->name || !*ntbp->name || ntbp->pos < 0)
    syntax(components_w);
pos = tell_pos(streams.str);
curr_pos = ntbp->pos;
fseek(streams.str, ntbp->pos, 0);                                        /* step 2 */
for (*token = 0; get_token(0, token) && *token != '{'; );
if (*token != '{') syntax(components_w);
state = SUB_ITEM;
if (func) func(0);                                    /* step 3 */
curr_pos = pos;
fseek(streams.str, pos, 0);
state = IN_ITEM;
for (*token = 0; *token != ',' && *token != '}'; get_token(0, token));
end_item();
}

static void do_defined()
{
if (!get_token(0, token) || strcmp(token, by_w) ||
    !get_token(0, definer) || *definer < 'a' || *definer > 'z')
    syntax(defined_w);
mk_in_name(defined_by, (*itemname)? itemname: array_w, classname);
if (type == ASN_ANY || type == ASN_BITSTRING || type == ASN_OCTETSTRING)
    {
    if (tag < 0 && type) tag = type;
    type |= ASN_CHOICE;
    }
else if (type == -1) type = ASN_CHOICE;
// else syntax(defined_w);
*inclass = 0;
}

static void get_def_paren(char *buf)
{
char *b, *c;
int lth, tlth;

get_must(0, buf);
if (def_constraintp) free(def_constraintp);
for (def_constraintp = c = calloc(1, lth = 128); *buf != ')'; get_must(0, buf))
    {
    tlth = strlen(buf) + 1;
    if (&c[tlth] > &def_constraintp[lth])
	{
        b = def_constraintp;
	def_constraintp = realloc(b, lth += 128);
	c = &def_constraintp[(c - b)];
	}
    c = cat(cat(c, buf), " ");
    }
}

static void get_paren(char *buf, long *minp, long *maxp, int parent)
{
char *c;
int lth;

get_must(0, buf);
if (!strcmp(buf, size_w))
    {
    get_size(buf, minp, maxp, parent);
//    if (type == ASN_UTCTIME || type == ASN_GENTIME) *minp = *maxp = 0;
    }
else
    {
    if (find_name(classname)->type != ASN_OBJ_ID &&
        (*buf == '_' || (*buf >= '0' && *buf <= '9') ||
        !strncmp(buf, min_w, 3)))
        {                      /* convert any upper bounds to numbers */
        get_min_max(buf, minp, maxp, parent);
	option |= ASN_RANGE_FLAG;
        }
    else for (c = &constraint_area.area[constraint_area.next]; *buf != ')';
        get_must(0, buf))
	{
	lth = strlen(buf);
	cat(&buf[lth++], " ");
	add_constraint(buf, lth);
	}
    }
}

static void get_size(char *loctoken, long *minp, long *maxp, int parent)
{
/**
Function: Gets min and max size from input
Returns: Min and max.  Also token contains the item from which max was derived
Inputs: token is a buffer
	min and max are self-explanatory
**/
if (!get_token(0, loctoken)) fatal(20, "("); /* gets the opening '(' */
if (!get_token(0, loctoken)) syntax("(");         /* gets the min..max */
get_min_max(loctoken, minp, maxp, parent);
if (!get_token(0, loctoken) ||               /* gets the ')' */
    *loctoken != ')')  fatal(20, ")");
}

static void get_min_max(char *loctoken, long *minp, long *maxp, int parent)
{
char *c;
c = cvt_size(minp, loctoken, parent);
if (*c != '.') *maxp = *minp;
else
    {
    while (*c == '.') c++;
    if (!*c) get_must(0, c);
    c = cvt_size(maxp, c, parent);
    }
}

static long get_tag(char *token)
{
/**
Procedure:
1. IF no next token, exit with fatal message
   IF token is APPLICATION OR PRIVATE OR UNIVERSAL
     	Set tag to application specific
       	IF no next token, exit with fatal message
   ELSE set tag to content specific
   IF token is an upper bound, get its value
   IF token is an ID, translate it
   ELSE
	IF token is an ID, copy that into token
        Get number in token
2. Convert number to true tag
   Return tag
**/
long ttag, tmp;
char *c;
struct id_table *idp;
struct ub_table *ubp;

get_must(0, token);                                         /* step 1 */
if (!strcmp(token, application_w) || !strcmp(token, private_w) ||
    !strcmp(token, universal_w))
    {
    if (*token == 'A') ttag = ASN_APPL_SPEC;
    else if (*token == 'P') ttag = ASN_PRIV_SPEC;
    else ttag = 0;
    get_must(0, token);
    }
else ttag = ASN_CONT_SPEC;
if (token[0] == '0' && (token[1] | 0x20) == 'x')
    {    	     /* special stuff for inexpressible tags */
    for (c = &token[2], tmp = 0; *c >= '0' && *c <= 'f'; c++)
	{
	tmp <<= 4;
	if (*c > 'F') *c -= 0x20;
	if (*c > '9') *c -= 7;
	tmp |= (*c - '0');
	}
    }
else
    {
    if ((ubp = is_ub(token)))
	{
        sprintf(token, "%ld", ubp->val);
	for (c = token; *c >= '0' && *c <= '9'; c++);
	*c = 0;
	}
    else if ((idp = find_id(token))) strcpy(token, idp->val);
    for(c = token, tmp = 0; *c >= '0' && *c <= '9'; tmp = (tmp * 10) + *c++ - '0');
    }
if (*c++) syntax(token);
get_known(0, c, "]");
if (token[1] > '9')
    {         /* more for inexpressible tags */
    ttag |= tmp >> 8;
    ttag |= (tmp & 0xFF) << 8;
    }
else if (tmp < 31) ttag |= tmp;                              /* step 2 */
else
    {
    ttag |= 31;
    if (tmp >= (1 << 14)) ttag |= 0x808000 + (((tmp & 0x7F) << 24) +
        ((tmp & 0x3F80) << 9)
	+ ((tmp & 0x1FC000) >> 6));
    else if (tmp >= (1 << 7)) ttag |= 0x8000 + (((tmp & 0x7F) << 16) +
        ((tmp & 0x3F80) << 1));
    else ttag |= (tmp << 8);
    }
return ttag;
}

