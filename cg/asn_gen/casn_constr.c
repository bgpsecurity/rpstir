/* $Id$ */
/*****************************************************************************
File:     asn_cconstr.c
Contents: Functions to generate .c files as part of ASN_CGEN program.
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
 * Copyright (C) BBN Technologies 2004-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/

char casn_constr_id[] = "@(#)casn_constr.c 828P";

#include "asn_gen.h"

struct tagq
    {
    struct tagq *next;
    long tag;
    };

static void addq(struct tagq **, long, struct name_table *),
    checkq(struct tagq *, long, struct name_table *),
    clear_data_item(FILE *),
    constr_def(int *, long*),
    find_path(char *, char *),
    freeq(struct tagq **),
    print_components(FILE *, char *),
    print_constraint(FILE *),
    print_enums(FILE *, char *),
    print_item(char *, long, int, long, long),
    print_range(FILE *, char *),
    print_primitive(char *name, long loctag),
    set_options(char *, int, char *);

static int numdefiners, numdefineds, thisdefined,
    constr_item(int, long),
    optional_def(); 

static char simple_opener[] =
"void %s(struct %s *mine, ushort level)\n\
    {\n\
    simple_constructor(&mine->%s, level++, %s);\n",

    tagged_opener[] =
"void %s(struct %s *mine, ushort level)\n\
    {\n\
    tagged_constructor(&mine->%s, level++, %s, 0x%X);\n",

    choice_type_add[] = "_type |= %d;\n",

    constructed_item[] = "    %s(&mine->%s, level);\n",

    simple_primitive[] =   "    simple_constructor(&mine->%s, level, %s);\n",

    tagged_primitive[] =
"    tagged_constructor(&mine->%s, level, %s, 0x%X);\n",

    data_init[] =  "%s = 0;\n",
    definer_numeric_entry[] = "    tcasnp++;\n\
    tcasnp->lth = _write_casn_num(tcasnp, %s);\n\
    tcasnp->level = level;\n",

    definer_catchall_entry[] = "    tcasnp++;\n\
    tcasnp->lth = _write_casn(tcasnp, (uchar *)\"\\377\\377\", 2);\n\
    tcasnp->level = level;\n",

    definer_oid_entry[] = "    tcasnp++;\n\
    tcasnp->type = %s;\n\
    tcasnp->lth = _write_objid(tcasnp, \"%s\");\n\
    tcasnp->level = level;\n",

    **definer_ids, // to store object identifiers

    derived_table[] = "void %s(struct casn *mine, ushort level)\n\
    {\n\
    struct casn *tcasnp;\n\
    \n\
    memset(mine, 0, sizeof(struct casn));\n\
    mine->tag = mine->type = %s;\n\
    mine->flags = ASN_TABLE_FLAG;\n\
    mine->level = level;\n\
    mine->ptr = (struct casn *)calloc(%d, sizeof(struct casn));\n\
    tcasnp = mine->ptr;\n\
    tcasnp->startp = (uchar *)\"%s\";\n\
    tcasnp->lth = %d;\n",

    pointer_tag_xw[] = "    mine->self.tag = 0x%X;\n\
    mine->self.type = %s;\n",

    pointer_func[] = "\
    mine->%s.startp = (uchar *)(void (*)(void *, ushort))%s;\n\
    mine->%s.min = sizeof(struct %s);\n",


    defined_flag[] =    "    mine->self.flags |= ASN_DEFINED_FLAG;\n",
    set_bool_def[] =    "    mine->%s.min = %d;\n",
    set_flags[] =       "    mine->%s.flags |= ",
    set_prim_flags[] =  "    mine->flags |= ",
    set_flags_self[] =  "    mine->%s.self.flags |= ",
    set_int_def[] =     "    mine->%s.ptr = (struct casn *)((long)%s);\n",

    set_sub_default[] = "    mine->%s.%s.flags |= ASN_DEFAULT_FLAG;\n",

    set_sub_val[] =     "    _write_objid(&mine->%s, \"%s\");\n",
    set_sub_min[] =     "    mine->%s.min = %d;\n",
    set_tag[] =         "    mine->%s.self.tag = %s;\n",
    set_tag_xw[] =      "    mine->%s.self.tag = 0x%X;\n",
    set_type_xw[] =     "    mine->%s.self.type = 0x%X;\n",
    sub_tag_type[] =    "    mine->%s.tag = mine->%s.type = %s;\n",

    sub_enum_fill[] =   "    _write_casn_num(&mine->%s, (ulong)%ld);\n",

#ifdef CONSTRAINTS
    name_constrainer[] =
"    mine->self.ptr = (struct casn *)(int (*)(struct casn *))%sConstraint;\n",
#endif

    constraint_opener[] = "int %sConstraint(struct %s *casnp)\n    {\n",
    start_objid_constraint[] =  "    if (vsize_objid(&casnp->self) > 0 &&\n\
        (",
    end_objid_constraint[] = ")) return 1;\n\
    return 0;\n\
    }\n\n",

    int_constraint[] = "!diff_casn(&casnp->self, &casnp->%s)",
    objid_constraint[] = "!diff_objid(&casnp->self, \"%s\")",
    start_int_constraint[] = "    long val;\n\
    if (read_casn_num((struct casn *)casnp, &val) < 0) return 0;\n\
    if (",
    end_int_constraint[] = ") return 1;\n\
    return 0;\n\
    }\n\n",

    range_set[] =  "\
    int ansr;\n\
    struct casn lo, hi;\n\
    memset(&lo, 0, sizeof(struct casn));\n\
    memset(&lo, 0, sizeof(struct casn));\n\
    lo.type = hi.type = ASN_INTEGER;\n\
    write(&lo, %s, %d);\n\
    write(&hi, %s, %d);\n\
    if (diff_casn(casnp, &lo) >= 0 && diff_casn(casnp, &hi) <= 0) ansr = 1;\n\
    else ansr = 0;\n\
    delete_casn(&lo);\n\
    delete_casn(&hi);\n\
    return ansr;\n\
    }\n\n",

    constr_boundset[] = "    mine->%s.self.min = %ld;\n\
    mine->%s.self.max = %ld;\n",
    sub_boundset[] = "    mine->%s.min = %ld;\n\
    mine->%s.max = %ld;\n",

    finale[] = "    mine->%s%s.flags |= ASN_LAST_FLAG;\n\
    }\n\n",

    short_finale[] = "    }\n\n",
    *dec_to_bin(uchar *, char *);

struct tagq *lasttagqp = (struct tagq *)0;

void cconstruct()
{
/*
Function: Creates constructors for the things defined an ASN.1 file.
Outputs: C code written to 'outstr'
Procedure:
1. WHILE have a next token
       Switch on state
2. Case GLOBAL 
	IF reading global returns GLOBAL, return
   Case IN_DEFINITION
	IF token is not '{' (rerun of table) AND reading definition returns
	    less than 0, return
	IF STATE is not GLOBAL, construct definition
3. Case IN_ITEM
   Case SUB_ITEM
	Read the item
	IF token is '}' OR ',' (indicating the end of an item)
	    Construct the item
   Default: Exit with fatal message
4. Search name table for pointer items (starting with '_') that have no
	parent that's a passthrough, i.e. no definition
	Make a definition for any found
*/ 
char *c;
int /* did, */ classgeneration;
struct name_table *ntbp, *ptbp;
long parenttype = -1;
if (state != SUB_ITEM) end_definition();
else end_item();
for (lasttagqp = (struct tagq *)0, classgeneration = numdefineds = 0; 
    get_token(0, token); )
    {
    switch (state)
    	{
    case GLOBAL:			 
	if (read_global() < 0) break;
	break;

    case IN_DEFINITION:                                     /* got ::= */
	numdefiners = 0;
	if (*token != '{' && read_definition(-1) < 0) return;
	if (state != GLOBAL) constr_def(&classgeneration, &parenttype);
    	break;
							    /* step 3 */
    case IN_ITEM:                                     /* got '{' */
    case SUB_ITEM:            
	if (read_item(-1, cconstruct) < 0) return;
	if ((*token == ',' || *token == '}') &&        /* end of item */
	    !constr_item(classgeneration, parenttype))
	    return;
	break;

    default:
	fatal(4, (char *)state);
	}
    }
for (ntbp = (struct name_table *)name_area.area; ntbp && ntbp->name; ntbp++)
    {
    if (*(c = ntbp->name) != '_') continue;
    cat(classname, c);
    for (ptbp = (struct name_table *)name_area.area; ptbp->name &&
	strcmp(ptbp->name, &c[1]); ptbp++);
    fprintf(outstr, simple_opener, c, c, self_w, find_define(ptbp->type));
    if (ntbp->type > ASN_CHOICE) fprintf(outstr, choice_type_add, ntbp->type);
    fprintf(outstr, pointer_func, self_w, &c[1], self_w, &c[1]);
    set_options(set_flags, ASN_POINTER_FLAG, self_w);
    fprintf(outstr, "    }\n");
    }
}

static void constr_def(int *classgenerationp, long *parenttypep)
{
/**
1. IF no tag, use type as tag
   ELSE IF have a type, transfer the constructed bit to the tag
   IF token is { AND (type is BIT STRING OR INTEGER OR ENUMERATED)
        Set enumerated flag
   IF this is a DEFINED BY in a table, find what it's called in the
	generation table
   See if it needs dup stuff
   IF it's a primitive AND no enumerated flag, clear duped flag
   IF it needs dup for other than 'OF' AND it's not imported
    	Print the OF stuff
   IF it's not imported AND (there's a '{' OR it's an OF OR it's a pointer)
        IF it's a pointer, print pointer opener
        IF it's not a table, print opener C text and stuff for definition
2. IF token is {
    Set parenttype to type
    IF it's not imported
        IF it's a defined item, print flag setting message
        Clear that flag
        IF it's a table
            Print table opener
            Get the path from the definer to the defined
        ELSE
            IF it needed a dup function, print dup stuff
            IF not universal tag, print tag msg
	    IF not derived from its type, print _type message
    Go to IN_ITEM state OR SUB_ITEM, depending on current state
3. ELSE  (line end) have to print sub-stuff
    IF it's not a passthrough
        Make itemname out of subclass, unless the replacement name's type
	    is primitive AND this is not an OF
        IF this is a pointer, print point, tag & type messages
        ELSE
            IF there's a subtype, use "array" as the itemname
	    IF there's max, print min/max and clear max
	    IF there's a subclass AND its type is primitive
                Use that as the subtype
            Print item with flags, except for OF flag, using as tag
		Either (IF there's a subtype AND (no subclass OR subitem is
                    separately defined)) the subtype
		Or none
	    IF there's (now) a subtype AND subclass AND this item has a max
                Set its bounds
        Print finale
4.      IF it has constraint, print the constraint
    Clear classname
    Go to GLOBAL state
**/
char *c;
int did;
long tmp;
struct name_table *ntbp;
struct parent *parentp;
if (curr_pos <= real_start) curr_pos = tell_pos(streams.str);
if (tag < 0) tag = type;
else if (type > 0 && !*defined_by) tag |= (type & ASN_CONSTRUCTED);
if (*token == '{' &&
    (type == ASN_BITSTRING || type == ASN_INTEGER ||
    type == ASN_ENUMERATED || type == ASN_OBJ_ID) && !(option & ASN_OF_FLAG))
    flags |= ASN_ENUM_FLAG;
if ((flags & ASN_TABLE_FLAG) && thisdefined > 0)
    c = find_defined_class(thisdefined);
else c = classname;
did = test_dup(c, &tmp);
if (type >= 0 && type < ASN_CONSTRUCTED && !(flags & ASN_ENUM_FLAG))
    did &= ~(ASN_DUPED_FLAG);
if (curr_pos > real_start &&
    (*token == '{' || (option & (ASN_OF_FLAG | ASN_POINTER_FLAG)) || max ||
    *lo_end || constraint_area.next || type >= ASN_CHOICE))
    {
    if (option == ASN_POINTER_FLAG)
	{
        c = replace_name(classname)->name;
	end_definition();
	return;
	}
    else c = classname;
    if ((flags & ASN_DEFINED_FLAG)) type = tag = ASN_CHOICE;
    if (tag > 0)
	{
	if (*subclass) ntbp = find_name(subclass);
	else ntbp = (struct name_table *)0;
	if (type < 0 && ntbp) type = ntbp->type;
        if (type == tag) fprintf(outstr, simple_opener, c, c, self_w,
            find_define(type));
        else fprintf(outstr, tagged_opener, c, c, self_w, find_define(type),
            tag);
	option &= ~(ASN_POINTER_FLAG);
	if ((option & ASN_OF_FLAG)) set_options(set_flags, option, self_w);
        else if ((option & ASN_RANGE_FLAG)) set_options(set_flags, option, self_w);
	if ((flags & ASN_ENUM_FLAG)) set_options(set_flags, flags, self_w);
        if (max)
	    fprintf(outstr, sub_boundset, self_w,
                (min > -0x8000)? min: -0x8000, self_w, max);
	if (subtype >= ASN_CHOICE && *defined_by)
	    {
            mk_subclass(defined_by);
	    tag = -1;
	    }
        if (type > ASN_CHOICE)
    	    {
            fprintf(outstr, choice_type_add, type);
    	    fprintf(outstr, finale, itemname, ".self");
    	    }
        }
    }
							    /* step 2 */
if (*token == '{')
    {
    state = IN_ITEM;
    if ((type == ASN_BITSTRING || type == ASN_INTEGER ||
        type == ASN_ENUMERATED) && !(option & ASN_OF_FLAG))
        flags |= ASN_ENUM_FLAG;
    *parenttypep = type;
    if (curr_pos > real_start)
    	{
    	if ((flags & ASN_DEFINED_FLAG)) fprintf(outstr, defined_flag);
    	else if ((flags & ASN_TABLE_FLAG))
            {
            ntbp = find_name(classname);
	    if (ntbp->type < 0) warn(34, ntbp->name);
	    ntbp = &((struct name_table *)name_area.area)[ntbp->parent.index];
	    for (parentp = &ntbp->parent, numdefineds = 0; parentp->next;
                numdefineds++, parentp = parentp->next);
            }
        }
    if (type >= 0 && type < ASN_CONSTRUCTED && subtype < 0)
        subtype = (short)type;
    if (!thisdefined) c = classname;
    else c = find_defined_class(thisdefined);
    *classgenerationp = find_name(c)->generation;
    end_item();
    did = 0;
    }
					        /* step 3 */
else                /* no further definition */
    {
    if (curr_pos > real_start && (max || constraint_area.next ||
        (option & (ASN_OF_FLAG | ASN_POINTER_FLAG))))
        {
	max = 0;
#ifdef CONSTRAINTS
	if (constraint_area.next)
            fprintf(outstr, name_constrainer, classname);
#endif
	if (*subclass)
	    {
            cat(itemname, subclass);
            if (*itemname != '_') *itemname |= 0x20;
            else itemname[1] |= 0x20;
            if ((ntbp = replace_name(subclass)))
		{
    	        if (!(option & ASN_OF_FLAG) && ntbp->type > 0 && ntbp->type <
    		    ASN_CONSTRUCTED) *itemname = 0;
    	        if (ntbp->type >= 0 && !(ntbp->type & ASN_CONSTRUCTED))
    		    {
                    if (!(ntbp->flags & ASN_ENUM_FLAG))
        	        *subclass = 0;      // makes it primitive in print_item
                    min = ntbp->min;
                    max = ntbp->max;
    		    }
    	        }
	    }
        else ntbp = 0;
        if (option== ASN_POINTER_FLAG)  // ptr but not OF ptrs
	    {
	    ntbp = replace_name(&subclass[1]);
	    fprintf(outstr, pointer_func, self_w, &subclass[1], self_w,
                &subclass[1]);
	    if (ntbp->type == ntbp->tag || ntbp->tag == 0xFFFFFFFF)
                fprintf(outstr, sub_tag_type, self_w, self_w,
                    find_define(ntbp->type));
	    else fprintf(outstr, pointer_tag_xw, ntbp->tag,
                find_define(ntbp->type));
            set_options(set_flags, ASN_POINTER_FLAG, self_w);
	    }
        else
            {
            if (subtype >= 0)
		{
                cat(itemname, array_w);
		type = subtype;
		}
	    if (ntbp && *ntbp->name != '_')
		{
                type = ntbp->type;
		tag = -1;   // to prevent printing tag in item
		}
            if (*itemname) print_item((*itemname == '_')? &itemname[1]:
                itemname, 
                (subtype > 0 && (!*subclass || (ntbp &&
                !(ntbp->flags & ASN_ENUM_FLAG))))?
                subtype: -1, option, max, min);
            if (subtype >= 0 && *subclass && ntbp && ntbp->max)
                fprintf(outstr, sub_boundset, itemname,
                (ntbp->min > -0x8000)? ntbp->min: -0x8000, itemname,
                ntbp->max);
	    }
	if (!*itemname) fprintf(outstr, short_finale);
	else if (*subclass == '_') fprintf(outstr, finale, self_w, "");
        else
	    {
	    if ((ntbp && ((ntbp->type > 0 && (ntbp->type & ASN_CONSTRUCTED)) ||
		(ntbp->flags & ASN_ENUM_FLAG))) || *subclass) c = ".self";
	    else c = "";
            fprintf(outstr, finale, itemname, c);
	    }
							    /* step 4 */
        }
    if (constraint_area.next) print_constraint(outstr);
    end_definition();
    }
}

static int constr_item(int classgeneration, long parenttype)
{
/**
1. IF the object is an item in a TABLE AND lack either a numeric string
	OR an itemname, fatal error
   IF it's a DEFINED BY AND (the definer has no child OR has no grandchild)
        Syntax error
   IF doing defineds beyond the first in a table, make the subclass name
   IF (explicit OR CHOICE OR ANY) AND have a tag bigger than universal AND
        not ENUM
 	Set explicit option
   IF no tag so far AND type is a universal primitive, use type as tag
   ELSE IF this is a DEFINED BY AND it's not an ANY, do nothing
   ELSE IF this item is explicitly tagged AND it's not a subdefined
 	primitive, set the constructed bit in the tag
   ELSE IF have a type, then 'Or' the constructed bit of the type into the tag
   IF ENUM is set in flags, set it in option
2. IF it's an imported item, do nothing
   ELSE IF it's a table item
 	IF no type, use itemname
 	ELSE use class name
 	Print the table line
 	IF have a name, print line to create sub-item
 	IF it's not the last item, print about next item
   ELSE IF it's not a FUNCTION
 	IF there's no itemname, make one from type or subclass
	IF in definee but no type or subclass, table error
        IF class is enumerated
            Print line to set tag
            Clear tag and type
3.      IF there's a subclass that's not a primitive
            IF it's a boolean definition, set the type to BOOLEAN with
                no name table entry
	    ELSE
		IF the subclass isn't in the table, error
                IF there's a type in the table
                  'Or' that object's constructed bit into the tag
		ELSE if the subclass isn't a pointer, warn of undefined variable
     	        IF table has a tag
                    IF item has an explicit tag, warn
     		    ELSE IF no tag so far
     		        Set the expected tag (for checking the last tag list)
     		        IF table tag is primitive AND item is explicit
                            Use that as tag (any constructed or implicit
                               item will set its own tag)
		IF the item's generation is less than th ecurrent one
		    Add the subclass as a child of this class
		    Test for looping
 	    IF there's no type, use type from table
 	    ELSE IF there's no subtype, use the subtype from the table
 	    IF explicit, 'Or' constructed into the tag
        IF the expected tag matches anything in the last_tag list
            Print warning
 	IF no expected tag so far, use the tag, or, if no tag so far
 	    Use the type as the expected tag
        IF this item is optional OR (parenttype is CHOICE AND there's no
            defined_by) OR parenttype is SET
            Add the expected tag to last_tag list
        ELSE clear last_tag list
	IF beyond the first defined column in a table, get the options
	    for it
        Print the item with all options, including tag if no defined_by left
 	IF there's a default, print that stuff
4. IF token does not indicate the last item, finish the item
   ELSE IF not in COMPONENTS OF
        IF it's not imported, print the finale
        IF table flag is set
    	    Set state to INDEFINITION
    	    IF doing defineds
		IF at the last one, setstate to GLOBAL
		ELSE bump up the name
	    ELSE (just did basic table) FOR each parent of basic table
		Find the path from definer to definee
		Print the whole constructor
		Set up to do first defined item
	    Go back to start of table
	ELSE IF there are constraints, print them
	Clear previous name
	Free the list of last tags
        IF not in state IN_DEFINITION, finish the definition
	ELSE finish item
   ELSE return 0
   Return 1
**/
struct name_table *ntbp = (struct name_table *)0, *ctbp, *ptbp;
struct parent *parentp;
struct alt_subclass *altscp;
long tag_tb, tmp;
char *c;
static struct name_table *ntablep;
static int bool_val;
							/* step 1 */
if ((flags & (ASN_TABLE_FLAG | ASN_DEFINED_FLAG)) == ASN_TABLE_FLAG)
    {
    c = 0;
    if (!*numstring) c = "numeric field";
    else if (!*itemname) c = "item name";
    if (c) fatal(20, c);
    }
if (*defined_by && (!(c = find_child(defined_by)) || !find_child(c)))
    fatal(19, defined_by);
if (thisdefined > 1) set_alt_subtype(ntablep, thisdefined);
if (((explicit1 & 1) || type == ASN_ANY) &&
    tag >= ASN_APPL_SPEC && !(flags & ASN_ENUM_FLAG))
    option |= ASN_EXPLICIT_FLAG;
if (tag < 0 && type < ASN_CONSTRUCTED) tag = type;
else if (*defined_by && tag > 0 && tag < ASN_CONSTRUCTED);
else if ((explicit1 & 1) && !(flags & ASN_ENUM_FLAG)) tag |= ASN_CONSTRUCTED;
else if (type >= 0 && type < ASN_CHOICE) tag |= (type & ASN_CONSTRUCTED);
if ((flags & ASN_ENUM_FLAG)) option |= ASN_ENUM_FLAG;
					                    /* step 2 */
if (curr_pos <= real_start);
else if ((flags & (ASN_TABLE_FLAG | ASN_DEFINED_FLAG)) == ASN_TABLE_FLAG)
    {
    if (type < 0 && !*subclass && !optional_def()) syntax(itemname);
    if (type < 0) c = itemname;
    else c = find_class(type);
    if (!numdefiners++)
	definer_ids = (char **)calloc(1, sizeof(char *));
    else definer_ids = (char **)realloc((char *)definer_ids, numdefiners * sizeof(uchar *));
    definer_ids[numdefiners - 1] = calloc(1, strlen(numstring) + 1);
    strcpy(definer_ids[numdefiners - 1], numstring);
				           /* chars are in form '\123' */
    }
else if (type != ASN_FUNCTION)
    {
    if (!*itemname)
        {
        if (type >= 0) c = &find_class(type)[3];
        else if (!*subclass) c = "no_item";
        else c = subclass;
        cat(itemname, c);
        }
    *itemname |= 0x20;
//     if (thisdefined > 0 && type < 0 && !*subclass) fatal(40, itemname);
    if ((option & ASN_ENUM_FLAG) && !sub_val) tag = type = -1;
					                    /* step 3 */
    tag_tb = -1;
    if (*subclass && find_type(subclass) == ASN_NOTYPE)
        {
	if (!strcmp(subclass, true_w) || !strcmp(subclass, false_w) ||
            !strcmp(subclass, either_w)) type = ASN_BOOLEAN;
        else
	    {
	    while (1)
		{
                if (!(ntbp = replace_name((*subclass != '_')? subclass:
                    &subclass[1]))) syntax(subclass);
		if (*ntbp->name != '_') break;
		}
            if (ntbp->type != -1)
                tag |= (ntbp->type & ASN_CONSTRUCTED);
	    else if (*subclass != '_') warn(34, ntbp->name);
            if (ntbp->tag != -1)
	        {
                if (tag >= ASN_APPL_SPEC && (explicit1 & 1) &&
                    ntbp->type < ASN_CHOICE) warn(15, (char *)tag);
                else if (tag < 0)
    	            {
    	            tag_tb = ntbp->tag;
		    if (ntbp->type >= ASN_CHOICE) tag_tb |= ASN_CONSTRUCTED;
                    if (!(ntbp->tag & ASN_CONSTRUCTED) && (explicit1 & 1))
                        tag = ntbp->tag;
    	            }
	        }
            if (!thisdefined && ntbp->generation < classgeneration)
    	        {
    	        add_child(subclass, (find_name(classname) -
                    (struct name_table *)name_area.area), 0, (long)-1, 0);
    	        loop_test((struct name_table *)name_area.area, ntbp, 0);
    	        }
            if (type < 0) type = ntbp->type;
            else if (subtype < 0) subtype = (short)ntbp->type;
            if ((explicit1 & 1))
		{
                tag |= ASN_CONSTRUCTED;
		if (tag_tb != -1) tag_tb |= ASN_CONSTRUCTED;
		if (tag >= ASN_APPL_SPEC) option |= ASN_EXPLICIT_FLAG;
		}
            if (!max && ntbp->type != -1 && ntbp->type < ASN_CONSTRUCTED &&
                (max = ntbp->max)) min = ntbp->min;
            }
        }
    if (*defined_by)  // constructed definee needs subclass
	{
        mk_subclass(defined_by);
	}               // definer needs subclass
    else if (*tablename && !(flags & ASN_DEFINED_FLAG)) 
	{                                            // not a definee
        mk_in_name(subclass, itemname, classname);   // is it a definer?
	if (!find_name(subclass)) *subclass = 0;     // no
        else mk_in_name(subclass, tablename, classname); // yes
	}
    else if (!(type & ASN_CONSTRUCTED))
	{   // primitives
	if (!ntbp || (!(ntbp->flags & ASN_ENUM_FLAG) && !ntbp->max))
	    {  // not enumerated ones and not ones with limits
	    if (type != ASN_BOOLEAN || thisdefined <= 0) // except booleans
                *subclass = 0;
	    }
	}
    if (tag_tb == -1)
        {
        if (tag != -1) tag_tb = tag;
        else if (type != ASN_CHOICE) tag_tb = type;
        }
    if (!(flags & ASN_ENUM_FLAG)) checkq(lasttagqp, tag_tb, ntbp);
    if (!(flags & (ASN_DEFINED_FLAG | ASN_ENUM_FLAG)) && type < ASN_CHOICE &&
        ((option & ASN_OPTIONAL_FLAG) || parenttype == ASN_SET ||
        parenttype == ASN_CHOICE))
        addq(&lasttagqp, tag_tb, ntbp);
    else if (lasttagqp) freeq(&lasttagqp);
    if (thisdefined > 1)
	{
	for (altscp = alt_subclassp, tmp = thisdefined - 2; tmp-- &&
	    altscp; altscp = altscp->next);
	option = altscp->options;
	}
    if (!*subclass && tag_tb < 0 && !(flags & ASN_ENUM_FLAG))
        type = tag_tb = ASN_NONE;
    print_item(itemname, tag_tb,
        (option & ~(ASN_TABLE_FLAG | ASN_ENUM_FLAG)), max, min);
    if ((option & ASN_ENUM_FLAG))
	    {
            tmp = find_name(classname)->type;
            fprintf(outstr, tagged_primitive, itemname, find_define(tmp),
                ASN_NOTYPE);
	    if (tmp == ASN_OBJ_ID)
		{
		fprintf(outstr, set_sub_val, itemname, sub_val);
		free(sub_val);
                sub_val = (char *)0;
		}
	    else if (tmp != ASN_BITSTRING)
                fprintf(outstr, sub_enum_fill, itemname, integer_val);
	    else fprintf(outstr, set_sub_min, itemname, integer_val);
	    }
    if (tag == ASN_BOOLEAN && *subclass && strcmp(subclass, either_w) &&
        (flags & (ASN_DEFINED_FLAG | ASN_TABLE_FLAG)) ==
        (ASN_DEFINED_FLAG | ASN_TABLE_FLAG))
        {
        bool_val = BOOL_DEFINED;
        if (!strcmp(subclass, true_w)) bool_val |= BOOL_DEFINED_VAL;
	if ((*defaultname && !strcmp(defaultname, true_w)))
            bool_val |= BOOL_DEFAULT;
        if (bool_val) fprintf(outstr, set_bool_def, itemname, bool_val);
	}
    else if (*defaultname && *defaultname != '{')
        {
        if (type == ASN_BOOLEAN || tag == ASN_BOOLEAN)
	    {
	    if (!strcmp(defaultname, true_w))
                fprintf(outstr, set_bool_def, itemname, BOOL_DEFAULT);
	    }
	else if (type == ASN_INTEGER && *defaultname == '0' &&
            !(ntbp && (ntbp->flags & ASN_ENUM_FLAG)))
	    fprintf(outstr, set_int_def, itemname, &defaultname[1]);
	else
	    {
	    if (*defaultname == '0') *defaultname = 'e';
            fprintf(outstr, set_sub_default, itemname, defaultname);
	    }
        }
    }
else clear_data_item(outstr);
					                    /* step 4 */
if (*token != '}') end_item();  /* not last */
else if (state != SUB_ITEM) /* last, but not in components */
    {
    if (curr_pos > real_start && 
        (flags & (ASN_DEFINED_FLAG | ASN_TABLE_FLAG)) != ASN_TABLE_FLAG) 
	{
#ifdef CONSTRAINTS
	if (def_constraintp)
            fprintf(outstr, name_constrainer, classname);
#endif
        fprintf(outstr, finale, itemname, 
            ((ntbp && ((ntbp->flags & ASN_ENUM_FLAG) || ntbp->max)) ||
            (type > 0 && (type & ASN_CONSTRUCTED)))? ".self": "");
	}
    if ((flags & ASN_TABLE_FLAG))
        {
        state = IN_DEFINITION;
        if (flags & ASN_DEFINED_FLAG)
            {
            if (thisdefined++ >= numdefineds)
		{
		thisdefined = 0;
		*tablename = 0;
                state = GLOBAL;
		}
            else (classname[strlen(classname) - 1])++;
            }
        else
	    {
	    for (ctbp = find_name(classname), parentp = &ctbp->parent;
		parentp; parentp = parentp->next)
		{
		if (parentp->index < 0) continue;
		ptbp = &((struct name_table *)name_area.area)[parentp->index];
	        find_path(path, ptbp->name);
	        fprintf(outstr, derived_table, ptbp->name,
                    find_define(ptbp->type), numdefiners + 1, path,
		    numdefiners);
		}
	    for (tmp = 0; tmp < numdefiners; tmp++)
		{
                if (definer_ids[tmp][1] == '.')
                    fprintf(outstr, definer_oid_entry, find_define(ASN_OBJ_ID),
                       definer_ids[tmp]);
		else if (strcmp(definer_ids[tmp], "0xFFFF"))
                    fprintf(outstr, definer_numeric_entry, definer_ids[tmp]);
		else fprintf(outstr, definer_catchall_entry);
		free(definer_ids[tmp]);
		}
	    free((char *)definer_ids);
	    definer_ids = (char **)0;
	    fprintf(outstr, "    }\n\n");
            flags |= ASN_DEFINED_FLAG;
            thisdefined = 1;
            ntablep = find_name(classname);
            strcat(classname, "Defined");
            }
        if (state != GLOBAL)
	    {
            fseek(streams.str, tablepos, 0);
	    curr_line = table_start_line;
	    }
        }
    else if (constraint_area.next)
	{
	if ((tmp = find_name(classname)->type) == ASN_INTEGER ||
            tmp == ASN_ENUMERATED || tmp == ASN_BITSTRING ||
            tmp == ASN_OBJ_ID)
            print_constraint(outstr);
	}
    if (lasttagqp) freeq(&lasttagqp);
    parenttype = -1;
    if (def_constraintp)
        {
        add_constraint(def_constraintp, strlen(def_constraintp));
        free(def_constraintp);
        def_constraintp = (char *)0;
        print_constraint(outstr);
        }
    if (state != IN_DEFINITION) end_definition();
    else end_item();
    }
else return 0;            /* last of components */
return 1;
}

static void addq(struct tagq **tagqp, long tmp, struct name_table *ptbp)
{
struct tagq *tqp;
struct name_table *ctbp;
struct parent *childp;
if (ptbp && *ptbp->name && ptbp->tag == -1 && tmp == -1 &&
    ptbp->type == ASN_CHOICE && !(ptbp->flags & ASN_DEFINED_FLAG))
    {
    for (childp = &ptbp->child; childp && childp->index > -1; childp =
        childp->next)
	{
	ctbp = &((struct name_table *)name_area.area)[childp->index];
	addq(tagqp, ctbp->tag, ctbp);
	}
    return;
    }
if (!*tagqp) *tagqp = tqp = (struct tagq *)calloc(1, sizeof(struct tagq));
else
    {
    for (tqp = *tagqp ; tqp->next; tqp = tqp->next);
    tqp->next = (struct tagq *)calloc(1, sizeof(struct tagq));
    tqp = tqp->next;
    }
tqp->tag = tmp;
}

static void checkq(struct tagq *tagqp, long tmp, struct name_table *ptbp)
{
struct name_table *ctbp;
struct parent *childp;
if (ptbp && *ptbp->name && ptbp->tag == -1 && tmp == -1 &&
    ptbp->type == ASN_CHOICE && !(ptbp->flags & ASN_DEFINED_FLAG))
    {
    for (childp = &ptbp->child; childp && childp->index > -1; childp =
        childp->next)
	{
	ctbp = &((struct name_table *)name_area.area)[childp->index];
	checkq(tagqp, ctbp->tag, ctbp);
	}
    return;
    }
for ( ; tagqp ; tagqp = tagqp->next)
    {
    if (tagqp->tag == tmp) break;
    if (tagqp->tag >= ASN_APPL_SPEC || tmp > ASN_APPL_SPEC) continue;
    if (tagqp->tag == ASN_ANY || tmp == ASN_ANY ||
	tagqp->tag == ASN_CHOICE || tmp == ASN_CHOICE) break;
    }
if (tagqp) warn(23, itemname);
}

static void clear_data_item(FILE *outstr)
{
char *c;
for (c = itemname; *c && *c != '('; c++);
if (!*c)
    {
    if (c[-1] <= ' ') *(--c) = 0;
    while (--c >= itemname && *c > ' ' && *c != '*');
    fprintf(outstr, data_init, &c[1]);
    }
}

static char *dec_to_bin(uchar *to, char *from)
{
uchar *b, carryc, minus, *ebuf;
long prod;
if ((minus = *from) == '_') from++;
else minus = 0;
memset(to, 0, ASN_BSIZE);
for (*(ebuf = &to[ASN_BSIZE - 1]) = *from++ - '0';
    *from >= '0' && *from <= '9'; from++)
    {
    for (carryc = *from - '0', b = ebuf; b >= to; b--)
	{
	prod = (*b * 10) + carryc;
	*b = (prod & 0xFF);
    	carryc = (uchar)(prod >> 8);
	}
    }
if (minus)
    {
    for (b = to; b <= ebuf; *b = ~*b, b++);
    for (b = ebuf, (*b)++; !*b && b > to; b--, (*b)++);
    }
for (b = to; *b == *to && b < ebuf; b++);
while (b <= ebuf) to += putoct((char *)to, (long)*b++);
*to = 0;
return from;
}

static void find_path(char *path, char *tablenamep)
{
struct name_table *ntbp, *ptbp;
struct parent *parentp, *definerp, *definedp;
char *a, *b, *c;
int upcount;
definerp = definedp = (struct parent *)0;
ntbp = find_name(tablenamep);
for (parentp = &ntbp->parent; parentp && !definerp; parentp = parentp->next)
    {
    ptbp = (struct name_table *)&name_area.area[parentp->index *
	sizeof(*ptbp)];
    if ((ptbp->flags & ASN_DEFINER_FLAG)) definerp = &ptbp->parent;
    }
if (!definerp) fatal(11, tablenamep);
for (parentp = &ntbp->parent, a = path; parentp; parentp = parentp->next)
    {
    ptbp = (struct name_table *)&name_area.area[parentp->index *
	sizeof(*ptbp)];
    if ((ptbp->flags & ASN_DEFINED_FLAG))
	{
	definedp = &ptbp->parent;
	if (a > path) *a++ = ' ';
        for (b = definerp->mymap, c = definedp->mymap; *b == *c; b++, c++);
	for (upcount = &definerp->mymap[definerp->map_lth - 1] - b;
	    upcount--; *a++ = '-');
        for(*a++ = *c++ - *b++ + '0'; *c; *a++ = *c++);
        *a = 0;
	}
    }
}

static void freeq(struct tagq **tagqpp)
{
struct tagq *tqp, *ntqp;
for (tqp = *tagqpp; tqp; tqp = ntqp)
    {
    ntqp = tqp->next;
    free((char *)tqp);
    }
*tagqpp = (struct tagq *)0;
}

static int optional_def()
{
/**
Function: Determines if the defined item in a table can be absent
Inputs: Classname
Outputs:
    0 if may not be absent
    1 if may be
Procedure:
1. Find the name table entry for the table
   Search each of its parents
	IF the defined object is not OPTIONAL, return 0
   Return 1
**/
struct name_table *ptbp, *ttbp = find_name(classname);
struct parent *parentp;
for (parentp = &ttbp->parent; parentp; parentp = parentp->next)
    {
    ptbp = &((struct name_table *)name_area.area)[parentp->index];
    if ((ptbp->flags & ASN_DEFINED_FLAG) && !(ptbp->flags & ASN_OPTIONAL_FLAG))
        return 0;
    }
return 1;
}

static char *next_word(char *c)
{
for (c++; (*c >= '0' && *c <= '9') || (*c >= 'A' && *c <= 'Z') || (*c >= 'a' &&
    *c <= 'z'); c++);
while (*c && *c <= ' ') c++;
return c;
}

static void print_components(FILE *outstr, char *c)
    {
    char *b;

    if (!*(c = next_word((b = c)))) syntax(b);
    if (wdcmp(c, component_w) && wdcmp(c, components_w)) syntax(c);
    b = &c[9];
    if (!*(c = next_word(c))) syntax(b);
    if (*b > ' ')   /* multiple components */
	{
	if (*c != '{') syntax(c);
	fprintf(outstr, "if (");
	do
	    {
	    while (*c && (*c < 'a' || *c > 'z')) c = next_word(c);
	    for (b = c; *c > ' '; c++);
	    if (!*c) syntax(b);
	    *c++ = 0;
	    while (*c == ' ') c++;
	    if (!*c || (wdcmp(c, absent_w) && wdcmp(c, present_w)))
                syntax(b);
	    fprintf(outstr, "%s.vsize() %s 0", b,
                (*c == 'A')? "<=": ">");
	    if (!*(c = next_word((b = c))) || (*c != ',' && *c != '}'))
                syntax(b);
	    if (*c == ',') fprintf(outstr, " && ");
	    }
	while (*c != '}');
	fprintf(outstr, ") return 1;\n");
	if (*(c = next_word(b = c)) && *c != '|') syntax(c);
	if (*c) c = next_word(c);
	}
    else fatal(31, "simple constraint");       /* simple constraint */
    }

static void print_constraint(FILE *outstr)
{
char *b, *c = constraint_area.area;

if (constraint_area.next)
    {
    if (!wdcmp(c, constrained_w))
	{
	if (wdcmp(next_word(c), by_w)) syntax(c);
	return;
	}
    fprintf(outstr, constraint_opener, classname, classname);
    c = constraint_area.area;
    if (!wdcmp(c, constrained_w))
	{
	if (wdcmp(next_word(c), by_w)) syntax(c);
	}
    else
	{
	b = c;
	if (*c == '_' || (*c >= '0' && *c <= '9') ||
            (!strncmp(c, min_w, 3) && (c[3] <= ' ' || c[3] == '.')))
	    {
    	    if (*b == 'M') b += 3;
	    else while(*b == '_' || (*b >= '0' && *b <= '9')) b++;
	    while (*b == ' ') b++;
	    }
	if (b > c && (!*b || *b == '.'))
	    {
            print_range(outstr, c);
	    return;
	    }
        else if (!wdcmp(c, with_w)) print_components(outstr, c);
	else if ((flags & ASN_ENUM_FLAG))
	    {
            print_enums(outstr, c);
	    return;
	    }
	else
	    {
	    warn(33, constraint_area.area);
	    c = &constraint_area.area[constraint_area.next];
	    }
	}
    fprintf(outstr, "return 0;\n}\n\n");
    }
}

static void print_enums(FILE *outstr, char *c)
    {
    struct id_table *idp;
    int classtype;
    char *b;

    classtype = find_name(classname)->type;
    if (classtype != ASN_OBJ_ID)
        fprintf(outstr, start_int_constraint);
    else fprintf(outstr, start_objid_constraint);
    while (*c)
	{
	for (b = c; *b > ' '; b++);
	if (*b) *b++ = 0;
	if (classtype == ASN_OBJ_ID)
	    {   //
	    if (*c > '2' && (idp = find_id(c))) c = idp->val;
	    if (*c >= '0' && *c < '3')
	         fprintf(outstr, objid_constraint, c);
	    else fprintf(outstr, "!diff_casn(&casnp->self, &casnp->%s)", c);
	    }
	else
	    {
	    if (*c == '_') *c = '-';
	    if ((*c < '0' || *c > '9') && *c != '-')
                fprintf(outstr, int_constraint, c);
            else fprintf(outstr, "val == %s", c);
	    }
	for (c = b; *c && *c <= ' '; c++);
	if (*c == '|' || !wdcmp(c, union_w))
	    {
            fprintf(outstr, " ||\n        ");
	    c = next_word(c);
	    }
	}
    if (classtype == ASN_OBJ_ID) fprintf(outstr, end_objid_constraint);
    else fprintf(outstr, end_int_constraint);
    }

static int print_flag(int option, char *string, int val)
{
fprintf(outstr, string);
if ((option &= ~val)) fprintf(outstr, " | ");
return option;
}

static void print_item(char *name, long loctag, int locoption,
    long locmax, long locmin)
{
/**
Procedure:
**/
char *c;

locoption &= ~(ASN_POINTER_FLAG);
locoption &= ~(ASN_OF_FLAG);
if (type >= 0 && ((type & ASN_CONSTRUCTED) ||
	// subclass makes it constructed unless defined boolean
    (*subclass && !(thisdefined && type == ASN_BOOLEAN)) ||
    (subtype > 0 && type < ASN_CONSTRUCTED && *tablename && 
    !(flags & ASN_DEFINED_FLAG))))  
    {
    if (*subclass || ((type & ASN_CONSTRUCTED) && type < ASN_CHOICE &&
        *itemname))
	{
	if (!*subclass) c = itemname;
	else c = subclass;
        fprintf(outstr, constructed_item, c, name);
	if (tag > 0)
	    {       // for wrapped definee
            if (tag < ASN_CONSTRUCTED && (type & ASN_CONSTRUCTED))
                fprintf(outstr, set_tag, name, find_define(tag));
		    // for explictly tagged enum
            else if (type > 0 && type != tag)
                fprintf(outstr, set_tag_xw, name, tag);
	    if (type > ASN_CHOICE) fprintf(outstr, set_type_xw, name, type);
	    }
        if (max)
	    fprintf(outstr, (*tablename)? sub_boundset: constr_boundset, name,
                (locmin > -0x8000)? locmin: -0x8000, name, locmax);

	}
    else if (type >= ASN_CHOICE)
        fprintf(outstr, constructed_item, find_class(type), name);
    else print_primitive(name, loctag);
    if (locoption) set_options(set_flags_self, locoption, name); 
    }
else 
    {
    print_primitive(name, loctag);
    if (locoption) set_options(set_flags, locoption, name);
    if (locmax) fprintf(outstr, sub_boundset, name, (locmin > -0x8000)? locmin:
        -0x8000, name, locmax);
    }
}

static void print_primitive(char *name, long loctag)
    {
    if (loctag < 0 && type >= 0 && type < ASN_APPL_SPEC) loctag = type;
    if (loctag >= 0 && (loctag < ASN_APPL_SPEC || loctag >= ASN_NONE) &&
        loctag == type)
        fprintf(outstr, simple_primitive, name, find_define(loctag));
    else if (loctag >= 0 && type >= 0)
        fprintf(outstr, tagged_primitive, name, find_define(type), loctag);
    }

static void print_range(FILE *outstr, char *c)
    {
    char *a, *b, savec, locbuf[20];

    if (*c == 'M')
        {
        strcpy(lo_end, "\\200\\000\\000\\000");
        c += 3;
        }
    else c = dec_to_bin((uchar *)lo_end, c);
    if (*c != '.') cat(hi_end, lo_end);
    else
        {
        while (*c == '.') c++;
        if (*c)
	    {
            if (!wdcmp(c, max_w))
	        {
	        strcpy(hi_end, "\\177\\377\\377\\376");
	        c += 3;
	        }
            else
	        {
	        if (*c > '9')
		    {
                    for (a = c; *a > ' '; a++);
		    savec = *a;
		    *a = 0;
                    sprintf(locbuf, "%ld", find_ub(c));
		    *a = savec;
		    b = locbuf;
		    }
	        else b = c;
	        a = dec_to_bin((uchar *)hi_end, b);
	        if (b != c) c = next_word(c);
	        else c = a;
	        }
	    }
        }
    fprintf(outstr, range_set, lo_end, strlen(lo_end) / 4, hi_end,
        strlen(hi_end) / 4);
    }

static void set_options(char *format, int option, char *name)
    {
    fprintf(outstr, format, name);
    if ((option & ASN_OPTIONAL_FLAG)) option = print_flag(option,
	"ASN_OPTIONAL_FLAG", ASN_OPTIONAL_FLAG);
    if ((option & ASN_OF_FLAG))  option = print_flag(option,
	"ASN_OF_FLAG", ASN_OF_FLAG);
    if ((option & ASN_RANGE_FLAG))  option = print_flag(option,
	"ASN_RANGE_FLAG", ASN_RANGE_FLAG);
    if ((option & ASN_DEFAULT_FLAG)) option = print_flag(option,
	"ASN_DEFAULT_FLAG", ASN_DEFAULT_FLAG);
    if ((option & ASN_EXPLICIT_FLAG)) option = print_flag(option,
	"ASN_EXPLICIT_FLAG", ASN_EXPLICIT_FLAG);
    if ((option & ASN_ENUM_FLAG)) option = print_flag(option,
	"ASN_ENUM_FLAG", ASN_ENUM_FLAG);
    if ((option & ASN_POINTER_FLAG)) option =  print_flag(option,
	"ASN_POINTER_FLAG", ASN_POINTER_FLAG);
    fprintf(outstr, ";\n");
    }
