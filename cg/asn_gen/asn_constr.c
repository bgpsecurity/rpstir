/* $Id$ */

/*****************************************************************************
File:     asn_constr.c
Contents: Functions to generate .c files as part of ASN_GEN program.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

char asn_constr_id[] = "@(#)asn_constr.c 860P";

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
    print_item(char *, char *, long, int, long, long),
    print_of(int, long),
    print_range(FILE *, char *),
    set_dup(char *classname, long tag);

static int numdefineds, thisdefined,
    constr_item(int, long),
    dot_to_oct_objid(char **, char *),
    obj_id(uchar *, char *),
    optional_def(), set_options(int, char *);

static char opener[] =
"%s::%s()\n\
{\n",
    choice_type_add[] = "_type |= %d;\n",

    ptr_opener[] = "\
%s *%s::operator->()\n\
    {\n\
    if (!_ptr) _point();\n\
    return (%s *)_ptr;\n\
    }\n\n\
%s *%s::point() { return (%s *)_ptr; }\n\n\
void %s::operator=(%s *objp)\n\
    {\n\
    _ptr = objp;\n\
    _set_supra(objp);\n\
    }\n\n\
void %s::_point()\n\
    {\n\
    if (_ptr) clear();\n\
    _ptr = (AsnObj *)new %s;\n\
    _set_ptr();\n\
    }\n\n",

    pointer_tag_xw[] = "_tag = 0x%X;\n\
_type = %s;\n\
ptr = 0;\n\
_flags |= ASN_POINTER_FLAG;\n",
    first_item[] = "_setup((AsnObj *)0, &%s,",
    later_item[] = "_setup(&%s, &%s,",
    data_init[] =  "%s = 0;\n",
    table_opener[] =
"AsnObj *objp = objid;\n\
_tag = _type = %s;\n\
_flags |= ASN_TABLE_FLAG;\n\
_sub = objp;\n",
    table_write[] = "objp = _setup_table(objp, \"%s\", %d, %d);\n",
    derived_table[] = "%s::%s()\n{\n\
wherep = new UcharArray((uchar *)\"%s\", %d);\n}\n\n",

    member_func[] = "%s *%s::member(long index)\n\
    {\n\
    AsnOf *ofp = (AsnOf *)this;\n\
    return (%s *)ofp->member(index);\n\
    }\n\n",

    objid_dots[] = "/* %s */\n",

    pointer_type_tag_w[] = "_tag = _type = %s;\n\
_ptr = 0;\n\
_flags |= ASN_POINTER_FLAG;\n",
    set_bool_def[] = "%s._set_def((long)%d);\n",
    set_int_def[] = "%s._set_def((long)%s);\n",
    set_sub_default[] =
"_set_sub_flag(&%s.%s, (ushort)(ASN_DEFAULT_FLAG));\n",
    set_sub_val[] = "_set_sub_val(&%s, (const uchar *)\"%s\", (long)%d); ",
    type_set[] = "_set_type(&%s, (ulong)0x%lX);\n",
    type_tag_w[] = "%s%s_tag = %s%s_type = %s;\n",
    type_xw[] = "_type = 0x%X;\n",
    tag_xw[] = "%s%s_tag = 0x%X;\n",
    sub_tag_xw[] = " (ulong)0x%X);\n",
    sub_class_w[] = " (ulong)%s);\n",
    sub_enum_tag_xw[] = "_set_tag(&%s, (ulong)%ld);\n",
    dup_func[] =
"AsnObj *%s::_dup()\n\
{\n\
%s *objp = new %s;\n\
_set_pointers(objp);\n\
return objp;\n\
}\n\n",
    index_op[] =
"%s& %s::operator[](int index) const\n\
{\n\
return *(%s *)_index_op(index);\n\
}\n\n",
    constraint_opener[] = "int %s::constraint() const\n{\n",
    start_objid_constraint[] = "int ansr = vsize();\n\
uchar *c;\n\
if (ansr <= 0) return 0;\n\
c = (uchar *)calloc(1, ansr);\n\
(AsnObjectIdentifier *)this->read(c);\n\
if (",

    end_objid_constraint[] = ") ansr = 1;\n\
else ansr = 0;\n\
free(c);\n\
return ansr;\n\
}\n\n",

    start_int_constraint[] = "long val = (long)*this;\nif (",
    end_int_constraint[] = ") return 1;\nreturn 0;\n}\n\n",
    range_set[] =
"uchar *lo = (uchar *)\"%s\",\n\
    *hi = (uchar *)\"%s\";\n\
int lo_lth = %d, hi_lth = %d;\n\
if (_num_diff(lo, lo_lth) >= 0 && _num_diff(hi, hi_lth) <= 0) return 1;\n",
    sub_boundset[] = "_boundset(&%s, %ld, %ld);\n",
    array_boundset[] = "_min = %ld;\n_max = %ld;\n",
    finale[] = "}\n\n",
    *dec_to_bin(uchar *, char *);

static struct tagq *lasttagqp = (struct tagq *)0;

void construct()
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
int did, classgeneration;
long tmp;
struct name_table *ntbp, *ptbp;
struct parent *parentp;
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
	if (*token != '{' && read_definition(-1) < 0) return;
	if (state != GLOBAL) constr_def(&classgeneration, &parenttype);
    	break;
							    /* step 3 */
    case IN_ITEM:                                     /* got '{' */
    case SUB_ITEM:            
	if (read_item(-1, construct) < 0) return;
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
    for (parentp = &ntbp->parent; parentp; parentp = parentp->next)
	{
	ptbp = &((struct name_table *)name_area.area)[parentp->index];
	if ((ptbp->flags & ASN_FALSE_FLAG)) break;
	}
    if (parentp) continue;
    if (strlen(c) >= ASN_BSIZE) fatal(10, c);
    strcpy(classname, c);
    if ((did = (test_dup(classname, &tmp) & ~ASN_OF_FLAG)))
        print_of(did, tmp);
    for (ptbp = (struct name_table *)name_area.area; ptbp->name &&
	strcmp(ptbp->name, &c[1]); ptbp++);
    fprintf(outstr, ptr_opener, &c[1], c, &c[1], &c[1], c, &c[1], c, &c[1],
        c, &c[1]);
    fprintf(outstr, opener, c, c);
    if (ntbp->type > ASN_CHOICE) fprintf(outstr, choice_type_add, ntbp->type);
    fprintf(outstr, pointer_type_tag_w, find_define(ptbp->type));
    fprintf(outstr, finale);
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
        IF it's an OF AND has defined member, print the member method
        Print opener C text and optional choice supplement
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
3. ELSE  (line end)
    IF it's not a passthrough
        IF it needed a dup function, print dup stuff
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
    {
    c = find_defined_class(thisdefined);
    ntbp = find_parent(c);
    if ((ntbp->flags & ASN_OF_FLAG)) fprintf(outstr, member_func, classname,
        ntbp->name, classname);
    }
else c = classname;
did = test_dup(c, &tmp);
if (type >= 0 && type < ASN_CONSTRUCTED && !(flags & ASN_ENUM_FLAG))
    did &= ~(ASN_DUPED_FLAG);
if ((did & ~(ASN_OF_FLAG)) &&
    curr_pos > real_start) print_of(did, tmp);
if (curr_pos > real_start &&
    (*token == '{' || (option & (ASN_OF_FLAG | ASN_POINTER_FLAG)) || max ||
    *lo_end || constraint_area.next || type >= ASN_CHOICE))
    {
    if (option == ASN_POINTER_FLAG)
	{
        c = replace_name(classname)->name;
	fprintf(outstr, ptr_opener, &c[1], c, &c[1], &c[1], c, &c[1], c,
            &c[1], c, &c[1]);
	}
    else c = classname;
    if ((option & ASN_OF_FLAG) && *subclass)
        {
	if (subtype < 0)
	    {
            get_subtype();
            if (subtype < 0)
                fprintf(outstr, member_func, subclass, classname, subclass);
	    subtype = -1;
	    }
	}
    fprintf(outstr, opener, c, c);
    if (type > ASN_CHOICE)
	{
        fprintf(outstr, choice_type_add, type);
	fprintf(outstr, finale);
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
    	if ((flags & ASN_DEFINED_FLAG))
            fprintf(outstr, "_flags |= ASN_DEFINED_FLAG;\n");
    	else if ((flags & ASN_TABLE_FLAG))
            {
            ntbp = find_name(classname);
	    if (ntbp->type < 0) warn(34, ntbp->name);
            else fprintf(outstr, table_opener, find_define(ntbp->type));
	    ntbp = &((struct name_table *)name_area.area)[ntbp->parent.index];
	    for (parentp = &ntbp->parent, numdefineds = 0; parentp->next;
                numdefineds++, parentp = parentp->next);
            }
        else
            {
            if ((did & ASN_DUPED_FLAG)) set_dup(classname, tag);
            if (!did && tag >= ASN_APPL_SPEC && tag != ASN_CHOICE)
                fprintf(outstr, tag_xw, "", "", tag);
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
        if ((did & ASN_DUPED_FLAG)) set_dup(classname, tag);
	if (*subclass)
	    {
            strcpy(itemname, subclass); // both are ASN_BSIZE
            if (*itemname != '_') *itemname |= 0x20;
            else itemname[1] |= 0x20;
            ntbp = replace_name(subclass);
	    if (!(option & ASN_OF_FLAG) && ntbp->type > 0 && ntbp->type <
		ASN_CONSTRUCTED) *itemname = 0;
	    }
        else ntbp = 0;
        if (option == ASN_POINTER_FLAG)
	    {
	    ntbp = replace_name(&subclass[1]);
	    if (ntbp->type == ntbp->tag || ntbp->tag == 0xFFFFFFFF)
                fprintf(outstr, pointer_type_tag_w,
                    find_define(ntbp->type));
	    else fprintf(outstr, pointer_tag_xw, ntbp->tag,
                find_define(ntbp->type));
	    }
        else
            {
            if (subtype >= 0) strcpy(itemname, array_w); // array_w is "array"
	    if (max)
		{
		fprintf(outstr, array_boundset, min, max);
		max = 0;
		}
            if (ntbp && ntbp->type < ASN_CONSTRUCTED)
                subtype = (short)ntbp->type;
            if (*itemname) print_item((*itemname == '_')? &itemname[1]:
                itemname, prevname,
                (subtype > 0 && (!*subclass || (ntbp &&
                !(ntbp->flags & ASN_ENUM_FLAG))))?
                subtype: 0, (option & ~(ASN_OF_FLAG)), max, min);
            if (subtype >= 0 && *subclass && ntbp->max)
                fprintf(outstr, sub_boundset, itemname, ntbp->min, ntbp->max);
	    }
        fprintf(outstr, finale);
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
        IF class is enumerated
            Print line to set tag
            Clear tag and type
	IF there's some sub_val
	    IF it's an OBJECT IDENTIFIER, convert it to printable octal
	    Print the sub_val
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
        Copy name to prevname
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
struct name_table *ntbp, *ctbp, *ptbp;
struct parent *parentp;
struct alt_subclass *altscp;
long tag_tb, tmp;
char *c;
static struct name_table *ntablep;
static int bool_val, size;
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
    fprintf(outstr, table_write, numstring, strlen(numstring) / 4,
        (*token == ',')? 1: 0);
				           /* chars are in form '\123' */
    }
else if (type != ASN_FUNCTION)
    {
    if (!*itemname)
        {
        if (type >= 0) c = &find_class(type)[3];
        else if (!*subclass) c = "no_item";
        else c = subclass;
        strcpy(itemname, c); // strlen(c) must be < ASN_BSIZE
        }
    *itemname |= 0x20;
    if ((option & ASN_ENUM_FLAG))
        {
        if (!sub_val)
	    {
            fprintf(outstr, sub_enum_tag_xw, itemname, integer_val);
            tag = type = -1;
	    }
	else
	    {
            if (find_name(classname)->type == ASN_OBJ_ID)
    	        {
                if ((size = dot_to_oct_objid(&c, sub_val)) < 0) syntax(token);
    	        }
    	    else size = strlen((c = sub_val));
    	    fprintf(outstr, set_sub_val, itemname, c, size);
    	    if (c != sub_val)
    	        {
    	        fprintf(outstr, objid_dots, sub_val);
    	        free(c);
    	        }
    	    else fprintf(outstr, "\n");
    	    tag = type = -1;
	    }
	}
					                    /* step 3 */
    tag_tb = -1;
    if (*subclass && find_type(subclass) == ASN_NOTYPE)
        {
	if (!strcmp(subclass, true_w) || !strcmp(subclass, false_w) ||
            !strcmp(subclass, either_w))
	    {
            type = ASN_BOOLEAN;
	    ntbp = 0;
	    }
        else
            {
            if (!(ntbp = replace_name((*subclass != '_')? subclass:
                &subclass[1]))) syntax(subclass);
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
	    if ((ntbp->flags & ASN_RANGE_FLAG)) option |= ASN_RANGE_FLAG;
            }
        }
    else ntbp = 0;
    if (tag_tb == -1)
        {
        if (tag != -1) tag_tb = tag;
        else if (type != ASN_CHOICE) tag_tb = type;
        }
    if (!(flags & ASN_ENUM_FLAG)) checkq(lasttagqp, tag_tb, ntbp);
    if (!(flags & (ASN_DEFINED_FLAG | ASN_ENUM_FLAG)) && !*defined_by &&
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
    print_item(itemname, prevname, (tag_tb < ASN_APPL_SPEC && !*defined_by)?0:
        tag_tb, (option & ~ASN_TABLE_FLAG), max, min);
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
    strncpy(prevname, itemname, strlen(itemname));
    }
else clear_data_item(outstr);
					                    /* step 4 */
if (*token != '}') end_item();  /* not last */
else if (state != SUB_ITEM) /* last, but not in components */
    {
    if (curr_pos > real_start) fprintf(outstr, finale);
    if ((flags & ASN_TABLE_FLAG))
        {
        state = IN_DEFINITION;
        if (flags & ASN_DEFINED_FLAG)
            {
            if (thisdefined++ >= numdefineds)
		{
		thisdefined = 0;
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
		fprintf(outstr, derived_table, ptbp->name, ptbp->name, path,
                    strlen(path) + 1);
		}
            flags |= ASN_DEFINED_FLAG;
            thisdefined = 1;
            ntablep = find_name(classname);
            if (strlen(classname) > ASN_BSIZE - 8) fatal(10, classname);
            strncat(classname, "Defined", 8);
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
    *prevname = 0;
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
if (!*tagqp) *tagqp = tqp = (struct tagq *)calloc(sizeof(struct tagq), 1);
else
    {
    for (tqp = *tagqp ; tqp->next; tqp = tqp->next);
    tqp->next = (struct tagq *)calloc(sizeof(struct tagq), 1);
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

static int dot_to_oct_objid(char **cpp, char *fromp)
    {
    uchar *a, *d;
    char *b;
    int size, tmp;

    a = (uchar *)calloc(1,strlen(fromp));
    if ((size = obj_id(a, fromp)) < 0)
	{
	free(a);
	return -1;
	}
    b = *cpp = (char *)calloc(4, size + 1);
    for (d = a, tmp = size; tmp--; sprintf(b, "\\%03o", *d++), b += 4);
    free(a);
    *b = 0;
    return size;
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

static int obj_id(uchar *top, char *fromp)
    {
    int i, val, siz, tmp;
    char *c = fromp;
    uchar *a, *b;

    if (*c < '0' || *c > '2' || c[1] != '.') return -1;
    for (val = 0; *c && *c != '.'; val = (val * 10) + *c++ - '0');
    val *= 40;
    for (c++, tmp = 0; *c && *c != '.'; tmp = (tmp * 10) + *c++ - '0');
    val += tmp;
    for (tmp = val, siz = 0; tmp; siz++) tmp >>= 7; /* size of first field */
					    /* put it into top */
    for (i = siz, tmp = val, b = &top[siz]; siz--; val >>= 7)
        *(--b) = (unsigned char)(val & 0x7F) | ((tmp != val)? 0x80: 0);
    if (*c) for (c++; *c; c++)                       /* now do next fields */
        {
        for (val = 0; *c >= '0' && *c <= '9'; val = (val * 10) + *c++ - '0');
        if (!val) siz = 1;
        else for (tmp = val, siz = 0; tmp; siz++) tmp >>= 7;
        for(a = &top[i], i += siz, tmp = val, b = &a[siz]; siz--; val >>= 7)
    	    *(--b) = (unsigned char)(val & 0x7F) | ((tmp != val)? 0x80: 0);
        if (!*c) break;
        }
    return i;
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
    fprintf(outstr, constraint_opener, classname);
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
	if (b > c && (!*b || *b == '.')) print_range(outstr, c);
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
	         fprintf(outstr, "!memcmp(c, \"%s\", %d)", c, strlen(c));
	    else fprintf(outstr, "!(AsnObj *)this->diff((AsnObj *)&%s)", c);
	    }
	else
	    {
	    if (*c == '_') *c = '-';
            fprintf(outstr, "val == %s", c);
	    if ((*c < '0' || *c > '9') && *c != '-')
                fprintf(outstr, "._get_sub_tag()");
	    }
	for (c = b; *c && *c <= ' '; c++);
	if (*c == '|' || !wdcmp(c, union_w))
	    {
            fprintf(outstr, " ||\n    ");
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

static void print_item(char *name, char *prevname, long loctag, int option,
    long max, long min)
{
/**
Procedure:
**/
if (!prevname || !*prevname) fprintf(outstr, first_item, name);
else fprintf(outstr, later_item, prevname, name);
option = set_options(option, name);
if (loctag < 0 || (loctag >= ASN_NONE && loctag < ASN_NOTYPE)) loctag = 0;
if (loctag > 0 && loctag < ASN_APPL_SPEC) fprintf(outstr, sub_class_w,
    find_define(loctag));
else fprintf(outstr, sub_tag_xw, loctag);
if (type > ASN_CHOICE) fprintf(outstr, type_set, name, type);
if (max) fprintf(outstr, sub_boundset, name, min, max);
}

static void print_of(int dup, long type)
{
char *c;
if (type > 0 && type < ASN_CONSTRUCTED && !(flags & ASN_ENUM_FLAG))
    c = find_class(type);
else c = classname;
if ((dup & ASN_DUPED_FLAG)) fprintf(outstr, dup_func, classname, c, c);
if ((dup & ASN_DUPED_FLAG) && (type <= 0 || type >= ASN_CONSTRUCTED ||
    (flags & ASN_ENUM_FLAG)))
    fprintf(outstr, index_op, classname, classname, classname);
}

static void print_range(FILE *outstr, char *c)
    {
    char *a, *b, savec, locbuf[20];

    if (*c == 'M')
        {
        strncpy(lo_end, "\\200\\000\\000\\000", 17);
        c += 3;
        }
    else c = dec_to_bin((uchar *)lo_end, c);
    if (*c != '.') strcpy(hi_end, lo_end);  // they are same size
    else
        {
        while (*c == '.') c++;
        if (*c)
	    {
            if (!wdcmp(c, max_w))
	        {
	        strncpy(hi_end, "\\177\\377\\377\\376", 17);
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
    fprintf(outstr, range_set, lo_end, hi_end, strlen(lo_end) / 4,
        strlen(hi_end) / 4);
    }

static int set_options(int option, char *name)
{
fprintf(outstr, " (ushort)");
if (option)
    {
    fprintf(outstr, "(");
    if ((option & ASN_OPTIONAL_FLAG)) option = print_flag(option,
	"ASN_OPTIONAL_FLAG", ASN_OPTIONAL_FLAG);
    if ((option & ASN_OF_FLAG)) option = print_flag(option,
	"ASN_OF_FLAG", ASN_OF_FLAG);
    if ((option & ASN_RANGE_FLAG)) option = print_flag(option,
	"ASN_RANGE_FLAG", ASN_RANGE_FLAG);
    if ((option & ASN_DEFAULT_FLAG)) option = print_flag(option,
	"ASN_DEFAULT_FLAG", ASN_DEFAULT_FLAG);
    if ((option & ASN_EXPLICIT_FLAG)) option = print_flag(option,
	"ASN_EXPLICIT_FLAG", ASN_EXPLICIT_FLAG);
    if ((option & ASN_ENUM_FLAG)) option = print_flag(option,
	"ASN_ENUM_FLAG", ASN_ENUM_FLAG);
    if ((option & ASN_POINTER_FLAG)) option = print_flag(option,
	"ASN_POINTER_FLAG", ASN_POINTER_FLAG);
    fprintf(outstr, "),");
    }
else fprintf(outstr, "0,");
return 0;
}

static void set_dup(char *classname, long loctag)
{
if (loctag == type)
    {
    if (type != ASN_SET)
        fprintf(outstr, type_tag_w, "", "", "", "", find_define(loctag));
    }
else
    {
    if (loctag > 0) fprintf(outstr, tag_xw, "", "", loctag);
    fprintf(outstr, type_xw, type);
    }
}

