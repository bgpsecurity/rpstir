/* Apr 25 2005 828U  */
/* Apr 25 2005 GARDINER unified asn_gen for C++, C and Java */
/* Aug  9 2004 799U  */
/* Aug  9 2004 GARDINER changed printing of typedef to #define */
/* Jul  8 2004 777U  */
/* Jul  8 2004 GARDINER lots of changes, cleared out commented junk */
/* Apr 15 2004 758U  */
/* Apr 15 2004 GARDINER removed get_derivation */
/* Apr 15 2004 757U  */
/* Apr 15 2004 GARDINER minor fixes for casn_tests */
/* Apr  7 2004 756U  */
/* Apr  7 2004 GARDINER changed 'this' to 'mine' */
/* Apr  7 2004 755U  */
/* Apr  7 2004 GARDINER added use of casn_w instead of AsnXXXX */
/* Mar 24 2004 742U  */
/* Mar 24 2004 GARDINER removed unused variable */
/* Mar 24 2004 741U  */
/* Mar 24 2004 GARDINER started */
/*****************************************************************************
File:     asn_chdr.c
Contents: Functions to generate .h files as part of the ASN_CGEN program.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Technologies, LLC
10 Moulton St.
Cambridge, Ma. 02140
617-873-3000
*****************************************************************************/

char casn_hdr_id[] = "@(#)casn_hdr.c 828P";

#include "asn_gen.h"

static void print_end(int, int),
    print_hdr(),
    print_item(char *, char *, long, int);

static int thisdefined,
    hdr_def(int *, int *),
    hdr_item(int, int);

static const char opener[] = "struct %s\n\
    {\n\
    struct casn self;\n",

    simple_definition[] = "void %s(struct casn *mine, ushort level);\n\n",

    any_item[] = "    struct %s %s;\n",
    forward[] = "class %s;\n\n",
    dup_point_func[] = "AsnObj *_%s%s();\n\n",
    func_line[] = "    %s;\n",
    index_op[] = "    AsnObj *_dup();\n    %s& operator[](int index) const;\n",

    assigner[] = "    %s & operator=(const %s &frobj)\
\n        { *(AsnObj *)this = frobj; return *this; }\n",

    num_assigner[] = "    %s & operator=(const long val)\
\n        { write(val); return *this; }\n",

    objid_assigner[] = "    %s & operator=(const char *val)\
\n        { write(val, strlen(val)); return *this; }\n",
    constructor[] = "    %s();\n",
    table_line[] = "    AsnObj objid[%d];\n",
    define_line[] = "#define %s %s\n\n",
    hi_lo[] = "    %s lo, hi;\n",
    assign_num[] =
"    long operator=(const long val) { return write(val); }\n",

    assign_char[] =
"    long operator=(const char *c) { return write(c); }\n",
    name_constrainer[] = "int %sConstraint(struct %s *);\n\n",

    finale[] = "    };\n\n\
void %s(struct %s *mine, ushort level);\n\n";

void cdo_hdr()
{
/**
Function: Searches object table by generation and calls print_hdr for each
item
Outputs: C header file written to 'outstr'
Procedure:
1. Find the latest generation in the object table
	At the same time, print forward declarations
   Starting at that generation, FOR each generation down to -1
 	FOR each item in the table
            IF it's of another generation OR is ruled out by exports,
		Continue in FOR
	    IF the name begins with '_'
		Get its parent as the current pointer
	       IF its pointee is of an earlier generation
                   Print a forward declaration
		IF it's not a passthrough
		    Print other stuff for it
    		    Continue in FOR
            ELSE IF it's an import OR is DEFINED OR is a DEFINER OR is an
		'intermediate' table (i.e. not the real table)
		Continue in FOR
	    ELSE IF this pointer is not imported AND (it's a table or a
		subdefined primitive) AND
                (it's a pass-through OR it's a primitive type))
		IF the real type is primitive AND not further defined
                    Use its name for the typedef
		IF it has no min/max AND is neither a constraint NOR a
                    defined-by, print a typedef
		ELSE print a special statement
		Continue in FOR
	    ELSE use this pointer as the current pointer
	    Seek to its place in the input file
	    Print its header stuff
	Decrement the generation
**/
struct name_table *ntbp, *entbp, *curr_ntbp;
int generation = -1, dup_ansr;
long tmp;
for (ntbp = (struct name_table *)name_area.area,
    entbp = &ntbp[name_area.next]; ntbp < entbp; ntbp++)
    {
    if (ntbp->generation > generation) generation = ntbp->generation;
    }
for ( ; generation >= -1; generation--)
    {
    for (ntbp = (struct name_table *)name_area.area; ntbp < entbp; ntbp++)
	{
	if (ntbp->generation != generation) continue;
	end_definition();
	cat(classname, ntbp->name);
	if (*ntbp->name == '_')
	    {
	    curr_ntbp =
                &((struct name_table *)name_area.area)[ntbp->parent.index];
	    if (!(curr_ntbp->flags & ASN_FALSE_FLAG))
		{
		dup_ansr = test_dup(ntbp->name, &tmp);
	        fprintf(outstr, opener, ntbp->name);
	        print_end(dup_ansr, 1);
		continue;
		}
	    }
        else if (ntbp->pos < real_start ||
            (ntbp->flags & (ASN_DEFINER_FLAG | ASN_DEFINED_FLAG)) ||
	    ((ntbp->flags & ASN_TABLE_FLAG) && ntbp->parent.index >= 0 &&
	    !(((struct name_table *)name_area.area)[ntbp->parent.index].flags &
	    ASN_TABLE_FLAG))) continue;
	else if (ntbp->pos >= real_start &&
            !(ntbp->flags & (ASN_TABLE_FLAG | ASN_ENUM_FLAG)) &&
            ((ntbp->flags & ASN_FALSE_FLAG) ||
            (ntbp->type != -1 && ntbp->type < ASN_CONSTRUCTED &&
             ntbp->tag < ASN_CONSTRUCTED)))
	    {
    	    cat(itemname, classname);
	    curr_ntbp = replace_name(itemname);
	    if (curr_ntbp->type != -1 && curr_ntbp->type < ASN_CONSTRUCTED &&
                !(curr_ntbp->flags & ASN_ENUM_FLAG))
		cat(itemname, casn_w);
    	    if (!ntbp->max && !(ntbp->flags & (ASN_CONSTRAINT_FLAG |
                ASN_DEFINED_FLAG)))
                fprintf(outstr, define_line, classname,
                    (ntbp->type & ASN_CONSTRUCTED)? itemname: casn_w);
	    else
		{
		fprintf(outstr, opener, classname);
		fprintf(outstr, finale, classname, classname);
		}
	    continue;
	    }
        else curr_ntbp = ntbp;
	fseek(streams.str, curr_ntbp->pos, 0);
	type = curr_ntbp->type;
	state = IN_DEFINITION;
	print_hdr();
	}
    }
}

static void print_hdr()
{
/*
Function: Creates class definitions for the things defined an ASN.1 file.

Outputs: C header data written to 'outstr'
Procedure:
1. WHILE there is another token
   	Switch on state
2.    Case IN_DEFINITION
	IF read_definition returns -1 OR state is global, return
	IF (token is '{' OR line end) AND making the definition returns 0
	    Return
3. Case IN_ITEM
   Case SUB_ITEM
	IF reading item returns -1, return
	IF (token is '}' OR ',' (indicating the end of an item)) AND
	    making header item returns 0, return
   Default: Exit with fatal message
*/
int dup_ansr, numdefineds;
for ( end_item(); get_token(0, token); )
    {
    switch (state)
    	{
    case IN_DEFINITION:
	if ((*token != '{' && read_definition(-1) < 0) || state == GLOBAL)
            return;
	if ((*token == '{' || *token == '\n') &&
	    !hdr_def(&numdefineds, &dup_ansr)) return;
	break;

							    /* step 3 */
    case IN_ITEM:
    case SUB_ITEM:
	if (read_item(-1, print_hdr) < 0) return;
	if ((*token == ',' || *token == '}') &&	      /* end of item */
	    !hdr_item(dup_ansr, numdefineds)) return;
	break;

    default:
	fatal(4, (char *)state);
	}
    }
}

static int hdr_def(int *numdefinedsp, int *dup_ansrp)
{
/**
1. IF there's a subclass
     	IF there's no itemname, make one from subclass
 	IF the final name has a universal type AND it's not a primitive
            that will have subs (i.e. ENUM)
            use that as subtype
 	ELSE IF object has the DEFINED flag in table
           Clear the TABLE option because this is the defined item
2. IF token is '{'
    Set state to IN_ITEM
    IF type is BIT STRING OR INTEGER, set enumerated flag
    IF it's a TABLE, print opener with class "AsnTableObj"
    ELSE
3.	IF it will have a dup or point function, print them
    	Get type class name
        IF no universal simple class OR ENUM flag is set
            Print opener C text with classname and type class
	    IF had no '{'
                IF a member of an OF
                    IF there's an explicit subclass
			Make an itemname from it
		    IF there's a subtype
			IF no subclass, use "array"
			IF it's a DEFINED BY, make the subclass from that
			ELSE make the subclass from the derivation
			Clear the subtype
                    Print item with flags
                    IF item was an OF, print index operator stuff
                ELSE IF it's a pointer, print pointer operations
                ELSE
		    Make dummy name from classname
                    Print item with flags
		IF constrained, print constraint line
	        Print lines for assigner, constructor and finale
    IF had no '{', return 0
    Clear assorted variables
    Return 1
**/
struct name_table *ntbp;
char *c;
long tmp;
struct parent *parentp;
if (*subclass)
    {
    if (!*itemname)
        {
        cat(itemname, ((*subclass == '_')? &subclass[1]: subclass));
        *itemname |= 0x20;
        }
    if ((ntbp = replace_name(subclass)) &&
        ntbp->type != 0xFFFFFFFF && ntbp->type < ASN_CONSTRUCTED &&
        !(ntbp->flags & ASN_ENUM_FLAG))
        subtype = (short)ntbp->type;
    }
					                    /* step 2 */
if (*token == '{')
    {
    state = IN_ITEM;
    if ((type == ASN_BITSTRING || type == ASN_INTEGER ||
        type == ASN_ENUMERATED || type == ASN_OBJ_ID) &&
        !(option & ASN_OF_FLAG) &&
        !(flags & ASN_TABLE_FLAG)) flags |= ASN_ENUM_FLAG;
    }
if ((flags & (ASN_TABLE_FLAG | ASN_DEFINED_FLAG)) == ASN_TABLE_FLAG)
    {               /* defined flag is turned on after printing table */
    ntbp = find_name(classname);
    classcount++;                   /* then go up one generation */
    ntbp = &((struct name_table *)name_area.area)[ntbp->parent.index];
    for (parentp = &ntbp->parent, *numdefinedsp = 0; parentp->next;
        (*numdefinedsp)++, parentp= parentp->next);
    }
else
    {
					                     /* step 3 */
    if ((flags & ASN_DEFINED_FLAG)) type = ASN_CHOICE;
    if ((flags & ASN_TABLE_FLAG) && thisdefined > 0)
        c = find_defined_class(thisdefined);
    else c = classname;
    *dup_ansrp = test_dup(c, &tmp);
    if (type >= 0 && type < ASN_CONSTRUCTED &&
        !(flags & ASN_ENUM_FLAG))
        /* now clear it for a primitive named something else
           had to wait after get_derivation to force AsnArray */
        *dup_ansrp &= ~(ASN_DUPED_FLAG);
    if (type < 0 || (type >= ASN_CONSTRUCTED && !(*classname & 0x20)) ||
        (flags & ASN_ENUM_FLAG) || max)
        {
        fprintf(outstr, opener, classname);
        classcount++;
        if (state == IN_DEFINITION)
            {
            if ((*dup_ansrp & ASN_OF_FLAG))
                {
	        if (*subclass)
	            {
                    if (!*itemname)
                        *strcpy(itemname, subclass) |= 0x20;
	            }
                if (subtype >= 0)
	            {
	            if (!*subclass) cat(itemname, array_w);
		    if (*defined_by) mk_subclass(defined_by);
	            else cat(subclass, casn_w);
	            subtype = -1;
	            }
                print_item(itemname, subclass, subtype, 0);
                }
	    else if (*lo_end) fprintf(outstr, hi_lo, c);
            else if (*classname != '_')
                {
                cat(itemname, classname);
                *itemname |= 0x20;
                print_item(itemname, c, type,
                    (option & ~(ASN_OF_FLAG)));
                }
            print_end(*dup_ansrp, 0);
            }
        }
    }
if (state == IN_DEFINITION) return 0;
end_item();
return 1;
}

static int hdr_item(int dup_ansr, int numdefineds)
{
/**
1. IF object is a FUNCTION, print itemname as function definition
2. ELSE IF the object is not an item in a TABLE
        IF object is a table definer, set type and subclass type from table
        IF it's a DEFINED BY
     	     If the definer has no child and grandchild, error
     	     Make the subclass name from the grandchild
     	     Clear defined_by
        IF doing defineds beyond the first in a table, make the subclass name
        ELSE IF have a universal type AND a subclass, clear the type
        IF no itemname
     	     Make a lower case name from :
     	     IF have a valid type, from last part of class anme
     	     ELSE IF no subclass, dummy name
     	     ELSE subclass
3.      IF have subclass AND the actual type is universal primitive AND
     	     it's not TABLE OR ENUM
     	     IF no type so far, use type from replacement object
     	     ELSE if no subtype so far, use type from "    "
        IF no subclass AND no type AND not ENUM, use "AsnNone" for subclass
	ELSE IF class is a BIT STRING, use "AsnBit" for subclass
        Print the item with name, class and options
4. IF token is not a '}' (non-last item) do end_item
   ELSE IF not doing any table stuff
        IF not in COMPONENTS OF
            Print the finale
	Return 0
   ELSE (end of class for table or defined-by)
	Set state to IN_DEFINITION
	IF doing a defined item
	    Print the finale
	    IF that's the last defined set, return 0
	    ELSE bump up the name
	ELSE
	    Print the table entry, assigner, constructor and finale
	    Set the DEFINED flag to make the defined class(es)
	    Get the table entry for the table
	    FOR each parent table (the derived ones), print the class definition
	    Set up for doing the defined class(es)
	Go back to the start of the table definition
   Return 1
**/
char *c;
struct name_table *ntbp;
static struct name_table *ntablep, *ptbp;
struct parent *parentp;
if (type == ASN_BOOLEAN) *subclass = 0;
							    /* step 1 */
if (type == ASN_FUNCTION) fprintf(outstr, func_line, itemname);
							    /* step 2 */
else if ((flags & (ASN_TABLE_FLAG | ASN_DEFINED_FLAG)) != ASN_TABLE_FLAG)
    {
    if ((option & ASN_TABLE_FLAG))
        {
        type = -1;
        mk_in_name(subclass, tablename, classname);
        }
    if (*defined_by) mk_subclass(defined_by);
    if (thisdefined > 1) set_alt_subtype(ntablep, thisdefined);
    else if (type >= 0 && type < ASN_APPL_SPEC && *subclass) type = -1;
    if (!*itemname)
        {
        if (type >= 0) c = &find_class(type)[3];
        else if (!*subclass) c = "no_item";
        else c = subclass;
        *strcpy(itemname, c) |= 0x20;
        }
					                    /* step 3 */
    if (*subclass && (ntbp = replace_name(subclass)) &&
        ntbp->type < ASN_CONSTRUCTED &&
        !(ntbp->flags & (ASN_TABLE_FLAG | ASN_ENUM_FLAG | ASN_CONSTRAINT_FLAG)))
        {
        if (type < 0)
	    {
            type = ntbp->type;
	    if (ntbp->max || (ntbp->flags & ASN_ENUM_FLAG))
		type |= ASN_CONSTRUCTED;  // to force print_item to print name
	    }
        else if (subtype < 0) subtype = (short)ntbp->type;
        }
    if (!*subclass && type < 0 && !(flags & ASN_ENUM_FLAG))
        cat(subclass, casn_w);
    else
        {
        if (thisdefined > 0) c = find_defined_class(thisdefined);
        else c = classname;
        if (!(ptbp = find_name(c))) syntax(itemname);
        else if (ptbp->type == ASN_BITSTRING) cat(subclass, casn_w);
	}
    print_item(itemname, subclass, type, option);
    }
					                    /* step 4 */
if (*token != '}') end_item();      /* not last */
else if (!(flags & ASN_TABLE_FLAG))
    {                  /* i.e. last but not TABLE or DEFINED BY */
    if (state != SUB_ITEM)      /* i.e. not in components */
	{
        print_end(dup_ansr, 1);
	}
    return 0;
    }
else
    {
    state = IN_DEFINITION;
    if (flags & ASN_DEFINED_FLAG)
        {
        print_end(dup_ansr, 1);
        if (thisdefined++ >= numdefineds) return (thisdefined = 0);
        else (classname[strlen(classname) - 1])++;
        }
    else
        {
        flags |= ASN_DEFINED_FLAG;
        thisdefined = 1;
        ntablep = find_name(classname);
	for (parentp = &ntablep->parent; parentp; parentp = parentp->next)
	    {
	    if (parentp->index < 0) continue;
	    ptbp = &((struct name_table *)name_area.area)[parentp->index];
	    fprintf(outstr, simple_definition, ptbp->name);
	    }
        strcat(classname, "Defined");
        }
    fseek(streams.str, tablepos, 0);
    curr_line = table_start_line;
    }
return 1;
}

static void print_end(int dup_ansr, int mode)
{
fprintf(outstr, finale, classname, classname);
if (def_constraintp)
    {
    fprintf(outstr, name_constrainer, classname, classname);
    free(def_constraintp);
    def_constraintp = (char *)0;
    }
}

static void print_item(char *itemname, char *subcls, long loctype,
    int option)
{
/**
Procedure:
1. IF there's no subcls OR it's an enumerated oid, use "casn" as the class name
   ELSE IF the itemname begins with '*', start at the second letter
//   IF it's really primitive, use "casn" as the class name
2. Print the item with class and item names
**/
char *c = subcls;
int tmp;

if (!*c || ((flags & ASN_ENUM_FLAG) && (tmp = find_name(classname)->type) ==
    ASN_OBJ_ID)) c = casn_w;
else if (*itemname == '*') c++;
if ((loctype > 0 && loctype < ASN_CONSTRUCTED) || (option & ASN_TABLE_FLAG))
    c = casn_w;
fprintf(outstr, any_item, c, itemname);
}
