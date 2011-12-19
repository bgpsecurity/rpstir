/* $Id$ */
/*****************************************************************************
File:     asn_hdr.c
Contents: Functions to generate .h files as part of the ASN_GEN program.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

char asn_hdr_id[] = "@(#)asn_hdr.c 860P";

#include "asn_gen.h"

static void print_end(int, int),
    print_hdr(),
    print_item(char *, char *, long, int);

static int thisdefined,
    hdr_def(int *, int *),
    hdr_item(int, int);

static char *get_derivation(int, long);

static const char opener[] = "class %s : public %s\n    {\n  public:\n",
    forward[] = "class %s;\n\n",
    any_item[] = "    %s %s;\n",
    dup_point_func[] = "AsnObj *_%s%s();\n\n",
    func_line[] = "    %s;\n",

    ptr_ops[] = "\
    %s *operator->();\n\
    %s *point();\n\
    void operator=(%s *);\n\
    operator %s* () { return reinterpret_cast<%s*>(_ptr);}\n\
    void _point();\n",

    index_op[] = "    AsnObj *_dup();\n    %s& operator[](int index) const;\n",
    assigner[] = "    %s & operator=(const %s &frobj)\
\n        { *(AsnObj *)this = frobj; return *this; }\n",
    num_assigner[] = "    %s & operator=(const long val)\
\n        { write(val); return *this; }\n",
    objid_assigner[] = "    %s & operator=(const char *val)\
\n        { write(val, strlen(val)); return *this; }\n",
    constructor[] = "    %s();\n",
    table_line[] = "    AsnObj objid[%d];\n",
    typedef_line[] = "typedef %s %s;\n\n",
    hi_lo[] = "    %s lo, hi;\n",

    member_func[] = "    %s *member(long index);\n",

    assign_num[] =
"    long operator=(const long val) { return write(val); }\n",
    assign_char[] =
"    long operator=(const char *c) { return write(c); }\n",
    constrainer[] = "    int constraint() const;\n",
    finale[] = "    };\n\n";

void do_hdr()
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
char *c;
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
        if (strlen(ntbp->name) >= ASN_BSIZE) fatal(10, ntbp->name);
	strcpy(classname, ntbp->name);
	if (*ntbp->name == '_')
	    {
	    if (find_name(&ntbp->name[1])->generation < generation)
                fprintf(outstr, forward, &ntbp->name[1]);
	    curr_ntbp =
                &((struct name_table *)name_area.area)[ntbp->parent.index];
	    if (!(curr_ntbp->flags & ASN_FALSE_FLAG))
		{
		if (((dup_ansr = test_dup(ntbp->name, &tmp)) & ASN_DUPED_FLAG))
		    c = "AsnArrayOfPtrs";
                else c = "AsnPtr";
	        fprintf(outstr, opener, ntbp->name, c);
		fprintf(outstr, ptr_ops, &ntbp->name[1], &ntbp->name[1],
                    &ntbp->name[1], &ntbp->name[1], &ntbp->name[1]);
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
    	    strcpy(itemname, classname);  // both ASN_BSIZE
	    curr_ntbp = replace_name(itemname);
	    if (curr_ntbp->type != -1 && curr_ntbp->type < ASN_CONSTRUCTED &&
                !(curr_ntbp->flags & ASN_ENUM_FLAG))
		strcpy(itemname, find_class(curr_ntbp->type)); // class names < ASN_BSIZE
    	    if (!ntbp->max && !(ntbp->flags & (ASN_CONSTRAINT_FLAG |
                ASN_DEFINED_FLAG)))
                fprintf(outstr, typedef_line, itemname, classname);
	    else
		{
		fprintf(outstr, opener, classname, itemname);
                if (!ntbp->max) fprintf(outstr, constrainer);
		fprintf(outstr, assigner, classname, classname);
		fprintf(outstr, constructor, classname);
		fprintf(outstr, finale);
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
        {    // both are ASN_BSIZE
        strcpy(itemname, ((*subclass == '_')? &subclass[1]: subclass));
        *itemname |= 0x20;
        }
    get_subtype();
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
    fprintf(outstr, opener, classname, (ntbp->type == ASN_OBJ_ID)?
        "AsnOIDTableObj": "AsnNumTableObj");
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
    c = get_derivation(*dup_ansrp, type);
    if (type >= 0 && type < ASN_CONSTRUCTED &&
        !(flags & ASN_ENUM_FLAG))
        /* now clear it for a primitive named something else
           had to wait after get_derivation to force AsnArray */
        *dup_ansrp &= ~(ASN_DUPED_FLAG);
    if (type < 0 || (type >= ASN_CONSTRUCTED && !(*classname & 0x20)) ||
        (flags & ASN_ENUM_FLAG) || max)
        {
        fprintf(outstr, opener, classname, c);
                               /* c is "derived from" class */
        classcount++;
        if (state == IN_DEFINITION)
            {
            if ((*dup_ansrp & ASN_OF_FLAG))
                {
	        if (*subclass)
	            {
                    if (!*itemname)
                        {
                        strncpy(itemname, subclass, strlen(subclass));
                        *itemname |= 0x20;
                        }
	            }
                if (subtype >= 0)
	            {
	            if (!*subclass)
			{
                        strcpy(itemname, array_w);  // array_w is "array"
    		        if (subtype < ASN_CHOICE) // don't print member_func
                            *dup_ansrp &= ~(ASN_OF_FLAG); // unless defined_by
			}
		    if (*defined_by) mk_subclass(defined_by);
	            else
                        {
                        char *b = get_derivation(ASN_DUPED_FLAG, subtype);
                        if (strlen(b) >= ASN_BSIZE) fatal(10, b);
                        strcpy(subclass, b);
                        }
	            subtype = -1;
	            }
                print_item(itemname, subclass, subtype, 0);
                }
            else if ((option & ASN_POINTER_FLAG))
	        fprintf(outstr, ptr_ops, &subclass[1], &subclass[1],
                    &subclass[1], &subclass[1], &subclass[1]);
	    else if (*lo_end) fprintf(outstr, hi_lo, c);
            else
                {
                strcpy(itemname, classname); // both are ASN_BSIZE
                *itemname |= 0x20;
                print_item(itemname, c, type,
                    (option & ~(ASN_OF_FLAG)));
                }
	    if (constraint_area.next) fprintf(outstr, constrainer);
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
	    IF constrained, print constrainer
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
        if (strlen(c) + 1 > ASN_BSIZE) fatal(10, c);
        strncpy(itemname, c, strlen(c));
        *itemname |= 0x20;
        }
					                    /* step 3 */
    if (*subclass && (ntbp = replace_name(subclass)) &&
        ntbp->type < ASN_CONSTRUCTED &&
        !(ntbp->flags & (ASN_TABLE_FLAG | ASN_ENUM_FLAG | ASN_CONSTRAINT_FLAG)))
        {
        if (type < 0) type = ntbp->type;
        else if (subtype < 0) subtype = (short)ntbp->type;
        }
    if (!*subclass && type < 0 && !(flags & ASN_ENUM_FLAG))
        strcpy(subclass, "AsnNone");
    else
        {
        if (thisdefined > 0) c = find_defined_class(thisdefined);
        else c = classname;
        if (!(ptbp = find_name(c))) syntax(itemname);
        else if (ptbp->type == ASN_BITSTRING) strcpy(subclass, "AsnBit");
	}
    print_item(itemname, subclass, type, option);
    }
					                    /* step 4 */
if (*token != '}') end_item();      /* not last */
else if (!(flags & ASN_TABLE_FLAG))
    {                  /* i.e. last but not TABLE or DEFINED BY */
    if (state != SUB_ITEM)      /* i.e. not in components */
	{
	if (def_constraintp)
	    {
	    fprintf(outstr, constrainer);
	    free(def_constraintp);
	    def_constraintp = (char *)0;
	    }
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
        fprintf(outstr, table_line, array);
        fprintf(outstr, assigner, classname, classname);
        fprintf(outstr, constructor, classname);
        fprintf(outstr, finale);
        flags |= ASN_DEFINED_FLAG;
        thisdefined = 1;
        ntablep = find_name(classname);
	for (parentp = &ntablep->parent; parentp; parentp = parentp->next)
	    {
	    if (parentp->index < 0) continue;
	    ptbp = &((struct name_table *)name_area.area)[parentp->index];
	    fprintf(outstr, opener, ptbp->name, classname);
	    if (ptbp->type == ASN_INTEGER || type == ASN_ENUMERATED)
		fprintf(outstr, assign_num);
	    else if (ptbp->type == ASN_OBJ_ID) fprintf(outstr, assign_char);
	    fprintf(outstr, assigner, ptbp->name, ptbp->name);
	    fprintf(outstr, constructor, ptbp->name);
	    fprintf(outstr, finale);
	    }
        if (strlen(classname) > ASN_BSIZE - 8) fatal(10, classname);
        strncat(classname, "Defined", 8);
        }
    fseek(streams.str, tablepos, 0);
    curr_line = table_start_line;
    }
return 1;
}

static char *get_derivation(int dup_ansr, long loctype)
{
/**
Function: Determines name of proper class from which derived
Input: Bit mask from test_dup()
Output: Pointer to name
Procedure:
1. Get a tentative type:
        IF there's a type, use that
        ELSE IF this is a pointer, use "AsnPtr"
	ELSE use "AsnObj"
2. IF it's just DUPED, use the proper type of "AsnArrayOf*s"
   ELSE IF (it's OF OR DUPED) AND (it's a SET OR SEQUENCE)
	IF it's both OF AND DUPED, use "AsnArrayOfSe*sOf"
	ELSE IF it's POINTER AND OF, use "AsnArrayOfPtrSe*Of"
	ELSE IF it's POINTER ADN DUPED,
	ELSE use "AsnSe*Of"
3. Return answer
**/
char derived_from[40];
char *c;
							    /* step 1 */
if (loctype >= 0) c = find_class(loctype);
else if ((option & ASN_POINTER_FLAG)) c = "AsnPtr";
else if (*subclass) c = subclass;
else c = "AsnObj";
							    /* step 2 */
if (dup_ansr == ASN_DUPED_FLAG) c = derived_dup(loctype);
else if ((dup_ansr & ~ASN_POINTER_FLAG) &&
    (loctype == ASN_SEQUENCE || loctype == ASN_SET))
    {
    if (strlen(c) + 14 >= sizeof(derived_from)) fatal(10, "derived_from");
    if (dup_ansr == (ASN_OF_FLAG | ASN_DUPED_FLAG))  /* both */
        strcat(strcat(strcpy(derived_from, "AsnArrayOf"), &c[3]), "sOf");
    else if (dup_ansr == (ASN_POINTER_FLAG | ASN_OF_FLAG))   /*  *Of */
	strcat(strcpy(derived_from, c), "Of");
    else if (dup_ansr == (ASN_POINTER_FLAG | ASN_DUPED_FLAG))
	strcat(strcat(strcpy(derived_from, "AsnArrayOfPtr"), &c[3]), "Of");
    else strcat(strcpy(derived_from, c), "Of");           /* plain OF */
    c = derived_from;
    }
return c;
}

static void print_end(int dup_ansr, int mode)
{

if ((dup_ansr & ASN_OF_FLAG)) fprintf(outstr, member_func, subclass);
if ((dup_ansr & ASN_DUPED_FLAG)) fprintf(outstr, index_op, classname);
if (mode || type < 0 || *subclass)
    {
    if ((flags & ASN_ENUM_FLAG) && !*subclass)
	{
	if (find_name(classname)->type == ASN_OBJ_ID)
            fprintf(outstr, objid_assigner, classname);
        else fprintf(outstr, num_assigner, classname);
	}
    fprintf(outstr, assigner, classname, classname);
    }
fprintf(outstr, constructor, classname);
fprintf(outstr, finale);
}

static void print_item(char *itemname, char *subcls, long type,
    int option)
{
/**
Procedure:
1. IF there's a type
	IF can find the class name for it
            Use that
	    IF option has the OF bit, append "Of" to class name
	ELSE use classname as the class
2. Print the item with class and item names
**/
char buf[16], *c = subcls;
int tmp;

if ((flags & ASN_ENUM_FLAG) && (tmp = find_name(classname)->type) == ASN_OBJ_ID)
   c = find_class(tmp);
else if (!*c) c = "AsnObj";
else if (*itemname == '*') c++;
if (type >= 0 && type < ASN_CHOICE)
    {
    if (!(c = find_class(type))) c = subcls;
    else if ((option & ASN_OF_FLAG))
	{
        if (strlen(c) + 2 >= sizeof(buf)) fatal(10, c);
	strcat(strcpy(buf, c), "Of");
	c = buf;
	}
    }
fprintf(outstr, any_item, c, itemname);
}
