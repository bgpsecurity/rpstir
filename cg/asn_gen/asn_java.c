/* Apr 25 2005 828U  */
/* Apr 25 2005 GARDINER unified asn_gen for C++, C and Java */
/* Jan  3 2005 817U  */
/* Jan  3 2005 GARDINER changed get_derivation() to make specific types */
/* Dec 15 2004 816U  */
/* Dec 15 2004 GARDINER simplified add_list */
/* Dec  7 2004 814U  */
/* Dec  7 2004 GARDINER simplified use of throws */
/* Nov 15 2004 812U  */
/* Nov 15 2004 GARDINER more fixes for asn_obj tests */
/* Nov  8 2004 811U  */
/* Nov  8 2004 GARDINER fixed for file-less JasnObj tests */
/* Oct 25 2004 810U  */
/* Oct 25 2004 GARDINER changes for JasnObj tests */
/* Oct  7 2004 809U  */
/* Oct  7 2004 GARDINER changes from full testing */
/* Sep 23 2004 808U  */
/* Sep 23 2004 GARDINER corrected print formats; moved constraint printing */
/* Jul 29 2004 788U  */
/* Jul 29 2004 GARDINER fixed lots of things */
/* May 19 2003 617U  */
/* May 19 2003 GARDINER converted to byte array form */
/* May 14 2003 616U  */
/* May 14 2003 GARDINER added function test; dropped non-real functions */
/* May 14 2003 615U  */
/* May 14 2003 GARDINER added delay_func_list for functions; improved function definition */
/* May 14 2003 614U  */
/* May 14 2003 GARDINER added code to strip asterisks from FUNCTIONs */
/* Jul  9 2001 586U  */
/* Jul  9 2001 GARDINER fixed printing of IDs and some printf formats */
/* Jun 21 2001 585U  */
/* Jun 21 2001 GARDINER further fix to constraints */
/* Jun 21 2001 584U  */
/* Jun 21 2001 GARDINER fixed set_sub_flag */
/* Jun  8 2001 581U  */
/* Jun  8 2001 GARDINER added printing of IDs */
/* Jun  1 2001 580U  */
/* Jun  1 2001 GARDINER added printing of Static.java */
/* May 30 2001 579U  */
/* May 30 2001 GARDINER changed formats; fixed lots of other problems */
/* Apr 26 2001 573U  */
/* Apr 26 2001 GARDINER started */
/*****************************************************************************
File:     asn_java.c
Contents: Functions to generate java files as part of ASN_GEN program.
System:   ASN development.
Created:  April 10, 2002
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2002 BBN Technologies, A Verizon company
Cambridge, Ma. 02140
*****************************************************************************/

char asn_java_id[] = "@(#)asn_java.c 828P";

#include "asn_gen.h"

struct tagq
    {
    struct tagq *next;
    long tag;
    };

static void add_delay_1param(char *, int, char *),
    add_delay_2param(char *, int, char *, char *),
    add_delay_list(char *),
    add_delay_func_list(char *),
    addq(struct tagq **, long, struct name_table *),
    checkq(struct tagq *, long, struct name_table *),
    clear_data_item(FILE *),
    java_def(int *, long*, long *),
    find_path(char *, char *),
    freeq(struct tagq **),
    new_file(char *, int),
    print_components(FILE *, char *),
    print_constraint(FILE *),
    print_delay_list(),
    print_delay_func_list(),
    print_dup(int, long, int),
    print_enums(FILE *, char *),
    print_item(char *, long, int, long, long),
    print_member(char *),
    print_range(FILE *, char *),
    set_tag(char *classname, long tag);

static int i_namesize, numdefineds, thisdefined,
    java_item(int, long, struct name_table *, int dup_ansr, int from_table),
    java_table(),
    mk_jsubclass(char *),
    optional_def(), set_options(int, char *);

static char *dec_to_bin(uchar *, char *),
    *get_derivation(int, long);

static char *add_list(char *, char *),
    any_item[] = "    public %s %s = new %s();\n\n",
    array_boundset[] = "        _min = %ld;\n\
        _max = %ld;\n",

    class_finale[] = "    }\n",
    constraint_opener[] = "    public int constraint()\n\
        {\n",

    constructor[] = "    public %s()\n\
        {\n",

    *delay_list,
    *delay_func_list,
    *dirname,
    data_init[] =  "        %s = 0;\n",
    definee_flags[] = "        _flags |= AsnStatic.ASN_DEFINED_FLAG;\n",
    derived_table[] = "    public %s()\n\
        {\n\
        wherep = \"%s\".getBytes();\n\
        }\n",

    dummy_constraint[] = "    constraint() { return 0; }\n",

    dup_func[] = "    public AsnObj _dup()\n\
        {\n\
        %s objp = new %s();\n\
        _set_pointers(objp);\n\
        return objp;\n\
        }\n\n",

    index_op[] = "    public %s index(int index) throws AsnException\n\
        {\n\
	AsnObj obj = _index_op(index);\n\
        if (obj == null) _callThrow();\
	return (%s)obj;\
        }\n\n",

    insert_remove[] = "\
    public int insert() { return _insert(); }\n\
    public int remove() { return _remove(); }\n\n",

    member_func[] = "\
    public %s member(int index)\n\
        {\n\
        AsnObj obj = _member(index);\n\
        return (%s)obj;\n\
        }\n\n",

    start_objid_constraint[] =  "        if (vsize() > 0 &&\n\
            (",
    end_objid_constraint[] = ")) return 1;\n\
        return 0;\n\
        }\n\n",

    int_constraint[] = "_enum_diff(%s) == 0",
    objid_constraint[] = "_diff_oid(\"%s\") == 0",
    start_int_constraint[] = "        AsnIntRef valp = new AsnIntRef();\n\
        if (_readref(valp) < 0) return 0;\n\
        if (",
    end_int_constraint[] = ") return 1;\n\
        return 0;\n\
        }\n\n",

    func_finale[] = "        }\n\n",
    func_line[] = "    public %s { %s };\n",
    import_line[] = "import %s.*;\n",
    *i_names,
    opener[] = "public class %s extends %s\n\
    {\n",

    package_line[] = "package %s;\n",
    pathname[80],
    ptr_add[] = "    public void add()\n\
	{\n\
	ref = new %s();\n\
	add((AsnObj)ref);\n\
	}\n",

    ptr_opener[] = "public class %s extends AsnRef %s \n\
    {\n",

    ptr_tag_xw[] = "        _tag = AsnStatic.%s;\n\
        _type = (short)AsnStatic.%s;\n",

    ptr_type_tag_w[] = "        _tag = (int)_type = (short)AsnStatic.%s;\n\
        _flags |= AsnStatic.ASN_POINTER_FLAG;\n",

    range_set[] = "        String s = \"\%s\";\n\
        byte[] lo = s.getBytes(),\n\
	    hi = s.getBytes();\n\
        int lo_lth = %d, hi_lth = %d;\n\
        if (_num_diff(lo, lo_lth) >= 0 && _num_diff(hi, hi_lth) <= 0)\n\
            return 1;\n",

    set_bool_def[] = "        %s._set_def(%d);\n",

    set_int_def[] = "        %s._set_def(%s);\n",
    set_ptr_flags[] = "        _flags |= AsnStatic.ASN_POINTER_FLAG;\n",

    set_sub_default[] = "        _set_sub_flag(%s.%s, (short)(AsnStatic.ASN_DEFAULT_FLAG));\n",
    setup_item[] = "        _setup(%s, %s,",
    static_oid[] = "    public static final String %s = \"%s\";\n",
    static_ub[] = "    public static final int %s = %ld;\n",
    static_opener[] = "public class %s\n\
    {\n",
    sub_boundset[] = "        %s._boundset(%ld, %ld);\n",
    sub_class_w[] = " (int)AsnStatic.%s);\n",
    sub_enum_tag_xw[] = "        _set_tag(%s, (int)%ld);\n",
    set_sub_oid[] =     "        _set_sub_oid(%s, \"%s\");\n",
    sub_tag_xw[] = " (int)0x%X);\n",
    table_constructor[] = "        int i;\n\
	for (i = 0; i < %d; objid[i++] = new %s());\
        _tag = AsnStatic.%s;\n\
        _type = (short)AsnStatic.%s;\n\
        _flags |= AsnStatic.ASN_TABLE_FLAG;\n\
        _sub = objid[0];\n",

    table_write[] =      "        _setup_table(objid[%d], \"%s\", objid[%d]);\n",
    table_write_last[] = "        _setup_table(objid[%d], \"%s\", null);\n",
    table_line[] = "    public %s objid[] = new %s[%d];\n",
    tag_xw[] = "        _tag = 0x%X;\n",
    type_set[] = "        _set_type((AsnObj)%s, (short)0x%lX);\n",
    type_tag_w[] = "        _tag = AsnStatic.%s;\n\
        _type = (short)AsnStatic.%s;\n",

    type_xw[] = "        _type = (short)AsnStatic.%s;\n";


static struct tagq *lasttagqp = (struct tagq *)0;

void jconstruct(char *dir, char *include_names, int include_namesize)
    {
/*
Function: Creates class definitions for the things defined an ASN.1 file.
Outputs: C code written to 'outstr'
Procedure:
1. WHILE have a next token
       Switch on state
2. Case GLOBAL 
	IF reading global returns GLOBAL, return
	IF have output file, close that
	Open new file with class name
	Write opening material for class
	Break
   Case IN_DEFINITION
	IF token is not '{' (rerun of table) AND reading definition returns
	    less than 0, return
	IF STATE is not GLOBAL, construct definition
	Break
3. Case IN_ITEM
   Case SUB_ITEM
	IF it's a table AND java_table returns 0, return
	ELSE IF java_item returns zero, return
	    FOR all members
		Read the item 
		Write the member and save the setup line
	    Write the constructor, the setups and the remainder of the class
	    Return what the last item returned
	Break
   Default: Exit with fatal message
4. Search name table for pointer items (starting with '_') that have no
	parent that's a passthrough, i.e. no definition
	Make a definition for any found
   IF there are any defined constants
	Open a file dirname/DirnameStatic.java
	Print all the constants there
	Close the file
*/ 
char *c;
int did, classgeneration;
long tmp;
struct name_table *ntbp, *ptbp;
struct ub_table *ubp, *eubp;
struct id_table *idp, *eidp;
long classtag = -1, parenttype = -1;

if (state != SUB_ITEM) end_definition();
else end_item();
if (dir)   /* don't if recursing */
    {
    dirname = dir;
    i_names = include_names;
    i_namesize = include_namesize;
    }
for (lasttagqp = (struct tagq *)0, classgeneration = numdefineds = 0;
    get_token(0, token); )
    {
    switch (state)
    	{
    case GLOBAL:			 
        strcpy(prevname, null_ptr_w);
	if (read_global() < 0) break;
	if (tell_pos(streams.str) >= real_start) new_file(classname, 1);
	break;

    case IN_DEFINITION:                                     /* got ::= */
	if (*token != '{' && read_definition(-1) < 0) return;
	if (state != GLOBAL) java_def(&classgeneration, &parenttype, &classtag);
    	break;
							    /* step 3 */
    case IN_ITEM:                                     /* got '{' */
    case SUB_ITEM:            
	if ((flags & ASN_TABLE_FLAG))
	    {
            if (!java_table()) return; 
	    }
        else for (state = IN_ITEM; 1;get_token(0, token))
	    {
    	    if (read_item(-1, construct) < 0) return;
    	    if ((*token == ',' || *token == '}') &&        
    	        !java_item(classgeneration, parenttype,
                (struct name_table*)0, 0, 0)) return;
	    if (state != IN_ITEM && state != SUB_ITEM) break;
	    }
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
    new_file(c, 1);
    did = test_dup(classname, &tmp);
    fprintf(outstr, ptr_opener, c,
        (ptbp->flags & ASN_OF_FLAG)? "implements AsnArrayInterface": "",
        &c[1]);
    fprintf(outstr, constructor, classname);
    type = ptbp->type;
    set_tag(c, (ptbp->tag > 0)? ptbp->tag: ptbp->type);
    print_delay_list();
    fprintf(outstr, set_ptr_flags);
    fprintf(outstr, func_finale);
    if ((did & ~ASN_OF_FLAG))
	{
        print_dup(did, tmp, 0);
	fprintf(outstr, insert_remove);
	}
    fprintf(outstr, ptr_add, &classname[1]);
    fprintf(outstr, class_finale);
    }
if (dir && ((ub_area.area && ub_area.next) ||
    (id_area.area && id_area.next > BUILT_IN_IDS)))
    {
    for(did = 0, ubp = (struct ub_table *)ub_area.area, eubp = &ubp[ub_area.next];
        ubp < eubp; ubp++)
        if (ubp->status) did++;
    if (did || id_area.next > BUILT_IN_IDS)
	{
        sprintf(classname, "%sStatic", dirname);
        classname[0] &= ~0x20;
    	i_namesize = 0;   /* prevent listing imports */
        new_file(classname, 0);
        fprintf(outstr, static_opener, classname);
	if (did)
    	    {
            for(ubp = (struct ub_table *)ub_area.area, eubp = &ubp[ub_area.next];
                ubp < eubp; ubp++)
                {
                if (ubp->status)
                    fprintf(outstr, static_ub, ubp->name, ubp->val);
                }
    	    }
	if (id_area.next > BUILT_IN_IDS)
	    {
            for(idp = (struct id_table *)id_area.area, eidp = &idp[id_area.next],
                idp += BUILT_IN_IDS; idp < eidp; idp++)
                fprintf(outstr, static_oid, idp->name, idp->val);
	    }
        fprintf(outstr, class_finale);
        fclose(outstr);
        }
    }
}

static void java_def(int *classgenerationp, long *parenttypep, long *classtagp)
{
/**
1. IF no tag, use type as tag
   ELSE IF have a type, transfer the constructed bit to the tag
   IF token is { AND (type is BIT STRING OR INTEGER OR ENUMERATED)
        Set enumerated flag
   IF this is a DEFINED BY in a table, find what it's called in the
	generation table
   See if it needs dup stuff
   Get its derivation
   IF the class if just a pass-through
	Print its stuff
	Return
   IF it's a primitive AND no enumerated flag, clear duped flag
   IF it's not imported AND (there's a '{' OR it's an OF)
        Print opener C text
   IF it needs dup for other than 'OF' AND it's not imported
    	Print the OF stuff
2. IF token is {
    Set parenttype to type and classtag to tag
    IF it's not imported
        IF it's a defined item, print flag setting message
        Clear that flag
        IF it's not a table
            IF it needed a dup function, print dup stuff
            IF not universal tag, print tag msg
	    IF not derived from its type, print _type message
    Go to IN_ITEM state OR SUB_ITEM, depending on current state
3. ELSE  (line end.  Either an OF or a typedef)
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
    char *a, *b, *c, *deriv;
    int did;
    long tmp;
    struct name_table *curr_ntbp, *ntbp;
    if (curr_pos <= real_start) curr_pos = tell_pos(streams.str);
    if (tag < 0) tag = type;
    else if (type > 0) tag |= (type & ASN_CONSTRUCTED);
    if (*token == '{' &&
        (type == ASN_BITSTRING || type == ASN_INTEGER ||
        type == ASN_ENUMERATED || type == ASN_OBJ_ID) && !(option & ASN_OF_FLAG))
        flags |= ASN_ENUM_FLAG;
    did = test_dup(classname, &tmp);
    deriv = get_derivation(did, type);
    ntbp = find_name(classname);
    if (ntbp && ntbp->pos >= real_start && (ntbp->flags & ASN_FALSE_FLAG))
	{
	cat(itemname, classname);
	curr_ntbp = replace_name(itemname);
        if (curr_ntbp->type != -1 && curr_ntbp->type < ASN_CONSTRUCTED &&
            !(curr_ntbp->flags & ASN_ENUM_FLAG))
	    cat(itemname, find_class(curr_ntbp->type));
	fprintf(outstr, opener, classname, itemname);
	fprintf(outstr, constructor, classname);
	if (ntbp->max) fprintf(outstr, array_boundset, ntbp->min, ntbp->max);
	fprintf(outstr, func_finale);
	fprintf(outstr, class_finale);
	end_definition();
	return;
	}
    if (type >= 0 && type < ASN_CONSTRUCTED && !(flags & ASN_ENUM_FLAG))
        did &= ~(ASN_DUPED_FLAG);
    if (curr_pos > real_start &&
        (*token == '{' || (option & ASN_OF_FLAG) || max ||
        *lo_end || constraint_area.next))
        fprintf(outstr, opener, classname,
            ((ntbp->type & ASN_CONSTRUCTED) || (ntbp->flags & ASN_TABLE_FLAG))?
            deriv: find_class(ntbp->type));
    							        /* step 2 */
    if (*token == '{')
        {
        state = IN_ITEM;
        if ((type == ASN_BITSTRING || type == ASN_INTEGER ||
            type == ASN_ENUMERATED) && !(option & ASN_OF_FLAG))
            flags |= ASN_ENUM_FLAG;
        *parenttypep = type;
	*classtagp = tag;
	if (curr_pos >= real_start)
	    {
            if ((flags & ASN_DEFINED_FLAG))
               add_delay_list("_flags |= ASN_DEFINED_FLAG;\n");
            else if (!(flags & ASN_TABLE_FLAG)) set_tag(classname, tag);
            if (type >= 0 && type < ASN_CONSTRUCTED && subtype < 0)
                subtype = (short)type;
            *classgenerationp = find_name(classname)->generation;
	    }
        end_item();
        did = 0;
        }
					        /* step 3 */
    else                /* no further definition */
        {
        if (curr_pos > real_start && (max || constraint_area.next ||
            (option & ASN_OF_FLAG)))
            {
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
	    if (subtype >= 0)
	        {
	        if (!*subclass) cat(itemname, array_w);
		if (*defined_by) mk_jsubclass(defined_by);
	        else cat(subclass, get_derivation(ASN_DUPED_FLAG, subtype));
	        }
	    if (*subclass && *itemname)
                fprintf(outstr, any_item, subclass, itemname, subclass);
            fprintf(outstr, constructor, classname);
            if ((did & ASN_DUPED_FLAG)) set_tag(classname, tag);
    	    if (*subclass && subtype < 0)
    	        {
                cat(itemname, subclass);
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
                    fprintf(outstr, ptr_type_tag_w,
                        find_define(ntbp->type));
    	        else fprintf(outstr, ptr_tag_xw, find_define(ntbp->tag),
                    find_define(ntbp->type));
    	        }
            else
                {
                if (subtype >= 0 && !*itemname) cat(itemname, array_w);
    	        if (max)
    		    {
    		    fprintf(outstr, array_boundset, min, max);
    		    max = 0;
    		    }
                if (ntbp && ntbp->type < ASN_CONSTRUCTED)
                    subtype = (short)ntbp->type;
                if (*itemname) print_item((*itemname == '_')? &itemname[1]:
                    itemname, 
//                    (subtype > 0 && (!*subclass || (ntbp &&
//                    !(ntbp->flags & ASN_ENUM_FLAG))))?
                    (subtype > 0)?
                    subtype: 0, (option & ~(ASN_OF_FLAG)), max, min);
		print_delay_list();
                if (subtype >= 0 && *subclass && ntbp && ntbp->max)
                    fprintf(outstr, sub_boundset, itemname, ntbp->min, ntbp->max);
    	        }
            fprintf(outstr, func_finale);
            if (constraint_area.next) print_constraint(outstr);
            if ((did & ASN_OF_FLAG)) print_dup(did, tmp, 0);
            if ((option & ASN_OF_FLAG) &&
	        (b = find_child(classname)) && (ntbp = find_name(b)) &&
	        ntbp->type >= ASN_CHOICE && (c = find_child(ntbp->name)) &&
	        (ntbp = find_name(c)) && (ntbp->flags & ASN_TABLE_FLAG))
	        {
	        c = find_child(ntbp->name);  // table name
	        a = (char *)calloc(1, strlen(c) + 8);
	        strcat(strcpy(a, c), "Defined");
                tmp = find_parent_index(ntbp, b);
                a[strlen(a) - 1] += (tmp - 1);  // adjust name
                fprintf(outstr, member_func, a, a);
	        free(a);
                }
            if ((option & ASN_OF_FLAG) && *subclass)
                {
        	if (subtype < 0)
        	    {
                    get_subtype();
                    if (subtype < 0)
                        fprintf(outstr, member_func, subclass, subclass);
        	    subtype = -1;
        	    }
                else if (subtype < ASN_CHOICE)
                    fprintf(outstr, member_func, subclass, subclass);
        	}
            fprintf(outstr, class_finale);
    							        /* step 4 */
            }
        else
	    {
	    ntbp = find_name(classname);
    	    if (ntbp->pos >= real_start &&
                !(ntbp->flags & (ASN_TABLE_FLAG | ASN_ENUM_FLAG)) &&
                ((ntbp->flags & ASN_FALSE_FLAG) ||
                (ntbp->type != -1 && ntbp->type < ASN_CONSTRUCTED &&
                 ntbp->tag < ASN_CONSTRUCTED)))
	        {
                cat(itemname, classname);
	        curr_ntbp = replace_name(itemname);
	        if (curr_ntbp->type != -1 && curr_ntbp->type < ASN_CONSTRUCTED &&
                    !(curr_ntbp->flags & ASN_ENUM_FLAG))
		    cat(itemname, find_class(curr_ntbp->type));
                if (!ntbp->max && !(ntbp->flags & ASN_CONSTRAINT_FLAG))
		    {
                    fprintf(outstr, opener, classname, itemname);
		    fprintf(outstr, class_finale);
		    }
		}
            }
        end_definition();
        }
    }

static int java_table()
    {
/**
Function: Constructs a table class, its definer class and its definee classes
Input: Starts with tablepos just after the word TABLE
Output: Java class data for the table, the definer and the definees
Returns: IF at end of file, zero; ELSE 1
Procedure:
1. Mark the starting position in input file
   WHILE still in an item state
       Read the item
       Save the setup for the item
   Write the member line of the table, followed by the constructor,
       the setups and all the rest 
2. Get a new file for the definer
   Write the constructor for the definer
3. Go back to the starting position in input file
   Modify the classname for the definees
   FOR all definees
       Get a new file
       Go back to the starting position in input file
       Print the opener
       FOR all items
           Read the item 
           Write the member line and save the setup line
       Write the constructor, setups and remainder of class
       Bump up the class name
   Return what the last item returned
**/
    uchar *b, *c;
    int i, j, dup_ansr;
    long tmp;
    struct name_table *ntbp, *ntablep, *ptbp;
    struct parent *parentp;
                                                           /* step 1 */
    while (state == IN_ITEM || state == SUB_ITEM)
	{
        if (read_item(-1, construct) < 0) return -1;
        if (type < 0 && !*subclass && !optional_def()) syntax(itemname);
        if (type < 0) c = (uchar *)itemname;
        else c = (uchar *)find_class(type);
	if (*token == ',')
	    {
            b = (uchar *)calloc(1,strlen(table_write) + strlen(numstring) + 16);
            sprintf((char *)b, table_write, array - 1, numstring, array);
	    }
	else
	    {
            b = (uchar *)calloc(1,strlen(table_write_last) + strlen(numstring) +
                4);
            sprintf((char *)b, table_write_last, array - 1, numstring);
	    }
        add_delay_list((char *)b);
        free(b);
	if (*token == '}') state = IN_DEFINITION;
	end_item();
	get_token(0, token);
	}
    state = IN_ITEM;
    ntablep = find_name(classname);
    if (ntablep->type == ASN_OBJ_ID) b = (uchar *)"AsnObjectIdentifier";
    else b = (uchar *)"AsnNumeric";
    fprintf(outstr, table_line, b, b, array);     /* print member */
    fprintf(outstr, constructor, classname);
    if (ntablep->type < 0) warn(34, ntablep->name);
    else 
        {
	  c = (uchar *)find_define(ntablep->type);
        fprintf(outstr, table_constructor, array, b, c, c);
	print_delay_list();
        fprintf(outstr, func_finale);
        fprintf(outstr, class_finale);
        }
    ntbp = &((struct name_table *)name_area.area)[ntablep->parent.index];
    for (parentp = &ntbp->parent, numdefineds = 0; parentp->next;
        numdefineds++, parentp = parentp->next);
							    /* step 2 */
    for (parentp = &ntablep->parent; parentp; parentp = parentp->next)
        {
        if (parentp->index < 0) continue;
        ptbp = &((struct name_table *)name_area.area)[parentp->index];
        find_path(path, ptbp->name);
        new_file(ptbp->name, 1);
        fprintf(outstr, opener, ptbp->name, classname);
	fprintf(outstr, derived_table, ptbp->name, path);
	fprintf(outstr, class_finale);
        }
                                                            /* step 3 */
    flags |= ASN_DEFINED_FLAG;
    thisdefined = 1;
    strcat(classname, "Defined");
    for (i = numdefineds; --i >= 0; )
	{
	new_file(classname, 1);
	c = (uchar *)find_defined_class(thisdefined);
        dup_ansr = test_dup((char *)c, &tmp);
        c = (uchar *)get_derivation(dup_ansr, ASN_CHOICE);
	fprintf(outstr, opener, classname, c);
        fseek(streams.str, tablepos, 0);
	while (*token != '{') get_token(0, token);
	add_delay_list(definee_flags);
	state = IN_ITEM;
	for (j = array, array = 0; --j >= 0; )
	    {
            if (read_item(-1, construct) < 0) return -1;  /* bumps up array */
    	    java_item(1, ptbp->type, ntablep, dup_ansr, 1);
	    end_item();
	    if (j > 0) get_token(0, token);
	    }
	}
    state = GLOBAL;
    return 1;
    }

static int java_item(int classgeneration, long parenttype, 
    struct name_table *ntablep, int dup_ansr, int from_table)
    {
/**        steps 1 - 3 are from asn_hdr, 4 - 7 from asn_constr
1. IF object is a FUNCTION, add itemname to the delayed function list
2. ELSE IF the object is not an item in a TABLE
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
4. IF the object is an item in a TABLE AND lacks either a numeric string
	OR an itemname, fatal error
   IF doing defineds beyond the first in a table, make the subclass name
   IF (explicit OR CHOICE OR ANY) AND have a tag AND not ENUM
 	Set explicit option
   IF no tag so far AND type is a universal primitive, use type as tag
   ELSE IF this is a DEFINED BY AND it's not an ANY, do nothing
   ELSE IF this item is explicitly tagged AND it's not a subdefined
 	primitive, set the constructed bit in the tag
   ELSE IF have a type, then 'Or' the constructed bit of the type into the tag
   IF ENUM is set in flags, set it in option
5. IF it's an imported item, do nothing
   ELSE IF it's not a FUNCTION
 	IF there's no itemname, make one from type or subclass
        IF class is enumerated
            Print line to set tag
            Clear tag and type
6.      IF there's a subclass that's not a primitive
            IF it's a boolean definition, set the type to BOOLEAN with
                no name table entry
	    ELSE
		IF the subclass isn't in the table, error
                IF there's a type in the table
                  'Or' that object's constructed bit into the tag
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
7. IF token does not indicate the last item, finish the item
   ELSE IF not in COMPONENTS OF
        IF it's not imported, print the func_finale
	ELSE IF there are constraints, print them
	Clear previous name
	Free the list of last tags
        IF not in state IN_DEFINITION, finish the definition
	ELSE finish item
   ELSE return 0
   Return 1
**/
    struct name_table *ntbp;
    struct alt_subclass *altscp;
    long tag_tb, tmp, sav_type = type;
    char *b, *c;
    int did, false_subclass = 0;
    static int bool_val;
    char bool_def[8];
						            /* step 1 */
    if (type == ASN_BOOLEAN)
	{
        if (from_table) strcpy(bool_def, subclass);
	*subclass = 0;
	}
    if (type == ASN_FUNCTION)       /* strip asterisks */
	{
	for (c = itemname; *c; )
	    {
	    while (*c && *c != '*') c++;
	    if (*c) strcpy(c, &c[1]);
	    }
	for (c = itemname; *c && *c != '('; c++);
	if (*c)
	    {
    	    b = (char *)calloc(1, sizeof(func_line) + strlen(itemname) + 14);
    	    sprintf(b, func_line, itemname,
                (strncmp(itemname, "void", 4))? "return 0;": "");
            add_delay_func_list(b);
    	    free(b);
	    }
	}
    							        /* step 2 */
    else if ((flags & (ASN_TABLE_FLAG | ASN_DEFINED_FLAG)) != ASN_TABLE_FLAG)
        {
        if ((option & ASN_TABLE_FLAG))
            {
            type = -1;
            mk_in_name(subclass, tablename, classname);
            }
        if (*defined_by) false_subclass = mk_jsubclass(defined_by);
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
            if (type < 0) type = ntbp->type;
            else if (subtype < 0) subtype = (short)ntbp->type;
            }
        if (!*subclass && type < 0 && !(flags & ASN_ENUM_FLAG))
            false_subclass = (int)cat(subclass, "AsnNone");
        else if ((ntbp = find_name(classname)) && ntbp->type == ASN_BITSTRING)
            false_subclass = (int)cat(subclass, "AsnSubDef");
        if (curr_pos >= real_start) print_member(subclass);
        if (false_subclass) *subclass = 0;    
        }
    							    /* step 4 */
    type = sav_type;
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
//    if (((explicit1 & 1) || type == ASN_CHOICE || type == ASN_ANY) &&
//        tag >= 0 && !(flags & ASN_ENUM_FLAG))
        option |= ASN_EXPLICIT_FLAG;
    if (tag < 0 && type < ASN_CONSTRUCTED) tag = type;
    else if (*defined_by && tag > 0 && tag < ASN_CONSTRUCTED);
    else if ((explicit1 & 1) && !(flags & ASN_ENUM_FLAG)) tag |= ASN_CONSTRUCTED;
    else if (type >= 0) tag |= (type & ASN_CONSTRUCTED);
    if ((flags & ASN_ENUM_FLAG)) option |= ASN_ENUM_FLAG;
					                    /* step 5 */
    if (curr_pos <= real_start);
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
        if ((option & ASN_ENUM_FLAG))
            {
            if (!sub_val)
    	        {
    	        b = (char *)calloc(1, sizeof(sub_enum_tag_xw) +
                    strlen(itemname) + 4);
                sprintf(b, sub_enum_tag_xw, itemname, integer_val);
    	        }
    	    else if (find_name(classname)->type == ASN_OBJ_ID)
		{
                b = (char *)calloc(1, sizeof(set_sub_oid) + strlen(sub_val) +
                    4);
                sprintf(b, set_sub_oid, itemname, sub_val);
                }
	    else syntax(token);
	    add_delay_list(b);
	    free(b);
            tag = type = -1;
            }
    					                        /* step 6 */
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
                if (ntbp->tag != -1)
    	            {
                    if (tag > ASN_APPL_SPEC && (explicit1 & 1) && tag != ASN_CHOICE)
                        warn(15, (char *)tag);
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
        else ntbp = 0;
        if (tag_tb == -1)
            {
            if (tag != -1) tag_tb = tag;
            else if (type != ASN_CHOICE) tag_tb = type;
            }
        if (!(flags & ASN_ENUM_FLAG)) checkq(lasttagqp, tag_tb, ntbp);
        if (!(flags & (ASN_DEFINED_FLAG | ASN_ENUM_FLAG)) &&
            ((option & ASN_OPTIONAL_FLAG) || parenttype == ASN_SET))
            addq(&lasttagqp, tag_tb, ntbp);
        else if (lasttagqp) freeq(&lasttagqp);
        if (thisdefined > 1)
    	    {
    	    for (altscp = alt_subclassp, tmp = thisdefined - 2; tmp-- &&
    	        altscp; altscp = altscp->next);
    	    option = altscp->options;
    	    }
        print_item(itemname, (tag_tb < ASN_APPL_SPEC && !*defined_by)?0:
            tag_tb, (option & ~ASN_TABLE_FLAG), max, min);
        if (tag == ASN_BOOLEAN && *bool_def && strcmp(bool_def, either_w) &&
            (flags & (ASN_DEFINED_FLAG | ASN_TABLE_FLAG)) ==
            (ASN_DEFINED_FLAG | ASN_TABLE_FLAG))
            {
            bool_val = BOOL_DEFINED;
            if (!strcmp(bool_def, true_w)) bool_val |= BOOL_DEFINED_VAL;
    	    if ((*defaultname && !strcmp(defaultname, true_w)))
                bool_val |= BOOL_DEFAULT;
            if (bool_val) add_delay_2param(set_bool_def, sizeof(set_bool_def) +
                strlen(itemname) + 4, itemname, (char *)bool_val);
	    }
        else if (*defaultname && *defaultname != '{')
            {
            if (type == ASN_BOOLEAN || tag == ASN_BOOLEAN)
    	        {
    	        if (!strcmp(defaultname, true_w))
                    add_delay_2param(set_bool_def, sizeof(set_bool_def) +
                    strlen(itemname) + 4, itemname, (char *)BOOL_DEFAULT);
    	        }
    	    else if (type == ASN_INTEGER && *defaultname == '0' &&
                !(ntbp && (ntbp->flags & ASN_ENUM_FLAG)))
	        add_delay_2param(set_int_def, sizeof(set_int_def) +
                    strlen(itemname) + strlen(defaultname), itemname,
                    &defaultname[1]);
    	    else
    	        {
    	        if (*defaultname == '0') *defaultname = 'e';
                add_delay_2param(set_sub_default, sizeof(set_sub_default) +
                    strlen(itemname) + strlen(defaultname),
                    itemname, defaultname);
    	        }
            }
        strcpy(prevname, itemname);
        }
    else clear_data_item(outstr);
					                        /* step 7 */
    if (*token != '}') end_item();  /* not last */
    else if (state != SUB_ITEM) /* last, but not in components */
        {
	if (curr_pos > real_start)
	    {
            fprintf(outstr, constructor, classname);
    	    print_delay_list();
    	    fprintf(outstr, func_finale);
    	    print_delay_func_list();
	    }
        did = test_dup(classname, &tmp);
        if ((dup_ansr & ASN_DUPED_FLAG) ||
		       /* exported? */
            ((did & ~(ASN_OF_FLAG)) && curr_pos > real_start))
            print_dup((!dup_ansr)? did: dup_ansr, tmp, dup_ansr);
	if (curr_pos > real_start)
	    {
            if (def_constraintp)
                {
                add_constraint(def_constraintp, strlen(def_constraintp));
                free(def_constraintp);
                def_constraintp = (char *)0;
                print_constraint(outstr);
                }
            fprintf(outstr, class_finale);
	    }
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
	    }
        strcpy(prevname, null_ptr_w);
        if (lasttagqp) freeq(&lasttagqp);
        parenttype = -1;
        if (state != IN_DEFINITION) end_definition();
        else end_item();
        *defined_by = (char)0;   /* only clear this when ending a constr item */
	state = GLOBAL;
        }
    else return 0;            /* last of components */
    return 1;
    }

static void add_delay_1param(char *format, int size, char *param)
    {
    char *b = (char *)calloc(1, size);
    sprintf(b, format, param);
    add_delay_list(b);
    free(b);
    }

static void add_delay_2param(char *format, int size, char *param1, char *param2)
    {
    char *b = (char *)calloc(1, size);
    sprintf(b, format, param1, param2);
    add_delay_list(b);
    free(b);
    }

static void add_delay_list(char *new_mem)
    {
    delay_list = add_list(delay_list, new_mem);
    }

static void add_delay_func_list(char *new_mem)
    {
    delay_func_list = add_list(delay_func_list, new_mem);
    }

static char *add_list(char *listp, char *new_mem)
    {
    int list_lth, lth = strlen(new_mem);

    if (!listp)
	{
	list_lth = 0;
        listp = (char *)calloc(1, lth + 2);
	}
    else
	{
        list_lth = strlen(listp);
        listp = (char *)realloc(delay_list, list_lth + lth + 2);
	}
    strcpy(&listp[list_lth], new_mem);
    return listp;
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
    fprintf(outstr, data_init, itemname);
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

static char *get_derivation(int dup_ansr, long loctype)
{
/**
Function: Determines name of proper class from which derived
Output: Pointer to name
Procedure:
1. Get a local class name
   Get a tentative type:
        IF there's a type, use that
        ELSE IF this is a pointer, use "AsnPtr"
	ELSE use "AsnObj"
2. IF it's just DUPED, use the proper type of class
   ELSE IF (it's OF OR DUPED) AND (it's a SET OR SEQUENCE)
	IF it's both OF AND DUPED, use "AsnSe*sOfArray"
	ELSE IF it's POINTER AND OF, use "AsnArrayOfPtrSe*Of"
	ELSE IF it's POINTER ADN DUPED,
	ELSE use "AsnSe*Of"
3. Return answer
**/
    static char derived_from[40];
    char *c;
							    /* step 1 */
    if (loctype >= 0) c = find_class(loctype);
    else if ((option & ASN_POINTER_FLAG)) c = "AsnRef";
    else if (*subclass) c = subclass;
    else c = "AsnObj";
							    /* step 2 */
    if (dup_ansr == ASN_DUPED_FLAG)     /* dup alone */
        {
        if (loctype == ASN_SET) c = "AsnSetArray";
	else if (loctype == ASN_SEQUENCE) c = "AsnSequenceArray";
	else if (loctype == ASN_BITSTRING) c = "AsnBitString";
	else if (loctype == ASN_OBJ_ID) c = "AsnObjectIdentifier";
	else if (loctype == ASN_CHOICE) c = "AsnChoice";
	else if (loctype == ASN_ANY) c = "AsnAny";
        else if (!(c = find_class(loctype))) c = "AsnArray";
        }
    else if ((dup_ansr & ~ASN_POINTER_FLAG) &&
        (loctype == ASN_SEQUENCE || loctype == ASN_SET))
        {
        if (dup_ansr == (ASN_OF_FLAG | ASN_DUPED_FLAG))  /* both */
            cat(cat(cat(derived_from, "Asn"), &c[3]), "OfArray");
        else if (dup_ansr == (ASN_POINTER_FLAG | ASN_OF_FLAG))   /*  *Of */
    	    cat(cat(derived_from, c), "Of");
        else if (dup_ansr == (ASN_POINTER_FLAG | ASN_DUPED_FLAG))
    	    cat(cat(cat(derived_from, "AsnArrayOfPtr"), &c[3]), "Of");
        else cat(cat(derived_from, c), "Of");           /* plain OF */
        c = derived_from;
        }
    else if ((flags & (ASN_TABLE_FLAG | ASN_DEFINED_FLAG)) == ASN_TABLE_FLAG)
        {               /* defined flag is turned on after printing table */
	c = (find_name(classname)->type == ASN_OBJ_ID)? "AsnOIDTableObj": 
            "AsnNumTableObj";
	}
    return c;
    }

static int mk_jsubclass(char *from)
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
return 1;
}

static void new_file(char *name, int asn)
    {
    char *c, *e;
    if (*dirname)
	{
    	if (outstr) fclose(outstr);
    	sprintf(pathname, "%s/%s.java", dirname, name);
    	if (!(outstr = fopen(pathname, "w"))) fatal(2, pathname);
    	fprintf(outstr, package_line, dirname);
	}
    for (c = i_names, e = &i_names[i_namesize]; c < e; )
	{
	fprintf(outstr, import_line, c);
	while (*c++);
	}
    if (asn) fprintf(outstr, import_line, "asn");
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
int fd, lth;

if (constraint_area.next)
    {
    if (!wdcmp(c, constrained_w))
	{
	if (wdcmp(next_word(c), by_w)) syntax(c);
	b = (char *)calloc(1, strlen(classname) + 20);
	strcat(strcpy(b, classname), "constraint.java");
	if ((fd = open(b, O_RDONLY)) < 0)
	    {
	    warn(41, classname);
	    fprintf(outstr, dummy_constraint);
	    }
	else
	    {
	    b = (char *)realloc(b, 80);
	    b[79] = 0;
	    while((lth = read(fd, b, 79)) == 79) fprintf(outstr, b);
	    if (lth)
		{
		b[lth] = 0;
		fprintf(outstr, b);
		}
	    close(fd);
	    }
	free(b);
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
	    else fprintf(outstr, int_constraint, c);
	    }
	else
	    {
	    if (*c == '_') *c = '-';
	    if ((*c < '0' || *c > '9') && *c != '-')
                fprintf(outstr, int_constraint, c);
            else fprintf(outstr, "valp.val == %s", c);
	    }
	for (c = b; *c && *c <= ' '; c++);
	if (*c == '|' || !wdcmp(c, union_w))
	    {
            fprintf(outstr, " ||\n            ");
	    c = next_word(c);
	    }
	}
    if (classtype == ASN_OBJ_ID) fprintf(outstr, end_objid_constraint);
    else fprintf(outstr, end_int_constraint);
    }

static void print_delay_list()
    {
    if (delay_list)
	{
	fprintf(outstr, delay_list);
	free(delay_list);
	delay_list = (char *)0;
	}
    }

static void print_delay_func_list()
    {
    if (delay_func_list)
	{
	fprintf(outstr, delay_func_list);
	free(delay_func_list);
	delay_func_list = (char *)0;
	}
    }

static int print_flag(int option, char *string, int val)
    {
    char *b;

    b = (char *)calloc(1, 20 + strlen(string));
    sprintf(b, "AsnStatic.%s", string);
    if ((option &= ~val)) strcat(b, " | ");
    add_delay_list(b);
    free(b);
    return option;
    }

static void print_item(char *name, long loctag, int option, long max, long min)
    {
/**
Procedure:
**/
    char *b;
    b = (char *)calloc(1, sizeof(setup_item) + strlen(prevname) + strlen(name) +
        4);
    sprintf(b, setup_item, prevname, name);
    add_delay_list(b);
    free(b);
    option = set_options(option, name);
    if (loctag < 0 || (loctag >= ASN_NONE && loctag < ASN_NOTYPE)) loctag = 0;
    if (loctag > 0 && loctag < ASN_APPL_SPEC) 
	{
	b = (char *)calloc(1, sizeof(sub_class_w) + 32);
        sprintf(b, sub_class_w, find_define(loctag));
	add_delay_list(b);
	free(b);
	}
    else 
	{
	b = (char *)calloc(1, sizeof(sub_tag_xw) + 32);
	sprintf(b, sub_tag_xw, loctag);
	add_delay_list(b);
	free(b);
	}
    if (type > ASN_CHOICE)
	{
	b = (char *)calloc(1, sizeof(type_set) + 32);
        sprintf(b, type_set, name, type);
	add_delay_list(b);
	free(b);
	}
    if (max) 
	{
	b = (char *)calloc(1, sizeof(sub_boundset) + strlen(name) + 32);
	sprintf(b, sub_boundset, name, min, max);      
	add_delay_list(b);
	free(b);
	}
    }

static void print_member(char *locclass)
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
    char buf[16], *c = locclass;
    int tmp;

    if ((flags & ASN_ENUM_FLAG))
	{
        if ((tmp = find_name(classname)->type) == ASN_OBJ_ID)
            c = find_class(tmp);
	else c = "AsnSubDef";
	}
    else if (!*c) c = "AsnObj";
    else if (*itemname == '*') c++;
    if (type >= 0 && type < ASN_CHOICE)
        {
        if (!(c = find_class(type))) c = classname;
        else if ((option & ASN_OF_FLAG))
    	    {
    	    cat(cat(buf, c), "Of");
    	    c = buf;
    	    }
        }
/*    lth = strlen(any_item) + (2 * strlen(c)) + strlen(itemname);
    b = (char *)calloc(1, lth + 2);
    sprintf(b, any_item, c, itemname, c);
    add_delay_list(b);
    free(b); */
    fprintf(outstr, any_item, c, itemname, c);
    }

static void print_dup(int dup, long loctype, int use_class)
{
char *c, *deriv;
if (loctype > 0 && loctype < ASN_CONSTRUCTED) c = find_class(loctype);
else c = classname;
if (!use_class && !(loctype & ASN_CONSTRUCTED))
    deriv = get_derivation(dup, loctype);
else deriv = classname;
if ((dup & ASN_DUPED_FLAG)) fprintf(outstr, dup_func, classname, classname);
if ((dup & ASN_DUPED_FLAG) && (loctype <= 0 || loctype >= ASN_CONSTRUCTED))
    fprintf(outstr, index_op, deriv, deriv);
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

static int set_options(int option, char *name)
    {

    add_delay_list(" (short)");
    if (option)
        {
        add_delay_list("(");
        if ((option & ASN_OPTIONAL_FLAG)) option = print_flag(option,
    	    "ASN_OPTIONAL_FLAG", ASN_OPTIONAL_FLAG);
        if ((option & ASN_OF_FLAG)) option = print_flag(option,
    	    "ASN_OF_FLAG", ASN_OF_FLAG);
        if ((option & ASN_DEFAULT_FLAG)) option = print_flag(option,
    	    "ASN_DEFAULT_FLAG", ASN_DEFAULT_FLAG);
        if ((option & ASN_RANGE_FLAG)) option = print_flag(option,
    	    "ASN_RANGE_FLAG", ASN_RANGE_FLAG);
        if ((option & ASN_EXPLICIT_FLAG)) option = print_flag(option,
    	    "ASN_EXPLICIT_FLAG", ASN_EXPLICIT_FLAG);
        if ((option & ASN_ENUM_FLAG)) option = print_flag(option,
    	    "ASN_ENUM_FLAG", ASN_ENUM_FLAG);
        if ((option & ASN_POINTER_FLAG)) option = print_flag(option,
    	    "ASN_POINTER_FLAG", ASN_POINTER_FLAG);
        add_delay_list("),");
        }
    else add_delay_list("0,");
    return 0;
    }

static void set_tag(char *loc_classname, long loctag)
{
char *b, *c = find_define(loctag);

if (c && (loctag == find_name(loc_classname)->type || *classname == '_'))
    {
    if (type != ASN_SET) 
	{
	b = (char *)calloc(1, sizeof(type_tag_w) + (2 * strlen(c)) + 4);
	sprintf(b, type_tag_w, c, c);
	add_delay_list(b);
	free(b);
	}
    }
else
    {
    if (loctag > 0) 
	{
        add_delay_1param(tag_xw, sizeof(tag_xw) + 4, (char *)loctag);
	}
    c = find_define(type);
    add_delay_1param(type_xw, sizeof(type_xw) + strlen(c) + 4, c);
    }
}

