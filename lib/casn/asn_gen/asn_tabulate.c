/*****************************************************************************
File:     asn_tabulate.c
Contents: functions to create the name table as part of the ASN_GEN program.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

#include "asn_gen.h"

static void
massage_table(
    struct name_table *);
static void
mk_table_child(
    int,
    long,
    int);
static void
set_false(
    struct name_table *,
    struct name_table *);
static void
sort_defineds(
    struct name_table *);
static void
tab_def(
    int,
    struct name_table *);
static void
tab_item(
    int,
    int);

void tabulate(
    void)
{
    /*
     * Function: Fills name_tab with info about the input file
     *
     *
     * Outputs: Name_tab filled in Procedure: WHILE there's a next token
     * Switch on state 1.  Case GLOBAL IF read_global returns < 0, break IF
     * token is '::=' Add object name to name_table IF position not yet set,
     * set it to current position Save index as current parent Clear 'name' Go
     * to IN_DEFINITION state 2.  Case IN_DEFINITION Read the definition IF
     * not in GLOBAL state, tabulate the definition IF in GLOBAL state clear
     * classname 3.  Case IN_ITEM IF token is '::=' OR '{', exit with fatal
     * message IF read_item returns -1, return IF token is '}' OR ','
     * (indicating the end of an item) Tabulate the item Default: Exit with
     * fatal message
     */
    int parent = 0;
    int in_choice = 0;
    struct name_table *ptbp = NULL;
    option = 0;
    if (state != SUB_ITEM)
        end_definition();
    else
        end_item();
    while (get_token(0, token))
    {
        switch (state)
        {
            /*
             * step 1
             */
        case GLOBAL:
            if (read_global() < 0)
                break;
            parent = add_name(classname, (ulong) - 1, 0);
            ptbp = &((struct name_table *)name_area.area)[parent];
            if ((ptbp->flags & ASN_FILLED_FLAG))
                warn(MSG_DUP_DEF, classname);
            else
                ptbp->flags |= ASN_FILLED_FLAG;
            if (ptbp->pos == -1)
                ptbp->pos = tell_pos(streams.str);
            classcount++;
            break;
            /*
             * step 2
             */
        case IN_DEFINITION:    /* got ::= */
            if (read_definition(parent) < 0)
                return;
            if (type >= ASN_CHOICE)
                in_choice = 1;
            else
                in_choice = 0;
            if (state != GLOBAL)
                tab_def(parent, ptbp);
            if (state == GLOBAL)
                end_definition();
            else
                end_item();
            break;
            /*
             * step 3
             */
        case IN_ITEM:          /* got '{' */
            if (*token == ':' || *token == '{')
                syntax(classname);
            if (read_item(parent, NULL) < 0)
                return;
            if (*token == ',' || *token == '}') /* end of item */
                tab_item(parent, in_choice);
            break;

        default:
            done(true, MSG_INVAL_STATE, state);
        }
    }
    if (name_area.area)
        massage_table((ptbp = (struct name_table *)name_area.area));
}

static void tab_def(
    int parent,
    struct name_table *ptbp)
{
/*
1. IF have a tag,
        IF type is constructed, put constructed bit in tag
        Put tag in name table
   ELSE set tag to type
2. Set max and min
   IF have a child (i.e. subclass) name
	IF no type yet AND not a pointer, mark parent false
        Add child to object table with
            current parent, path of zero, type and option
   ELSE IF no type nor table nor choice, error
   ELSE IF have a primitive universal subtype, set parent subtype
3. IF (item is subdefined AND type is BIT STRING OR INTEGER OR
        ENUMERATED) OR there's a range
	IF there's a range AND type is not INTEGER, error
        Set enumerated flag and option
   IF in explicit area, set EXPLICIT flag
   Add object name to table with type and option
4. IF at line end
        Set to GLOBAL state
   IF table flag is set, set it in object table
   Clear assorted variables
   Set state to IN_ITEM
*/
    if (*defined_by)
        mk_table_child(parent, (long)0, option);
    /*
     * in case name table moved!
     */
    ptbp = &((struct name_table *)name_area.area)[parent];
    if (tag >= 0)
    {
        if (type > 0 && type < ASN_CHOICE)
            tag |= (type & ASN_CONSTRUCTED);
        ptbp->tag = tag;
    }
    else
        tag = ptbp->type = type;
    /*
     * step 2
     */
    if ((ptbp->max = max))
        ptbp->min = min;
    if (*subclass)
    {
        if (type < 0)
            add_name(classname, (long)-1, ASN_FALSE_FLAG);
        if (ptbp->pos < real_start && ptbp->type == (long)0xFFFFFFFF)
            ptbp->type = 0;     /* so imported passthru won't be undefined */
        add_child(subclass, parent, 0, (ulong) - 1, 0);
    }
    else if (type < 0 && !(flags & ASN_TABLE_FLAG))
        syntax(subclass);
    else if (subtype >= 0 && subtype < ASN_CONSTRUCTED)
        ptbp->subtype = subtype;
    /*
     * step 3
     */
    if ((*token == '{' && (type == ASN_BITSTRING || type == ASN_INTEGER ||
                           type == ASN_ENUMERATED || type == ASN_OBJ_ID) &&
         !(option & ASN_OF_FLAG)) || *lo_end)
    {
        if (*lo_end && type != ASN_INTEGER)
            warn(MSG_NOT_SUPPORTED, "range definition");
        flags |= ASN_ENUM_FLAG; /* for read_item */
        option |= ASN_ENUM_FLAG;        /* for add_name just below */
    }
    if (explicit1 & 1)
        option |= ASN_EXPLICIT_FLAG;
    if (constraint_area.next)
        option |= ASN_CONSTRAINT_FLAG;
    add_name(classname, type, (option & ASN_OF_FLAG) ?
             (option &= ~(ASN_POINTER_FLAG)) : option);
    /*
     * step 4
     */
    if ((option & ASN_TABLE_FLAG))
        ptbp->flags |= ASN_TABLE_FLAG;
    if (*token == '\n')
        state = GLOBAL;
    else
        state = IN_ITEM;
}

static void tab_item(
    int parent,
    int in_choice)
{
/*
1. IF in a choice, make an "in-name"
   IF it's a DEFINED BY, make a table entry
   IF it's a boolean, clear subclass (in case it's a BOOLEAN DEFINED BY)
2. IF it's not a universal type OR (in a CHOICE but not a function)
	IF subclass is not a pointer OR item is not imported
	IF there's no subclass OR (in a choice AND have a tag) use in-name
	    for child name
	ELSE use subclass
        Add child with current parent and path of 'did'
	IF this has a tag
	    Find the child's name table entry
	    IF that's a member (not a class), give it the tag
	IF used in-name for child AND have a subclass
	    Add child having subclass name and previous child as parent
   Add any alternate subclass name which is not a universal name as a child of
	this parent
   IF there's a table name, i.e. this is a definer
	Make a dummy name of itemnameIntablename
	Add that to object table with current parent, definer flag and path
        of 'did'
	Make a dummy name of tablenameIntablename
	Add that to table as child of current item with table flag and path of
            zero
	Add table name to table as child of that item with table flag and path
            of zero
   IF no itemname AND no type AND no subclass AND not imported
	Print warning
3. IF it's a comma, increment the item count ('did')
   ELSE
     	IF have a stream for a subordinate item
	    Copy all its contents to main stream
	    Mark new stream emptied
        Go to GLOBAL state
*/
    int child,
        tmp;
    static long did = 0;
    char *c,
        locbuf[128],
       *child_name;
    struct alt_subclass *altscp;
    long loctag;
    struct name_table *ntbp;
    /*
     * step 1
     */
    if (in_choice)
    {
        if (*itemname)
            mk_in_name(locbuf, itemname, classname);
        else if (*subclass)
        {
            mk_in_name(locbuf, subclass, classname);
            *locbuf |= 0x20;
        }
    }
    if (*defined_by)
        mk_table_child(parent, did, option);
    if (type == ASN_BOOLEAN)
        *subclass = 0;
    /*
     * step 2
     */
    if ((type < 0 && *subclass) ||
        (in_choice && *itemname && !*tablename && type != ASN_FUNCTION))
    {
        if (*subclass != '_' || tell_pos(streams.str) >= real_start)
        {
            child_name = (!*subclass
                          || (in_choice && tag >= 0)) ? locbuf : subclass;
            child =
                add_child(child_name, parent, did,
                          (child_name == subclass) ? (long)((ulong) -1) : type,
                          (option & ~(ASN_TABLE_FLAG)));
            if (tag > 0)
            {
                ntbp = &((struct name_table *)name_area.area)[child];
                if ((*ntbp->name & 0x20))
                    ntbp->tag = tag;
            }
            if (child_name == locbuf && *subclass)
                add_child(subclass, child, did, (ulong) - 1,
                          (option & ~(ASN_TABLE_FLAG)));
        }
        else
            child = 0;          /* dummy value in case used below as index */
        if (!*subclass)
        {
            if (tag == -1)
                loctag = type;
            else
                loctag = tag + ((tag >= ASN_APPL_SPEC && (explicit1 & 1)) ?
                                ASN_CONSTRUCTED : 0);
            ((struct name_table *)name_area.area)[child].tag = loctag;
        }
    }
    else
        child = parent;
    for (altscp = alt_subclassp; altscp; altscp = altscp->next)
    {
        if (*altscp->name && find_type(altscp->name) == ASN_NOTYPE)
            add_child(altscp->name, parent, did, (ulong) - 1, 0);
    }
    if (*tablename)
    {
        mk_in_name(itemname, itemname, classname);
        child = add_child(itemname, parent, did,
                          ((child == parent) ? type :
                           ((struct name_table *)name_area.area)[child].type),
                          ASN_DEFINER_FLAG);
        if (!
            (c = (char *)calloc(strlen(tablename) + strlen(classname) + 4, 1)))
            done(true, MSG_MEM);
        mk_in_name(c, tablename, classname);
        tmp = add_child(c, child, 0, (ulong) - 1, ASN_TABLE_FLAG);
        tmp = add_child(tablename, tmp, 0, (ulong) - 1, ASN_TABLE_FLAG);
        free(c);
        *tablename = 0;
    }
    if (!*itemname && type < 0 && !*subclass &&
        tell_pos(streams.str) >= real_start)
        warn(MSG_MISSING, "item name");
    /*
     * step 3
     */
    if (*token == ',')
    {
        did++;
        end_item();
    }
    else                        /* last */
    {
        if (*peek_token(0) == '(')
        {
            get_known(0, &token[2], "(");
            while (get_token(0, &token[2]) && token[2] != ')');
        }
        did = 0;
        end_definition();
    }
}

static struct name_table *find_definer(
    char *definername,
    int parent)
{
/**
Function: Finds the item in the table which is the definer, based on the
definername, which may be segmented.  On the way, it makes table entries for any
missing items.  It may call itself for later segments in definer name
Inputs:
    File descriptor for file being read
    Pointer to (segmented?) definer name
Also uses inclass, an array containing the name of the class containing the
    item which is the first segment of definer
Outputs:
    Entries in name table for any intermediate items not yet in table
Returns: Pointer to table entry for the definer
Procedure:
1. Mark off first segment
   Look for segmentIninclass in the table
   IF the name is found OR there's no more to the definer, return the pointer
2. Save the current classname, itemname and file position
   IF there's already a definition of inclass
        Go back to the definition of the inclass
        Read until the segment is found
        Add segmentIninclass as a child of the inclass
        Make the subclass the new inclass
3.      Call this function with remaining definer name
   ELSE Add segmentInclass as child of the inclass with unknown offset
   Restore saved items
   Return the name table pointer
**/
    long oldpos,
        oldtype;
    int numitems,
        oldstate,
        oldoption;
    struct name_table *ntbp;
    char *b,
       *c,
       *testname,
       *oldclass,
       *olditem,
       *oldsubclass,
       *oldtoken,
        segment[128];
    /*
     * step 1
     */
    for (c = segment; *definername && *definername != '.';
         *c++ = *definername++);
    *c = 0;
    if (*definername)
        definername++;
    if (!(testname = (char *)calloc(ASN_BSIZE + (2 * strlen(classname)) +
                                    strlen(itemname) + strlen(subclass) +
                                    strlen(token) + 8, 1)))
        done(true, MSG_MEM);
    mk_in_name(testname, segment, inclass);
    ntbp = find_name(testname);
    if (!ntbp || !ntbp->name)
    {
        /*
         * step 2
         */
        for (c = testname; *c; c++);
        c = cat((oldclass = &c[1]), classname);
        c = cat((olditem = &c[1]), itemname);
        c = cat((oldsubclass = &c[1]), subclass);
        c = cat((oldtoken = &c[1]), token);
        oldpos = tell_pos(streams.str);
        oldstate = state;
        oldoption = option;
        oldtype = type;
        if ((ntbp = find_name(inclass))->name && ntbp->pos >= 0)
        {
            fseek(streams.str, ntbp->pos, 0);
            cat(classname, inclass);
            for (numitems = 0; get_token(0, token) && *token != '}' &&
                 strcmp(token, segment);)
            {
                if (*token == ',')
                    numitems++;
            }
            if (!strcmp(token, segment))
            {
                cat(itemname, token);
                *itemname = 0;
                parent = ntbp - (struct name_table *)name_area.area;
                read_item(parent, NULL);
                ntbp = &((struct name_table *)name_area.area)
                    [add_child(testname, parent, numitems, -1, 0)];
                ntbp->pos = tell_pos(streams.str);
                if (*subclass)
                    cat(inclass, subclass);
                else if (!(b = find_class(type)))
                    done(true, MSG_UNDEF_TYPE, segment);
                else
                    cat(inclass, b);
                /*
                 * step 3
                 */
                if (*definername)
                    ntbp = find_definer(definername, parent);
                fseek(streams.str, oldpos, 0);
            }
        }
        else if (ntbp->name)
            ntbp = &((struct name_table *)name_area.area)
                [add_child
                 (testname, (ntbp - (struct name_table *)name_area.area), -1,
                  -1, 0)];
        cat(classname, oldclass);
        cat(itemname, olditem);
        cat(subclass, oldsubclass);
        cat(token, oldtoken);
        state = oldstate;
        option = oldoption;
        type = oldtype;
    }
    free(testname);
    return ntbp;
}

static struct name_table *last_false(
    struct name_table *table,
    struct name_table *ptbp)
{
/**
Function: Finds lowest generation 'false' child of ptbp, which must be false
Returns: IF there's a false child, pointer to its lowest false child
	 ELSE what a call of this function for the child returns
Procedure:
1. Find the sole child of this parent
   IF it's not false, return the parent pointer
   Return what this functions calls for the child
**/
    struct name_table *ctbp;
    struct parent *cparentp,
       *childp;
    int curr_parent = ptbp - table;
    /*
     * for(ctbp = table; ctbp->name; ctbp++)
     */
    for (childp = &ptbp->child; childp && childp->index >= 0;
         childp = childp->next)
    {
        ctbp = &table[childp->index];
        for (cparentp = &ctbp->parent; cparentp; cparentp = cparentp->next)
        {
            if (cparentp->index == curr_parent)
                break;
        }
        if (!cparentp)
            continue;
        if (!(ctbp->flags & ASN_FALSE_FLAG))
            return ptbp;
        return last_false(table, ctbp);
    }
    syntax("in last_false()");
    return (struct name_table *)0;      /* just to keep lint happy */
}

static void massage_table(
    struct name_table *table)
{
/**
Function: Completes the table by filling in the full paths for all names
Procedure:
1. Clean up DEFINED BYs whose TABLEs had not been defined at the time the
       DEFINED BY was encountered (and flag pointer items) , thus:
   FOR each item in table
	IF its name indicates a pointer, set pointer flag
	IF it's not a DEFINED BY, continue
        IF it has parent which is a definer
    	    Find the TABLE which is a child of the definer
            Make it a child of the defined
    	    Remove the definer as a parent of the defined
1.5 FOR each name in table
	FOR each of its parents, list this as a child
2. FOR each name in table that has no parent AND is not a pointer
        Mark it generation 0 and count it
   IF no name in table has no parent, do loop test
3. Starting at generation 0, FOR successive generations WHILE have another
	generation
4.	FOR each parent in that generation
	    Find a map of the parent for this generation
5.	    FOR each child of this parent
                Find a pointer to that parent
		IF none OR the child already has a map indicating a later
		    generation, continue in the FOR
		Prefix its path with its parent's path
		Set its generation to current generation + 1
		Note another generation to be done
6. FOR each name in table
	IF it is a derived TABLE
	    Look through its parents
                IF parent is a definer, set table's tag thus:
                    IF parent has a tag, to parent's tag
    		    ELSE (definer is not a universal), to grandparent's tag
                ELSE set the position of its defined parent to that of the
                    table (to make the header file entry come out right)
            Sort the parents in order of precedence
	ELSE IF it's a POINTER OR an OF item
	    IF it has any children that are false
		Trace them down (only 1 child each) to the last false one
		Mark that with the POINTER or OF flags of the main item
	    IF it's a POINTER and pointee's generation is younger than pointer's
		Make the pointee a child of the pointer (for export, if needed)
	IF item in table is FALSE
            Find its lowest false descendant
            Give all the false ancestors of that (only) descendant
		the type and tag(if they have none) of that descendant
   FOR each name in table
	IF it is a basic TABLE
            Set table's tag to parent's and parent's position to table's
**/
    struct name_table *ptbp = NULL;
    struct name_table *ctbp;
    struct name_table *lftbp;
    int curr_parent;
    int generation;
    int last;
    int lth;
    char *func = "massage_table";
    struct parent *pparentp;
    struct parent *cparentp;
    struct parent *childp;
    /*
     * step 1
     */
    for (ctbp = table; ctbp->name; ctbp++)
    {
        ctbp->child.index = -1;
        if (*ctbp->name == '_')
            ctbp->flags |= ASN_POINTER_FLAG;
        if (!(ctbp->flags & ASN_DEFINED_FLAG))
            continue;
        /*
         * ctbp is a defined item
         */
        for (cparentp = &ctbp->parent; cparentp && cparentp->index >= 0;
             cparentp = cparentp->next)
        {
            ptbp = &((struct name_table *)name_area.area)[cparentp->index];
            if (!(ptbp->flags & ASN_DEFINER_FLAG))
                continue;
            /*
             * ptbp is the (only) definer item
             */
            /*
             * cparentp is the item in the defined pointing to definer
             */
            for (lftbp = table; lftbp->name; lftbp++)
            {
                if (!(lftbp->flags & ASN_TABLE_FLAG))
                    continue;
                /*
                 * lftbp is a table item
                 */
                for (pparentp = &lftbp->parent; pparentp &&
                     pparentp->index != cparentp->index;
                     pparentp = pparentp->next);
                /*
                 * pparentp (if any) points to definer item
                 */
                if (pparentp)
                    break;
            }
            if (!lftbp->name)
            {
                cat(classname, ptbp->name);
                warn(MSG_NO_TABLE, ptbp->name);
                continue;
            }
            /*
             * lftbp is the (only) TABLE child of definer
             */
            add_child(lftbp->name, (ctbp - table), 0, -1, 0);
            if (cparentp == &ctbp->parent)
            {
                if ((pparentp = cparentp->next))
                {
                    *cparentp = *pparentp;
                    free(pparentp);
                }
                else
                    done(true, MSG_INTERNAL, func);
            }
            else
            {                   /* find the one before, pparentp */
                for (pparentp = &ctbp->parent; pparentp && pparentp->next !=
                     cparentp; pparentp = pparentp->next);
                if (!pparentp)
                    done(true, MSG_INTERNAL, func);
                pparentp->next = cparentp->next;
                free(cparentp);
                cparentp = pparentp;
            }
            break;
        }
    }
    /*
     * step 1.5
     */
    for (ctbp = table, lth = 0; ctbp->name; ctbp++, lth++)
    {
        for (cparentp = &ctbp->parent; cparentp && cparentp->index >= 0;
             cparentp = cparentp->next)
        {
            ptbp = &table[cparentp->index];
            for (pparentp = &ptbp->child;
                 pparentp->index != lth && pparentp->next;
                 pparentp = pparentp->next);
            if (pparentp->index != lth)
            {
                if (pparentp->index < 0)
                    pparentp->index = lth;
                else
                {
                    pparentp->next =
                        (struct parent *)calloc(sizeof(struct parent), 1);
                    pparentp->next->index = lth;
                }
            }
        }
    }
    /*
     * step 2
     */
    for (ctbp = table, generation = 0; ctbp->name; ctbp++)
    {
        for (cparentp = &ctbp->parent; cparentp && cparentp->index >= 0;
             cparentp = cparentp->next)
        {
            ptbp = &((struct name_table *)name_area.area)[cparentp->index];
            if (!(ptbp->flags & ASN_POINTER_FLAG))
                break;
        }
        if (!cparentp || cparentp->index < 0)
        {
            ctbp->generation = 0;
            generation++;
        }
    }
    if (!generation && loop_test(table, table, 0))
        done(true, MSG_NESTING);
    /*
     * step 3
     */
    for (generation = last = 0; generation <= last; generation++)
    {
        for (ptbp = table; ptbp->name; ptbp++)  /* step 4 */
        {
            if (ptbp->generation != generation)
                continue;
            curr_parent = ptbp - table;
            for (pparentp = &ptbp->parent, lth = 0; pparentp;
                 pparentp = pparentp->next)
            {
                if (pparentp->map_lth == generation)
                    break;
            }
            /*
             * step 5
             */
            for (childp = &ptbp->child; childp && childp->index >= 0;
                 childp = childp->next)
            {
                ctbp = &table[childp->index];
                for (cparentp = &ctbp->parent; cparentp;
                     cparentp = cparentp->next)
                {
                    if (cparentp->index != curr_parent)
                        continue;
                    if (generation > 31 && loop_test(table, ptbp, 0))
                        done(true, MSG_NESTING);
                    if (((pparentp->map_lth + 2) >> 4) >
                        (cparentp->map_lth >> 4))
                    {
                        if (!(cparentp->mymap = recalloc(cparentp->mymap,
                                                         cparentp->map_lth,
                                                         ((pparentp->map_lth +
                                                           17) & ~0xF))))
                            done(true, MSG_MEM);;
                    }
                    cparentp->mymap[pparentp->map_lth] =
                        cparentp->mymap[cparentp->map_lth - 1];
                    strncpy(cparentp->mymap, pparentp->mymap,
                            (size_t) pparentp->map_lth);
                    cparentp->map_lth = pparentp->map_lth + 1;
                    if ((last = generation + 1) > ctbp->generation)
                        ctbp->generation = last;
                }
            }
        }
    }
    for (ctbp = table; ctbp->name; ctbp++)      /* step 6 */
    {
        if ((ctbp->flags & ASN_TABLE_FLAG) && ctbp->pos < real_start)
        {
            for (cparentp = &ctbp->parent, lth = 0; cparentp;
                 cparentp = cparentp->next)
            {
                if (cparentp->index < 0)
                    continue;
                ptbp = &table[cparentp->index];
                if ((ptbp->flags & ASN_DEFINER_FLAG))
                {
                    if (ptbp->type != (long)0xFFFFFFFF)
                        ctbp->type = ptbp->type;
                    else
                        ctbp->type = table[ptbp->parent.index].type;
                    if (lth++)
                        done(true, MSG_MULTIPLE_DEFINERS, ctbp->name);
                }
                else if ((ptbp->flags & ASN_DEFINED_FLAG))
                    ptbp->pos = ctbp->pos;
            }
            sort_defineds(ctbp);;
        }
        else if ((ctbp->flags & (ASN_OF_FLAG | ASN_POINTER_FLAG)))
        {
            curr_parent = (ctbp - table);
            for (childp = &ctbp->child; childp && childp->index >= 0;
                 childp = childp->next)
            {
                ptbp = &table[childp->index];
                for (pparentp = &ptbp->parent; pparentp;
                     pparentp = pparentp->next)
                {
                    if (pparentp->index != curr_parent)
                        continue;
                    if ((ptbp->flags & ASN_FALSE_FLAG))
                        last_false(table, ptbp)->flags |=
                            ((ctbp->flags & (ASN_OF_FLAG | ASN_POINTER_FLAG)));
                }
            }
        }
        if ((ctbp->flags & ASN_FALSE_FLAG))
        {
            curr_parent = ((lftbp = last_false(table, ctbp)) - table);
            for (childp = &ctbp->child; childp && childp->index >= 0;
                 childp = childp->next)
            {
                ptbp = &table[childp->index];
                for (pparentp = &ptbp->parent; pparentp &&
                     pparentp->index != curr_parent;
                     pparentp = pparentp->next);
                if (pparentp)
                    break;
            }
            /*
             * ptbp is child of lftbp, i.e. the non-false item
             */
            if (!ptbp->name)
                done(true, MSG_NO_CHILD, lftbp->name);
            set_false(table, ptbp);
        }
    }
    for (ctbp = table; ctbp->name; ctbp++)
    {
        if ((ctbp->flags & ASN_TABLE_FLAG) && ctbp->pos >= real_start)
        {
            ptbp = &table[ctbp->parent.index];
            ctbp->type = ptbp->type;
            ptbp->pos = ctbp->pos;
        }
    }
}

static void mk_table_child(
    int parent,
    long offset,
    int option)
{
    /*
     * Procedure: 1. Add this as a child of the current parent with the
     * DEFINED flag and the, if it is in option, the OPTIONAL flag 2. IF the
     * defining object name isn't in the object table OR it appears more than
     * once, fatal error 3. IF there's a table item that is a child of the
     * defining object Make that table item also a child of this defined
     * object ELSE make this defined object a child of the definer (this will
     * be sorted out at the end when the table has been defined
     */
    int child;
    struct name_table *ntbp,
       *entbp,
       *tntbp;
    struct parent *parentp;
    if (parent < 0)
        return;
    child = add_child(defined_by, parent, offset, (ulong) ASN_CHOICE,   /* step
                                                                         * 1 */
                      (ASN_DEFINED_FLAG | (option & ASN_OPTIONAL_FLAG)));
    if (!(ntbp = find_definer(definer, parent)) || !ntbp->name)
    {
        warn(MSG_NO_TABLE, definer);
        return;
    }
    tntbp = (struct name_table *)name_area.area;
    parent = ntbp - tntbp;
    for (entbp = &tntbp[name_area.next]; tntbp < entbp; tntbp++)        /* step
                                                                         * 3 */
    {
        if (!(tntbp->flags & ASN_TABLE_FLAG))
            continue;
        for (parentp = &tntbp->parent; parentp && parentp->index != parent;
             parentp = parentp->next);
        if (parentp)
            break;
    }
    if (tntbp < entbp)
    {
        add_child(tntbp->name, child, 0, (ulong) - 1, 0);
        ntbp = &((struct name_table *)name_area.area)[child];
        ntbp->pos = tntbp->pos;
    }
    else
        add_child(defined_by, parent, offset, (ulong) ASN_CHOICE,
                  ASN_DEFINED_FLAG);
    *defined_by = 0;
}

static void set_false(
    struct name_table *table,
    struct name_table *ctbp)
{
/**
Function: Sets the type of all parents of this item which are flagged FALSE
    to this item's type.  It is recursive
Inputs: pointer to start of table
	pointer to this item in the table
**/
    struct parent *pparentp;
    struct name_table *ptbp;
    for (pparentp = &ctbp->parent; pparentp; pparentp = pparentp->next)
    {
        if (pparentp->index >= 0 &&
            ((ptbp = &table[pparentp->index])->flags & ASN_FALSE_FLAG))
        {
            ptbp->type = ctbp->type;
            if (ptbp->tag == (long)0xFFFFFFFF)
                ptbp->tag = ctbp->tag;
            set_false(table, ptbp);
        }
    }
}

static void copy_parent(
    struct parent *to,
    struct parent *from)
{
    to->index = from->index;
    to->map_lth = from->map_lth;
    to->mymap = from->mymap;
}

static void sort_defineds(
    struct name_table *ntbp)
{
    struct parent tparent;
    struct parent *parentp = NULL;
    struct parent *nparentp;
    struct parent *pparentp = NULL;
    do
    {
        for (nparentp = (parentp = &ntbp->parent)->next;
             nparentp && strcmp(parentp->mymap, nparentp->mymap) <= 0;
             pparentp = parentp, nparentp = (parentp = parentp->next)->next);
        if (nparentp)
        {
            if (parentp == &ntbp->parent)
            {
                copy_parent(&tparent, parentp);
                copy_parent(parentp, nparentp);
                copy_parent(nparentp, &tparent);
            }
            else
            {
                pparentp->next = nparentp;
                parentp->next = nparentp->next;
                nparentp->next = parentp;
            }
        }
    }
    while (nparentp);
}
