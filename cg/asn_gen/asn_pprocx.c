/*
 * $Id$ 
 */
/*****************************************************************************
File:     asn_pprocx.c
Contents: Functions to do all pre-processing sub-functions as part of the
          ASN_GEN program.
System:   ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

*****************************************************************************/

const char asn_pprocx_rcsid[] =
    "$Header: /nfs/sub-rosa/u1/IOS_Project/ASN/Dev/rcs/cmd/asn_gen/asn_pproc.c,v 1.1 1995/01/11 22:43:11 jlowry Exp gardiner $";
char asn_pprocx_id[] = "@(#)asn_pprocx.c 828P";

#include "asn_gen.h"

/*
 * values used by what_type and class_instance 
 */
#define TYP_REF  1
#define VAL_REF  2
#define VERB    -1

extern struct import_table *imtbp;
               /*
                * pointer to entry for imported file currently being read 
                */

extern FILE *make_substr(
    char *);

extern void empty_substr(
    FILE *,
    FILE *,
    char *,
    int,
    char *);

static int collect_args(
    int,
    char ***),
    what_type(
    char *);

static void append_name(
    char **,
    char *),
    do_macro_from_string(
    FILE *,
    struct macro_table *,
    char **),
    find_class_item(
    char *,
    struct class_table *,
    struct with_syntax *,
    char *),
    insert_name(
    char *,
    long);

static char *copy_word(
    char *,
    char *),
   *extend_buf(
    char *,
    char **,
    int),
   *fill_id_type(
    char *,
    struct class_table *,
    FILE *),
   *scan_known(
    char *,
    char *),
   *scan_must(
    char *,
    char *),
   *skip_word(
    char *);

struct chain *add_chain(
    struct chain *chp,
    size_t siz)
{
    while (chp->next)
        chp = chp->next;
    if (!(chp->next = (struct chain *)calloc(siz, 1)))
        fatal(7, (char *)0);
    return chp->next;
}

int add_class_def(
    int fd)
{
/**
Function: Adds to the class table the definition of a class, e.g.
    TYPE-IDENTIFIER ::= CLASS { ... }
    WITH SYNTAX { ... }
This is called from pre_proc_def when the word CLASS is detected
Procedure:
1. IF this class has already been defined, error
   Get the next member of the table and fill in the name
2. Fill in the class definitions up to the right brace
	IF the first item in the table is full, add a new one
        First get the item name and put that in the item name
	Then get the remainder (which may be several words concatenated) and
	    put themn into the predicate
3. Check that there is then "WITH SYNTAX {"
   Fill in the syntax up to the right brace
	IF the first item in the table is full, add a new one
	IF the first token is '[', set the optional flag and get next token
	IF token is '&' get the next token as the subject and get another
	Append succeeding tokens UNTIL a '&' is reached
        Write that as the verb
	Get the next token as the object
	IF item is optional, get the terminal ']'
4. Return GLOBAL state
**/
    struct class_table *ctbp;
    struct class_item *citp;
    struct with_syntax *wsxp;
    uchar *c,
        savec;
    /*
     * step 1 
     */
    for (ctbp = (struct class_table *)class_area.area; ctbp && ctbp->name &&
         strcmp(classname, ctbp->name); ctbp++);
    if (ctbp && ctbp->name)
        fatal(17, classname);
    ctbp = (struct class_table *)expand_area(&class_area);
    fill_name(&ctbp->name, classname);
    get_known(fd, token, "{");
    /*
     * step 2 
     */
    for (savec = 0; savec != '}';)
    {
        get_known(fd, token, "&");
        get_must(fd, token);
        if (!ctbp->item.name)
            citp = &ctbp->item;
        else
            citp = (struct class_item *)add_chain((struct chain *)&ctbp->item,
                                                  sizeof(struct class_item));
        fill_name(&citp->name, token);
        for (c = (uchar *) token, savec = 0; !savec;)
        {
            get_must(fd, (char *)c);
            if (*c == ',' || *c == '}')
            {
                savec = *c;
                *c = 0;
            }
            else
            {
                while (*c)
                    c++;
                *c++ = ' ';
            }
        }
        fill_name(&citp->predicate, token);
    }
    /*
     * step 3 
     */
    for (*token = 0; *token <= ' ';)
    {
        get_must(fd, token);
    }
    if (strcmp(token, with_w))
        syntax(token);
    get_known(fd, token, syntax_w);
    get_known(fd, token, "{");
    while (1)
    {
        get_must(fd, token);
        if (*token == '}')
            break;
        if (!ctbp->with_syntax.verb)
            wsxp = &ctbp->with_syntax;
        else
            wsxp = (struct with_syntax *)add_chain((struct chain *)&ctbp->
                                                   with_syntax,
                                                   sizeof(struct with_syntax));
        if (*token == '[')
        {
            wsxp->optional = 1;
            get_must(fd, token);
        }
        if (*token == '&')
        {
            get_must(fd, token);
            fill_name(&wsxp->subject, token);
            get_must(fd, token);
        }
        for (c = (uchar *) token; *c; c++);
        *c++ = ' ';
        do
        {
            get_must(fd, (char *)c);
            if (*c != '&')
            {
                while (*c)
                    c++;
                *c++ = ' ';
                *c = 0;
            }
        }
        while (*c != '&');
        c[-1] = 0;
        fill_name(&wsxp->verb, token);
        get_must(fd, token);
        fill_name(&wsxp->object, token);
        if (wsxp->optional)
            get_known(fd, token, "]");
    }
    return GLOBAL;
}

void add_class_member(
    struct class_table *ctbp,
    char *name)
{
    struct class_table *nctbp;
    if ((nctbp = find_class_entry(name)))
        fatal(17, name);
    nctbp = (struct class_table *)expand_area(&class_area);
    fill_name(&nctbp->name, name);
    nctbp->item.next = ctbp->item.next; /* inherit item structure */
    nctbp->item.name = ctbp->item.name;
    nctbp->item.predicate = ctbp->item.predicate;
    nctbp->with_syntax.next = ctbp->with_syntax.next;   /* and syntax */
    nctbp->with_syntax.optional = ctbp->with_syntax.optional;
    nctbp->with_syntax.subject = ctbp->with_syntax.subject;
    nctbp->with_syntax.verb = ctbp->with_syntax.verb;
    nctbp->with_syntax.object = ctbp->with_syntax.object;
}

struct import_table *add_import_item(
    struct import_table *timtbp,
    char *itemname)
{
/**
Function: Adds an item to the import table
Inputs: Pointer to current element in import table.  IF this is null, add
    another element to table and use that
Outputs: import_item is added to the current element in table
Returns: Pointer to current element
Procedure:
1. IF no current element, get the next one in the table
   ELSE append another item at the end of the chaun
2. Put the name in that new item
   Return the element pointer
**/
    struct import_item *itemp = &timtbp->item;
    /*
     * step 1 
     */
    if (!timtbp)
    {
        timtbp = (struct import_table *)expand_area(&import_area);
        itemp = &timtbp->item;
    }
    else if (itemp->objname)
    {
        while (itemp->next)
            itemp = itemp->next;
        if (!(itemp->next =
              (struct import_item *)calloc(sizeof(struct import_item), 1)))
            fatal(7, (char *)0);
        itemp = itemp->next;
    }
    /*
     * step 2 
     */
    fill_name(&itemp->objname, itemname);
    return timtbp;
}

static char in_name[128] = "\
nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn\
nnnnnnnnnnnnnnnnyyyyyyyyyynnnnnn\
nyyyyyyyyyyyyyyyyyyyyyyyyyynnnnn\
nyyyyyyyyyyyyyyyyyyyyyyyyyynnnnn";

void add_macro(
    int fd,
    char *name)
{
/**
Function: Adds a macro and its definition to the table, provided it is in the
main file or is imported
Procedure:
1. IF in main file OR macro is imported
        Add a macro to the table
        Fill in its name
   Collect argument list
2. Collect all the outputs, examining each token
	IF token does not match one in the argument list, append it to
	    string collected so far
	ELSE fill in next macro_item with string-so-far-%s and index of
	    matched argument
3. IF macro is for real
        Fill in the last macro_item
4.      IF there's a constraint, add that to the macro
**/
    int count,
        braces,
        mac_size,
        parens,
        got_def;
    size_t lth,
        size;
    struct macro_table *mtbp;
    char *macbuf,
       *c,
      **argpp,
       *b,
       *d;
    struct macro_item *mitp;
    /*
     * step 1 
     */
    macbuf = (char *)calloc((mac_size = 100), 1);
    if (!fd || is_imported(name))
    {
        mtbp = (struct macro_table *)expand_area(&macro_area);
        mitp = &mtbp->item;
        fill_name(&mtbp->name, name);
    }
    else
        mtbp = (struct macro_table *)0;
    count = collect_args(fd, &argpp);
    if (mtbp)
        mtbp->arg_count = count;
    else
        free((char *)argpp);
    /*
     * step 2 
     */
    get_known(fd, token, colon_ch);
    get_known(fd, token, colon_ch);
    get_known(fd, token, equal_ch);
    for (braces = parens = got_def = 0, c = macbuf; braces || *token != '}';)
    {
        get_must(fd, token);
        count = -1;
        if (*token == ',' || (*token == '{' && !braces))
            cat(&token[1], "\n");
        if (*token == '{')
            braces++;
        else if (*token == '}')
            braces--;
        else if (mtbp && !is_reserved(token))
        {
            for (b = token; *b; b++)
            {
                if (*b == '.')
                    continue;
                for (d = &b[1]; in_name[(int)*d] == 'y'; d++);
                for (count = mtbp->arg_count; --count >= 0;)
                {
                    lth = strlen(argpp[count]);
                    if (d == &b[lth] && !strncmp(argpp[count], b, lth))
                        break;
                }
                if (count >= 0)
                    break;
            }
            if (*token == '(')
                parens++;
            if (count < 0 && !parens && !braces && got_def++)
                break;
            if (*token == ')')
                parens--;
        }
        while (&c[strlen(token) + 4] >= &macbuf[mac_size])
            macbuf = extend_buf(macbuf, &c, (mac_size += 100));
        if (count >= 0)
        {
            if (b > token)
            {
                *b = 0;
                c = cat(cat(c, " "), token);
            }
            c = cat(c, " %s");
            if (mitp->prefix)
                mitp =
                    (struct macro_item *)add_chain((struct chain *)mitp,
                                                   sizeof(struct macro_item));
            fill_name(&mitp->prefix, &macbuf[1]);       /* skip initial space */
            *(c = macbuf) = 0;
            mitp->index = count;
        }
        else if (*token != '\n' || c[-1] != '\n')
            c = cat(cat(c, " "), token);
    }
    if (*token == '}')
        *token = 0;             /* had terminating braces */
    /*
     * step 3 
     */
    if (mtbp)
    {
        mitp = (struct macro_item *)add_chain((struct chain *)mitp,
                                              sizeof(struct macro_item));
        fill_name(&mitp->prefix, &macbuf[1]);
        mitp->index = -1;       /* makes no difference, since it has no %s */
        free((char *)argpp);
        /*
         * step 4 
         */
        if (!*token && *peek_token(fd) == '(')
        {
            if (!(b = c = (char *)calloc((size = 32), 1)))
                fatal(7, (char *)0);
            get_known(fd, c++, "(");
            *c++ = ' ';
            for (get_must(fd, token); 1; get_must(fd, token))
            {
                while (size <= strlen(token) + (c - b) + 1)
                    b = extend_buf(b, &c, size += 32);
                c = cat(cat(c, token), " ");
                if (*token == ')')
                    break;
            }
            mitp = (struct macro_item *)add_chain((struct chain *)mitp,
                                                  sizeof(struct macro_item));
            mitp->prefix = b;
            mitp->index = -1;
        }
    }
    free(macbuf);
}

static void append_name(
    char **pp,
    char *val)
{
    char *c,
        locbuf[80];
    size_t lth;
    for (c = val; *c > ' '; c++);
    strncpy(locbuf, val, (lth = (c - val)));
    locbuf[lth] = 0;
    if (!*pp)
        fill_name(pp, locbuf);
    else
    {
        for (c = locbuf; *c > ' '; c++);
        if (!(*pp = (char *)realloc(*pp, (strlen(*pp) + lth + 2))))
            fatal(7, (char *)0);
        cat(cat(&(*pp)[strlen(*pp)], " "), val);
    }
}

void class_instance(
    int fd,
    FILE * str,
    struct class_table *ctbp,
    char *item)
{
/**
Function: Translates syntax of an item in a class into a table entry for later
output   NOTE: Assumes opening brace has been read
Procedure:
1. IF the first syntax entry is empty but has a next, go to that
2. FOR all tokens up to terminal brace
	Get next token
	IF its type is the same as the current type OR
            (current type is not VERB AND (within braces OR parens)
	    IF it's a '{' AND in TYP_REF
		IF local buffer is a macro
		    Do the macro substitution
		    Replace local buffer with capitalized item
		    Decrement brace count
		ELSE undefined macro error
	    ELSE
                Append it to local buffer
		IF current type is VAL_REF AND locbuf begins with '{'
		    Replace locbuf with completed object ID
		    Set token to terminal brace
	ELSE
            IF current type is VERB
    	        IF buffer doesn't match syntax verb, error
	    ELSE IF current type is TYP-REF OR VAL_REF
    	        Save local buffer as type-ref or val-ref
    	    Set current type
	    Clear local buffer
3. IF there's a subject but no id OR object but no value, syntax error
   Find item in table list(s)
   Put Type-reference and value-reference into appropriate places
   Return GLOBAL
**/
    struct with_syntax *wsxp = &ctbp->with_syntax;
    struct table_entry *tbep = 0;
    struct table_out *tbop;
    struct macro_table *mtbp;
    int curr_typ,
        typ,
        braces,
        parens,
        do_it = (!fd || is_imported(item));
    char *nouns[2],
        locbuf[128],
       *c,
       *b;
    /*
     * step 1 
     */
    nouns[0] = nouns[1] = 0;
    if (!wsxp->verb)
        wsxp = wsxp->next;
    if (!wsxp)
        fatal(20, "syntax entry");
    /*
     * step 2 
     */
    for (braces = 1, parens = 0, curr_typ = -2, c = locbuf; braces || parens;)
    {
        get_must(fd, token);
        if (*token < ' ')
            continue;
        if (*token == '{')
            braces++;
        else if (*token == '(')
            parens++;
        if (do_it && (((typ = what_type(token)) && typ == curr_typ) ||
                      (curr_typ != VERB && (parens || braces > 1))))
        {
            if (*token == '{' && curr_typ == TYP_REF)
            {
                if ((mtbp = find_macro(locbuf)))
                {
                    do_macro(fd, str, mtbp);
                    cat(locbuf, item);
                    *locbuf &= ~(0x20);
                    braces--;
                }
                else
                    fatal(27, locbuf);
            }
            else if (curr_typ != VAL_REF && *locbuf != '{')
                c = cat(cat(c, " "), token);
            else
            {
                cat(locbuf, token);
                cat(locbuf, get_obj_id(fd, locbuf, (char *)0));
                cat(token, "}");
                curr_typ = typ;
            }
        }
        else if (do_it)
        {
            if (curr_typ == VERB)
            {
                while (wsxp && strcmp(locbuf, wsxp->verb))
                {
                    if (wsxp->table_outp)
                        find_class_item(item, ctbp, wsxp, nouns[1]);
                    wsxp = wsxp->next;
                }
                if (!wsxp)
                    fatal(20, locbuf);
            }
            else
            {
                if (*locbuf == '{' && braces == 1)
                {
                    for (b = locbuf; *b == '{' || *b == ' '; b++)
                    {
                        if (*b == '{')
                        {
                            while (*(--c) == ' ');
                            if (*c != '}')
                                syntax(c);
                            *c = 0;
                        }
                    }
                    for (cat(locbuf, b); *(--c) == ' '; *c = 0);
                    curr_typ = what_type(locbuf);
                }
                if (curr_typ > 0)
                    fill_name(&nouns[curr_typ - TYP_REF], locbuf);
            }
            curr_typ = typ;
            c = cat(locbuf, token);
        }
        if (*token == '}')
            braces--;
        else if (*token == ')' && --parens < 0)
            syntax(token);
    }
    /*
     * step 3 
     */
    if (do_it)
    {
        if ((wsxp->subject && !nouns[0]) || (wsxp->object && !nouns[1]))
            fatal(20, (!*nouns) ? "Type" : "id");
        for (tbop = &ctbp->table_out; tbop; tbop = tbop->next)
        {
            for (tbep = &tbop->table_entry;
                 tbep && tbep->item && strcmp(tbep->item, item);
                 tbep = tbep->next);
            if (tbep)
            {
                if (!tbep->item)
                    fill_name(&tbep->item, item);
            }
            else if (!do_it)
                break;          /* did one; have no more */
            else
                continue;       /* none here; keep trying */
            if (nouns[0])
                append_name(&tbep->value, nouns[0]);
            if (nouns[1])
                append_name(&tbep->id, nouns[1]);
            do_it = 0;          /* did one */
        }
    }
    end_definition();
}

static int collect_args(
    int fd,
    char ***argppp)
{
    size_t count;
    char **argpp = (char **)0;
    struct class_table *ctbp;
    int braces;
    for (get_must(fd, token), braces = count = 0; *token != '}' || braces;
         get_must(fd, token))
    {
        if (*token == ',' || *token == '{' || *token == '}')
        {
            if (*token == '{')
                braces++;
            else if (*token == '}')
                braces--;
            continue;
        }
        if (find_type(token) != ASN_NOTYPE || (ctbp = find_class_entry(token)))
        {
            get_known(fd, token, colon_ch);
            get_must(fd, token);
        }
        if ((!count && !(argpp = (char **)calloc(sizeof(char *), 1))) ||
            (argpp
             && !(argpp =
                  (char **)realloc((char *)argpp,
                                   sizeof(char *) * (count + 1)))))
            fatal(7, (char *)0);
        fill_name(&argpp[count++], token);
    }
    *argppp = argpp;
    return count;
}

void collect_ids(
    int fd,
    struct class_table *ctbp,
    FILE * str)
{
/**
Function: Collects supported IDs for a class
Procedure:
1. Find the table_out that has the name of classname
   Set the table_entry pointer to that
   Get the opening brace
   WHILE still within braces
	Get next token
	IF it's left brace, up braces count
	ELSE IF it's right brace, drop brace count
	ELSE IF it's not '|', add it to the list of supported IDs
**/
    struct table_entry *tbep;
    struct table_out *tbop;
    int braces,
        item;
    char locbuf[12];
    /*
     * step 1 
     */
    for (tbop = &ctbp->table_out; tbop && tbop->table_name &&
         strcmp(tbop->table_name, classname); tbop = tbop->next);
    if (!tbop)
        syntax(token);
    tbep = &tbop->table_entry;
    get_known(fd, token, "{");
    for (braces = item = 1; braces;)
    {
        get_must(fd, token);
        if (*token == '{')
        {
            sprintf(locbuf, "item%d", item++);
            class_instance(fd, str, ctbp, locbuf);
        }
        else if (*token == '}')
            braces--;
        else if (*token != '|' && *token != ',' && *token != '.')
        {
            if (tbep->item)
                tbep = (struct table_entry *)add_chain((struct chain *)tbep,
                                                       sizeof(struct
                                                              table_entry));
            fill_name(&tbep->item, token);
        }
    }
    end_definition();
}

void collect_id_type(
    int fd,
    struct class_table *ctbp,
    FILE * str)
{
/**
Function: Collects data for references to a class, such as
    algorithm  ALGORITHM.&id ( { SupportedAlgorithms } ),
    parameters ALGORITHM.&Type ( { SupportedAlgorithms } {@algorithm} }
Called from pre_proc_item after the class name has been encountered
Procedure:
1. IF the class table doesn't have a verb in its first or second syntax entry,
	error  (First one may be empty in the case of a derived class)
   Get the '&' and membername,   Search the syntax list looking for a subject or object that matches the
	membername
   IF none, error
   IF the next token will be left parenthesis
        Get the lparen, the lbrace, the table name, the rbrace and the next token
        IF that token is lbrace
    	    Get the '@', the ID name and the rbrace
        Get the final rparen
2. Call fill_id_type.
**/
    char *c,
        locbuf[128],
       *tbuf;
    int tbuf_size;
    struct with_syntax *wsxp = &ctbp->with_syntax;
    /*
     * step 1 
     */
    if (!wsxp->verb)
        fatal(20, "syntax table");
    if (!ctbp->instance_name)
        fill_name(&ctbp->instance_name, classname);
    c = tbuf = (char *)calloc((tbuf_size = 40), 1);
    get_known(fd, token, "&");
    get_must(fd, token);        /* membername */
    c = cat(cat(c, " &"), token);
    while (wsxp && (!wsxp->subject || strcmp(token, wsxp->subject)) &&
           (!wsxp->object || strcmp(token, wsxp->object)))
        wsxp = wsxp->next;
    if (!wsxp)
        fatal(28, token);
    if (*peek_token(fd) == '(')
    {
        get_known(fd, token, "(");
        get_known(fd, token, "{");
        c = cat(c, " ( { ");
        while (&c[strlen(token)] > &tbuf[tbuf_size - 10])
            tbuf = extend_buf(tbuf, &c, tbuf_size += 50);
        get_must(fd, token);    /* table name */
        while (&c[strlen(token)] > &tbuf[tbuf_size - 10])
            tbuf = extend_buf(tbuf, &c, tbuf_size += 50);
        get_known(fd, locbuf, "}");
        get_must(fd, locbuf);
        c = cat(cat(cat(c, token), " } "), locbuf);
        if (*locbuf == '{')
        {
            get_known(fd, locbuf, "@");
            get_must(fd, locbuf);       /* ID name */
            while (&c[strlen(token)] > &tbuf[tbuf_size - 10])
                tbuf = extend_buf(tbuf, &c, tbuf_size += 50);
            c = cat(cat(c, " @ "), locbuf);
            get_known(fd, locbuf, "}");
            get_known(fd, locbuf, ")");
            c = cat(c, " } ) ");
        }
    }
    fill_id_type(tbuf, ctbp, str);
    free(tbuf);
}

char *copy_word(
    char *to,
    char *from)
{
    while (*from > ' ')
        *to++ = *from++;
    *to = 0;
    return to;
}

void do_macro(
    int fd,
    FILE * str,
    struct macro_table *mtbp)
{
/**
Function: Makes necessary substitutions for a macro and prints the resulting
code
Procedure
1. Print the classname
   Collect the arguments
2. Call do_macro_from_string
**/
    char **argpp,
        locbuf[80];
    int count;
    /*
     * step 1 
     */
    cat(locbuf, classname);
    *locbuf &= ~(0x20);         /* capitalize name */
    fprintf(str, "%s ::= ", locbuf);
    if (*token != '{')
        get_must(fd, token);
    if (*token != '{')
        fatal(26, few_w);
    if ((count = collect_args(fd, &argpp)) != mtbp->arg_count)
        fatal(26, (count > mtbp->arg_count) ? many_w : few_w);
    /*
     * step 2 
     */
    do_macro_from_string(str, mtbp, argpp);
    free((char *)argpp);
}

void do_macro_from_string(
    FILE * str,
    struct macro_table *mtbp,
    char **argpp)
{
/**
Function: Makes necessary substitutions for a macro and puts the resulting
code in a mallocked string
Procedure
2. FOR each macro_item
	Scan the prefix word by word
    	    IF there's a class name
		IF haven't a class yet, use this one
		Print the remains of the prefix with the appropriate arg
		Skip to the end of the current prefix
    	    ELSE IF there's a macro
		Get the string from that
		Append it to the buffer
		IF the next item's prefix is '}', skip to next item
		ELSE skip to the end of the current prefix
	    ELSE copy the word to the buffer
3. FOR all the temp buffer
	IF at an '&'
	    Call fill_id_type
	    Print the stuff it puts im token
	Skip to the next '&'
	Print the stuff in between
**/
    char *a,
       *b,
       *c,
       *argp,
       *tbuf,
        savec,
        locbuf[80],
        subfilename[80],
      **locargpp = (char **)0;
    int count,
        arg_num,
        old_arg_num,
        tbufsize;
    struct macro_item *mitp;
    struct class_table *ctbp,
       *tctbp;
    struct macro_table *tmtbp;
    FILE *substr = (FILE *) 0;
    /*
     * step 1 
     */
    c = tbuf = (char *)calloc((tbufsize = 50), 1);
    for (mitp = &mtbp->item, ctbp = (struct class_table *)0; mitp;
         mitp = mitp->next)
    {
        argp = (mitp->index >= 0) ? argpp[mitp->index] : "";
        for (b = mitp->prefix; *b && *b <= ' '; b++);
        for (; *b; b = skip_word(b))
        {
            if ((tctbp = find_class_entry(b)))
            {
                if (!ctbp)
                    ctbp = tctbp;
                a = skip_word(b);
                a--;            /* prepend a space */
                count = 4 + strlen(a) + strlen(argp);
                if (&c[count] >= &tbuf[tbufsize])
                    tbuf = extend_buf(tbuf, &c, tbufsize += count);
                sprintf(c, a, argp);
                while (*c)
                    c++;
                while (*b)
                    b++;
            }
            else if ((tmtbp = find_macro(b)))
            {
                cat(locbuf, classname);
                copy_word(c, b);
                mk_in_name(classname, c, locbuf);
                count = 1 + strlen(classname) + 2;
                while (&c[count] >= &tbuf[tbufsize])
                    tbuf = extend_buf(tbuf, &c, (tbufsize += count));
                cat(copy_word(cat(c, " "), classname), " ");
                fprintf(str, (c = tbuf));
                if (!substr)
                    substr = make_substr(subfilename);
                c = cat(cat(tbuf, classname), " ::= ");
                fprintf(substr, (c = tbuf));
                *tbuf = 0;
                b = skip_word(b);
                if (*b == '{')
                {
                    locargpp =
                        (char **)calloc(sizeof(char *), tmtbp->arg_count);
                    for (b = skip_word(b), count = 1, arg_num = old_arg_num =
                         0; *b && (count > 1 || *b != '}'); b = skip_word(b))
                    {
                        if (*b == '{')
                            count++;
                        else if (*b == '}')
                            count--;
                        else if (*b == '(')
                            count += 20;
                        else if (*b == ')')
                            count -= 20;
                        else if (*b && *b < ' ')
                            b++;
                        else if (*b == '%' && b[1] == 's')
                            locargpp[arg_num++] = argpp[old_arg_num++];
                        else if (*b > ' ')
                        {
                            if (arg_num >= tmtbp->arg_count)
                                fatal(26, many_w);
                            for (a = b; *a > ' '; a++);
                            locargpp[arg_num] = (char *)calloc((&a[1] - b), 1);
                            strncpy(locargpp[arg_num++], b, (a - b));
                        }
                    }
                    if (arg_num < tmtbp->arg_count)
                        fatal(26, few_w);
                }
                if (locargpp)
                    argpp = locargpp;
                do_macro_from_string(substr, tmtbp, argpp);
                if (mitp->next && mitp->next->prefix
                    && *mitp->next->prefix == '}')
                    mitp = mitp->next;
            }
            else
            {
                for (a = b; *b > ' ' || *b == '\n'; b++);
                savec = *b;
                *b = 0;
                count = 1 + strlen(a) + strlen(argp);
                if (&c[count] >= &tbuf[tbufsize])
                    tbuf = extend_buf(tbuf, &c, (tbufsize += count));
                *c++ = ' ';
                sprintf(c, a, argp);
                *b = savec;
                while (*c)
                    c++;
                *c = 0;
            }
        }
    }
    /*
     * step 3 
     */
    for (c = tbuf; *c;)
    {
        if (*c == '&')
        {
            if (ctbp)
            {
                c = fill_id_type(c, ctbp, str);
                fprintf(str, token);
            }
            else
                c++;
        }
        for (b = c; *c && *c != '&'; c++);
        savec = *c;
        *c = 0;
        fprintf(str, b);
        *c = savec;
    }
    fprintf(str, "\n\n");
    if (substr)
        empty_substr(str, substr, tbuf, tbufsize, subfilename);
    free(tbuf);
    if (locargpp)
        free(locargpp);
    *token = 0;
}

int encr_xform(
    int fd,
    char *loctoken)
{
/**
Procedure:
1. Get next token (to discard)
   IF it's a known type, get its expected sequel
   Put BIT STRING into token
**/
    long tmp;
    get_must(fd, loctoken);
    if ((tmp = find_type(loctoken)) != ASN_NOTYPE)
        get_expected(fd, tmp, loctoken);
    insert_name(loctoken, ASN_BITSTRING);
    return ASN_BITSTRING;
}

char *extend_buf(
    char *buf,
    char **ebuf,
    int lth)
{
    char *c;
    if (!(c = realloc(buf, lth)))
        fatal(7, (char *)0);
    *ebuf += (c - buf);
    return c;
}

char *fill_id_type(
    char *string,
    struct class_table *ctbp,
    FILE * str)
{
/**
Function: Translates references to a class, such as
    algorithm  ALGORITHM.&id ( { SupportedAlgorithms } ),
    parameters ALGORITHM.&Type ( { SupportedAlgorithms } {@algorithm} }
Called from collect_id_type or do_macro
Procedure:
1. Get the '&' and membername,   Search the syntax list looking for a subject or object that matches the
	membername
   IF the next token will not be left parenthesis, translate the name & return
   Get the lparen, the lbrace, the table name, the rbrace and the next token
   IF that token is lbrace
	Get the '@', the ID name, the rbrace and the final rparen
2. IF there is an @item, i.e. it's a DEFINED BY
	IF the syntax entry's table name doesn't match the last item, error
	Get the ')', the '{', the '@' and the ID name
	IF the predicate isn't a boolean, bit string OR octet string, use "ANY"
	ELSE use the predicate
	Copy that into token followed by " DEFINED BY" and the ID name
   ELSE i.e. it's a definer
	Put the item into the table
	Copy into token "OBJECT IDENTIFIER TABLE" followed by the table name
3. Set the syntax entry's table pointer
**/
    char *c,
        locbuf[128],
        tbname[64];
    ulong tmp;
    struct with_syntax *wsxp = &ctbp->with_syntax;
    struct table_out *tbop;
    struct class_item *citp;
    /*
     * step 1 
     */
    if (!wsxp->verb)
        fatal(20, "syntax table");
    if (!ctbp->instance_name)
        fill_name(&ctbp->instance_name, classname);
    string = scan_known(string, "&");
    string = scan_must(string, locbuf);
    while (wsxp && (!wsxp->subject || strcmp(locbuf, wsxp->subject)) &&
           (!wsxp->object || strcmp(locbuf, wsxp->object)))
        wsxp = wsxp->next;
    if (!wsxp)
        fatal(28, string);
    while (*string && *string <= ' ')
        string++;
    if (*string != '(')
    {
        for (citp = &ctbp->item; citp && strcmp(citp->name, wsxp->object);
             citp = citp->next);
        if (!citp)
            fatal(28, wsxp->object);
        for (c = citp->predicate; *c && !is_reserved(c);)
        {
            while (*c > ' ')
                c++;
            while (*c && *c <= ' ')
                c++;
        }
        if ((*c & 0x20))
            fprintf(str, any_w);
        else
            fprintf(str, citp->predicate);
        return string;
    }
    string = scan_known(string, "(");
    string = scan_known(string, "{");
    string = scan_must(string, tbname);
    string = scan_known(string, "}");
    string = scan_must(string, locbuf);
    if (*locbuf == '{')
    {
        string = scan_known(string, "@");
        string = scan_must(string, locbuf);     /* ID name */
        for (c = locbuf; *c; c++);
        string = scan_known(string, "}");       /* throw away 2 */
        string = scan_known(string, ")");
    }
    else
        *locbuf = 0;            /* no @ item */
    /*
     * step 2 
     */

    if ((ctbp->with_syntax.next || wsxp->subject))
    {
        for (tbop = &ctbp->table_out; tbop && tbop->table_name &&
             strcmp(tbname, tbop->table_name); tbop = tbop->next);
        if (!tbop)
            tbop = (struct table_out *)add_chain((struct chain *)&ctbp->
                                                 table_out,
                                                 sizeof(struct table_out));
        if (!tbop->table_name)
            fill_name(&tbop->table_name, tbname);
    }
    if (*locbuf)
    {
        if (!(citp = &ctbp->item)->name)
            citp = citp->next;
        if (!citp)
            fatal(28, tbname);
        while (citp && strcmp(citp->name, wsxp->object))
            citp = citp->next;
        for (c = citp->predicate; *c > ' '; c++);
        if (!*c)
            tmp = find_type(citp->predicate);
        else
        {
            *c = 0;
            tmp = find_type(citp->predicate);
            *c = ' ';
        }
        if (tmp != ASN_BOOLEAN && tmp != ASN_OCTETSTRING
            && tmp != ASN_BITSTRING)
            c = "ANY";
        else
            c = citp->predicate;
        sprintf(token, "%s DEFINED BY %s IN %s", c, locbuf, classname);
    }
    else                        /* it's an identifier */
    {
        if (ctbp->with_syntax.next || wsxp->subject)
        {
            cat(cat(token, "OBJECT IDENTIFIER TABLE "), tbop->table_name);
        }
    }
    /*
     * step 3 
     */
    wsxp->table_outp = &ctbp->table_out;
    return string;
}

void fill_name(
    char **to,
    char *from)
{
    if (*to)
        free(*to);
    if (!(*to = (char *)calloc(strlen(from) + 1, 1)))
        fatal(7, (char *)0);
    cat(*to, from);
}

void fill_table_entry(
    int fd,
    int index)
{
/**
Function: Fills in one or more table entries
Inputs: Descriptor for input file
	Index of current class in table
Procedure:
1. Find a free table item in the class's table_out
   Copy the classname there as the item
2. Search all the with_syntax entries for ones that point to a table
	Read the input file until the definition of the syntax is found
	IF the subject or object in the syntax entry is a value-identifier
	    Fill in the id field
	IF the subject or object in the syntax entry is a type-identifier
	    IF the value field is full, chain on another table entry
	    Fill in the value field
3. IF the first table item now has a successor, copy the ID to all successors
**/
    char *idp,
       *valp;
    struct class_table *ctbp = &((struct class_table *)class_area.area)[index];
    struct with_syntax *wsxp,
        tsx;
    struct table_entry *ftbp,
       *xtbp;
    /*
     * step 1 
     */
    if ((ftbp = &ctbp->table_out.table_entry)->id)
        ftbp = (struct table_entry *)add_chain((struct chain *)ftbp,
                                               sizeof(struct table_entry));
    fill_name(&ftbp->item, classname);
    /*
     * step 2 
     */
    for (wsxp = &ctbp->with_syntax; wsxp; wsxp = wsxp->next)
    {
        scan_syntax(fd, wsxp, &tsx);
        idp = valp = (char *)0;
        if (wsxp->subject)
        {
            if ((*(wsxp->subject) & 0x20))
                idp = tsx.subject;
            else
                valp = tsx.subject;
        }
        if (wsxp->object)
        {
            if ((*(wsxp->object) & 0x20))
                idp = tsx.object;
            else
                valp = tsx.object;
        }
        if (idp)
            fill_name(&ftbp->id, idp);
        if (valp)
        {
            if ((xtbp = ftbp)->value)
                xtbp = (struct table_entry *)add_chain((struct chain *)xtbp,
                                                       sizeof(struct
                                                              table_entry));
            fill_name(&xtbp->value, valp);
        }
        if (tsx.subject)
            free(tsx.subject);
        if (tsx.object)
            free(tsx.object);
        free(tsx.verb);
    }
    /*
     * step 3 
     */
    for (xtbp = ftbp; xtbp->next; xtbp = xtbp->next)
        fill_name(&xtbp->next->id, xtbp->id);
}

struct class_table *find_class_entry(
    char *name)
{
    struct class_table *ctbp;
    char *c,
        savec;
    for (c = name; *c && *c != '.'; c++);
    savec = *c;
    *c = 0;
    for (ctbp = (struct class_table *)class_area.area; ctbp && ctbp->name &&
         strcmp(ctbp->name, name); ctbp++);
    *c = savec;
    if (!ctbp || !ctbp->name)
        return (struct class_table *)0;
    return ctbp;
}

static void find_class_item(
    char *item,
    struct class_table *ctbp,
    struct with_syntax *wsxp,
    char *val)
{
    struct class_item *citp;
    struct table_entry *tbep;
    char *b,
       *c;
    for (citp = &ctbp->item; citp && strcmp(citp->name, wsxp->object);
         citp = citp->next);
    if (!citp)
        return;
    c = 0;
    for (b = citp->predicate; *b && wdcmp(b, default_w); b++);
    if (*b)
    {
        while (*b > ' ')
            b++;
        while (*b && *b <= ' ')
            b++;
        if (*b)
        {
            for (c = b; *b > ' '; b++);
            if (!wsxp->table_outp || !(tbep = &wsxp->table_outp->table_entry))
                syntax(token);
        }
    }
    if (val && c && (!wdcmp(val, true_w) || !wdcmp(val, false_w) ||
                     !wdcmp(val, either_w)) && strcmp(c, val))
        c = val;
    if (wsxp->table_outp && (tbep = &wsxp->table_outp->table_entry))
    {
        while (tbep && tbep->item && strcmp(item, tbep->item))
            tbep = tbep->next;
        if (tbep && tbep->item && c)
            append_name(&tbep->value, c);
    }
}

struct macro_table *find_macro(
    char *name)
{
    struct macro_table *mtbp,
       *emtbp;
    char *c,
        savec;
    for (c = name; *c > ' '; c++);
    savec = *c;
    *c = 0;
    for (mtbp = (struct macro_table *)macro_area.area, emtbp =
         &mtbp[macro_area.next]; mtbp < emtbp && strcmp(name, mtbp->name);
         mtbp++);
    if (mtbp >= emtbp)
        mtbp = (struct macro_table *)0;
    *c = savec;
    return mtbp;
}

void free_imports(
    )
{
    struct import_table *timtbp,
       *eimtbp;
    struct import_item *itemp,
       *nitemp;
    for (timtbp = (struct import_table *)import_area.area,
         eimtbp = &timtbp[import_area.next]; timtbp && timtbp < eimtbp;
         timtbp++)
    {
        for (itemp = timtbp->item.next; itemp; itemp = nitemp)
        {
            nitemp = itemp->next;
            free(itemp->objname);
            free((char *)itemp);
        }
        free(timtbp->name);
    }
    free(import_area.area);
    import_area.area = (char *)0;
    import_area.next = import_area.size = 0;
}

void get_exports(
    int fd,
    FILE * str)
{
/**
Function: Reads the export list and checks the items
Procedure:
1. Add the exported items to the name table & write them
   IF it was the ALL word, exit
2. IF in an imported file
        Check that all items being imported are on the export list
3.	IF any item on the export list is not being imported
            Delete it (this is safe since no children have yet been tabulated)
**/
    struct name_table *ntbp,
       *bntbp,
       *entbp,
       *lntbp;
    struct import_item *itemp;  /* step 1 */
    long start = name_area.next;
    int export_all = 0;
    if (!fd)
        fprintf(str, "%s ", token);
    for (*token = 0; get_token(fd, token) && *token != ';';)
    {
        if (*token > ' ' && *token != ',')
        {
            if (!strcmp(token, all_w))
                export_all = 1;
            else
                add_name(token, (long)-1, (!fd) ? ASN_EXPORT_FLAG : 0);
        }
        if (!fd)
            fprintf(str, "%s ", token);
    }
    if (!fd)
        fprintf(str, ";\n\n");
    if (export_all)
        return;
    bntbp = &((struct name_table *)name_area.area)[start];
    entbp = &((struct name_table *)name_area.area)[name_area.next - 1];
    if (imtbp && imtbp->name)   /* step 2 */
    {
        for (itemp = &imtbp->item; itemp; itemp = itemp->next)
        {
            for (ntbp = bntbp;
                 ntbp <= entbp && strcmp(ntbp->name, itemp->objname); ntbp++);
            if (ntbp > entbp)
            {
                cat(classname, imports_w);
                warn(21, itemp->objname);
            }
        }
        for (ntbp = bntbp; ntbp <= entbp;)      /* step 3 */
        {
            for (itemp = &imtbp->item;
                 itemp && strcmp(ntbp->name, itemp->objname);
                 itemp = itemp->next);
            if (!itemp)
            {
                free(ntbp->name);
                lntbp =
                    &((struct name_table *)name_area.area)[--name_area.next];
                memmove((char *)ntbp, (char *)&ntbp[1],
                        ((lntbp - ntbp) * sizeof(struct name_table)));
                memset((char *)entbp--, 0, sizeof(struct name_table));
            }
            else
                ntbp++;
        }
    }
}

void get_fnames(
    int fd)
{
/**
Function: Builds import table
Procedure:
1. WHILE there's another token AND it's not ';'
	DO
    	    IF in original file AND token is not a special symbol AND
                token hasn't already been done
                Add the object name to the entry
	WHILE next token is not ';' AND it's not FROM
2. 	IF token is ';' OR there's no objname next, syntax error
        IF the next token is not ';' AND the token after that is not 'IN'
            AND there's no name after that, syntax error
        Get the file name
3.      IF the entry has a member AND the file name is not the source
	    See if there is already an entry for this file
	    IF not, put the name in this entry and flag as new
	    Add the item to the table
    	    IF there alrady is an import entry for this file, append these
                items to it
    	    ELSE make a new entry for these items
**/
    char *objname = (char *)0;
    struct import_table *eimtbp,
       *timtbp,
        ximtb;
    struct import_item *itemp;
    ximtb.name = ximtb.item.objname = (char *)0;
    ximtb.item.next = (struct import_item *)0;
    while (get_must(fd, token) && *token != ';')
    {
        do
        {
            if (!fd && *token >= 'A' && *token <= 'z' && !was_imported(token))
                add_import_item(&ximtb, token);
            if (!get_token(fd, token))
                break;          /* error msg later */
        }
        while (*token != ';' && strcmp(token, from_w));
        /*
         * step 2 
         */
        if (*token == ';' || !get_token(fd, token))
            syntax(token);
        objname = (char *)calloc(1, strlen(token) + 2);
        strcpy(objname, token);
        if (!get_token(fd, token))
            syntax(token);
        if (!strcmp(token, in_w))
        {
            if (get_token(fd, token) && *token != ';' && *token != ',')
            {
                objname = (char *)realloc(objname, strlen(token) + 2);
                strcpy(objname, token);
            }
            else
                syntax(token);
        }
        else if (*token != ';' && *token != ',')
        {
            free(objname);
            syntax(token);
        }
        /*
         * step 3 
         */
        if (ximtb.item.objname && strcmp(objname, source))
        {
            for (timtbp = (struct import_table *)import_area.area,
                 eimtbp = &timtbp[import_area.next];
                 timtbp < eimtbp && strcmp(timtbp->name, objname); timtbp++);
            if (timtbp >= eimtbp)
            {
                timtbp = (struct import_table *)0;
                fill_name(&ximtb.name, objname);
            }
            timtbp = add_import_item(timtbp, ximtb.item.objname);
            for (itemp = &timtbp->item; itemp->next; itemp = itemp->next);
            itemp->next = ximtb.item.next;
            if (ximtb.name)
                timtbp->name = ximtb.name;
            ximtb.name = (char *)0;
            free(ximtb.item.objname);
            ximtb.item.objname = (char *)0;
            ximtb.item.next = (struct import_item *)0;
        }
    }
    if (objname)
        free(objname);
    if (*token != ';')
        fatal(14, token);
    *token = 0;
}

char *get_obj_id(
    int fd,
    char *name,
    char *basename)
{
/**
Function: Interprets an object identifier string of the form
    xxx(1) 3 yyy 5 ...
  where 'xxx(1)' is here defined, 'yyy' was previously defined, and numbers
  are taken as is
Returns: ID string in dot notation in a mallocked string
Procedure:
1. WHILE token is not '}'
	IF token is not a name, use it as the value
	ELSE IF that name is in the id table, use its value
	ELSE
	    Get the value
	    Add the name and value to the table
	Append the new value to the current id_string
	Get the next token
	IF it's '(' AND the rest of the definition doesn't match what we have
	    Fatal error
	IF it's a name, save it for use as an ID name
2. Return the id_string
**/
    struct id_table *pidp;
    char *id_string,
       *eid_string,
       *val_string,
        locbuf[80],
        locname[80];
    size_t lth,
        tmp;
    for (id_string = 0, cat(locname, name); *token != '}';)
    {
        if (*token <= '9')
            val_string = token;
        else
        {
            for (pidp = (struct id_table *)id_area.area; pidp && pidp->name &&
                 strcmp(locname, pidp->name); pidp++);
            if (pidp && pidp->name && *pidp->name && (!basename ||
                                                      strcmp(pidp->name,
                                                             basename)))
            {
                if (!pidp->val)
                {
                    warn(18, pidp->name);
                    val_string = "";
                }
                else
                    val_string = pidp->val;
            }
            else
            {
                get_must(fd, locbuf);
                if (*locbuf == '(')
                {
                    get_must(fd, token);
                    get_known(fd, locbuf, ")");
                    tmp = strlen(token);
                    fill_name(&val_string, token);
                    if (!pidp->name || strcmp(pidp->name, basename))
                    {
                        pidp = add_id(locname);
                        pidp->val = val_string;
                    }
                }
                else if (*locbuf == '}')
                {
                    if (id_string)
                        fatal(13, token);
                    fill_name(&id_string, token);
                    return id_string;
                }
                else if (*locbuf >= '0' && *locbuf <= '9')
                    fatal(18, name);
                else
                    fatal(18, name);
            }
        }
        tmp = strlen(val_string);
        if (!id_string)
        {
            fill_name(&id_string, val_string);
            eid_string = &id_string[lth = tmp];
        }
        else
        {
            id_string = (char *)realloc(id_string, lth + tmp + 2);
            eid_string = cat(cat(&id_string[lth], "."), val_string);
            lth = eid_string - id_string;
        }
        val_string = 0;
        get_must(fd, token);
        if (*token == '(')
        {
            get_must(fd, token);
            get_known(fd, locbuf, ")");
            if (strcmp(token, pidp->val))
                fatal(17, locname);
            get_must(fd, token);
        }
        if (*token >= 'a' && *token <= 'z')
            cat(locname, token);
        else
            *locname = 0;
    }
    return id_string;
}

static void insert_name(
    char *buf,
    long typ)
{
    char *c = cat(buf, find_typestring(typ));
    if (typ == ASN_OBJ_ID)
        c = cat(cat(c, " "), identifier_w);
    else if (typ == ASN_BITSTRING || typ == ASN_OCTETSTRING)
        c = cat(cat(c, " "), string_w);
}

int is_imported(
    char *name)
{
    struct import_item *itemp;
    for (itemp = &imtbp->item; itemp && strcmp(name, itemp->objname);
         itemp = itemp->next);
    return (itemp) ? 1 : 0;
}

char *scan_known(
    char *from,
    char *kn)
{
    while (*from && *from <= ' ')
        from++;
    while (*kn && *kn++ == *from)
        from++;
    if (*kn)
        syntax(from);
    return from;
}

char *scan_must(
    char *from,
    char *to)
{
    char *c;
    for (c = from; *c && *c <= ' '; c++);
    if (!*c)
        syntax(from);
    while (*c > ' ')
        *to++ = *c++;
    *to++ = 0;
    return c;
}

char *skip_word(
    char *from)
{
    while (*from > ' ')
        from++;
    while (*from && *from == ' ')
        from++;
    return from;
}

int was_imported(
    char *name)
{
    struct import_table *timtbp,
       *eimtbp;
    struct import_item *itemp;
    for (timtbp = (struct import_table *)import_area.area,
         eimtbp = &timtbp[import_area.next]; timtbp && timtbp < eimtbp;
         timtbp++)
    {
        for (itemp = &timtbp->item; itemp && strcmp(name, itemp->objname);
             itemp = itemp->next);
        if (itemp)
            return 1;
    }
    return 0;
}

void scan_syntax(
    int fd,
    struct with_syntax *wsxp,
    struct with_syntax
    *tsxp)
{
    char *c;
    int ansr;
    size_t lth,
        siz = strlen(wsxp->verb);
    memset((char *)tsxp, 0, sizeof(struct with_syntax));
    get_must(fd, token);
    do
    {
        if (what_type(token) == 0)
        {
            if (wsxp->subject)
                fill_name(&tsxp->subject, token);
        }
        else if (!(*token & 0x20))      /* must be a "verb" */
        {
            if (strncmp(token, wsxp->verb, (lth = strlen(token))))
            {
                if (tsxp->subject)
                {
                    free(tsxp->subject);
                    tsxp->subject = (char *)0;
                }
                continue;
            }
            for (c = &token[lth], *c++ = ' ';
                 !strncmp(token, wsxp->verb, lth) && lth < siz;
                 c += (ansr + 1), *c++ = ' ', lth = c - token)
            {
                ansr = get_must(fd, c);
            }
            if (!strcmp(token, wsxp->verb) && lth == siz)
            {
                if (wsxp->object)
                    get_must(fd, token);
                if (*token == '{')
                {
                    get_must(fd, token);
                    get_known(fd, &token[ansr + 2], "}");
                }
                fill_name(&tsxp->object, token);
            }
        }
    }
    while ((ansr = get_token(fd, token)) && *token != '}');
    if (!ansr)
        syntax(wsxp->verb);
}

void test_paren(
    int fd,
    char *buf,
    char *linebuf,
    char **linendpp,
    char *elinebuf)
{
    int parens = 1;
    get_must(fd, &buf[2]);
    if (buf[2] == '(')
        parens++;
    else if (buf[2] == ')')
        parens--;
    buf[1] = ' ';
    if (!fd && (*linendpp = cat(cat(*linendpp, buf), " ")) >= elinebuf)
        syntax(linebuf);
    while (*buf != ')' || parens)
    {
        get_must(fd, buf);
        if (!fd && (*linendpp = cat(cat(*linendpp, buf), " ")) >= elinebuf)
            syntax(linebuf);
        if (*buf == '(')
            parens++;
        else if (*buf == ')')
            parens--;
    }
    *buf = 0;
}

static int what_type(
    char *string)
{
/**
Function: Determines type of string
Outputs: IF '{' OR '}'              0
         ELSE IF value-reference,   VAL_REF
	 ELSE IF type-reference,    TYP_REF
	 ELSE IF all caps ("verb")  VERB
**/
    char *c;
    if (*string > 'z')
        return 0;
    if ((*string & 0x20) || !strcmp(string, true_w) ||
        !strcmp(string, false_w) || !strcmp(string, either_w))
        return VAL_REF;
    if (find_type(string) != ASN_NOTYPE)
        return TYP_REF;
    for (c = &string[1]; *c && (!(*c & 0x20) || *c == ' '); c++);
    if (*c)
        return TYP_REF;
    return VERB;
}
