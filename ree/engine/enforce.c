/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Rule Editor/Engine for Address and AS Number PKI
 * Verison 1.0
 * 
 * COMMERCIAL COMPUTER SOFTWARE—RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
/* */

/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include "enforce.h"

static int isForCA, curr_file, rule_index, definedTag, inWrapper, inGroup;
int bad_rule_file;
uchar *failure_point;    /* address of object that failed a rule */
char *map_string;

struct fasn *rasnp;             /* ptr to current rules item */

static struct fasn *toprasnp,   /* ptr to top rule item */
    *grasnp,                    /* ptr to start of group's rules */
    *prasnp,                    /* ptr to first rule of parameters */
    *sav_rule_fasnp,            /* ptr to where bad rule or object was found */
    *get_limit(struct fasn *);

static struct asn *casnp,       /* ptr to current cert/CRL item */
    *wrapper_asnp,              /* ptr to struct asn of current wrapper */
    *topcasnp,                  /* ptr to top cert/CRL item */
    *mod_asnp;                  /* ptr to cert/CRL item to be modified */

static int
    atChoice     (),
    atDate       (),
    atDefinedBy  (),
    atFileRef    (),
    atNamedBits  (),
    atRule       (),
    atRuleChoice (),
    atRuleD      (),
    atSequence   (),
    atSet        (),
    atSetSeqOf   (),
    atSpecial    (),
    atWrapper    (),
    atGroupRule(struct asn *),
    atGroupRules(struct asn *, struct fasn *),
    atGroupSubRule(),
    atMember(int),
    bit_match(int),
    bump(char *, char *, char **),
    cf_obj_obj(struct asn *, struct asn *),
    cf_obj_rule(struct asn *, struct fasn *, int),
    check_AddrRanges(),
    check_CA_rules(),
    check_keyMethod(),
    check_limits(),
    check_subordination(),
    do_rule(uchar),
    get_fasn_num(struct fasn *),
    get_fasn_vnum(struct fasn *),
    hit_bad_rule(struct fasn *),
    hit_error(struct asn *, struct fasn *),
    in_range(struct fasn *),
    is_required(struct fasn *),
    limit_test(struct fasn *),
    locate(struct asn **, struct fasn *),
    matches_target(uchar, uchar),
    member_has_rule(),
    navigate(struct asn **, uchar **, uchar *),
    set_next(char *, char *, char *, char **),
    set_num();

static void set_obj_min_max(struct asn *, struct asn **, struct asn **),
       set_rule_min_max(struct fasn *, struct fasn **, struct fasn **);

static int (*call_table[])() =
    {
    atSequence,       /* sequence */
    atSet,            /* set */
    atSequence,       /* sequence containing definer/definee */
    atSetSeqOf,       /* seqOf */
    atSetSeqOf,       /* setOf */
    atChoice,         /* choice */
    atDefinedBy,      /* definedBy */
    atRule,           /* primitive */
    atRuleD,          /* definer */
    atDate,           /* date */
    atNamedBits,      /* named bits */
    atFileRef,        /* file ref */
    atWrapper,        /* wrapper */
    atSpecial         /* special */
    };

int enforce(struct asn **icasnpp, struct fasn *inrasnp, uchar **failPointpp)
    {
/**
Name: enforce()
Function: Applies rules to an ASN.1-encoded object
Inputs: Address of ptr to struct asn for test object
	Ptr to rules
Outputs: Ptr to struct in test object for error or serial number
         IF rule error, name of file
	 IF any error, offset to point of error in test or rule
Returns: <0 means error
	 >0 means no error.  1 is default; 2 means a serial number must be put
	    in at point designated
Procedure:
1. IF can't get file, return error
   IF atRuleChoice returns OK
	IF there's a serial number to be added
	    Set the pointer
	    Return 2
	Return 1
   ELSE Start building lone response
        IF not a bad rule, fill in the offset in object
	IF can't get the rule file name, use '?'
	Fill in the file name
	Get the rule file and calculate the offset
	Adjust the offset for names of any file references earlier in the file
	Fill in the offset
	IF the rule has a name, fill that in
	Return the error
**/
    struct fasn *trasnp;
    struct asn asn;
    char *a, *b, *c, *e;
    int offset;
							/* step 1 */
    topcasnp = casnp = *icasnpp;
    inGroup = inWrapper = isForCA = 0;
    rule_index = definedTag = bad_rule_file = -1;
    wrapper_asnp = mod_asnp = (struct asn *)0;
    grasnp = sav_rule_fasnp = prasnp = (struct fasn *)0;
    toprasnp = rasnp = inrasnp;
    failure_point = map_string = (char *)0;
    if (atRuleChoice() >= 0)
	{
        if (mod_asnp)
	    {
	    *icasnpp = mod_asnp;
	    return 2;
	    }
        return 1;
	}
    else
        {
        if (verbose && map_string && *map_string)
            {
            if (!inGroup) printf("\n");
            printf("    Failed at %s\n", map_string);
            }
        if (map_string) free(map_string);
        if (bad_rule_file < 0)  /* not a rule error */
            {
            *failPointpp = failure_point;
            return -(FAIL_RULE);
            }
        else
            {
            *icasnpp = (struct asn *)sav_rule_fasnp;
            return  -(BAD_RULE);
            }
        }
    return 0;       /* never encountered */
    }

static int atRuleChoice()
/*
Function: Tests item pointed to by casnp against rules
Inputs: Ptr to cert/CRL structure (casnp)
	rasnp at RuleChoice
Returns: If OK, >= 0, else -1
Procedure:
1. WHILE the rule is a FileRef
        IF converting it to point to the file returns error, return -1
   IF rule is a NULL,
	Skip to next test object
        Return 1
2. IF rule tag is out of bounds, return -1;
   Dispatch to rule function and note what it returns
   IF no error, advance rasnp to next Rule Choice at level of this one
   Return what dispatch returned
*/
    {
    uchar *ref;
    int ansr, lev, op;

                          				    /* step 1 */
    lev = rasnp->level;
    ref = GET_FILE_ASN_REF((rasnp));
    if (!ref) return hit_error(casnp, rasnp);
    if (*ref == ASN_NULL)
	{
	casnp = skip_asn(casnp, casnp, 1);
        rasnp++;
        return 1;
	}
							    /* step 2 */
    if ((*ref & ASN_PRIV_CONSTR) != ASN_PRIV_CONSTR) return hit_bad_rule(rasnp);
    op = *ref - (uchar)(ASN_PRIV_CONSTR);
    if (op >= sizeof(call_table) / sizeof(int *)) return hit_bad_rule(rasnp);
    if ((ansr = call_table[op]()) > 0)
	{
        while (rasnp->level > lev) rasnp++;
	}
    return ansr;
    }

int atChoice()
/*
Inputs: casnp is at choice item
	rasnp at Choice rule
Outputs: Sets rasnp to next rule at level of Choice
Procedure:
0. IF this is a tagged choice, advance casnp
1. Note where we're at in the test object
   FOR each member of the Choice rule
	IF atMember returns 1, note success
   IF none found, return -1
   Return 1
*/
    {
    int ansr, member;
    ushort rlevel;
    struct fasn *trasnp;
    struct asn *hit_asnp, *old_casnp;
                                                        // step 0
    if (rasnp[-1].level == rasnp->level &&
        *(rasnp[-1].stringp) == ASN_CONT_SPEC) casnp++;
						        /* step 1 */
    old_casnp = casnp;
    trasnp = rasnp++;     /* rasnp at 1st Member */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    for (hit_asnp = (struct asn *)0, rlevel = rasnp->level, member = 1;
        rasnp->level == rlevel; member++)
	{
	casnp = old_casnp;
	if ((ansr = atMember(-1)))
	    {
	    if (hit_asnp) return hit_bad_rule(rasnp);   /* 2nd hit */
	    hit_asnp = casnp;
	    if (ansr < 0)
                {
                map_stuff(member);
                return ansr;
                }
	    }
	while (rasnp->level > rlevel) rasnp++;
	}
    if (!hit_asnp) return hit_error(old_casnp, trasnp);
    casnp = hit_asnp;
    return 1;
    }

int atDate()
/**
Inputs: casnp points to address of cert/CRL date
	rasnp points to date rule in rules or null
Procedure:
1. Get the window limits
2. IF the date is not DER, fix it
   Get the count of seconds in this date
3. IF range is absolute dates, set ref date to 0
   ELSE IF ref is for clock, get no. of secs from clock as ref date
   ELSE IF rule isn't a printable string, return bad rule error
   ELSE IF navigating there doesn't get to a time OR date there is bad,
        return bad rule error
   ELSE	advance rule pointer
4. IF this date vs. ref date is outside the min-max window, return -1
**/
    {
    int min, momin, max, momax, tmp;
    ulong ref_date, this_date;
    struct asn asn, *tasnp;
    uchar *c, *ref, clock_time[20];
    struct fasn *savgrasnp = grasnp, *min_rasnp, *max_rasnp;
							/* step 1 */
    momin = momax = 0;
    grasnp = rasnp++;            /* rasnp goes to first item */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    min = get_fasn_num((min_rasnp = rasnp++));
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (*(ref = GET_FILE_ASN_REF(rasnp)) == ASN_BOOLEAN)
	{
	momin = 1;
	rasnp++;
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	}
    max = get_fasn_num((max_rasnp = rasnp++));
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (*(ref = GET_FILE_ASN_REF(rasnp)) == ASN_BOOLEAN)
	{
	momax = 1;
	rasnp++;
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	}  
     /* rasnp now at ref, if any */
							/* step 2 */
    tmp = (*casnp->stringp == ASN_UTCTIME)? 13: 15;
    if (asn_start(casnp)[casnp->lth - 1] != 'Z' || casnp->lth < tmp)
	return hit_error(casnp, rasnp);
    this_date = get_asn_time(casnp);
							/* step 3 */
    if (rasnp->level < rasnp[-1].level)  // no ref
	{
        ref_date = 0; /* no ref */
	put_asn_time(clock_time, ref_date);
	tasnp = &asn;
	tasnp->stringp = clock_time;
	tasnp->lth = clock_time[1];
	}
    else if (!rasnp->lth)  // empty ref
	{
        ref_date = (ulong)time((time_t *)0);
	rasnp++;
        put_asn_gentime(clock_time, ref_date);
        tasnp = &asn;
        tasnp->stringp = clock_time;
        tasnp->lth = (int)clock_time[1];
	}
    else if (*(ref = GET_FILE_ASN_REF(rasnp)) != ASN_PRINTABLE_STRING)
        return hit_bad_rule(rasnp);
    else if (locate(&tasnp, rasnp) < 0 || !tasnp ||
    	    (*tasnp->stringp != ASN_UTCTIME && *tasnp->stringp != ASN_GENTIME) ||
    	    (ref_date = get_asn_time(tasnp)) == 0xFFFFFFFF)
            return hit_bad_rule(rasnp);
    else rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
						    /* step 4 */
    if ((min = time_diff(this_date, ref_date, tasnp, momin, min)) < 0 ||
	(min = time_diff(this_date, ref_date, tasnp, momax, max)) > 0)
	{
	return hit_error(casnp, (min < 0)? min_rasnp: max_rasnp);
	}
    casnp++;
    grasnp = savgrasnp;
    return 1;
    }

int atDefinedBy()
/**
Inputs: casnp is at cert/CRL definee
	rasnp at DefinedBy rule  (Members)
	rule_index provides index to definee
Procedure:
1. Save member level
   IF no rule index OR
      skipping through rules for amount of rule_index goes beyond, return -1
   See what the member returns
   Skip the rest of the definees
2. Return what the member returned
**/
    {
    int ansr, index = rule_index; // preserve rule_index, canceled by atSequence
    int lev = rasnp->level;
    struct fasn *tfasnp;
						        /* step 1 */
    if (rule_index < 0) return hit_bad_rule(rasnp);
    rasnp++;            /* at Member */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (!(tfasnp = skip_fasn(rasnp, rasnp, rule_index)))
        return hit_bad_rule(rasnp);
    rasnp = tfasnp;
    if ((ansr = atMember(1)) < 0) return map_stuff(index + 1);
    while (rasnp->level > lev) rasnp++;
    return ansr;
    }

int atFileRef()
/**
This should never happen
**/
    {
    return hit_bad_rule(rasnp);
    }

atGroupRule(struct asn *tasnp)
/**
Function: Implements a group rule
Inputs: tasnp is at first member of the group to which the group rule applies
	casnp is at end of group to which rules apply
	rasnp is at the group rule
	grasnp is at rules for tasnp (to help navigate over optional items)
Returns: IF no error, 1 ELSE -1
Procedure:
1. Try the ifcase
   Clear any error in that case
2. Try the thencase
   IF the (ifcase was true AND the thencase failed) OR
        (the ifcase was false AND the thencase succeeded), return error

**/
    {
    int ifansr, thenansr = 0, rlevel;
    struct asn *savcasnp = casnp;
							/* step 1 */
    casnp = tasnp;
    rasnp++;            /* at name or location, if any, else rule choice */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (*(GET_FILE_ASN_REF(rasnp)) == ASN_UTF8_STRING) rasnp++;  /* skip name */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    rlevel = rasnp->level;
    if ((ifansr = atGroupSubRule()) < 0)
	{
        failure_point = (uchar *)0;       /* failures don't count in ifcase */
        sav_rule_fasnp = (struct fasn *)0;
	}
    casnp = tasnp;
							/* step 2 */
    if (ifansr > 0)
	{
        thenansr = atGroupSubRule();
        if (bad_rule_file >= 0) return -1;
        if (thenansr <= 0)
    	    {
            if (!failure_point) return hit_error(casnp, rasnp);
    	    return -1;
    	    }
	}
    else while(rasnp && rasnp->level <= rlevel) rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    casnp = savcasnp;

    return 1;
    }

int atGroupRules(struct asn *tasnp, struct fasn *trasnp)
/**
Function: Implements zero or more group rules
Inputs: tasnp is at the group to which group rules apply
	trasnp is ptr to rules for tasnp (to navigate over optional items)
	casnp is at end of group to whch rules apply
	rasnp is at Sequence OF group rules
Returns: IF no error, 1 ELSE -1
Procedure:
1. Save the old group rule ptr
   FOR each GroupRule
	Set group rule ptr to this one
    	IF atGroupRule returns < 0, return -1;
   Restore old group rule pointer
   Return 1
**/
    {
    int ansr;
    ushort level;
    struct fasn *savgrasnp = grasnp;

						    /* step 1 */
    if (!rasnp || !rasnp->level ||
        *GET_FILE_ASN_REF(rasnp) != ASN_SEQUENCE) return hit_bad_rule(rasnp);
    for (level = (++rasnp)->level; rasnp && rasnp->level == level; )
        {
        grasnp = trasnp;
        if ((ansr = atGroupRule(tasnp)) < 0) return ansr;
        while (rasnp->level > level) rasnp++;
        }
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    grasnp = savgrasnp;
    return ansr;
    }

int atGroupSubRule()
/**
Inputs: casnp at object to be tested
	rasnp at the sub-rule
	grasnp at rule for casnp
Returns: IF error, -1, ELSE IF found, 1; ELSE IF not found 0;
Procedure:
1. IF there are locations
	FOR each location
            IF the target of the sub-rule is absent or error, return response
	    See if the target is really there
	Skip over the location rules
   Determine if the test is to be negated
2. IF there's a rule choice,
	IF the member is absent, set answer to 0
        ELSE set answer to what rule choice returns
   ELSE use answer from locations
   IF the test is to be negated, flip meaning
   Return result
**/
    {
    struct fasn *sgrasnp = grasnp, *savrasnp;
    struct asn *savcasnp = casnp, *tasnp;
    int ansr, negate, lev;
    uchar *ref;
							/* step 1 */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (rasnp->level == (++rasnp)->level) return 1;   /* empty condition */
    lev = rasnp->level;
    if (*(ref = GET_FILE_ASN_REF(rasnp)) == ASN_SEQUENCE) /* have locations */
	{
	for (rasnp++; rasnp && rasnp->level == lev + 1; rasnp++)
	    {
            if ((ansr = locate(&casnp, rasnp)) <= 0) return ansr;
	    savrasnp = rasnp;
	    rasnp = grasnp;
	    tasnp = casnp;
	    ansr = atMember(0);
	    casnp = tasnp;
	    rasnp = savrasnp;
	    }
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	while (rasnp->level > lev) rasnp++;
	}
    else ansr = 1;
    negate = 0;
    if (*(GET_FILE_ASN_REF(rasnp)) == ASN_BOOLEAN)  /* at negation? */
	{
	negate = 1;
        rasnp++;    /* now at RuleChoice, if any */
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	}
						/* step 2 */
    if (rasnp && rasnp->level >= lev && ansr > 0) ansr = atRuleChoice(casnp);
    if (ansr >= 0)
	{
        if (negate) ansr = (~ansr & 1);
        casnp = savcasnp;
        grasnp = sgrasnp;
	}
    return ansr;
    }

int atMember(int mode)
    {
/**
Name: atMember()
Function: Applies rules to test member
Inputs: Mode: 1 means do rule test too; 0 means skip rule test(just navigating);
             -1 means do rule test, but don't call hit_error() on error (it's
                a CHOICE)
        casnp is at test member
	rasnp is at rules for casnp
Outputs: casnp is at present member
	 rasnp is at rules for casnp
Returns: 1 if member is present and OK, 0 if member is absent and optional,
	 -1 if member has error or (is absent and not optional)
Procedure:
1. Skip the name, if any
   Get the rule for the tag
   Get the optionality rule
   Get the size limits, if any
1a IF not at a definedBy
        if object's tag doesn't match
            IF it's not optional, return -1 (with or without hit_error)
        	Return 0
2. IF there's a size rule AND size is out of bounds, return -1
3. IF not checking OR there's no rule for this member
        Skip to next member
	Skip to rule for next member
	Return 1
   ELSE return what atRuleChoice returns
**/
    int ansr, opt, rlevel, tag, min_lth, max_lth;
    struct fasn *tfasnp;
						    /* step 1 */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    rlevel = rasnp->level + 1;
    if ((rasnp++)->lth)       /* rasnp at name or Tag */
	{
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
        if (*(GET_FILE_ASN_REF(rasnp)) == ASN_UTF8_STRING) rasnp++;
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
                    /* at Tag, if any */
        if (*(GET_FILE_ASN_REF(rasnp)) == ASN_CONT_SPEC)
	    {
            tfasnp = rasnp;
	    if (!(tag = get_fasn_vnum(rasnp)) || tag == 0xFFFFFFFF)
                return hit_bad_rule(rasnp);
	    if (rule_index >= 0 && definedTag < 0) definedTag = tag;
	    rasnp++;
	    }
        else tag = -1;
                 /* rasnp at boolean or size */
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
        if ((opt = (*(GET_FILE_ASN_REF(rasnp)) == ASN_BOOLEAN)? 1: 0))
            rasnp++;         /* go to size, if any */
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
        if (rasnp->level == rlevel &&
            *(GET_FILE_ASN_REF(rasnp)) == ASN_SEQUENCE)
	    {
            if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	    if (!(tfasnp = get_limit(++rasnp))) return hit_bad_rule(rasnp);
	    if ((min_lth = get_fasn_num(tfasnp)) == 0xFFFFFFFF ||
	        !(tfasnp = get_limit(++rasnp))) return hit_bad_rule(rasnp);
	    if ((max_lth = get_fasn_num(tfasnp)) == 0xFFFFFFFF) return hit_bad_rule(tfasnp);
		    /* rasnp is at high limit */
	    rasnp++;
            if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
            if (rasnp->level == rlevel + 1) 
                {
                rasnp++; /* at maxsiz */
                if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
                }
	    }
        else min_lth = max_lth = -1;
                                                     // step 1a
        if (*rasnp->stringp != ASN_PRIV_CONSTR + 6)
            {
            if (tag > 0 && tag != ASN_NONE && tag != (int)*casnp->stringp)
                {
                if (!opt && mode >= 0)
                    return hit_error(casnp, rasnp);
    	        return 0;
    	        }
    	    if (tag == ASN_NONE && casnp->stringp &&
                *casnp->stringp == definedTag)
    		    /* casnp->stringp may be null at end of wrapper */
    	        return hit_error(casnp, rasnp);
            }
						        /* step 2 */
        if (max_lth >= 0 && (casnp->lth < min_lth || casnp->lth > max_lth))
            return hit_error(casnp, tfasnp);
	}
							    /* step 3 */
	/* rasnp at rule, if any */
    if (!mode || (rasnp && rasnp->level < rlevel))
	{
        if (tag != ASN_NONE) casnp = skip_asn(casnp, casnp, 1);
	while (rasnp && rasnp->level >= rlevel) rasnp++;
	}
    else return atRuleChoice();
    return 1;
    }

int atNamedBits()
    {
/*
Function: Tests bits and groups of bits in string of named bits
Inputs: casnp is at BIT STRING
	rasnp is at NamedBits structure
Returns: IF no error, 0, ELSE -1
Procedure:
1. IF any unallowed bits are present, return -1
   IF any required bits are absent, return -1
2. IF there are group rules, return what atGroupRules returns
*/
    int ansr, lev = rasnp->level + 1;
    struct asn *tasnp = casnp;
    struct fasn *trasnp = rasnp;
							/* step 1 */
    rasnp++;        /* go to forbid member */
    if (!rasnp || !rasnp->level ||
        rasnp->level != lev) return hit_bad_rule(rasnp);
    if ((ansr = bit_match((uchar)id_forbid)) < 0)
        return hit_error(casnp, rasnp);
    rasnp++;        /* go to require member */
    if (!rasnp || !rasnp->level ||
        rasnp->level != lev) return hit_bad_rule(rasnp);
    if ((ansr = bit_match((uchar)id_require)) < 0)
        return hit_error(casnp, rasnp);
    if (rasnp[1].level == lev)
	{
	rasnp++;
	ansr = atGroupRules(tasnp, trasnp);
	}
    casnp = &tasnp[1];
    return ansr;
    }

int atRule()
/**
Function: Tests object for Rule
Inputs: casnp is at object
	rasnp is at Rule
**/
    {
    return doRule(0);
    }

int atRuleD()
/*
Function: Tests definer
Inputs: casnp is at definer
	rasnp is at Rule
Outputs: Sets rule_index, if no error
*/
    {
    int ansr;

    if ((ansr = doRule(1)) >= 0) ansr = 1;
    return ansr;
    }

int atSequence()
/*
Name: atSequence()
Function: Test all members of sequence against their rules and test whole
sequence with the GroupRules
Inputs: casnp is at sequence
	rasnp is at Sequence rule
Procedure:
1. IF this is not a SequenceD, clear rule_index
   Save pointers to top test item and rules, for use with GroupRules
   Starting at first member in test object and in rules,
   FOR each member of the rules
        IF at end of members in test object AND not doing DEFINED BY
	    IF at end of a wrapper, get the address of the thing after
    	    IF definition says member must be present, return hit_error
	    Break out of FOR
	IF atMember returns -1, return that
	IF it returned 0, we're at the same test object, so
	    Go to rules for next test object
	IF not in a definerSequence, clear rule_index
   IF not at end of test object, return hit_error
2. IF there are GroupRules, return what atGroupRules returns
   Return 1
*/
    {
    struct asn *savcasnp = casnp, *tasnp;
    struct fasn *savrasnp = rasnp, *trasnp;
    uchar *c;
    int ansr, definerSeq = 0, member;
    ushort clevel, rlevel;  /* rlevel is Member */
							    /* step 1 */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (*(GET_FILE_ASN_REF(rasnp)) != RULE_SEQUENCED_TAG)
        rule_index = definedTag = -1;
    else definerSeq = 1;
    tasnp = (++casnp);   /* at first member */
    if (!tasnp->level) return hit_error(&casnp[-1], rasnp);
    rasnp += 2;  /* at first Member */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    rlevel = rasnp->level;
    for (clevel = casnp->level, member = 1; rasnp->level == rlevel; member++)
	{
	if (casnp->level < clevel && !definerSeq)
	    {
	    if (!casnp->stringp)
		{
                casnp = &wrapper_asnp[1];
		clevel = casnp->level + 1;
		}
            if (is_required(rasnp))
		{
                return hit_error(casnp, rasnp);
		}
	    break;
	    }
	if ((ansr = atMember(1)) < 0)
            {
            map_stuff(member);
            return ansr;
            }
	if (!ansr) while (rasnp->level > rlevel) rasnp++;
        if (!definerSeq) rule_index = definedTag = -1;
	}
    if (casnp->level >= clevel) 
      return (rasnp->level)? hit_error(casnp, rasnp): hit_bad_rule(rasnp);
    if (rasnp->level == rlevel) rasnp = skip_fasn(rasnp, rasnp, 1);
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (rasnp->level && rasnp->level == rlevel - 1)
        return atGroupRules(savcasnp, savrasnp);
    return 1;
    }

int atSet()
/*
Name: atSet()
Function: Test all members of set against their rules and test whole
set with the GroupRules.  Assumes the SET is properly ordered and that the rules
are ordered by tag.
Inputs: casnp is at set
	rasnp is at Set rule
Procedure:
1. FOR each member in test item
	Scan the rules for a tag that matches the test item
	IF tag not found in rules OR this rule was hit before, return -1
	Note index of rule matched
	IF this member has error, return -1
        Clear rule_index
   FOR all rule members not used, IF it's not optional, return -1
2. IF there are GroupRules, return what atGroupRules returns
   Return 1
*/
    {
    struct fasn *savrasnp = rasnp;
    struct asn *savcasnp = casnp, *tasnp;
    uchar *c, *cm, *em, *matches, *old_so_free = so_free;
    int ansr, member;
    ushort rlevel, clevel; 
							    /* step 1 */
    if (!rasnp || !&rasnp[1] || !&rasnp[2] || !rasnp[2].level) return hit_bad_rule(rasnp);
    rlevel = rasnp[2].level;  // at Member
    em = matches = so_free;
       //  clevel at Member
    for (clevel = (++casnp)->level; casnp->level == clevel ;
        casnp = skip_asn(casnp, casnp, 1))
	{
        for (cm = matches, rasnp = &savrasnp[2], member = 1;
            rasnp && rasnp->level == rlevel;
            rasnp = skip_fasn(rasnp, rasnp, 1), cm++, member++)
    	    {
	    if (cm >= em)
		{
		*em++ = 0;
		so_free = em;
		}
            rasnp++;       /* to tag */
            if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	    if (*casnp->stringp == *fasn_start(rasnp)); break;
	    }
	if (rasnp->level < rlevel || *cm) return hit_error(casnp, &savrasnp[2]);
	*cm = 1;
	if (atMember(1) < 0) return map_stuff(member);
	rule_index = definedTag = -1;
	}
    tasnp = casnp;
    casnp = &savcasnp[1];
    for (cm = matches, rasnp = &savrasnp[2], member = 1;
        rasnp && rasnp->level == rlevel;
	rasnp = skip_fasn(rasnp, rasnp, 1), member++)
	{
	if (!*cm && atMember(1) < 0) return map_stuff(member);
	}
							    /* step 2 */
    so_free = old_so_free;
    if (rasnp && rasnp->level && rasnp->level == rlevel - 1)
        return atGroupRules(savcasnp, savrasnp);
    return 1;
    }

int atSetSeqOf()
/*
Name: atSetSeqOf()
Function: Test all members of set or sequence against their rules and test
whole set or sequence with the GroupRules
Inputs: casnp is at set/seq of
	rasnp is at SetSeqOf rule
Procedure:
1. Save ptr to SetSeqOf rule
   FOR each member, WHILE at member level, count up member
	Set rasnp to Member rule
	IF atMember() returns -1, return -1
	Clear rule_index (a set/seq of can't have a definer at this level)
2. Get min and max, if any
   IF number of members is below min oe above max, return -1
3. IF there are GroupRules, return what atGroupRules returns
*/
    {
    struct fasn *savrasnp = rasnp, *trasnp;
    struct asn *tasnp, *savcasnp = casnp;
    int count, max, level, grp_level, tmp;
    uchar *ref;
							/* step 1 */
    rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    grp_level = rasnp->level;
    trasnp = rasnp;    /* at Member rule */
    ++casnp;           /* at first member */
    for (level = casnp->level, count = 0;  casnp->level == level; count++)
        {
        rasnp = trasnp;
 	if (atMember(1) < 0) return map_stuff(count + 1);
	rule_index = definedTag = -1;
	}
							/* step 2 */
    ref = GET_FILE_ASN_REF(rasnp);
    if (*ref == (ASN_CONT_SPEC | 1))
	{
        if ((tmp = get_fasn_vnum(rasnp)) == 0xFFFFFFFF) return hit_bad_rule(rasnp);
	if (count < tmp) return hit_error(casnp, rasnp);
	rasnp++;
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	ref = GET_FILE_ASN_REF(rasnp);
	}
    if (*ref == (ASN_CONT_SPEC | 2))
	{
        if ((tmp = get_fasn_vnum(rasnp)) == 0xFFFFFFFF) return hit_bad_rule(rasnp);
	if (count > tmp) return hit_error(casnp, rasnp);
	rasnp++;
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	ref = GET_FILE_ASN_REF(rasnp);
	}
						    /* step 3 */
    if (rasnp->level == grp_level)
        {
        if (*(GET_FILE_ASN_REF(rasnp)) != ASN_SEQUENCE)
            return hit_bad_rule(rasnp);
        if (atGroupRules(savcasnp, savrasnp) < 0)
            {
            if (verbose) printf("    Failed in group rule\n");
            inGroup = 1;
            return -1;
            }
	}
    return 1;
    }

int atSpecial()
/**
Inputs: rasnp is at Special rule
Procedure:
1. Do what the rule says
**/
    {                  /* increment rasnp to get off present level */
    int ansr, level = casnp->level,
        num; /* the definer */
    struct fasn *trasnp;

    rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if ((num = get_fasn_num(rasnp)) == 0xFFFFFFFF) return hit_bad_rule(rasnp);
    if (num == id_set_num) ansr = set_num();
    else if (num == id_limits) ansr = check_limits();
    else if (num == id_subordinate) ansr = check_subordination();
    else if (num == id_keyIDMethod) ansr = check_keyMethod();
    else if (num == id_isForCA) ansr = isForCA = 1;
    else if (num == id_allowIFFCA) ansr = check_CA_rules();
    else if (num == id_addrRanges) ansr = check_AddrRanges();
    else ansr = hit_bad_rule(rasnp);
    rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    return ansr;
    }

int atWrapper()
/*
Inputs: Ptr to address of cert/CRL member
	rasnp is at Wrapper rule
Procedure:
1. Go to the next rule
   ASN.1-decode the contents of the wrapper
   Save the next casnp beyond the wrapper
   Set casnp to the start of the newly decoded contents
2. Call atRuleChoice for the rule contents and the decoded contents
   Restore the next casnp after the wrapper
   Return what atRuleChoice returned
*/
    {
    struct asn *old_casnp, *asnbase, *old_mod_asnp = mod_asnp,
        *old_wrapper_asnp = wrapper_asnp;
    uchar *c, *p;
    ulong *lp;
    int ansr, lth;
						    /* step 1 */
    rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    wrapper_asnp = casnp;
    c = asn_start(casnp);
    lth = casnp->lth;
    if (*casnp->stringp == ASN_BITSTRING)
	{
        c++;
	lth--;
	}
    if ((ansr = make_asn_table(&asnbase, c, lth)) <= 0)
        {
        printf("casnp = %X ", casnp);
        fatal(3, "wrapper");
        }
    else
	{
    	old_casnp = &casnp[1];
    	casnp = asnbase;
        inWrapper = 1;
						    /* step 2 */
        ansr = atRuleChoice();
	}
    casnp = old_casnp;
    if (!old_mod_asnp && mod_asnp) mod_asnp = wrapper_asnp;
    wrapper_asnp = old_wrapper_asnp;
    free(asnbase);
    inWrapper = 0;
    return ansr;
    }

static int bit_match(int mode)
    {
/**
Function: Examines a bit string to see if it matches the rule
Input: mode is forbid, allow, require, part-forbid or part-allow without the
	ASN_CONT_SPEC0
       casnp is at bit string
       rasnp is at rule
Returns: -1 if failed, 0 if no match, 1 if match
Procedure:
1. IF the test string is longer than the rule string AND
        mode is forbid, return -1
   Scan the string up to the end of the shorter one
	IF some bits match, remember that
	IF (requiring AND test bits don't match rule bits) OR
	    (forbidding AND some test bits match rule bits)
            return -1
   IF forbidding, return 0 (test string has no more bits)
   IF allowing
        IF matched something, return 1
	ELSE return 0
   IF there are more bits set in rule AND requiring, return -1
   IF matched some, return 1
   Return 0
**/
    uchar *rvalp,
	*cvalp = asn_start(casnp),
	*c, *ec, *er, *r, x, hit;

    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    rvalp = fasn_start(rasnp);
    mode &= ~(ASN_CONT_SPEC0);
    r = &rvalp[1];
    c = &cvalp[1];
                                                 // step 1
    if (casnp->lth > rasnp->lth && mode == id_forbid) return -1;
    for (er = &rvalp[rasnp->lth], ec = &cvalp[casnp->lth], hit = x = 0;
        r < er && c < ec; r++, c++)
        {
	hit |= (x = (*c & *r));
        if ((mode == id_require && x != *r) ||
	    (mode == id_forbid && x)) return -1;
	    }
    if (mode == id_forbid) return 0;
    if (mode == id_allow) return (hit)? 1: 0;
    while (r < er && !*r) r++;
    if (r < er && mode == id_require) return -1;
    return (hit)? 1: 0;
    }

static int bump(char *s, char *e, char **enavpp)
    {
    char *a, *b, *incr = "123456789A-------BCDEF0";
    if ((*e = incr[*e - '0']) == '0')
	{
	for (a = &e[-1]; a >= s && (*a = incr[*a - '0']) == '0'; a--);
	if (a < s)
	    {
	    for (a = *enavpp, b = &a[-1]; a > s; *a-- = *b--);
	    *s = '1';
	    (*enavpp)++;
	    return 1;
	    }
	}
    return 0;
    }


static int cf_obj_obj(struct asn *cminp, struct asn *cmaxp)
    {
/**
Function: Compares integers, bit strings or octet strings of two objects
Inputs: Ptr to lesser object
	Ptr to larger object
Returns:  1 if larger object is larger than smaller
	 -1 if   "      "    is smaller "    "
	  0 if   "    object equals smaller
Procedure:
1. Set pointers and lengths
   IF objects are integers, return results of comparison
   IF objects are BIT STRINGs, adjust pointers and lengths
   Find shorter of objects
   IF comparison of objects for this length shows a difference OR
	objects are the same length, return the difference
   IF larger object is longer, return 1
   IF smaller  "     "   "       "   -1
   Return 0
**/
    int ansr, lth, minlth, maxlth, sign;
    uchar *e, *np = asn_start(cminp),
          *xp = asn_start(cmaxp);
						    /* step 1 */
    if (!cminp || !cminp->stringp || !cmaxp || !cmaxp->stringp)
        fatal(8, "cf_obj_obj");
    if (*cminp->stringp != *cmaxp->stringp) fatal(9, "cf_obj_obj");
    if (*cminp->stringp == ASN_INTEGER)
	{
        sign = 1;
        if ((*xp & 0x80))   // xp is negative
            {
            if (!(*np & 0x80)) return -1;  // np is positive
            sign = -1;   // both negative
            }
        else if ((*np & 0x80)) return 1; // np neg & xp pos
	if (cminp->lth == cmaxp->lth) return sign * memcmp(xp, np, cminp->lth);
	else return (cminp->lth < cmaxp->lth)? sign: -sign;
	}
    minlth = cminp->lth;
    maxlth = cmaxp->lth;
    lth = ((minlth < maxlth)? minlth: maxlth);
    if (*cminp->stringp == ASN_BITSTRING)
	{
	lth--;
	np++;
	xp++;
	minlth--;
	maxlth--;
	}
    if ((ansr =  memcmp(xp, np, lth)) || minlth == maxlth) return ansr;
    return (minlth < maxlth)? 1: -1;
    }

static int cf_obj_rule(struct asn *tcasnp, struct fasn *tfasnp, int mode)
    {
/**
Function: Compares integers, bit strings or octet strings of an object vs. rule
Inputs: Ptr to object
	Ptr to rule
        Mode of operation: 1= comparing obj max to rule max
                           0=     "      "  min  "  "    "
                          -1=     "      "   "   "  "   min
Returns:  1 if object is larger than rule
	 -1 if   "    is smaller "    "
	  0 if   " equals rule
Procedure:
1. Set pointers and lengths
   IF object is an integer, return results of comparison
   IF object is a BIT STRING, adjust pointers and lengths
   Find shorter of object and rule
   IF comparison of object and rule for this length shows a difference OR
	object and rule are the same length, return the difference
   IF object is longer AND it has any remaining non-zero bytes, return 1
   IF rule   "    "     "  "   "   "    "        "    "   "      "    -1
   Return 0
**/
    int ansr, lth, clth, rlth;
    uchar *e, *c = asn_start(tcasnp),
          *f;
						    /* step 1 */
    if (!tfasnp || !tfasnp->level) return hit_bad_rule(tfasnp);
    f = fasn_start(tfasnp);
    if (!tcasnp || !tcasnp->stringp || !tfasnp || !tfasnp->stringp)
        fatal(8, "cf_obj_rule");
    if (*tcasnp->stringp != *tfasnp->stringp) fatal(9, "cf_obj_rule");
    if (*tcasnp->stringp == ASN_INTEGER)
	{
	if (tcasnp->lth == tfasnp->lth) return memcmp(c, f, tcasnp->lth);
	else return (tcasnp->lth < tfasnp->lth)? -1: 1;
	}
    clth = tcasnp->lth;
    rlth = tfasnp->lth;
    lth = ((clth < rlth)? clth: rlth);
    if (*tcasnp->stringp == ASN_BITSTRING)
	{
	lth--;
	c++;
	f++;
	clth--;
	rlth--;
	}
    if ((ansr =  memcmp(c, f, lth)) || clth == rlth) return ansr;
    if (!mode) return -1;
    return (clth < rlth)? mode: -mode;
    }

int check_AddrRanges()
    {
/**
Function: Checks individual numbers or ranges of numbers in the object against
ranges of numbers in the rules
Inputs: casnp (a global) is at the first sequence of choices
	rasnp (a global) is at the Special rule's definer
Returns: 1 if no error, else -1
Procedure:
1. IF the sequence of choices is empty (have no addresses), return OK
   IF the definee of the rule is empty (no addresses allowed), return error
   FOR all the rules
1.1	IF have a range whose min is > its own max, report bad rule
        Calculate this rule's max + 1
1.2	IF next rule's min is <= this rule's max + 1, report bad rule
   Starting at the first choice in the object, FOR each object choice
        Set up the object's min & max pointers
2.	Starting at the first rule
        WHILE rule's max is less than object's min
            Skip to the next choice in the rules
	IF beyond end of rules, return -1
	IF the object's min is less than the rule's min OR
	    the object's max is more than the rule's max OR
            there's a maxsize AND either one is too big, return -1
        Bump cmax up by one
        IF cmax is >= next min, return error
3. Skip to the the next rule after this Special one
  Return 1
**/
    ushort clev, rlev;
    struct asn *cminp, cmax, *next_cminp;
    struct fasn *frasnp,
	*next_fasnp,
	*tfasnp, rmax, *rmaxp;
    uchar *b, *c, cc, cmaxbuf[20], rmaxbuf[20];
    int ansr = 0, have_range, maxsiz;
						    /* step 1 */
    if (!rasnp || !rasnp->level || !&rasnp[1] || !rasnp[1].level ||
        !&rasnp[2] || !rasnp[2].level)
        fatal(8, "check_AddrRanges");
    frasnp = &rasnp[2];  // start at first range in rules
    if (!casnp->lth) return 1;
    rlev = frasnp->level;
    for (tfasnp = frasnp, next_fasnp = skip_fasn(tfasnp, tfasnp, 1);
        next_fasnp && next_fasnp->level >= rlev; tfasnp = next_fasnp,
        next_fasnp = skip_fasn(next_fasnp, tfasnp, 1))
        {
        have_range = 0;
	if (*GET_FILE_ASN_REF(tfasnp) == ASN_SEQUENCE) // have a range 
            {
            if (!tfasnp || !tfasnp->level || !&tfasnp[1] || !tfasnp[1].level || 
                !&tfasnp[2] || !tfasnp[2].level)
                fatal(8, "check_AddrRanges"); 
            rmaxp = &tfasnp[2]; // set to max of range
            if (tfasnp[1].lth != tfasnp[2].lth || 
                memcmp(fasn_start(&tfasnp[1]), fasn_start(&tfasnp[2]), tfasnp[1].lth))
                have_range = 1; 
            }
	else rmaxp = tfasnp;  // set to current rule
        if (rmaxp->lth > 17) return hit_bad_rule(rmaxp);
        copynbytes(rmaxbuf, GET_FILE_ASN_REF(rmaxp),
            rmaxp->lth + fasn_start(rmaxp) - GET_FILE_ASN_REF(rmaxp));
        rmax.stringp = rmaxbuf;
        rmax.lth = rmaxp->lth;
        if (rmax.lth < 2)
            {
            ansr = hit_bad_rule(rmaxp);
            if (!verbose) return ansr;
            }
        rmax.level = rmaxp->level;
        if (*GET_FILE_ASN_REF((&rmax)) == ASN_BITSTRING) // round up the max
            {
            c = fasn_start(&rmax);
            cc = c[rmax.lth - 1];  // last byte
            if (have_range)  // check before rounding up
                {
                if ((cc & (1 << *c)))  // last bit is 1
                    {
                    ansr = hit_bad_rule(&tfasnp[2]);
                    if (!verbose) return ansr;
                    }  
                }                
            cc |= ((1 << *c) - 1);  // round it up
            }
                                                        // step 1.1
	if (rmaxp != tfasnp)    // have a range
	    {          // get start of range
            if (tfasnp[1].lth > 17) return hit_bad_rule(&tfasnp[1]);
            copynbytes(cmaxbuf, GET_FILE_ASN_REF((&tfasnp[1])),
                tfasnp[1].lth + fasn_start(&tfasnp[1]) -
                GET_FILE_ASN_REF((&tfasnp[1])));
            cmax.stringp = cmaxbuf;
            cmax.lth = tfasnp[1].lth;
            if (cmax.lth < 2)
                {
                ansr = hit_bad_rule(&tfasnp[1]);
                if (!verbose) return ansr;
                }
            cmax.level = tfasnp[1].level;
            if (*cmaxbuf == ASN_BITSTRING && have_range)
                {
                c = asn_start(&cmax);
                cc = c[cmax.lth - 1];
                if (!(cc & (1 << *c)))  // last bit is 0
                    {
                    ansr = hit_bad_rule(rmaxp);
                    if (!verbose) return ansr;
                    }
                }
            if (cf_obj_rule(&cmax, &rmax, 0) > 0)
                {
                ansr = hit_bad_rule(tfasnp);
                if (!verbose) return ansr;
                }
	    }
	if (*GET_FILE_ASN_REF(next_fasnp) == ASN_SEQUENCE) // get next rule
            rmaxp = &next_fasnp[1];
	else rmaxp = next_fasnp;
        if (!rmaxp || !rmaxp->level ||
            rmaxp->lth > 17) return hit_bad_rule(rmaxp);
        copynbytes(cmaxbuf, GET_FILE_ASN_REF(rmaxp),
            rmaxp->lth + fasn_start(rmaxp) - GET_FILE_ASN_REF(rmaxp));
        cmax.stringp = cmaxbuf;
        cmax.lth = rmaxp->lth;
        cmax.level = rmaxp->level;
        b = fasn_start(&rmax);
                                                          // step 1.2
       if (*rmaxbuf == ASN_BITSTRING && cmax.lth > rmax.lth)
            {  // have to bump at the right place
            for (c = &b[rmax.lth]; rmax.lth < cmax.lth; *c++ = 0, rmax.lth++,
                rmaxbuf[1]++);
            }
        for (c = &b[rmax.lth - 1]; c > b; c--)
            {
            (*c)++;   // bump it up
            if (*c != 0) break;  // no carry
            }

        if (cf_obj_rule(&cmax, &rmax, 0) <= 0)
            {
            ansr = hit_bad_rule(tfasnp);
            if (verbose)
                {

                printf(" at ");
                for (c = &b[1]; c < &b[rmax.lth]; printf("%02X ", *c++));
                }
            else return ansr;
            }
        }
    if (ansr) return -1;
    casnp++;      /* at the first object choice */
    if (!&rasnp[1] || !rasnp[1].level) return hit_bad_rule(rasnp);
    if (!rasnp[1].lth) return hit_error(casnp, &rasnp[1]);
    cmax.stringp = cmaxbuf;
    for (clev = casnp->level; casnp->level >= clev;
        casnp++)
	{
	if (!casnp->lth) return hit_error(casnp, rasnp);
	if (*casnp->stringp == ASN_SEQUENCE)
	    {
	    cminp = (++casnp);
    	    if (*cminp->stringp != *(++casnp)->stringp)
                return hit_error(casnp, rasnp);
	    }           /* leaves casnp at upper limit */
	else cminp = casnp;
	if (casnp[1].level < clev) next_cminp = (struct asn *)0; // at end
	else 
            {
            if (*(next_cminp = &casnp[1])->stringp == ASN_SEQUENCE) 
	        next_cminp++;          // min of following range
            if (next_cminp->lth > 17) return hit_error(next_cminp, frasnp);
            }
        copynbytes(cmaxbuf, casnp->stringp, FULL_LENGTH(casnp));
	if (!(cmax.lth = casnp->lth)) return hit_error(casnp, frasnp);
	cmax.level = casnp->level;
	if (*cmax.stringp == ASN_BITSTRING)
	    {
	    c = asn_start(&cmax);
	    if (*c) c[cmax.lth - 1] |= ((1 << *c) - 1); // fill unused bits with ones
	    }
	else if (*cmaxbuf != ASN_OCTETSTRING && *cmaxbuf != ASN_INTEGER)
	    return hit_error(casnp, rasnp);      /* unsupported data type */
	if (*cminp->stringp != *(GET_FILE_ASN_REF((&frasnp[1]))))
            return hit_error(casnp, &frasnp[1]);
								/* step 2 */
	for (tfasnp = frasnp; tfasnp->level >= rlev;
            tfasnp = skip_fasn(tfasnp, tfasnp, 1))
	    {
    	    if (*GET_FILE_ASN_REF(tfasnp) == ASN_SEQUENCE) rmaxp = &tfasnp[2];
    	    else rmaxp = tfasnp;
            copynbytes(rmaxbuf, GET_FILE_ASN_REF(rmaxp),
                rmaxp->lth + fasn_start(rmaxp) - GET_FILE_ASN_REF(rmaxp));
            rmax.stringp = rmaxbuf;
   	    rmax.lth = tfasnp[2].lth;
    	    rmax.level = tfasnp[2].level;
    	    if (*GET_FILE_ASN_REF((&rmax)) == ASN_BITSTRING)
    	        {
    	        c = fasn_start(&rmax);
    	        if (*c) c[rmax.lth - 1] |= ((1 << *c) - 1);
    	        }
            if (cf_obj_rule(cminp, &rmax, 0) <= 0) break;
	    }
	if (tfasnp->level < rlev) return hit_error(cminp, frasnp);
	if (tfasnp[3].level == tfasnp[2].level)
	    {
            maxsiz = get_fasn_num(&tfasnp[3]);
	    if (*cmax.stringp == ASN_BITSTRING) maxsiz++;
	    }
	else maxsiz = 0;
	if ((maxsiz && cminp->lth > maxsiz) ||
	    cf_obj_obj(cminp, &cmax) < 0 ||
            cf_obj_rule(cminp, &tfasnp[1], -1) < 0)
            return hit_error(cminp, &tfasnp[1]);
	if ((maxsiz && cmax.lth > maxsiz) ||
            cf_obj_rule(&cmax, &rmax, 1) > 0)
            return hit_error(casnp, &tfasnp[2]);
        b = asn_start(&cmax);
        for (c = &b[cmax.lth - 1]; c > b; c--)
            {
            (*c)++;
            if (*c != 0) break;  // no carry
            }
	if (next_cminp && cf_obj_obj(&cmax, next_cminp) <= 0)
	    return hit_error(next_cminp, &tfasnp[2]);
	}
    rasnp = skip_fasn(rasnp, rasnp, 1);
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    return 1;
    }

static uchar nameConstraintID[] = { 0x55, 0x1d, 0x1e },
	     policyMappingID[]  = { 0x55, 0x1d, 0x21 },
	     keyUsageID[]       = { 0x55, 0x1d, 0xF  };
#define CERT_SIGN_BIT 0x4

int check_CA_rules()
    {
/**
Function: Checks that, if doing a CA, all appropriate extensions for a CA
are present, or, if not doing a CA, that none is present
Inputs: casnp points to Extensions
Procedure:
1. Search extensions to see if name constraint OR policy mapping OR
        cert-sign bit in key usage is present
	Note which one was found
        IF one is present AND not doing for a CA
            Return negative of offset to offender
2. IF doing for a CA AND didn't find all, return -1
   Return 1
**/
    struct asn *tasnp, *stasnp;
    int ansr, level = casnp[1].level;
    uchar *c;
							    /* step 1 */
    for (ansr = 0, tasnp = &casnp[1]; tasnp->level == level;
        tasnp = skip_asn(tasnp, tasnp, 1))
	{
	stasnp = &tasnp[1];
        if (!memcmp(asn_start(stasnp), nameConstraintID, stasnp->lth))
	    ansr |= 1;
        else if (!memcmp(asn_start(stasnp), policyMappingID, stasnp->lth))
	    ansr |= 2;
        else if (!memcmp(asn_start(stasnp), keyUsageID, stasnp->lth))
	    {
	    if (*(++stasnp)->stringp == ASN_BOOLEAN) stasnp++; /* to octets */
	    c = asn_start(stasnp);       /* inside oct string */
	    if ((c[3] & CERT_SIGN_BIT)) ansr |= 4;
	    }
	if (ansr && !isForCA)
	    {
	    casnp = stasnp;
	    return hit_error(stasnp, rasnp);
	    }
	}
    if (isForCA && ansr != 7) return hit_error(casnp, rasnp);
    return 1;
    }

int check_keyMethod()
    {
/**
Function: Checks key identifier against subject's public key, if method calls
    for that
Inputs: casnp is at the subject key identifier extension's extnValue.octet
        rasnp is at definer
Procedure:
1. Go to the rule for key hash type
   IF that is either of the ones that use a hash
2.      Find the subject public key
	Hash it appropriately
	IF that differs from the current value, return error
   Return OK
**/
    int ansr, num;
    struct asn *savcasnp = casnp, *tasnp;
    uchar *b, *navp, *enavp;

    if (rasnp[1].level == rasnp->level) ++rasnp;   /* if a definee */
    else return hit_bad_rule(rasnp);
    if (*(GET_FILE_ASN_REF(rasnp)) != ASN_SEQUENCE) return hit_bad_rule(rasnp);
    rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (*(GET_FILE_ASN_REF(rasnp)) != ASN_INTEGER) return hit_bad_rule(rasnp);
    if (((num = get_fasn_num(rasnp)) == id_key_sha1 ||
        num == id_key_trunc_sha1) && rasnp[1].level == rasnp->level)
	{
						    /* step 2 */
	rasnp++;
        if (!rasnp || !rasnp->level ||
	    *GET_FILE_ASN_REF(rasnp) != ASN_PRINTABLE_STRING)
	    return hit_bad_rule(rasnp);
	navp = so_free;
	enavp = so_free += copynbytes(navp, fasn_start(rasnp), rasnp->lth);
	b = navp;
	tasnp = casnp;
	if ((ansr = navigate(&tasnp, &b, enavp)) < 0) return ansr;
	if (!ansr) return hit_error(casnp, grasnp);
	sha1_hash(&asn_start(tasnp)[1], tasnp->lth - 1, 0, enavp, &ansr, HASH_BOTH);
	b = &enavp[ansr];
	if (num == id_key_trunc_sha1)
	    {
	    enavp += ansr - 8;
            *enavp &= 0xF;
	    *enavp |= 0x40;
	    }
	if (savcasnp->lth != b - enavp || memcmp(enavp, asn_start(savcasnp),
	    b - enavp)) return hit_error(savcasnp, rasnp);
	}
    return 1;
    }

int check_limits()
    {
/**
Inputs: casnp is at test item, which must be an OF
        rasnp is at definer for special rule
Procedure:
1. IF location calls for navigation
        Make temporary copy of location rule (for use with multi-level OFs )
        Count the 'alls', setting any to start at the beginning
2. Set up the start of a list of items
   FOR all items at all levels specified
	IF location is found
    	    IF it's in the list, increment its count
    	    ELSE make a new item for it
	    IF at an all_count, increment it
	ELSE IF have 'alls' set the string for the next one
3. IF there are any limits
       FOR each item in the list of limits
    	    Find it in the list
    	    IF the count is too high or too low, return -1
	    Set its count to 1
4. FOR each item in the list
	IF its count exceeds 1, return -1
   Back rasnp up one because atSpecial will increment it
5. Return 1

**/
    struct fasn *lrasnp, *savgrasnp, *sav_rasnp;
    struct asn *stasnp, *scasnp;
    int ansr, level, have_spec;
    long val;
    char *a, *b, *c,
        *lasts, *laste, /* start and end of last 'all' field */
        *navp, *enavp;  /* start and end on navigation string */
    uchar *old_free = so_free;
    int all_count, min;
    struct count_list
	{
	struct asn *asnp;
	int count;
	} *count_list, *clistp;
						        /* step 1 */
    if (!&rasnp[1] || !rasnp[1].level) return hit_bad_rule(rasnp);
    if (rasnp[1].level == rasnp->level) ++rasnp;   /* at definee */
    else return hit_bad_rule(rasnp);
    sav_rasnp = rasnp;
    if (*(GET_FILE_ASN_REF(rasnp)) != ASN_SEQUENCE) return hit_bad_rule(rasnp);
    rasnp++;        /* at location */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (*GET_FILE_ASN_REF(rasnp) == ASN_PRINTABLE_STRING)
	{
        if (*(c = fasn_start(rasnp)) != 'd') return hit_bad_rule(rasnp);
		        /* get location data, except for initial 'd' */
	navp = so_free;
        so_free += copynbytes(so_free, &c[1], rasnp->lth - 1);
	enavp = so_free;
        *so_free++ = 0;         /* mark end */
        for (all_count = 0, b = c = navp, lasts = (char *)0; *c; c++)
    	    {
    	    if (*c == 'a')
    	        {
    	        *c = '0';
                all_count++;
		lasts = c;
    	        }
    	    }
        laste = lasts;
	for (min = all_count << 2; min--; *so_free++ = 0); /* make spares */
	}
    else return hit_bad_rule(rasnp);
    rasnp++; /* at IdAndLimits, if any */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (rasnp->level == rasnp[-1].level) have_spec = 1;
    else have_spec = 0;
    if (have_spec && *GET_FILE_ASN_REF(rasnp) != ASN_SEQUENCE)
        return hit_bad_rule(rasnp);
    so_free = ROUND4(so_free);
    count_list = (struct count_list *)so_free;
    count_list->asnp = (struct asn *)0;
							    /* step 2 */
    savgrasnp = grasnp;
    for (scasnp = ++casnp; 1; )
	{
	grasnp = savgrasnp;
	b = navp;
	if ((ansr = navigate(&stasnp, (uchar **)&b, enavp)) < 0)
            return hit_error(casnp, grasnp);
	if (ansr > 0)
	    {
    	    for (clistp = count_list; clistp->asnp &&
    	        (clistp->asnp->lth != stasnp->lth ||
                memcmp(asn_start(clistp->asnp), asn_start(stasnp),
                stasnp->lth));
    	        clistp++);
    	    if (clistp->asnp) clistp->count++;
    	    else
    	        {
    	        clistp->asnp = stasnp;
    	        clistp->count = 1;
    	        clistp[1].asnp = (struct asn *)0;
		clistp[1].count = 0;
    	        }
	    if (all_count) laste += bump(lasts, laste, &enavp);
    	    }
	else if (all_count && !set_next(navp, lasts, laste, &enavp)) break;
	if (all_count) casnp = scasnp;
	if (casnp->level < scasnp->level) break;
	}
							    /* step 3 */
    if (have_spec)
	{
        rasnp++;
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	for (level = rasnp->level; rasnp && rasnp->level == level; rasnp++)
	    {
	    rasnp++;     /* at ObjIdOrInt */
            if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
            if (*rasnp->stringp == ASN_OCTETSTRING)
                {
                for (clistp = count_list; clistp->asnp &&
                    memcmp(clistp->asnp->stringp, fasn_start(rasnp), rasnp->lth); 
                    clistp++);
                }
            else
                {        
                for (clistp = count_list; clistp->asnp &&
		    (clistp->asnp->lth != rasnp->lth ||
                    memcmp(asn_start(clistp->asnp), fasn_start(rasnp),
                    rasnp->lth)); clistp++);
                }
	    rasnp++;        /* at max */
            if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	    if (clistp->asnp)
		{
		if (clistp->count > get_fasn_num(rasnp))
                    {
                    if (verbose) printf("\n    Too many\n");
                    return hit_error(clistp->asnp, rasnp);
                    }
		clistp->count = 1;
		}
            if (!&rasnp[1] || !rasnp[1].level) return hit_bad_rule(&rasnp[1]);
	    if (rasnp[1].level == rasnp->level) /* have min */
		{
		rasnp++;            /* at min */
                if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
		if ((min = get_fasn_num(rasnp)) == 0xFFFFFFFF) return hit_bad_rule(rasnp);
		if ((!clistp->asnp && min > 0) ||
		    (min && clistp->count < min))
                    {
                    if (verbose) printf("\n    Too few/one missing\n");
		    return hit_error(clistp[(clistp->asnp)? 0: -1].asnp,
                        rasnp);
                    }
		}
	    }
	}
							/* step 4 */
    for (clistp = count_list; clistp->asnp; clistp++)
	{
	if (clistp->count > 1) return hit_error(clistp->asnp, sav_rasnp);
	}
    so_free = old_free;
    rasnp--;        /* because atSpecial will increment it */
    return 1;                                           /* step 5 */
    }

int check_subordination()
    {
/**
Name: check_subordination()
Function: Checks that name pointed to by casnp matches current CA name for
amount specified
Inputs: casnp is at name
	rasnp is at definer for special rule
Returns: 1 if OK, -1 if not
Procedure:
1. Check rule
2. IF number is not zero
	Find the length of num members
	IF didn't run off the end, use that length
	ELSE use full length of CA name
   ELSE check full issuer name
   IF name doesn't match for requisite number of bytes, return -1
   Return 1
**/
    int num;
    struct asn *rdn_asnp, *ava_asnp, *tasnp;
							/* step 1 */
    if (!issuer_asnp) return hit_bad_rule(rasnp);
    if (rasnp[1].level == rasnp->level) ++rasnp;   /* at a definee */
    else return hit_bad_rule(rasnp);
    if (*(GET_FILE_ASN_REF(rasnp)) != ASN_INTEGER) return hit_bad_rule(rasnp);
							/* step 2 */
    if ((num = get_fasn_num(rasnp)))
	{
        for (rdn_asnp = &issuer_asnp[1], tasnp = &casnp[1];
            rdn_asnp->stringp && num;
            rdn_asnp = skip_asn(rdn_asnp, rdn_asnp, 1))
    	    {
    	    for (ava_asnp = &rdn_asnp[1], tasnp++;
                ava_asnp->level == rdn_asnp[1].level && num;
    	        ava_asnp = skip_asn(ava_asnp, ava_asnp, 1),
                tasnp = skip_asn(tasnp, tasnp, 1), num--)
		{
		if (ava_asnp->lth != tasnp->lth ||
		    memcmp(ava_asnp->stringp, tasnp->stringp,
                    FULL_LENGTH(tasnp))) break;
		}
            /* stops at first of diff or num members */
    	    }
	if (num) return hit_error(casnp, rasnp);
	}
    else if (memcmp(casnp[1].stringp, issuer_asnp[1].stringp,
        issuer_asnp->lth))
        return hit_error(casnp, rasnp);
    casnp = skip_asn(casnp, casnp, 1);
    return 1;
    }

int copynbytes(uchar *to, uchar *from, int lth)
    {
    memcpy(to, from, lth);
    return lth;
    }

int doRule(int mode)
/**
Function: Tests cert/CRL for Rule
Inputs: mode 0 = plain rule, 1 = definer
        casnp is at test object (which may be definer)
	rasnp is at Rule or RuleD
Procedure:
1. IF the least-first item is present, note item is least significant first
   IF ForbidAllowRequire item is missing OR
        (doing a definer AND rule is forbid), return bad rule
1a FOR each member of Target sequence
    	IF it's a bit string AND beyond the first Target, return -1
        IF it matches the instance, break out of FOR
   IF had an error, return -1
   IF (forbidding AND found target) OR (not forbidding AND didn't find)
	return hit_error
   IF at a definer, set the rule index
   Skip to the end of these targets
   Go to next test item
2. IF there's a RuleChoice,
	IF in definer mode, return bad rule
        ELSE note what a call to the RuleChoice returns
   ELSE set rasnp
   Return answer from calls
*/
    {
    int ansr, index;
    struct asn *tasnp;
    struct fasn *tfasnp;
    uchar *ref, typ, lsf, forbid;
    ushort rlevel;
				                    /* step 1 */
    rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    if (*(ref = GET_FILE_ASN_REF(rasnp)) == ASN_BOOLEAN)
	{
	lsf = *ref;
	rasnp++;
        if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	}
    else lsf = 0;
    ref = GET_FILE_ASN_REF(rasnp);
    typ = *ref & ~(ASN_CONT_SPEC0);
    if ((*ref & ASN_CONT_SPEC0) != ASN_CONT_SPEC0 ||
        (mode && (typ == id_forbid || typ >= id_part_forbid)))
        return hit_bad_rule(rasnp);
						    /* step 1a */
    tfasnp = rasnp;
    rasnp++;
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    for (rlevel = rasnp->level, index = 0; rasnp->level == rlevel;
        index++, rasnp = skip_fasn(rasnp, rasnp, 1))
    	{
    	ref = GET_FILE_ASN_REF(rasnp);     /* at a target */
    	if (*ref == ASN_BITSTRING && index) return hit_bad_rule(rasnp);
        if ((ansr = matches_target(typ, lsf))) break;
    	}
    if (ansr < 0) return -1;
    if (typ == id_forbid || typ == id_part_forbid) forbid = 1;
    else forbid = 0;
    if ((ansr && forbid) || (!ansr && !forbid)) return hit_error(casnp, tfasnp);
    if (mode) rule_index = index;
    while (rasnp->level >= rlevel) rasnp++;
    casnp = skip_asn(casnp, casnp, 1);
					        /* step 2 */
    if ((*ref & ASN_PRIV_SPEC) == ASN_PRIV_SPEC)
	{
	if (mode) return hit_bad_rule(rasnp);
        ansr = atRuleChoice();
	}
    return (mode)? ansr: 1;
    }

int get_fasn_num(struct fasn *fasnp)
    {
    struct asn asn;
    if (*GET_FILE_ASN_REF(fasnp) != ASN_INTEGER) return 0xFFFFFFFF;
    return get_fasn_vnum(fasnp);
    }

int get_fasn_vnum(struct fasn *fasnp)  // for tagged integers
    {
    struct asn asn;
    asn.stringp = GET_FILE_ASN_REF(fasnp);
    asn.lth = fasnp->lth;
    asn.level = fasnp->level;
    return get_asn_num(&asn);
    }

struct fasn *get_limit(struct fasn *tfasnp)
    {
    int param;

    if (!tfasnp || !tfasnp->level) 
        {
        hit_bad_rule(tfasnp);
        return (struct fasn *)0;
        }
    if (*(GET_FILE_ASN_REF(tfasnp)) == (ASN_CONT_SPEC + 1))
	{
	for (param = get_fasn_vnum(tfasnp), tfasnp = prasnp; param--; tfasnp++);
	}
    return tfasnp;
    }

int hit_bad_rule(struct fasn *trasnp)
    {
    int offset;
    uchar *c;

    if (!trasnp->stringp || !trasnp->level)
        c = &fasn_start(&trasnp[-1])[trasnp->lth];
    else c = trasnp->stringp;
    offset = c - rfile_asnbase->stringp;

    if (verbose) printf("\nBad rule at offset %d (0x%X)", offset, offset);
    bad_rule_file = 1;
    sav_rule_fasnp = rasnp = trasnp;
    return -2;
    }

int hit_error(struct asn *asnp, struct fasn *fasnp)
    {
    casnp = asnp;
    failure_point = asnp->stringp;
    sav_rule_fasnp = fasnp;
    return -1;
    }

int in_range(struct fasn *trasnp)
    {
/**
Returns: 1 if within range; 0 if not
**/
    trasnp++;
    if (!trasnp || !trasnp->level || !&trasnp[1] || !trasnp->level) 
        return hit_bad_rule(trasnp);
    if (limit_test(trasnp) < 0 || limit_test(&trasnp[1]) > 0)
	return 0;
    return 1;
    }

int is_required(struct fasn *trasnp)
    {
/**
Inputs: casnp beyond a sequence/set
	rasnp at a member
Returns: 1 if member is required; 0 if not
Procedure:
1. IF the rule has no length, return 0  (definedBy possibility)
   Skip the name
   IF the tag is ASN_NONE, return 0
   IF rule has the optional flag, return 0
   IF skip to RuleChoice
   IF rule is definedBy
	IF no rule_index, return bad rule
	Skip to the the defined member
	Return what is_required returns for that
   Return 1
**/
    int rlevel, tag, tmp;
						/* step 1 */
    if (!(trasnp++)->lth) return 0;  /* else rasnp at name or Tag */
    if (!trasnp || !trasnp->level) return hit_bad_rule(trasnp);
    rlevel = trasnp->level;
    if (*(GET_FILE_ASN_REF(trasnp)) == ASN_UTF8_STRING) trasnp++;
                    /* at Tag, if any */
    if (!trasnp || !trasnp->level) return hit_bad_rule(trasnp);
    if (*(GET_FILE_ASN_REF(trasnp)) == ASN_CONT_SPEC)
        {
        if (!(tag = get_fasn_num(trasnp))) return hit_bad_rule(trasnp);
	if (tag == ASN_NONE) return 0;
        trasnp++;
        if (!trasnp || !trasnp->level) return hit_bad_rule(trasnp);
        }
    if (*(GET_FILE_ASN_REF(trasnp)) == ASN_BOOLEAN) return 0;
    if (*(GET_FILE_ASN_REF(trasnp)) == ASN_SEQUENCE) trasnp++;
    if (!trasnp || !trasnp->level) return hit_bad_rule(trasnp);
    if (trasnp->level == rlevel &&
        *(GET_FILE_ASN_REF(trasnp)) == RULE_DEFINEDBY_TAG)
	{
	if (rule_index < 0) return hit_bad_rule(trasnp);
        trasnp = skip_fasn(&trasnp[1], trasnp, rule_index);
	return is_required(trasnp);
	}
    return 1;
    }

int limit_test(struct fasn *trasnp)
    {
/**
Function: Compares an object to a rule for the limit
Inputs: Pointer to rule having limit
        casnp is at object to be tested
Returns: -1 if object < rule; 0 if equal; 1 if object > rule, -2 if bad rule
Procedure:
1. IF the rule calls for a parameter
	Step through the parameters to find the parameter
	Use that as the rule pointer
2. IF the rule is for an integer OR some other right-justified string
	Compare them that way
   ELSE compare them as left-justified strings
**/
    uchar *d, *e, *c = asn_start(casnp),
        *ref;
    int ansr = 0, lth, param;

    if (!(trasnp = get_limit(trasnp)) || !trasnp->level) return hit_bad_rule(trasnp) - 1;
    ref = (GET_FILE_ASN_REF(trasnp));

    if (*ref == ASN_INTEGER || *ref == ASN_CONT_SPEC)
	{
	if (casnp->lth > trasnp->lth) ansr = 1;
	else if (casnp->lth < trasnp->lth) ansr = -1;
	else
	    {
	    d = fasn_start(trasnp);
	    ansr = memcmp(c, d, casnp->lth);
            if (*ref == ASN_INTEGER && (*c & 0x80) != (*d & 0x80))
    	        ansr = -ansr;
	    }
	}
    else if (*ref == ASN_OCTETSTRING)
	{
	lth = (trasnp->lth > casnp->lth)? casnp->lth: trasnp->lth;
	ref = fasn_start(trasnp);
	if (!(ansr = memcmp(c, ref, lth)))
	    {
	    if (casnp->lth > lth)
		{
                for (e = &c[casnp->lth], c += lth; c < e && !*c; c++);
		ansr = (c < e)? 1: -1;
		}
	    else if (trasnp->lth > lth)
		{
                for (e = &ref[trasnp->lth], ref += lth; ref < e && !*ref; ref++);
		ansr = (ref < e)? -1: 1;
		}
	    }
	}
    else return hit_bad_rule(trasnp);
    return ansr;
    }

int locate(struct asn **aasnpp, struct fasn *lrasnp)
    {
/**
Name: locate()
Function: Locates a test item based on a location rule
Inputs: Address of ptr to test item
	Pointer to location rule
	casnp is at start of location search
	grasnp is at rule for casnp (to navigate over optional items)
Output: Address of located item.  Not valid if none found
Returns: 1 if found, 0 if not found, -1 if bad rule
Procedure:
1. IF rule calls for navigation
        Navigate there
	See if it is there
2. ELSE IF rule specifies a tag
	Drop down to member level of test item
        FOR each member of the test item, look for the tag
	    At each member, advance the group rule to the current item's tag
3. ELSE IF rule specifies an identifier
	Make a location string
	Count the number of 'alls'
	Save the identifier rule
	Search the members for an instance of the identifier
	IF one found, return 1
4. IF couldn't find it, return 0, else return 1
**/
    struct asn *savcasnp, *tasnp = casnp;
    struct fasn *trasnp;
    uchar *old_free, *ref, *b;
    char *navp, *enavp, *lasts, *laste;
    int ansr = 1, level, glevel, tag, of, tmp;
							    /* step 1 */
    if (!grasnp || *(ref = GET_FILE_ASN_REF(grasnp)) == RULE_SEQOF_TAG ||
        *ref == RULE_SETOF_TAG)
        of = 1;
    else of = 0;
    if (!lrasnp || !lrasnp->level) return hit_bad_rule(lrasnp);
    if (*(ref = GET_FILE_ASN_REF(lrasnp)) == ASN_PRINTABLE_STRING)
	{
	navp = fasn_start(lrasnp);
	if ((ansr = navigate(&tasnp, (uchar **)&navp, &navp[lrasnp->lth])) < 0)
            return hit_bad_rule(lrasnp);
	if (ansr > 1) ansr = 1;
	}
							    /* step 2 */
    else if (*ref == ASN_CONT_SPEC)
	{
	glevel = grasnp->level;
        tag = get_fasn_vnum(lrasnp);
        level = tasnp->level;
	do
	    {
            if (*tasnp->stringp == tag) break;
            tasnp = skip_asn(tasnp, tasnp, 1);
	    if (!of)
		{  /* advance grasnp to next instance of tasnp's current tag */
		for (grasnp = skip_fasn(grasnp, grasnp, 1);
                    grasnp->level == glevel;
                    grasnp = skip_fasn(grasnp, grasnp, 1))
		    {
    		    trasnp = &grasnp[1];
    		    if (*GET_FILE_ASN_REF(trasnp) == ASN_UTF8_STRING) trasnp++;
    		    if (*GET_FILE_ASN_REF(trasnp) == ASN_CONT_SPEC)
			{
                        if (get_fasn_num(trasnp) == *tasnp->stringp) break;
			}
		    }
		if (grasnp->level != glevel) return 0;
		}
	    }
	while (tasnp->level == level);
        if (tasnp->level != level) return 0;
        }
							    /* step 3 */
    else if (*ref == ASN_SEQUENCE)
	{
	lrasnp++;       /* go to location */
        if (!lrasnp || !lrasnp->level) return hit_bad_rule(lrasnp);
	navp = old_free = so_free;
        enavp = so_free += copynbytes(navp, fasn_start(lrasnp), lrasnp->lth);
	*so_free++ = 0;
	for (laste = navp, ansr = 0, lasts = (char *)0; laste < enavp; laste++)
	    {
	    if (*laste == 'a')
		{
                *laste = '0';
		lasts = laste;
		ansr++;
		}
	    }
	for (ansr <<= 2; ansr--; *so_free++ = 0);   /* add spares */
	laste = lasts;
	lrasnp++;       /* at identifier rule */
        if (!lrasnp || !lrasnp->level) return hit_bad_rule(lrasnp);
	for (trasnp = grasnp, savcasnp = casnp, ansr = 0; !ansr; )
	    {
	    casnp = savcasnp;
	    grasnp = trasnp;
	    b = navp;     /* navigate changes b if file ref is encountered */
	    if ((ansr = navigate(&tasnp, &b, enavp)) < 0) return ansr;
	    if (ansr &&     /* found something at that index */
	        ((*(GET_FILE_ASN_REF(lrasnp)) == ASN_CONT_SPEC &&
		*tasnp->stringp == get_fasn_num(lrasnp)) ||
		(*(GET_FILE_ASN_REF(lrasnp)) != ASN_CONT_SPEC &&
	        (tasnp->lth == lrasnp->lth &&  /*  matched id */
		!memcmp(tasnp->stringp, GET_FILE_ASN_REF(lrasnp),
		    FULL_LENGTH(tasnp)))))) break;
		{            /* try next one */
		if (!lasts || !set_next(navp, lasts, laste, &enavp)) break;
		}
	    }
	}
    if (ansr > 0)
	{
        *aasnpp = tasnp;
	rasnp = lrasnp;
	}
    return ansr;
    }

int map_stuff(int val)
    {
    int siz = 8;
    char *c;

    if (map_string && *map_string) siz += strlen(map_string);
    c = (char *)calloc(1, siz);
    if (siz > 8) sprintf(c, "%d.%s", val, map_string);
    else sprintf(c, "%d", val);
    if (map_string) free(map_string);
    map_string = c;
    return -1;
    }

int matches_target(uchar mode, uchar lsf)
    {
/**
Function: Tests cert/CRL against a target
Inputs: mode is tag of ForbidAllowRequire
	lsf is non-zero if items are least-significant-first
	casnp is at object
	rasnp is at Target
Returns: 1 if matched OK, 0 if failure, -1 if bad rule
Procedure:
1. IF target is a Tag, an integer or an object identifier
        IF the item doesn't match, return 0
   ELSE IF target is a character/octet string
	IF the item is shorter than the rule, return 0
	ELSE IF full match AND lengths don't match, return 0
    	IF least-significant-first, adjust start of match
        IF the item doesn't match the rule for the rule's length, return 0
2. ELSE IF it's a bit string, return what bit_match returns
   ELSE IF it's a range, return what in_range returns
3. ELSE IF target is an 'and', 'or' or 'just1' condition
	IF it's an 'and' condition, count the number of targets
	ELSE just one target
	FOR the all items at this level
	    IF it matches a target, decrement target-count
	IF target-count > 0, return 0
   ELSE return -1
   Return 1
**/

    struct asn *tasnp;
    uchar *ref,   
        *rvalp,
	*cvalp = asn_start(casnp);
    ushort level;
    int i;
						    /* step 1 */
    if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
    rvalp = fasn_start(rasnp);
    ref = GET_FILE_ASN_REF(rasnp);   // at a  target
    if (*ref == ASN_CONT_SPEC || *ref == ASN_INTEGER || *ref == ASN_OBJ_ID)
	{
        if ((*ref == ASN_CONT_SPEC && *casnp->stringp != get_fasn_num(rasnp)) ||
    	    (*ref == ASN_INTEGER && get_asn_num(casnp) != get_fasn_num(rasnp)) ||
            (*ref == ASN_OBJ_ID && (rasnp->lth != casnp->lth ||
            memcmp(rvalp, cvalp, rasnp->lth))))
    	    return 0;
	}
    else if (*ref == ASN_OCTETSTRING)
	{
	if (casnp->lth < rasnp->lth) return 0;
	else if (mode <= id_require && rasnp->lth != casnp->lth) return 0;
        if (lsf) cvalp += (casnp->lth - rasnp->lth);
        if (memcmp(rvalp, cvalp, rasnp->lth)) return 0;
	}
						    /* step 2 */
    else if (*ref == ASN_BITSTRING) return bit_match(mode);
    else if (*ref == ASN_SEQUENCE) return in_range(rasnp);
						    /* step 3 */
    else if ((*ref & ASN_CONT_SPEC))
        {
	level = rasnp->level;
	if ((*ref & 1))
	    {
    	    for (i = 0; rasnp && rasnp->level == level;
                i++, rasnp = skip_fasn(rasnp, rasnp, 1));
            if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	    }
	else i = 1;
        for (tasnp = casnp; tasnp->level == casnp->level; casnp++)
	    {
	    for ( ; rasnp && rasnp && rasnp->level == level;
	        rasnp = skip_fasn(rasnp, rasnp, 1))
	        {
	        if (matches_target((uchar)id_allow, lsf)) i--;
	        }
            if (!rasnp || !rasnp->level) return hit_bad_rule(rasnp);
	    }
	casnp = tasnp;
	if (i > 0) return 0;
        }
    else return hit_bad_rule(rasnp);
    return 1;
    }

static int navigate(struct asn **aasnpp, uchar **navpp, uchar *enavp)
    {
/**
Name: navigate()
Function: Moves through test item and rule set in accordance with navigation
string.  (Rule set is used to tell which items are optional.)
Inputs: Address of ptr to test object reached
	Ptr to present place in navigation string
	Ptr to end of navigation string
	casnp points to item from which to navigate (first member of set or seq)
	rasnp is at navigation string
	grasnp is at rule for casnp (to navigate over optional items)
Output: pointer to test object reached (null if none)
Returns: IF encounters a rule defect, -1 (Assumes the caller will use
              hit_error or hit_bad_rule
         IF not found, 0
         IF found, count of nav bytes used.
Procedure:
1. Find out if starting point is a member of an OF
   Starting at beginning of navigation string, WHILE not at end of string
	IF asked to go to the top, set the test object and the rules to their
	    tops
	ELSE IF asked to go up
	    Back up to next higher level in test object
	    IF at a RuleChoice, go up to the Member
	    Go up to the RuleChoice for this Member
	    Go up to the Member
	    Set 'of' variable for that
	ELSE IF asked to go down
	    Go to the next object struct asn
	    IF at a Member
                Go to the RuleChoice
	    Note if it's an OF
	    Go to the first Member
	ELSE IF asked to go to last item
	    IF not an OF, return error
	    Go beyond in test object and back up one, counting them
	ELSE IF asked to go back
	    Determine how many
	    IF at a RuleChoice, go up to the Member
	    FOR each count
		Go back one in test item
		IF none, return bad rule
	        IF not an OF, go back to previous Member
                IF that's at a different level, return bad rule
		IF atMember returns success, reset test object to where it was
		ELSE IF at last count, return 0
		Reset rules to Member
	ELSE IF *nav is not a decimal digit, return error
        ELSE (asked to go forward)
	    IF at a RuleChoice, go to first Member
	    Find the count
	    IF it's not an OF
    		WHILE haven't exhausted count AND not at end of members
    		    IF member test returns OK,
    			Go to next test object
    		    Go to next rule item
	        IF at end of members, return not found
	    ELSE
		Skip required number of test items
		IF not at right level, return failure
   Return pointer to found object
**/
    uchar *navp, *ref;
    int tmp, of, rlevel, clevel;
    struct asn *stasnp, *tasnp = casnp;
    struct fasn *tgrasnp, *savrasnp;
						    /* step 1 */
    if (!grasnp || *(ref = GET_FILE_ASN_REF(grasnp)) == RULE_SEQOF_TAG ||
        *ref == RULE_SETOF_TAG)
        of = 1;
    else of = 0;
    *aasnpp = (struct asn *)0;
    for (navp = *navpp; navp < enavp; navp++)
        {
	*navpp = navp;
	if (*navp == 't')
	    {
	    tasnp = topcasnp;
	    grasnp = toprasnp;
            if (*(ref = GET_FILE_ASN_REF(grasnp)) == RULE_SEQOF_TAG ||
                *ref == RULE_SETOF_TAG)
                of = 1;
            else of = 0;
	    }
        else if (*navp == 'u')
	    {
	    if (!tasnp->level) return hit_bad_rule(rasnp);
	    for (tmp = tasnp->level; tasnp->level >= tmp; tasnp--);
	    if (*(GET_FILE_ASN_REF(grasnp)) >= ASN_PRIV_CONSTR)
		for (tmp = grasnp->level; grasnp->level >= tmp; grasnp--);
            if (grasnp->level < toprasnp->level) return hit_bad_rule(rasnp);
			/* now at Member */
	    for (grasnp--; *GET_FILE_ASN_REF(grasnp) < ASN_PRIV_CONSTR;
                grasnp--);
            if (grasnp->level < toprasnp->level) return hit_bad_rule(rasnp);
			/* now at RuleChoice above Member */
            for (tmp = grasnp->level; grasnp->level >= tmp; grasnp--);
            if (grasnp->level < toprasnp->level) return hit_bad_rule(rasnp);
			/* now at higher Member */
	    if (*(GET_FILE_ASN_REF((&grasnp[-1]))) == ASN_SEQUENCE) of = 0;
	    else of = 1;
	    }
        else if (*navp == 'd')
	    {
	    if (!(*tasnp->stringp & ASN_CONSTRUCTED)) return 0;
	    tasnp++;
	    if (*(ref = GET_FILE_ASN_REF(grasnp)) == ASN_SEQUENCE)
		{
    		grasnp++;  /* go into member */
                            /* then stop at last item */
		for (tmp = grasnp->level; grasnp->level >= tmp &&
                    *GET_FILE_ASN_REF(grasnp) < ASN_PRIV_CONSTR; grasnp++);
		if (grasnp->level != tmp) /* no RuleChoice */
                    return hit_bad_rule(rasnp);
		ref = GET_FILE_ASN_REF(grasnp);
		}
            if (*ref == RULE_FILEREF_TAG) return hit_bad_rule(rasnp);
            else if (*ref > RULE_SETOF_TAG) return hit_bad_rule(rasnp);
	    else if (*ref <= RULE_SEQUENCED_TAG) of = 0;
	    else of = 1;
	    grasnp += 2 - of;
	    }
	else if (*navp == 'e')
	    {
	    if (!of) return hit_bad_rule(rasnp);
	    for (tmp = tasnp->level; tasnp->level >= tmp; tasnp++);
	    for (tasnp--; tasnp->level > tmp; tasnp--);
	    if (*(GET_FILE_ASN_REF(grasnp)) >= ASN_PRIV_CONSTR) grasnp++;
		/* leaves it at Member */
	    }
	else if (*navp == '-')
	    {
	    if (*(ref = GET_FILE_ASN_REF(grasnp)) >= ASN_PRIV_CONSTR)
		{
		for (tmp = grasnp->level; grasnp->level >= tmp; grasnp--);
		if (grasnp->level <= toprasnp->level)
                    return hit_bad_rule(rasnp);
		}
	    for (tmp = 0, navp++; navp < enavp && *navp >= '0' && *navp <= '9';
		tmp = (tmp * 10) + *navp - '0');
	    if (navp[-1] == '-') tmp = 1;
	    while (tmp--)
		{
    	        stasnp = skip_asn(tasnp, &tasnp[-100], -1);
    	        if (stasnp->level == tasnp->level) tasnp = stasnp;
		else return hit_bad_rule(rasnp);
		if (!of)
		    {
                    for (rlevel = (grasnp--)->level; grasnp->level > rlevel;
                        grasnp--);
		    if (grasnp->level < toprasnp->level)
                        return hit_bad_rule(rasnp);
		    }
		savrasnp = rasnp;
		tgrasnp = grasnp;
		casnp = tasnp;
		clevel = atMember(0);
		rasnp = savrasnp;
		grasnp = tgrasnp;
                if (clevel > 0) tasnp = stasnp;
		else if (!tmp) return 0;
		}
	    }
        else if (*navp < '0' || *navp > 'F') return -1;
	else
	    {
	    if (*(GET_FILE_ASN_REF(grasnp)) >= ASN_PRIV_CONSTR) grasnp += 2 - of; /* to Member */
	    for (tmp = 0; navp < enavp && *navp >= '0' && *navp <= 'F'; navp++)
                tmp = (tmp << 4) + *navp - '0' - ((*navp > '9')? 7: 0);
	    *navpp = navp--;
	    if (!of)
		{
		stasnp = casnp;
    		casnp = tasnp;
		clevel = casnp->level;
                savrasnp = rasnp;
                for (rlevel = (rasnp = grasnp)->level; tmp-- &&
                    casnp->level == clevel; )
    		    {
		    if (atMember(0) < 0) return hit_bad_rule(rasnp);
		    while (rasnp->level > rlevel) rasnp++;
		    }
		tasnp = casnp;
		casnp = stasnp;
		grasnp = rasnp;
		rasnp = savrasnp;
	        if (tasnp->level < clevel) return 0;
		}
	    else if ((stasnp = skip_asn(tasnp, tasnp, tmp))->level ==
		tasnp->level) tasnp = stasnp;
	    else return 0;     /* not enough struct asns */
	    }
        }
    *aasnpp = tasnp;
    return 1;
    }

int set_next(char *navp, char *lasts, char *laste, char **enavpp)
    {
/**
Function: Increments a navigation string that has "alls" in it
Inputs: Ptr to tstart of string
	Ptr to start of last "all" field.
	Ptr to end of last "all" field
	Ptr to address of ptr to end of nav string
Returns: 0 if no more possibilities, else 1
Procedure
1. Note if least field is zero
   Zeroize it
   Find the previous 'all'
   IF none, break out of FOR
2. IF least field was zero
        WHILE this field is zero, go to the previous one, if any
	IF none break out of FOR
	Zeroize it
	Find next previous 'all'
	IF none, break out of FOR
   Increment current field
**/
    char *a, *c;
    int tmp;
							/* step 1 */
    for (c = laste; c >= lasts && *c == '0'; c--);
    if (*c < '0' || *c > 'F') c++;
    if (!(tmp = c - lasts)) tmp = *lasts - '0';
    while (c >= lasts) *c-- = '0';
    for ( ; c >= navp && (*c < '0' || *c > 'F'); c--);
    if (c < navp) return 0;
                                                        /* step 2 */
    if (!tmp)
	{
	while (!tmp)
	    {
	    for ( ; c > navp && (*c < '0' || *c > 'F'); c--);
	    if (c < navp) return 0;
	    for (a = c; *a == '0'; a--);
	    if (*a > '0' && *a <= 'F') tmp = 1;
	    }
	if (c < navp) return 0;
	while(*a > '0' && *a <= 'F') *a-- = '0';
	for (c = &a[-1]; c >= navp && (*c < '0' || *c > 'F'); c--);
	if (c < navp) return 0;
	}
    for (a = c; *a >= '0' && *a <= 'F'; a--);
    if ((tmp = bump(a, c, enavpp)))
        {
        lasts += tmp;
        laste += tmp;
        }
    return 1;
    }



static int set_num()
    {
/**
Function: Marks spot where number is to be changed
Inputs: casnp is at cert serial number or CRL number item in CRL
Returns: 1
Procedure:
1. Mark current struct asn in global mod_asnp and advance casnp
   Return 1
**/
		                                        /* step 1 */
    mod_asnp = casnp++;
    return 1;
    }

int time_diff(ulong this_date, ulong ref_date, struct asn *tasnp, int unit,
    int limit)
    {
/**
Function: calculates difference of this_date - ref_date (or, if using months,
  casnp - tasnp),
    subtracts the limit and returns result.  Either date may be the later
**/
    int diff, y1, y2;
    uchar *t1 = asn_start(tasnp),  /* tasnp may be GenTime */
	*t2 = asn_start(casnp);

    if (unit)
	{
        if (*tasnp->stringp == ASN_GENTIME)
	    {
            y1 = get_num(&t1[GENTYR], GENTYRSIZ) - 1900;
	    t1 += 2;
	    }
	else if ((y1 = get_num(&t1[UTCYR], UTCYRSIZ)) < UTCBASE) y1 += 100;
        if ((y2 = get_num(&t2[UTCYR], UTCYRSIZ)) < UTCBASE) y2 += 100;
	diff = ((y2 - y1) * 12) + get_num(&t2[UTCMO], UTCMOSIZ) -
            get_num(&t1[UTCMO], UTCMOSIZ);
	y1 = get_num(&t1[UTCDA], UTCDASIZ);
	y2 = get_num(&t2[UTCDA], UTCDASIZ);



	y1 = memcmp(&t2[UTCDA], &t1[UTCDA],
            UTCDASIZ + UTCHRSIZ + UTCMISIZ + UTCSESIZ);
	     /* if casnp earlier in month, y1 < 0 */
	if (diff <= 0  && y1 < 0) diff--;
	else if (diff >= 0 && y1 > 0) diff++;
	}
    else diff = (int)(this_date - ref_date);
    return (diff - limit);;
    }

