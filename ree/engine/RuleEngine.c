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

char RuleEngine_sfcsid[] = "@(#)RuleEngine.c 601p";

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <time.h>
#include "enforce.h"

extern uchar *eoram, *so_free,
    *asn_setup(struct asn *);

int get_asn_file(char *fname, struct asn **asnpp);

char _ident[4];

char *verbose, *msgs[] =
    {
    "Succeeded\n",
    "Invalid parameter %s\n",       /* 1 */
    "Error reading %s\n",
    "Error making table for %s\n",  /* 3 */
    "Request is not a %s\n",
    "Can't open %s\n",              /* 5 */
    "%s is an invalid rule file\n",
    "%s%s at offset %d (0x%X)\n",   /* 7 */
    "Unexpected null pointer in %s\n",
    "Unmatched types in %s\n",      /* 9 */
    };

uchar *start_free, *so_free, *eoram;

struct asn *issuer_asnp, *rfile_asnbase;

clock_t cpu_time_start;
struct timespec real_time_start, real_time_end;

void fatal(int err, char *param)
    {
    if (err) fprintf(stderr, msgs[err], param);
    exit(err);
    }

int main(int argc, char **argv)
    {
/**
Function: Tests a certificate or CRL against a rule set
Output: Message of results
Procedure:
1. Scan input parameters to see if verbose mode
   Scan input parameters for file names
        IF it's a switch, skip it
        ELSE IF have no rule file yet
            Read in rule file
        ELSE 
2.          Read in the test file
            Test it
            Report results
**/
    char *b, *c, **pp;
    uchar *rule_data, *file_data, *failPointp;
    struct asn *test_asnp, *easnp, *asnp, *tasnp;
    struct fasn *rules_asnp = (struct fasn *)0,
        *er_asnp;
    int crl = 0, diff, err, num_files;
    long i, num_asns;
    double rt, nseconds, seconds;

    start_free = (uchar *)calloc(1, 10000);
    eoram = &start_free[10000];
							    /* step 1 */
    for (verbose = (char *)0, pp = &argv[1]; *pp; pp++)
	{
	c = *pp;
        if (*c == '-')
            {
            if (c[1] == 'v') verbose = c;
            else fatal(1, c);
            }
        }
    for (pp = &argv[1], num_files = 0; *pp /* && num_files < 1 */; pp++)
	{
	c = *pp;
        if (*c == '-') continue;
        else if (!rules_asnp)
            {
            diff = get_asn_file(c, (struct asn **)&asnp);
            rfile_asnbase = asnp; 
            er_asnp = (struct fasn *)&asnp[diff];
            for (asnp++; asnp->level > 0 && asnp->level < 4; asnp++);
            if (asnp->level != 4) fatal(6, c);
            issuer_asnp = asnp;
            while(asnp->level >= 4 && asnp->level < 8) asnp++;
            if (asnp->level != 8) fatal(6, c);
            if (*asnp->stringp != ASN_UTF8_STRING || 
                (++asnp)->level != 8 || 
                *asnp->stringp != ASN_PRIV_CONSTR)
                fatal(6, c);
            rules_asnp = (struct fasn *)asnp;
            }
        else                                           // step 2
            {
            num_files++;
            diff = get_asn_file(c, &test_asnp);
            easnp = &test_asnp[diff];
            if (!crl)
                {        // is this a CRL?
                diff =  (*test_asnp[2].stringp == 160)? 2: 1;
                asnp = skip_asn(&test_asnp[2], test_asnp, diff);
                if (*asnp->stringp == ASN_INTEGER) crl = -1;
                else crl = 1;
                }
            so_free = start_free;
            tasnp = &test_asnp[1];  // rules start at toBeSigned
            printf("%s ", c);
            err = enforce(&tasnp, rules_asnp, &failPointp);
            if (!verbose) printf("%s\n", (err >= 0)? "passed": "failed");
            else if (err >= 0) printf("passed\n");
            if (err == -(FAIL_RULE)) 
	        {
               	i = failPointp - test_asnp->stringp; 
	        if (verbose) printf(msgs[7], "    Failed", "", i, i);
	        }
            free(test_asnp->stringp);
            free(test_asnp);
            }
        }
    free(rfile_asnbase->stringp);
    free(rfile_asnbase);
    fatal(0, (char *)0);
    }

int count_asns(unsigned char *from)
    {
/**
Function: Counts number of ASN.1 items in string pointed to by from
Inputs: Pointer to ASN.1-encoded string
Outputs: Count of number of items
Procedure: Calls the recursive version
**/
    int count_sub_asns(uchar **);
    return (1 + count_sub_asns(&from));
    }

int count_sub_asns(uchar **from)
    {
/**
Function: Counts ASN.1 items in recursive fashion
Inputs: Pointer to address of start of item
Outputs: 'from' pointer set to address of next item
	 Returns count of items
Procedure:
1. DO
 	Set up local asn for current item
        Count it
        IF current item has indefinite length
            IF item is constructed
	        DO
	            Add contents of subordinate items to count
                UNTIL remaining data is double null
            ELSE scan forward to double null
2. 	ELSE
	    IF have no end pointer yet, set end pointer
	    IF item is primitive, advance pointer by its length
	    IF no end pointer, return count
   WHILE have an end pointer AND haven't reached it
3. Set 'from' pointer
   Return count
**/
    int count = 0;
    uchar *c = *from, *e = (uchar *)0;
    struct asn asn;
    do  						    /* step 1 */
        {
        asn.stringp = c;
        asn.level = 0;
        c = asn_setup(&asn);
        count++;
        if ((asn.level & ASN_INDEF_FLAG))
            {
      	    if ((*asn.stringp & ASN_CONSTRUCTED))		    
    	        {
    	        do
    		    {
    	            count += count_sub_asns(&c);
    		    }
    	        while (*c || c[1]);
    	        }
    	    else while (*c || c[1]) c++;
            c += 2;
            }
        else                                                /* step 2 */
            {
            if (!e) e = &c[asn.lth];
            if (!(*asn.stringp & ASN_CONSTRUCTED)) c += asn.lth;
            }
        }
    while (e && c < e);
    *from = c;                                              /* step 3 */
    return count;
    }

int get_asn_file(char *fname, struct asn **asnpp)
    {
    int fd, num_asns;
    char *c;
    uchar *a, *b, *d;
    long i, j, k;

    if ((fd = open(fname, O_RDONLY)) < 0) fatal(5, fname);
    a = b = (uchar *)calloc(1, (j = k = 1024));
    while ((i = read(fd, a, j)) == j)
        {
        d = (uchar *)realloc(b, k + j);
        b = d;
        a = &b[k];
        k += j;
        }
    i = (k - j) + i;
    if (i == 0) fatal(2, fname);
    close(fd);
    if ((num_asns = make_asn_table(asnpp, b, i)) < 0) fatal(3, fname);
    return num_asns;
    }

int make_asn_table(struct asn **asnbase, uchar *c, ulong lth)
    {
    uchar *b;
    struct asn *asnp;
    int i, count = count_asns(c) + 1;
    if (!(*asnbase = (struct asn *)calloc(count, sizeof (struct asn)))) 
        return 0;
    (asnp = *asnbase)->stringp = c;
    b = asn_setup(asnp);
    if ((i = decode_asn(&asnp, &asnp[count], c, lth, 0)) < 0)
        count = (c - asnp->stringp);
    return count;
    }
