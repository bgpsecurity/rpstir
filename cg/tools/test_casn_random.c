
/* ***** BEGIN LICENSE BLOCK *****
 * 
 * BBN Address and AS Number PKI Database/repository software
 * Version 3.0-beta
 * 
 * US government users are permitted unrestricted rights as
 * defined in the FAR.  
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) Raytheon BBN Technologies Corp. 2008-2010.  All Rights Reserved.
 *
 * Contributor(s):  Christopher Small
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <extensions.h>
#include <casn.h>
#include <certificate.h>
#include <roa.h>
#include <manifest.h>
#include <crlv2.h>

/*
 * this program takes one or more filenames on the command line and
 * tries to read it in in as any of a number of different objects.
 * 
 * it's really meant to be run from test_casn_random_driver.sh that
 * generates files full of random garbage and throws them at this
 * program. The goal is to make sure that the casn code always
 * generates an error, and neither accepts bad data nor core dumps on
 * bad data.
 *
 * Acceptable errors to get are #1 (stream doesn't match object,
 * i.e. bad syntax) and #22 (invalid length field).
 */

#define TEST(t) { \
	struct t guy; \
	int ret; \
	t(&guy, (ushort)0); \
        ret = get_casn_file(&guy.self, filename, 0) ; \
	if (ret >= 0) { \
	    printf("accepted %s as a " #t " (should have failed)\n", filename);	\
	} \
    }

int main (int argc, char **argv)
{
    char *filename;

    if (argc < 2) {
	printf("need to specify at least one file "
	       "(of garbage) to test on the command line\n");
	exit(1);
    }

    for (filename = *++argv; filename != NULL; filename = *++argv) {
	TEST(Certificate);
	TEST(ROA);
	TEST(Manifest);
	TEST(CertificateRevocationList);
	TEST(CRLEntry);
    }
    exit(0);
}
