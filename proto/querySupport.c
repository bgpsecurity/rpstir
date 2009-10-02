/* ***** BEGIN LICENSE BLOCK *****
 *
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 *
 * US government users are permitted unrestricted rights as
 * defined in the FAR.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  David Montana
 *
 * ***** END LICENSE BLOCK ***** */

/*
  $Id: query.c 857 2009-09-30 15:27:40Z dmontana $
*/

/****************
 * Functions and flags shared by query and server code
 ****************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "scm.h"
#include "scmf.h"
#include "sqhl.h"
#include "roa_utils.h"
#include "querySupport.h"
#include "err.h"

static scm *scmp = NULL;
static scmcon *connect = NULL;
static scmtab *table = NULL;

static int rejectStaleChain = 0;
static int rejectStaleManifest = 0;
static int rejectStaleCRL = 0;
static int rejectNoManifest = 0;

/* routine to parse the filter specification file which  determines how to
 * handle the various meta-data SCM_FLAG_XXX flags (ignore, matchset, matchclr)
 */
int parseStalenessSpecsFile(char *specsFilename)
{
  char str[WHERESTR_SIZE], str2[WHERESTR_SIZE], str3[WHERESTR_SIZE];
  FILE *input = fopen (specsFilename, "r");

  if (input == NULL) {
    printf ("Could not open specs file: %s\n", specsFilename);
    exit(-1);
  }
  while (fgets (str, WHERESTR_SIZE, input)) {
    int got = sscanf(str, "%s %s", str2, str3);
    if (got == 0) continue;
    if (str2[0] == '#') continue;
    if (got == 1) {
	  perror ("Bad format for specs file\n");
	  return -1;
	}
    if (strcmp(str2, "StaleCRL") == 0) {
      rejectStaleCRL = str3[0] == 'n' || str3[0] == 'N';
    } else if (strcmp(str2, "StaleManifest") == 0) {
      rejectStaleManifest = str3[0] == 'n' || str3[0] == 'N';
    } else if (strcmp(str2, "StaleValidationChain") == 0) {
      rejectStaleChain = str3[0] == 'n' || str3[0] == 'N';
    } else if (strcmp(str2, "NoManifest") == 0) {
      rejectNoManifest = str3[0] == 'n' || str3[0] == 'N';
    } else {
      printf ("Bad keyword in specs file: %s\n", str2);
      return -1;
    }
  }
  return 0;
}

void getSpecsVals(int *rejectStaleChainp, int *rejectStaleManifestp,
				  int *rejectStaleCRLp, int *rejectNoManifestp) {
  *rejectStaleChainp = rejectStaleChain;
  *rejectStaleManifestp = rejectStaleManifest;
  *rejectStaleCRLp = rejectStaleCRL;
  *rejectNoManifestp = rejectNoManifest;
}

void addQueryFlagTests(char *whereStr, int needAnd) {
  addFlagTest(whereStr, SCM_FLAG_VALIDATED, 1, needAnd);
  if (rejectStaleChain)
	addFlagTest(whereStr, SCM_FLAG_NOCHAIN, 0, 1);
  if (rejectStaleCRL)
	addFlagTest(whereStr, SCM_FLAG_STALECRL, 0, 1);
  if (rejectStaleManifest)
	addFlagTest(whereStr, SCM_FLAG_STALEMAN, 0, 1);
  if (rejectNoManifest)
	addFlagTest(whereStr, SCM_FLAG_ONMAN, 1, 1);
}
