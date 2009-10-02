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

/****
 * routine to parse the filter specification file which  determines how to
 * handle the various meta-data SCM_FLAG_XXX flags (ignore, matchset, matchclr)
 * - Returns 0 on success, -1 on failure
 ****/
extern int parseStalenessSpecsFile(char *specsFilename);

/*****
 * read out the values from parsing the staleness specs
 *****/
extern void getSpecsVals(int *rejectStaleChainp, int *rejectStaleManifestp,
						 int *rejectStaleCRLp, int *rejectNoManifestp);

/******
 * put the appropriate tests for SCM_FLAG_XXX flags in the where
 *   string of a query
 ******/
extern void addQueryFlagTests(char *whereStr, int needAnd);
