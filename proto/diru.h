/*
  $Id$
*/

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
 * Copyright (C) BBN Technologies 2007-2010.  All Rights Reserved.
 *
 * Contributor(s):  Mark Reynolds
 *
 * ***** END LICENSE BLOCK ***** */

#ifndef _DIRU_H_
#define _DIRU_H_

/*
  Directory utility functions
*/

extern int   strwillfit(char *inbuf, int totlen, int already, char *newbuf);
extern int   isadir(char *indir);
extern int   splitdf(char *dirprefix, char *dirname, char *fname,
		     char **outdir, char **outfile, char **outfull);
extern int   isokfile(char *fname);
extern char *r2adir(char *indir);

#endif
