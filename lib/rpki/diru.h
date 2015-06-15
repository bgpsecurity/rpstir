/*
 * $Id$ 
 */


#ifndef _DIRU_H_
#define _DIRU_H_

/*
 * Directory utility functions 
 */

extern int strwillfit(
    char *inbuf,
    int totlen,
    int already,
    char *newbuf);
extern int isadir(
    char *indir);
extern int splitdf(
    char *dirprefix,
    char *dirname,
    char *fname,
    char **outdir,
    char **outfile,
    char **outfull);
extern int isokfile(
    char *fname);
extern char *r2adir(
    char *indir);

#endif
