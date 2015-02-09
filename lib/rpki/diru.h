#ifndef _DIRU_H_
#define _DIRU_H_

/*
 * Directory utility functions
 */

/*
 * This function is a safe version of strcat. Based on the amount of data
 * already in a string (already) and the length of a new string, it will
 * append the new string if it will fit in the allocated size (totlen)
 * allowing also for one character left over for the trailing NUL. Returns the
 * new length of the string on success and a negative error code on failure.
 *
 * Note that if already is given as a negative number the length in the input
 * buffer is calculated.
 */
extern int strwillfit(
    char *inbuf,
    int totlen,
    int already,
    char *newbuf);

/*
 * Returns 1 if the argument is a directory, 0 if it isn't and a negative
 * error code on failure.
 */
extern int isadir(
    char *indir);

/*
 * This function splits a filename into an absolute path and a filename. It
 * allocates memory for both returned values. On success it returns 0 and on
 * failure it returns a negative error code.
 */
extern int splitdf(
    char *dirprefix,
    char *dirname,
    char *fname,
    char **outdir,
    char **outfile,
    char **outfull);

/*
 * This function returns 0 if the indicated file is an acceptable file, which
 * means a regular file that is also not a symlink, and a negative error code
 * otherwise.
 */
extern int isokfile(
    char *fname);

/*
 * Convert a (possibly) relative path name of a directory into an absolute
 * pathname in canonical form. Check that said directory really exists.
 *
 * Returns allocated memory holding the absolute path.
 */
extern char *r2adir(
    char *indir);

#endif
