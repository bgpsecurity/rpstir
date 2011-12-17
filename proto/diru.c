/*
  $Id$
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

#include "diru.h"
#include "err.h"


/*
  Returns 1 if the argument is a directory, 0 if it isn't
  and a negative error code on failure.
*/

int isadir(char *indir)
{
  struct stat mystat;
  int sta;

  if ( indir == NULL || indir[0] == 0 )
    return(-1);
  memset(&mystat, 0, sizeof(mystat));
  sta = stat(indir, &mystat);
  if ( sta < 0 )
    return(sta);
  if ( S_ISDIR(mystat.st_mode) )
    return(1);
  else
    return(0);
}

/*
  Convert a (possibly) relative path name of a directory into
  an absolute pathname in canonical form. Check that said directory
  really exists.

  Returns allocated memory holding the absolute path.
*/

char *r2adir(char *indir)
{
  char *mydir;
  char *outdir;
  char *ptr;

  if ( indir == NULL || indir[0] == 0 )
    return(NULL);
  if ( isadir(indir) <= 0 )
    return(NULL);
// get current dir
  mydir = (char *)calloc(PATH_MAX, sizeof(char));
  if ( mydir == NULL )
    return(NULL);
  outdir = (char *)calloc(PATH_MAX, sizeof(char));
  if ( outdir == NULL )
    {
      free((void *)mydir);
      return(NULL);
    }
  ptr = getcwd(mydir, PATH_MAX);
  if ( ptr == NULL )
    {
      free((void *)mydir);
      free((void *)outdir);
      return(NULL);
    }
  if ( chdir(indir) < 0 )
    {
      free((void *)mydir);
      free((void *)outdir);
      return(NULL);
    }
  ptr = getcwd(outdir, PATH_MAX);
  (void)chdir(mydir);
  free((void *)mydir);
  if ( ptr == NULL )
    {
      free((void *)outdir);
      return(NULL);
    }
  return(outdir);
}

/*
  This function is a safe version of strcat. Based on the amount of data
  already in a string (already) and the length of a new string, it will
  append the new string if it will fit in the allocated size (totlen)
  allowing also for one character left over for the trailing NUL. Returns
  the new length of the string on success and a negative error code on
  failure.
 
  Note that if already is given as a negative number the length in the
  input buffer is calculated.
*/

int strwillfit(char *inbuf, int totlen, int already, char *newbuf)
{
  int newlen;

  if ( inbuf == NULL || newbuf == NULL )
    return(ERR_SCM_INVALARG);
  if ( already < 0 )
  {
    if ( inbuf[0] == 0 )
      already = 0;
    else
      already = strlen(inbuf);
  }
  if ( newbuf[0] == 0 )
    newlen = 0;
  else
    newlen = strlen(newbuf);
  if ( (already+newlen) >= totlen )
    return(ERR_SCM_INVALSZ);
  strncat(inbuf, newbuf, newlen);
  return(already+newlen);
}

/*
  This function splits a filename into an absolute path and a filename.
  It allocates memory for both returned values. On success it returns
  0 and on failure it returns a negative error code.
*/

int splitdf(char *dirprefix, char *dirname, char *fname,
	    char **outdir, char **outfile, char **outfull)
{
  char *slash;
  char *work;
  char *outd = NULL;
  char *outf = NULL;
  int   wsta = -1;

  if ( fname == NULL || fname[0] == 0 )
    return(ERR_SCM_INVALARG);
  if ( outdir != NULL )
    *outdir = NULL;
  if ( outfile != NULL )
    *outfile = NULL;
  if ( outfull != NULL )
    *outfull = NULL;
  work = (char *)calloc(PATH_MAX, sizeof(char));
  if ( work == NULL )
    return(ERR_SCM_NOMEM);
/*
  First form a path. in the special case that the prefix and the dirname
  both null and fname contains no / characters, then use the current directory
*/
  if ( dirprefix == NULL && dirname == NULL && strchr(fname, '/') == NULL )
    {
      (void)getcwd(work, PATH_MAX);
      wsta = strwillfit(work, PATH_MAX, wsta, "/");
      if ( wsta < 0 )
      {
        free((void *)work);
        return(wsta);
      }
      wsta = strwillfit(work, PATH_MAX, wsta, fname);
      if ( wsta < 0 )
      {
        free((void *)work);
        return(wsta);
      }
    }
  else
    {
      if ( dirprefix != NULL && dirprefix[0] != 0 )
//	(void)strcpy(work, dirprefix);
      {
        wsta = strwillfit(work, PATH_MAX, wsta, dirprefix);
        if ( wsta < 0 )
        {
          free((void *)work);
          return(wsta);
        }
      }
      if ( dirname != NULL && dirname[0] != 0 )
	{
	  if ( work[0] != 0 )
          {
            wsta = strwillfit(work, PATH_MAX, wsta, "/");
            if ( wsta < 0 )
            {
              free((void *)work);
              return(wsta);
            }
          }
	  wsta = strwillfit(work, PATH_MAX, wsta, dirname);
          if ( wsta < 0 )
          {
            free((void *)work);
            return(wsta);
          }
	}
      if ( work[0] != 0 )
      {
        wsta = strwillfit(work, PATH_MAX, wsta, "/");
        if ( wsta < 0 )
        {
          free((void *)work);
          return(wsta);
        }
      }
      wsta = strwillfit(work, PATH_MAX, wsta, fname);
      if ( wsta < 0 )
      {
        free((void *)work);
        return(wsta);
      }
    }
  slash = strrchr(work, '/');
  if ( slash == NULL )
    {
      free((void *)work);
      return(ERR_SCM_NOTADIR);
    }
  if ( slash[1] == 0 )
    {
      free((void *)work);
      return(ERR_SCM_BADFILE);
    }
  *slash = 0;
  outd = r2adir(work);
  if ( outd == NULL )
    {
      free((void *)work);
      return(ERR_SCM_NOTADIR);
    }
  if ( outdir != NULL )
    *outdir = outd;
  outf = strdup(slash+1);
  if ( outf == NULL )
    return(ERR_SCM_NOMEM);
  if ( outfile != NULL )
    *outfile = outf;
  if ( outfull != NULL )
    {
      (void)snprintf(work, PATH_MAX, "%s/%s", outd, outf);
      *outfull = strdup(work);
      if ( *outfull == NULL )
	return(ERR_SCM_NOMEM);
    }
  free((void *)work);
  return(0);
}

/*
  This function returns 0 if the indicated file is an acceptable file, which
  means a regular file that is also not a symlink, and a negative error code
  otherwise.
*/

int isokfile(char *fname)
{
  struct stat mystat;

  if ( fname == NULL || fname[0] == 0 )
    return(ERR_SCM_INVALARG);
  if ( stat(fname, &mystat) < 0 )
    return(ERR_SCM_BADFILE);
  if ( ! S_ISREG(mystat.st_mode) )
    return(ERR_SCM_BADFILE);
  return(0);
}
