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
#include <fam.h>

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
