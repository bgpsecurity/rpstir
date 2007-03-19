/*
  $Id$
*/

#ifndef _ERR_H_
#define _ERR_H_

/*
  Error codes
*/

#define ERR_SCM_NOERR         0
#define ERR_SCM_COFILE       -1  	/* cannot open file */
#define ERR_SCM_NOMEM        -2	        /* out of memory */
#define ERR_SCM_INVALARG     -3	        /* invalid argument */
#define ERR_SCM_SQL          -4         /* SQL error */
#define ERR_SCM_INVALCOL     -5	        /* invalid column */
#define ERR_SCM_NULLCOL      -6         /* null column */
#define ERR_SCM_NOSUCHTAB    -7         /* no such table */
#define ERR_SCM_NODATA       -8         /* no matching data in table */
#define ERR_SCM_NULLVALP     -9         /* null value pointer */
#define ERR_SCM_INVALSZ     -10         /* invalid size */
#define ERR_SCM_ISLINK      -11	        /* links not processed */
#define ERR_SCM_BADFILE     -12         /* invalid file */
#define ERR_SCM_INVALFN     -13	        /* inconsistent filename */
#define ERR_SCM_NOTADIR     -14         /* not a directory */
#define ERR_SCM_INTERNAL    -15	        /* internal error */

#endif
