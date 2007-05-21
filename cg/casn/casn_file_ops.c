/* $Id$ */
/* Aug  2 2006 847U  */
/* Aug  2 2006 GARDINER chenged to use _casn_obj_err() */
/* Aug  2 2006 846U  */
/* Aug  2 2006 GARDINER added corrections from KTJL */
/* Aug  5 2004 797U  */
/* Aug  5 2004 GARDINER fixed open call */
/* Aug  3 2004 796U  */
/* Aug  3 2004 GARDINER added compiler conditional O_DOS */
/* Apr 15 2004 760U  */
/* Apr 15 2004 GARDINER changed decode_casn call */
/* Mar 25 2004 744U  */
/* Mar 25 2004 GARDINER fixed warnings */
/* Mar 25 2004 743U  */
/* Mar 25 2004 GARDINER started */
/* */
/*****************************************************************************
File:     casn_file_ops.c
Contents: Functions to handle ASN.1 objects in files.
System:   Compact ASN development.
Created:
Author:   Charles W. Gardiner <gardiner@bbn.com>

Remarks:

COPYRIGHT 2004 BBN Systems and Technologies
10 Moulton St.
Cambridge, Ma. 02138
617-873-3000
*****************************************************************************/

char casn_file_ops_sfcsid[] = "@(#)casn_file_ops.c 847P";
#include "casn.h"
#include <fcntl.h>
#include <unistd.h>

#ifndef _DOS
#define O_DOS 0
#else
#define O_DOS (O_BINARY | S_IWRITE |  S_IREAD)
#endif

int _casn_obj_err(struct casn *, int);

int get_casn_file(struct casn *casnp, char *name, int fd)
    {
    long siz, tmp;
    uchar *b, *c;

      // if name is NULL, we were passed an active file descriptor
    if (name && (fd = open(name, (O_RDONLY | O_DOS))) < 0)
        return _casn_obj_err(casnp, ASN_FILE_ERR);
    for (siz = 1024, b = c = (uchar *)calloc(1, siz); 1; )
	{
	if ((tmp = read(fd, c, 1024)) == 1024)
	    {
	    b = (uchar *)realloc(b, siz + 1024);
	    c = &b[siz];
	    siz += 1024;
	    }
	else if (tmp < 0)
            {
            if (name) close(fd); // if we opened it
            return _casn_obj_err(casnp, ASN_FILE_ERR);
            }
    	else break;
	}
    if (name) close(fd); // if we opened it
    siz = (siz - 1024 + tmp);
    tmp = decode_casn(casnp, b);
    free(b);
    if (tmp < 0) return tmp;
    if (tmp < siz) _casn_obj_err(casnp, ASN_FILE_SIZE_ERR);
    return tmp;
    }

int put_casn_file(struct casn *casnp, char *name, int fd)
    {
    uchar *b;
    int siz;

      // if name is NULL, we were passed an active file descriptor
    if (name && (fd = open(name, (O_WRONLY | O_CREAT | O_TRUNC | O_DOS),
        0777)) < 0) return _casn_obj_err(casnp, ASN_FILE_ERR);
    if ((siz = size_casn(casnp)) < 0)
        {
        if (name) close(fd);
        return siz;
        }
    b = (uchar *)calloc(1, siz);
    encode_casn(casnp, b);
    write(fd, b, siz);
    free(b);
    if (name) close(fd);
    return siz;
    }
