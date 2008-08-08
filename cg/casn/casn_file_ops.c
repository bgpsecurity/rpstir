/* $Id$ */
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
 ***** BEGIN LICENSE BLOCK *****
 *
 * BBN Address and AS Number PKI Database/repository software
 * Version 1.0
 *
 * COMMERCIAL COMPUTER SOFTWARE RESTRICTED RIGHTS (JUNE 1987)
 * US government users are permitted restricted rights as
 * defined in the FAR.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT
 * WARRANTY OF ANY KIND, either express or implied.
 *
 * Copyright (C) BBN Technologies 2004-2007.  All Rights Reserved.
 *
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK *****
*****************************************************************************/

char casn_file_ops_sfcsid[] = "@(#)casn_file_ops.c 864P";
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

    // the semantics of using O_CREAT with O_EXCL will cause the
    // file open to fail if it already exists, so we must unlink it
    if (name) (void)unlink(name);
      // if name is NULL, we were passed an active file descriptor
    if (name && (fd = open(name,
        (O_WRONLY | O_CREAT | O_TRUNC | O_DOS | O_EXCL), 0755)) < 0)
        return _casn_obj_err(casnp, ASN_FILE_ERR);
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
