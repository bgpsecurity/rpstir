/* Oct 31 1996 392U  */
/* Oct 31 1996 GARDINER tidied for gcc */
/* Jun 15 1995 229U  */
/* Jun 15 1995 GARDINER fixed start of each output line */
/* Mar  8 1994   1U  */
/* Mar  8 1994 GARDINER Started on SPARC */
/* $Id$ */
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
 * Contributor(s):  Charles Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
char bin_to_six_sfcsid[] = "@(#)bin_to_six.c 392P";
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

unsigned char ibuf[100], obuf[2048], binbuf[2048];
char *msgs[] =
    {
    "Finished OK\n",
    "Can't find string\n",
    "No search string\n",
    };

int sixBitEncode(char *, char *, int);
void fatal(int);

int main (argc,argv)
int argc;
char *argv[];
{
int ilth, olth;
unsigned char *a;

if (argc > 1)
    {
    write (1,argv[1], (int)strlen (argv[1]));
    write (1,"\n",1);
    } 

for (a = binbuf, *obuf = ' '; (ilth = read (0,binbuf,48)); )
    {
    olth = 1 + sixBitEncode ((char *)binbuf,(char *)&obuf[1],ilth);
    obuf[olth++] = '\n';
    write (1,obuf,olth);
    }
fatal (0);
 return(0);
}

void fatal(int err)
{
fprintf (stderr,msgs[err]);
exit (err);
}
