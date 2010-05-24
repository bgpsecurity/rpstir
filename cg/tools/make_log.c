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
 * Copyright (C) Raytheon BBN Technologies Corp. 2010.  All Rights Reserved.
 *
 * Contributor(s): Charlie Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>

/* converts a list of file names to a log file to go in LOGS. 
   It is  straight filter*/

char buf[512];

int main( int argc, char **argv)
  {
  fprintf(stdout, "cd+++++++ ./\n");
  while (fgets(buf, 512, stdin))
    {
    fprintf(stdout, ">f+++++++ %s", buf);
    }
  return 0;
  }  
