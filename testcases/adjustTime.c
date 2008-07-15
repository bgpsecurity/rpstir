/* $Id: adjustTime.c 453 2008-05-28 15:30:40Z cgardiner $ */

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
 * Copyright (C) BBN Technologies 2008.  All Rights Reserved.
 *
 * Contributor(s):  Charles W. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <casn.h>

static char *units = "YMWDhms";

int adjustTime(struct casn *timep, long now, char *deltap)
  {
  char *unitp = &deltap[strlen(deltap) - 1];
  if (!strchr(units, *unitp)) return -1;
  long val;
  sscanf(deltap, "%ld", &val);
  if (*unitp == 's') ;   // val is right
  else if (*unitp == 'm') val *= 60;
  else if (*unitp == 'h') val *= 3600;
  else if (*unitp == 'D') val *= (3600 * 24);
  else if (*unitp == 'W') val *= (3600 * 24 * 7);
  else if (*unitp == 'M') val *= (3600 * 24 * 30);
  else if (*unitp == 'Y') val *= (3600 * 24 * 365);
  write_casn_time(timep, (ulong)(now + val));
  return 0;
  }
