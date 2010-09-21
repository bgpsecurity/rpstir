/* $Id: make_oidtable.c 453 2008-07-25 15:30:40Z cgardiner $ */

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
 * Copyright (C) Raytheon BBN Technologies Corp. 2008-2010.  All Rights Reserved.
 *
 * Contributor(s):  Charles W. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */
char make_oidtable_sfcsid[] = "@(#)make_oidtable.c 869P";
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

struct oidtable
  {
  char *oid;
  char *label;
  };

char *msgs[] = {
    "Finished OK\n",
    "Can't open %s\n",
    "Error in this line: %s",
    "Usage: tablefilename, file.h ...\n",
    };

static int diff_oid(char *o1, char *o2)
  {
  int x1, x2;
  char *c1, *c2;
  for (c1 = o1, c2 = o2; 1; c1++, c2++)
    {
    sscanf(c1, "%d", &x1);
    sscanf(c2, "%d", &x2);
    if (x1 > x2) return 1;
    if (x1 < x2) return -1;
    while(*c1 && *c1 != '.') c1++;
    while(*c2 && *c2 != '.') c2++;
    if (!*c1)
      {
      if (!*c2) return 0;
      return -1;
      }
    else if (!*c2) return 1;
    }
  return 0; // never happens
  }

static void fatal(int err, char *param)
  {
  fprintf(stderr, msgs[err], param);
  exit(err);
  }

int main (int argc, char **argv)
  {
  char *outfile = *(++argv), linebuf[512];
  struct oidtable *oidtable;
  int numoids = 16, oidnum;
  FILE *str;
  if (argc < 2) fatal(3, (char *)0);
  
  oidtable = (struct oidtable *)calloc(numoids, sizeof(struct oidtable));
  for (argv++, oidnum = 0; argv && *argv; argv++)
    {
    // int linenum = 1;
    if (!(str = fopen(*argv, "r"))) fatal(1, *argv);
    char *c;
    while (fgets(linebuf, 512, str))
      {
      // fprintf(stderr, "%d %s", linenum++, linebuf);
      if (strncmp(linebuf, "#define ", 8)) continue;
      char *l, *o;
      if (linebuf[8] == '_') continue;
      for (c = &linebuf[8]; *c && *c <= ' '; c++);
      if (!*c) fatal(2, linebuf);
      for (l = c; *c && *c > ' '; c++);
      if (!*c) fatal(2, linebuf);
      *c++ = 0;
      while (*c && *c <= ' ') c++;
      if (!*c || *c != '"') continue;
      c++;
      if (!*c || *c <'0' || *c > '9') fatal(2, linebuf);
      int j;
      if (sscanf(c, "%d.",  &j) < 1 || j > 2) continue;
      o = c;
      for (o = c; *c && *c != '.' && *c != '"'; c++);
      if (!*c) fatal(2, linebuf);
      if (*c != '.') continue;    // just one segment
      while (*c && *c != '"') c++;
      if (!*c) fatal(2, linebuf);
      *c = 0;
      if (oidnum >= numoids) oidtable = (struct oidtable *)realloc(oidtable,
        (numoids += 16) * sizeof(struct oidtable));
      // fprintf(stderr, "oidnum %d numoids %d\n", oidnum, numoids);
      struct oidtable *odp = &oidtable[oidnum];
      odp->label = (char *)calloc(1, strlen(l) + 2);
      strcpy(odp->label, l);
      odp->oid = (char *)calloc(1, strlen(o) + 2);
      strcpy(odp->oid, o);
      oidnum++;
      }
    fclose(str);
    }
  int i;
  for (i = 1; i <oidnum; )
    {
    struct oidtable *lodp = &oidtable[i - 1],
                    *hodp = &oidtable[i];
    if (diff_oid(lodp->oid, hodp->oid) < 0)  // need to swap
      {
      struct oidtable tod;
      tod.oid = hodp->oid;
      tod.label = hodp->label;
      hodp->oid = lodp->oid;
      hodp->label = lodp->label;
      lodp->oid = tod.oid;
      lodp->label = tod.label;
      i = 1;
      }
    else i++;
    }
  if (!(str = fopen(outfile, "w"))) fatal(1, outfile);
  char lastoid[256];
  memset(lastoid, 0, 256);
  for (i = 0; i < oidnum; i++)
    {
    struct oidtable *curr_oidp = &oidtable[i];  // eliminate duplicates
    if (strlen(lastoid) == strlen(curr_oidp->oid) && !strcmp(lastoid, curr_oidp->oid))
      continue;
    fprintf(str, "%s %s\n", curr_oidp->oid, curr_oidp->label);
    strcpy(lastoid, curr_oidp->oid);
    }
  fclose(str);
  fatal(0, outfile);
  return 0;
  }


