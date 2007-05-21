#ifndef _PARSE_H
#define _PARSE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <linux/limits.h>
#include <time.h>

/*
  $Id$
*/

char *getMessageFromString(char *, unsigned int, unsigned int *, char);
char *makeWarningStr(char *, unsigned int, unsigned int *);
char *makeInfoStr(char *, unsigned int, unsigned int *);
char *makeUpdateStr(char *, unsigned int, unsigned int *);
char *makeAddStr(char *, unsigned int, unsigned int *);
char *makeLinkStr(char *, unsigned int, unsigned int *);
char *makeRemoveStr(char *, unsigned int, unsigned int *);
char *makeFatalStr(char *, unsigned int, unsigned int *);
char *makeErrorStr(char *, unsigned int, unsigned int *);
char *makeGenericStr(char *, unsigned int, unsigned int *, char);
char *makeStartStr(unsigned int *);
char *makeEndStr(unsigned int *);
int looksOK(char *, unsigned int);
int has_I_Format(char *, unsigned int);
int has_Text_Value(char *, unsigned int);
int has_Correct_Extension(char *, unsigned int);
int has_newline(char *str, unsigned int len);


#endif
