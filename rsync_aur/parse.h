#ifndef _PARSE_H
#define _PARSE_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>

/*
 * $Id$ 
 */

char *getMessageFromString(
    const char *,
    unsigned int,
    unsigned int *,
    char);
char *makeWarningStr(
    const char *,
    unsigned int,
    unsigned int *);
char *makeInfoStr(
    const char *,
    unsigned int,
    unsigned int *);
char *makeUpdateStr(
    const char *,
    unsigned int,
    unsigned int *);
char *makeAddStr(
    const char *,
    unsigned int,
    unsigned int *);
char *makeLinkStr(
    const char *,
    unsigned int,
    unsigned int *);
char *makeRemoveStr(
    const char *,
    unsigned int,
    unsigned int *);
char *makeFatalStr(
    const char *,
    unsigned int,
    unsigned int *);
char *makeErrorStr(
    const char *,
    unsigned int,
    unsigned int *);
char *makeGenericStr(
    const char *,
    unsigned int,
    unsigned int *,
    char);
char *makeStartStr(
    unsigned int *);
char *makeEndStr(
    unsigned int *);
int looksOK(
    const char *,
    unsigned int);
int has_I_Format(
    const char *,
    unsigned int);
int has_Text_Value(
    const char *,
    unsigned int);
int has_Correct_Extension(
    const char *,
    unsigned int);
int has_newline(
    const char *str,
    unsigned int len);

/*
 * Lower level parsing utilities. 
 */
long next_dirblock(
    FILE * fp);
int is_manifest(
    const char *path);

#endif
