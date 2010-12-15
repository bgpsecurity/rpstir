/*
  Low-level string parsing utilities

  $Id$
*/

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
 * Copyright (C) Raytheon BBN Technologies Corp. 2007-2010.
 * All Rights Reserved.
 *
 * Contributor(s):  Andrew Chi
 *
 * ***** END LICENSE BLOCK ***** */

int endswith(const char *s, const char *suffix);
int startswith(const char *s, const char *prefix);
void lstrip(char *s, const char *delimiters);
void rstrip(char *s, const char *delimiters);
void strip(char *s, const char *delimiters);
int exists_non_delimiter(const char *s, const char *delimiters);
char *start_of_next_field(const char *s, const char *delimiters);
char *dirname(char *dest, int dest_len, const char *path);
char *this_field(char *dest, int dest_length, const char *src,
		 const char *delimiters);
int field_length(const char *s, const char *delimiters);
