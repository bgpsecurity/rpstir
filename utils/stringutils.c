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

#include <stdlib.h>
#include <string.h>

/* Does string s end with suffix? */
int endswith(const char *s, const char *suffix)
{
  int s_len, suffix_len;
  
  if (!s || !suffix)
    return 0;
  
  s_len = strlen(s);
  suffix_len = strlen(suffix);
  if (s_len < suffix_len)
    return 0;

  if (strncmp(&s[s_len - suffix_len], suffix, suffix_len) == 0)
    return 1;
  else
    return 0;
}


/* Does string s start with prefix? */
int startswith(const char *s, const char *prefix)
{
  int s_len, prefix_len;

  if (!s || !prefix)
    return 0;

  s_len = strlen(s);
  prefix_len = strlen(prefix);
  if (s_len < prefix_len)
    return 0;

  if (strncmp(s, prefix, prefix_len) == 0)
    return 1;
  else
    return 0;
  return 0;
}


/* Return true if the string contains at least one non-delimiter
   character.  */
int exists_non_delimiter(const char *s, const char *delimiters)
{
  const char *pc;
  if (!s || !delimiters)
    return 0;

  for (pc = s; *pc != '\0'; ++pc)
    if (!strchr(delimiters, *pc))
      return 1;

  return 0;
}


/* Strip all leftmost delimiter characters from input string (in place). */
void lstrip(char *s, const char *delimiters)
{
  int i, len, num_leftmost_delims;
  if (!s || !delimiters)
    return;
  len = strlen(s);
  num_leftmost_delims = 0;
  for (i = 0; i < len && strchr(delimiters, s[i]); i++)
    num_leftmost_delims++;
  if (num_leftmost_delims > 0)
    memmove(s, &s[num_leftmost_delims], len - num_leftmost_delims + 1);
}


/* Strip all rightmost delimiter characters from input string (in place). */
void rstrip(char *s, const char *delimiters)
{
  int i, len;
  if (!s || !delimiters)
    return;
  len = strlen(s);
  for (i = len - 1; i >= 0 && strchr(delimiters, s[i]); i--)
    s[i] = '\0';
}


/* Strip all leftmost and rightmost delimiter characters (in place). */
void strip(char *s, const char *delimiters)
{
  lstrip(s, delimiters);
  rstrip(s, delimiters);
}


/* Return the next field, i.e. pointer to the beginning of the next
   contiguous string of non-delimiter characters.  Note that this
   skips the current contiguous string of non-delimiter characters.
   Returns NULL if there are no more non-delimiter characters in the
   string. */
char *start_of_next_field(const char *s, const char *delimiters)
{
  const char *pc;
  
  if (!s || !delimiters)
    return NULL;

  /* Skip current set of non-delimiters */
  for (pc = s; *pc != '\0' && !strchr(delimiters, *pc); ++pc) ;

  /* Skip delimiters */
  for (; *pc != '\0' && strchr(delimiters, *pc); ++pc) ;

  if (*pc == '\0')		/* end of string */
    return NULL;

  return (char *)pc;
}


/*
  Copy the directory string for a particular path to the destination
  buffer.  A path which ends in '/' will simply be copied, whereas a
  path with no '/' returns the string ".".  At most dest_len
  characters will be copied, including the terminating '\0'.  If
  dest_len was not enough space, a NULL is returned.
 */
char *dirname(char *dest, int dest_len, const char *path)
{
  const char *right_most_slash;
  int dir_length;

  if (!path)
    return NULL;

  /* Search for right-most slash. */
  right_most_slash = strrchr(path, '/');
  if (!right_most_slash) {
    if (dest_len < 2)
      return NULL;
    else
      return strcpy(dest, ".");
  }

  /* Copy directory substring, terminating with null. */
  dir_length = right_most_slash - path + 1;
  if (dir_length > dest_len - 1)
    return NULL;
  strncpy(dest, path, dir_length);
  dest[dir_length] = '\0';
  
  return dest;
}

/* Copy the current field (contiguous string of non-delimiter
   characters) into the destination buffer, up to dest_length-1 bytes.
   Append '\0' to terminate the C string.  If the buffer size is
   insufficient, safely null-terminate the destination buffer and
   return NULL.
*/
char *this_field(char *dest, int dest_length, const char *src,
			const char *delimiters)
{
  const char *pc = src;
  int bytes_written = 0;
  int insufficient_buffer = 0;
  
  if (!dest || dest_length < 1 || !src || !delimiters)
    return NULL;

  while (*pc != '\0' && !strchr(delimiters, *pc)) {
    if (bytes_written == dest_length - 1) {
      insufficient_buffer = 1;
      break;
    }
    dest[bytes_written] = *pc;
    bytes_written++;
    pc++;
  }
  dest[bytes_written] = '\0';

  if (insufficient_buffer)
    return NULL;
  else
    return dest;
}


/* Return the length of the current field (contiguous string of
   non-delimiter characters).  Returns -1 on error cases. */
int field_length(const char *s, const char *delimiters)
{
  int len = 0;
  if (!s || !delimiters)
    return -1;
  while (*s != '\0' && !strchr(delimiters, *s)) {
    len++;
    s++;
  }
  return len;
}
