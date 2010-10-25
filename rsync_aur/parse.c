#include <stdio.h>
//#include <linux/limits.h>
#include "parse.h"

#include "main.h"

/*
  $Id$
*/

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
 * Copyright (C) Raytheon BBN Technologies Corp. 2007.  All Rights Reserved.
 *
 * Contributor(s):  Peiter "Mudge" Zatko
 *
 * ***** END LICENSE BLOCK ***** */

/**************************************************************
 * function: getMessageFromString(char *, unsigned int len,   *
 *              unsigned int *retlen, char flags)             *
 * returns: char *                                            *
 *                                                            *
 * input is a char * to a line from the log file, the length  *
 *   of the char * string, pointer to returned str len        *
 *     and a verbose value                                    *
 *                                                            *
 * It is expected that this function will be called in from   *
 * within a while(fgets(... call. The char buffer should      *
 * be at least PATH_MAX                                       *
 *                                                            *
 * The string that is being parsed is expected to be from     *
 *  an rsync itemized changes output logfile  ( rsync flags   *
 *  '-i' or '--itemize-changes' only ). This means that we    *
 * are expecting the default outformat of "%i %n%L" from      *
 * rsync.                                                     *
 *                                                            *
 * The flags value will specify how unknown or ancillary      *
 * info will be handled. A value of 0 means that error and    *
 * information data will be ignored and the function should   *
 * return NULL (remember it's in an fgets() loop and anything *
 * sent from the output of this should make sure it is !NULL) *
 * if it does not know what to do with a line.                *
 *                                                            *
 * XXX - TODO                                                 *
 *  there really needs to be a sanity check to make sure that *
 *  the string being read in (or handed in) ends in '\n'.     *
 *  Possibly introducing a '\n' if not there or else error    *
 *  that the string is not in the correct format (ends in \n).*
 *************************************************************/
char *
getMessageFromString(char *str, unsigned int len, 
            unsigned int *retlen, char flags)
{
  unsigned char Y, X;
  char *retStr = NULL;

  /* len < 2 so we are sure that we have at least YX or '*\ '
     for parsing */

  if ( (!str) || (len < 2) )
    return(NULL);

  Y = (unsigned char)*str;
  X = (unsigned char)*(str + 1);

  switch (Y) {
    case '*':
      /* deletion event */
      if (looksOK(str, len) != TRUE) {
        if (flags & WARNING_FLAG) {
          retStr = makeWarningStr(str, len, retlen);
          return(retStr);
        } else {
          return(NULL);
        }
      }
      /* looks OK - create and return REMOVE */
      retStr = makeRemoveStr(str, len, retlen);
      return(retStr);
      break;
    case '<':
      /* transfer to remote host */
      if (looksOK(str, len) != TRUE) {
        if (flags & WARNING_FLAG) {
          retStr = makeWarningStr(str, len, retlen);
          return(retStr);
        } else {
          return(NULL);
        }
      }
      /* we passed the looksOK test - if flags wants INFO
         then return an INFO str, else return NULL */
      if (flags & INFO_FLAG) {
        retStr = makeInfoStr(str, len, retlen);
        return(retStr);
      } else {
        return(NULL);
      }
      break;
    case '>':
      /* transfer to local host (receiving file) */
      /* this is what we are primarily interested in */
      if (looksOK(str, len) != TRUE) {
        if (flags & WARNING_FLAG) {
          retStr = makeWarningStr(str, len, retlen);
          return(retStr);
        } else {
          return(NULL);
        }
      }  
      retStr = makeAddStr(str, len, retlen);
      return(retStr);
      break;
    case 'c':
      /* change/creation (directory or symlink) */
      /* transfer to remote host */
      if (looksOK(str, len) != TRUE) {
        if (flags & WARNING_FLAG) {
          retStr = makeWarningStr(str, len, retlen);
          return(retStr);                                     
        } else {                                              
          return(NULL);                                       
        }                                                     
      }                                                       
      /* we passed the looksOK test - if this is a 
         change specifying a symlink then create a
         link message */
      if (X == 'L') {
        retStr = makeLinkStr(str, len, retlen);
        return(retStr);
      }
      /* it looksOK, it's not a Link, so if verbose
         wants INFO strings make one and return it,
         otherwise return(NULL); */
      if (flags & INFO_FLAG) {                                        
        retStr = makeInfoStr(str, len, retlen);               
        return(retStr);                                       
      } else {                                                
        return(NULL);                                         
      }                                                       
      break;
    case 'h':
      /* hard link to another element */
      if (looksOK(str, len) != TRUE) {
        if (flags & WARNING_FLAG) {
          retStr = makeWarningStr(str, len, retlen);          
          return(retStr);                                     
        } else {                                              
          return(NULL);                                       
        }                                                     
      }                                                       
      /* passed the looksOK test */
      retStr = makeLinkStr(str, len, retlen);
      return(retStr);
      break;
    case '.':
      /* not being updated - possible attribute change */
      if (looksOK(str, len) != TRUE) {
        if (flags & WARNING_FLAG) {
          retStr = makeWarningStr(str, len, retlen);          
          return(retStr);                                     
        } else {                                              
          return(NULL);                                       
        }                                                     
      }                                                       
      if (flags & INFO_FLAG) {
        retStr = makeInfoStr(str, len, retlen);
        return(retStr);
      } else {
        return(NULL);
      }
      break;
    default:
      /* unknown - send as WARNING */
      if (flags & ERROR_FLAG) {
        retStr = makeErrorStr(str, len, retlen);
        return(retStr);
      } else {
        return(NULL);
      }
      break;
  } 

  return(NULL);
}

/*********************************************************
 * makeGenericStr(char *, unsigned int, unsigned int *,  *
 *                char)                                  *
 *                                                       *
 * this function is used for (F) fatal error, (X) error, *
 * (W) warning, and (I) information strings.             *
 *                                                       *
 * The function returns "C\ [string]\r\n" where C is the *
 * above mentioned value. The entire string is returned  *
 * as more is better than less for these codes.          *
 ********************************************************/
char *
makeGenericStr(char *str, unsigned int len, unsigned int *retlen, char c)
{
  /* WARNING - have not included parsing of strings to include 
     escaping of CR or LF to '\013' and '\010' */

  char *retStr;
  unsigned int holdLen;
  int i;
  
  /* we are going to send back X\ [text]\r\n - so we are tacking on         
     4 chars and there's the risk that strncat will tack on \0 as a         
     fifth... */                                              
  if (len >= (PATH_MAX - 5))                                  
    holdLen = PATH_MAX;                                       
  else                                                        
    holdLen = len + 5;                                        
                                                              
  retStr = (char *)malloc(holdLen);                           
  if (!retStr)                                                
    return(NULL);                                             
                                                              
  memset(retStr, '\0', holdLen);                              
                                                              
  snprintf(retStr, 3, "%c ", c); /* stupid snprintf wanting to tack on '\0' */ 
                                                              
  /* memcpy((char *)(retStr + 2), str, holdLen); */           
  strncat(retStr, str, holdLen);                              
                                                              
  i = strlen(retStr);                                         
  if ( ( (char)*(retStr + (i - 1)) == 0x0a)  ||               
       ( (char)*(retStr + (i -1)) == 0x0d ) ) {               
    *(char *)(retStr + (i - 1)) = 0x0;                        
  }                                                           
  if ( ( (char)*(retStr + (i - 2)) == 0x0a)  ||               
       ( (char)*(retStr + (i - 2)) == 0x0d) ) {               
    *(char *)(retStr + (i - 2)) = 0x0;                        
  }                                                           
                                                              
  strncat(retStr, "\r\n", 2);                                 
  *retlen = strlen(retStr);                                   
                                                              
  return(retStr);                                             
                                                              
}                                                             
                                                              
char *
makeWarningStr(char *str, unsigned int len, unsigned int *retlen)
{     
  char *retStr;                                               
                                                              
  retStr = makeGenericStr(str, len, retlen, 'W');             
  if (retStr)                                                 
    return(retStr);                                           
  else                                                        
    return(NULL);                                             

}                                                             


char *
makeInfoStr(char *str, unsigned int len, unsigned int *retlen)
{
  char *retStr;

  retStr = makeGenericStr(str, len, retlen, 'I');
  if (retStr)
    return(retStr);
  else
    return(NULL);

}

char *
makeFatalStr(char *str, unsigned int len, unsigned int *retlen)
{
  char *retStr;                                               
                                                              
  retStr = makeGenericStr(str, len, retlen, 'F');             
  if (retStr)                                                 
    return(retStr);                                           
  else                                                        
    return(NULL);                                             
                                                              
}                                                             

char *
makeErrorStr(char *str, unsigned int len, unsigned int *retlen)
{
  char *retStr;

  retStr = makeGenericStr(str, len, retlen, 'X');
  if (retStr)
    return(retStr);                                           
  else
    return(NULL);

}

char *
makeUpdateStr(char *str, unsigned int len, unsigned int *retlen)
{

  /* the update string will contain "\010" and "\013" as replacements
     for any in-line NL and CR values. Additionally, we need to 
     preface the message with "U " and suffix it with "\r\n". We
     do NOT include the 9 character %i format string.

     Thus, the output string is: "U path_and_filename\r\n"

     We compute the storage size for the output string as:
       number of NL and CR values found within the path_and_filename
       component of the log message multiplied by 3 + 2 for the
       preface and 3 for the suffix (tacking on a \0).

     STRIKE THE ABOVE - we're using fgets() as the initial input from
     the log file - and so HOW WOULD WE COME ACROSS AN EMBEDDED \n?!?!

     The solution:

     This function assumes that at the very least that the checks for       
     has_I_Format and has_Text_Value have passed succesfully. Further       
     that since this is an UPDATE string that the log line has the
     proper extension {der,cer,pem,crl,roa}. Though           
     we still try to make sure that the input string is at least
     11 characters in length at the beginning of the function.
                                                              
     As the output from this is not expected to be handled by the
     shell (it is envisioned that {f}open(), etc. are used) we
     don't need to worry about escaping shell nasties such as 
     *;'` etc. etc.                                           
                                                              
  */                                                          
                                                              
  unsigned int tempLen, malloc_length;                        
  char *retStr, *ptr;                                         
                                                              
  /* sanity check */                                          
  if (len < 11)                                               
    return(NULL);                                             
                                                              
  /* pesky trailing NL that we will be clobbering anyway */   
  if ( (char)*(str + (len - 1)) == '\n')                      
    tempLen = len - 1;                                        
  else                                                        
    tempLen = len;                                            
                                                              
  /* our return string will be the string passed in minus the 
     9 chars in the %i description at the end plus 2 for "U " 
     plus 3 for "\r\n\0" at the end */                        
  malloc_length = tempLen - 10 + 2 + 3;                       
  retStr = (char *)malloc(malloc_length);                     
  memset(retStr, '\0', malloc_length);                        
                                                              
  snprintf(retStr, 3, "U "); /* 3 due to snprintf including '\0' in it's    
                                length... which is dopey */   
                                                              
  strncat(retStr, (char *)(str + 10), (malloc_length - 3));   
                                                              
  ptr = strrchr(retStr, '\n');                                
  if (ptr) {                                                  
    *(char *)ptr = '\0';                                      
  } else {                                                    
    *(char *)(retStr + malloc_length - 1) = '\0';             
  }                                                           
                                                              
  strncat(retStr, "\r\n", 2); /* 3 or 2 to include the '\0'... will check */
                                                              
  *retlen = strlen(retStr);                                   
                                                              
  return(retStr);                                             
}

char *
makeAddStr(char *str, unsigned int len, unsigned int *retlen)
{

  unsigned int tempLen, malloc_length;
  char *retStr, *ptr;

  /* sanity check */
  if (len < 11)
    return(NULL);
                                                              
  /* pesky trailing NL that we will be clobbering anyway */   
  if ( (char)*(str + (len - 1)) == '\n')                      
    tempLen = len - 1;                                        
  else                                                        
    tempLen = len;                                            
                                                              
  /* our return string will be the string passed in minus the 
     9 chars in the %i description at the end plus 2 for "U " 
     plus 3 for "\r\n\0" at the end */                        
  malloc_length = tempLen - 10 + 2 + 3;                       
  retStr = (char *)malloc(malloc_length);                     
  memset(retStr, '\0', malloc_length);                        
                                                              
  snprintf(retStr, 3, "A "); /* 3 due to snprintf including '\0' in its    
                                length... which is dopey */   
                                                              
  strncat(retStr, (char *)(str + 10), (malloc_length - 3));   
                                                              
  ptr = strrchr(retStr, '\n');                                
  if (ptr) {                                                  
    *(char *)ptr = '\0';                                      
  } else {                                                    
    *(char *)(retStr + malloc_length - 1) = '\0';             
  }                                                           
                                                              
  strncat(retStr, "\r\n", 2); /* 3 or 2 to include the '\0'... will check */
                                                              
  *retlen = strlen(retStr);                                   
                                                              
  return(retStr);                                             

}

char *
makeLinkStr(char *str, unsigned int len, unsigned int *retlen)
{
  UNREFERENCED_PARAMETER(str);
  UNREFERENCED_PARAMETER(len);
  UNREFERENCED_PARAMETER(retlen);
  /* this requires more than just makeGenericStr() */
  /* STUB */
  return(NULL);
}

char *
makeRemoveStr(char *str, unsigned int len, unsigned int *retlen)
{

  char *retStr;
  int holdLen;

  holdLen = len + 2;

  retStr = (char *)malloc(holdLen);
  if (!retStr) {
    perror("makeRemoveStr:malloc");
    exit(1);
  }

  memset(retStr, '\0', holdLen);

  strncpy(retStr, str, len);

  *(char *)retStr = 'R';

  *(char *)(retStr + len - 1) = '\0';

  strncat(retStr, "\r\n", 2);
  *retlen = strlen(retStr);

  return(retStr);
}

int
looksOK(char *str, unsigned int len)
{
  int c, i;

  c = i = 0;

  /* start with simple sanity checks - minumum length, 
     ascii characters, etc. etc. Then move on to more message
     specific checks. */

  /* we expect even in the smallest log message that there
     will be two characters. This would end up being a message
     from a delete '*\ [sometext]'. */
  if (len < 2) 
    return(FALSE);

  /* PATH_MAX is the longest absolute path with filename allowed on
     most systems. For Linux it is 4096. We also have at MOST 9
     flags in the rsync %i format which will be followed by a SPACE */

  if (len > (PATH_MAX + 10))
    return(FALSE);

  /* test for a newline */
  if (!has_newline(str, len))
    return(FALSE);

  /* we expect the entire string to be either printable chars 
     or cr|nl */
  for (i = 0; i < (int)len; i++) {
    c = (char)*(str + i);
    if ( !(isprint(c)) && ((c != 0x0d) && (c != 0x0a)) )
      return(FALSE);
  }

  c = (unsigned char)*str;
  
  switch (c) {
    case '*':
      if ( ((char)*(str + 1)) != 0x20 )
        return(FALSE);
      if (len < 3)
        return(FALSE);
      if (!has_Correct_Extension(str, len))
        return(FALSE);
      break;
    case '<':
      if (!has_I_Format(str, len))
        return(FALSE);
      if (!has_Text_Value(str, len))
        return(FALSE);
      break;
    case '>':  /* need to put in checks for {sym,hard}link stuff */
      if (!has_I_Format(str, len))
        return(FALSE);
      if (!has_Text_Value(str, len))
        return(FALSE);
      if (!has_Correct_Extension(str, len))
        return(FALSE);
      break;
    case 'c':
      if (!has_I_Format(str, len))
        return(FALSE);
      if (!has_Text_Value(str, len))
        return(FALSE);                                        
      break;
    case 'h':  /* need to see what the data of this actually ends up being */
      if (!has_I_Format(str, len))
        return(FALSE);
      if (!has_Text_Value(str, len))
        return(FALSE);
      break;
    case '.':
      if (!has_I_Format(str, len))
        return(FALSE);
      if (!has_Text_Value(str, len))
        return(FALSE);
      break;
    default:
      return(FALSE);
      break;
  }

  return(TRUE);
}

/************************************************
 * int has_newline(char *, unsigned int)        *
 *   a very trivial function that returns TRUE  *
 *   if there is a \n in the string and FALSE   *
 *   otherwise.                                 *
 *                                              *
 * Since we are ultimately reading in the str   *
 * from fgets() we are really only worried about*
 * situations where the buffer length was       *
 * exceeded.                                    *
 ************************************************/
int
has_newline(char *str, unsigned int len)
{
  char *nl = NULL;

  UNREFERENCED_PARAMETER(len);
  nl = strrchr(str, '\n');
  if (nl) {
    return(TRUE);
  } else {
    return(FALSE);
  }
}

int
has_I_Format(char *str, unsigned int len)
{
  /* this will check that the first 9 chars appear to be from the %i
     format, that there is a space afterwards, and some text as an
     argument */

  int i, c, Y, X;
  
  if (len < 11) /* YXcstpogz\ [file... */
    return(FALSE);

  Y = (char)*(str);
  X = (char)*(str + 1);

  switch(Y) {
    case '<':
    case '>':
    case 'c':
    case 'h':
    case '.':
      break;
    default:
      return(FALSE);
      break;
  }

  switch(X) {
    case 'f':
    case 'd':
    case 'L':
    case 'D':
    case 'S':
      break;
    default:
      return(FALSE);
      break;
  }

  for (i=0 ; i <= 8 ; i++) {
    c = (char)*(str + i);
    if ((!isprint(c)) || c == 0x20)
      return(FALSE);
  }

  c = (char)*(str + 9);
  if (c != 0x20)
    return(FALSE);

   
  return(TRUE);
}

int
has_Text_Value(char *str, unsigned int len)
{
  /* checks to make sure there is some data after the %i format,
     we would expect this to be a filename most of the time */
  int c;

  if (len < 11)
    return(FALSE);

  /* the 10th char should be a space */
  c = (char)*(str + 9);
  if (c != 0x20)
    return(FALSE);
  
  /* the 11th char should be at the very least printable */
  c = (char)*(str + 10);
  if (!isprint(c))
    return(FALSE);

  return(TRUE);
}

int
has_Correct_Extension(char *str, unsigned int len)
{
  char *ptr;
  char hold[32];
  unsigned int endlen;

  UNREFERENCED_PARAMETER(len);
  memset(hold, '\0', sizeof(hold));

  for (ptr = str; *ptr >= ' '; ptr++);
  if (!strncmp(&ptr[-8], "MANIFEST", 8)) return (TRUE);

  ptr = strrchr(str, '.');

  if (!ptr)
    return(FALSE);

  ptr++;
  if ( (*ptr == '\0') || (*ptr == '\n') || (*ptr == 0x0d) )
    return(FALSE);

  strncpy(hold, ptr, sizeof(hold) - 1);

  endlen = strlen(hold);

  /* 4 with \n */
  if ((endlen == 4) || (endlen == 3)) {

    if (endlen == 4) {
      if (hold[endlen - 1] != '\n')
        return(FALSE);
    }

    if ( strncasecmp(hold, "cer", 3) == 0)
      return(TRUE);

    if ( strncasecmp(hold, "pem", 3) == 0)
      return(TRUE);

    if ( strncasecmp(hold, "der", 3) == 0)                    
      return(TRUE);                                           
                                                              
    if ( strncasecmp(hold, "crl", 3) == 0)                    
      return(TRUE);                                           
                                                              
    if ( strncasecmp(hold, "roa", 3) == 0)                    
      return(TRUE);                                           
                                                              
    if ( strncasecmp(hold, "man", 3) == 0)                    
      return(TRUE);             

    if ( strncasecmp(hold, "mft", 3) == 0)
      return (TRUE);

    if ( strncasecmp(hold, "mnf", 3) == 0)
      return (TRUE);
  }                                                           
                                                              
  return(FALSE);                                              
}                                                             

char *
makeStartStr(unsigned int *retlen)
{
  time_t seconds;
  char *time_str, *out_str;

  seconds = time(NULL);

  time_str = ctime(&seconds);

  out_str = (char *)malloc(strlen(time_str) + 4);
  if (!out_str) 
    return(NULL);
   
  snprintf(out_str, 3, "B "); /* auto tack of \0 */

  strncat(out_str, time_str, strlen(time_str));

  *(char *)(out_str + ((strlen(out_str) - 1))) = '\0';

  strncat(out_str, "\r\n", 2);
  *retlen = (strlen(out_str));
  return(out_str);
} 

char *
makeEndStr(unsigned int *retlen)
{
  time_t seconds;
  char *time_str, *out_str;

  seconds = time(NULL);

  time_str = ctime(&seconds);

  out_str = (char *)malloc(strlen(time_str) + 4);
  if (!out_str)  
    return(NULL);
    
  snprintf(out_str, 3, "E "); /* auto tack of \0 */
        
  strncat(out_str, time_str, strlen(time_str));

  *(char *)(out_str + ((strlen(out_str) - 1))) = '\0';
      
  strncat(out_str, "\r\n", 2);
  *retlen = (strlen(out_str));
  return(out_str);
}   

