#include "main.h"

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

/*
  $Id$
*/

extern void usage(const char *);

struct name_list
  {
  char *namep;
  int state;
  struct name_list *nextp;
  };

static void free_name_list(struct name_list *rootlistp)
  {
  struct name_list *currp, *nextp;
  for (currp = rootlistp; currp; currp = nextp)
    {
    free(currp->namep);
    nextp = currp->nextp;
    if (currp > rootlistp) free(currp);
    }
  }

static char *makeCDStr(unsigned int *retlenp, char *dir)
{
  char *buf;
  char *ret;

  *retlenp = 0;
  buf = (char *)calloc(PATH_MAX+6, sizeof(char));
  if ( buf == NULL )
    return(NULL);
  if (dir == NULL) {
    ret = getcwd(buf+2, PATH_MAX+1);
    if ( ret == NULL )
    {
      free((void *)buf);
      return(NULL);
    }
  } else {
    strncpy (buf+2, dir, PATH_MAX+1);
  }
  buf[0] = 'C';
  buf[1] = ' ';
  (void)strncat(buf, "\r\n", 2);
  *retlenp = strlen(buf);
  return(buf);
}


/* Does string s end with suffix? */
static int endswith(const char *s, const char *suffix)
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
static int startswith(const char *s, const char *prefix)
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
static int exists_non_delimiter(const char *s, const char *delimiters)
{
  const char *pc;
  if (!s || !delimiters)
    return 0;

  for (pc = s; *pc != '\0'; ++pc)
    if (!strchr(delimiters, *pc))
      return 1;

  return 0;
}


/* Return the next field, i.e. pointer to the beginning of the next
   contiguous string of non-delimiter characters.  Note that this
   skips the current contiguous string of non-delimiter characters.
   Returns NULL if there are no more non-delimiter characters in the
   string. */
static char *start_of_next_field(const char *s, const char *delimiters)
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


/* Copy the current field (contiguous string of non-delimiter
   characters) into the destination buffer, up to dest_length-1 bytes.
   Append '\0' to terminate the C string.  If the buffer size is
   insufficient, safely null-terminate the destination buffer and
   return NULL.
*/
static char *this_field(char *dest, int dest_length, const char *src,
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
/*
static int field_length(const char *s, const char *delimiters)
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
*/

/*
  Copy the directory string for a particular path to the destination
  buffer.  A path which ends in '/' will simply be copied, whereas a
  path with no '/' returns the string ".".  At most dest_len
  characters will be copied, including the terminating '\0'.  If
  dest_len was not enough space, a NULL is returned.
 */
static char *dirname(char *dest, int dest_len, const char *path)
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

/*
  Detect the end of the current "directory block" in the rsync log
  file.  Returns the file position indicator via ftell() for the
  beginning of the *next* directory block, or end-of-file.  The file
  position indicator is restored to the current value at the end of
  this function.

  Returns -1 on error.

  Sample file:
  
  *deleting SPARTA/1/C3A60F37CFC8876F19337BAAC87279C1B53DC38F.cer
  *deleting SPARTA/SPARTA-ELS/2/0BFBDDC896073CA14265D5C50C04857A680F23F8.cer
  .d..t.... SPARTA/1/
  >f..t.... SPARTA/1/RhlvrxS2z8WclJS4Um2J01Bhd-E.crl
  >f..t.... SPARTA/1/RhlvrxS2z8WclJS4Um2J01Bhd-E.mnf
  .d..t.... SPARTA/SPARTA-ELS/2/
  >f..t.... SPARTA/SPARTA-ELS/2/0vSi6U4ZC_yKRITgmwzqC3Tq1H8.crl
  >f..t.... SPARTA/SPARTA-ELS/2/0vSi6U4ZC_yKRITgmwzqC3Tq1H8.mnf
  .d..t.... isc/2/
  >f..t.... isc/2/r-Vxn-I7YluASnxRHksRELhf_Qk.crl
  >f..t.... isc/2/r-Vxn-I7YluASnxRHksRELhf_Qk.mnf
  .d..t.... isc/3/
  >f..t.... isc/3/i8T5t-AgIfdC-yr_BzVVcm_7kT0.crl
  >f..t.... isc/3/i8T5t-AgIfdC-yr_BzVVcm_7kT0.mnf

  An example of a "directory block" would be:
  
  .d..t.... SPARTA/1/
  >f..t.... SPARTA/1/RhlvrxS2z8WclJS4Um2J01Bhd-E.crl
  >f..t.... SPARTA/1/RhlvrxS2z8WclJS4Um2J01Bhd-E.mnf

*/
static long next_dirblock(FILE *fp)
{
  long initial_pos;
  long line_start_pos;
  char first_directory[PATH_MAX];
  int first_line;		/* boolean */
  const char *delimiters = " \n\r\t";
  
  if (!fp)
    return -1;
  
  initial_pos = ftell(fp);

  /*  Search line by line for a change in directory. */
  first_line = 1;
  first_directory[0] = '\0';
  line_start_pos = -1;
  do {
    char line[PATH_MAX+40];
    char fullpath[PATH_MAX];
    char directory[PATH_MAX];
    char *fullpath_start;
    
    line_start_pos = ftell(fp);
    if (!fgets(line, PATH_MAX+40, fp))
      break;		   /* Stop searching; it's the end of file. */

    if (!exists_non_delimiter(line, delimiters))
      continue; /* Skip blank lines. */

    fullpath_start = start_of_next_field(line, delimiters);
    if (!fullpath_start) {
      line_start_pos = -1;	/* error code */
      fprintf(stderr, "Malformed rsync log file line: %s", line);
      break;
    }

    if (!this_field(fullpath, PATH_MAX, fullpath_start, delimiters)) {
      line_start_pos = -1;	/* error code */
      fprintf(stderr, "Insufficient buffer to hold path: %s",
	      fullpath_start);
      break;
    }

    if (!dirname(directory, PATH_MAX, fullpath)) {
      line_start_pos = -1;	/* error code */
      fprintf(stderr, "Insufficient buffer to hold directory.  Path = %s\n",
	      fullpath);
      break;
    }

    if (first_line) {
      /* The following is safe despite strncpy weakness.  By this
	 point, 'directory' will be safely NULL-terminated, and
	 'first_directory' and 'directory' are equal sized buffers. */
      strncpy(first_directory, directory, PATH_MAX);
      first_line = 0;
    }

    if (strncmp(first_directory, directory, PATH_MAX) != 0)
      break;		    /* Stop searching; new directory found. */
    
  } while (1);

  fseek(fp, initial_pos, SEEK_SET);
  return line_start_pos;
}


static int is_manifest(const char *path)
{
  if (!path)
    return 0;

  if (endswith(path, ".man") ||
      endswith(path, ".mnf") ||
      endswith(path, ".mft")) {
    return 1;
  } else {
    return 0;
  }
}


int main(int argc, char *argv[])
  {

  /* tflag = tcp, uflag = udp, nflag = do nothing, just print
     what you would have done, {w,e,i}flag = {warning,error,
     information} flags for what will be sent, ch is for getopt */

  int tflag, uflag, nflag, fflag, sflag, ch;
  int portno;
  unsigned int retlen;
  FILE *fp;
  char *sendStr;
  char *topDir = NULL;
  struct write_port wport;
  char flags;  /* our warning flags bit fields */

  tflag = uflag = nflag = fflag = sflag = ch = 0;
  portno = retlen = 0;
  flags = 0;

  memset((char *)&wport, '\0', sizeof(struct write_port));

  if (argc == 2 && *argv[1] != '-') // process a script file
    {
    char *cc, *cx, *buf, *e;
    int fd, bufsize;
    if ( (fd = open(argv[1], O_RDONLY)) < 0 || (bufsize = lseek(fd, 0, SEEK_END)) <= 0 ||
      (buf = (char *)calloc(1, bufsize + 6)) == 0 || lseek(fd, 0, SEEK_SET) != 0 ||
      read(fd, buf, bufsize + 4) != bufsize)
      {
      fprintf(stderr, "failed to open %s\n", argv[1]);
      exit(1);
      }
    for (cc = buf, e = &buf[bufsize]; cc < e; cc++)  // null out white space
      {
      if (*cc <= ' ') *cc = 0;
      }
    for (cc = buf; cc < e; )
      {
      while (*cc == 0 && cc < e) cc++;
      if (*cc++ == '-')
        {
        if (*cc == 'e') flags |= ERROR_FLAG;
        else if (*cc == 'i') flags |= INFO_FLAG;
        else if (*cc == 'n') nflag = 1;
        else if (*cc == 's') sflag = 1;
        else if (*cc == 'w') flags |= WARNING_FLAG;
        else if (*cc == 'd'|| *cc == 'f' || *cc == 't' || *cc == 'u')
          {
          for (cx = &cc[1]; *cx == 0 && cx < e; cx++);
          if (*cc == 'd') topDir = strdup(cx);
          else if (*cc == 'f')
            {
            fflag = 1;
            char *ce;
            for (ce = cx; *ce > ' '; ce++);
            *ce = 0;
            if (!(fp = fopen(cx, "r")))
               {
               fprintf(stderr, "failed to open %s\n", cx);
               exit(1);
               }
            }
          else if (*cc == 't') { tflag = 1; portno = atoi(cx); }
          else if (*cc == 'u') { uflag = 1; portno = atoi(cx); }
          for (cc = cx; *cc > ' '; cc++);
          }
        else myusage(argv[0]);
        cc++;
        }
      while (*cc == 0 && cc < e) cc++;
      }
    free(buf);
    }
  else if (argc > 2 && *argv[1] != '-')
    {
    fprintf(stderr, "Too many script files: %s\n", argv[2]);
    exit(1);
    } 
  else
    {
    while ((ch = getopt(argc, argv, "t:u:f:nweid:sh")) != -1)
      {
      switch (ch)
        {
        case 't':  /* TCP flag */
          tflag = 1;
          portno = atoi(optarg);
          break;
        case 'u':  /* UDP flag */
          uflag = 1;
          portno = atoi(optarg);
          break;
        case 'n': /* do nothing flag - print what messages would have been
                     sent */
          nflag = 1;
          break;
        case 'w': /* create warning message(s) */
          flags = flags | WARNING_FLAG;
          break;
        case 'e': /* create error message(s) */
          flags = flags | ERROR_FLAG;
          break;
        case 'i': /* create information message(s) */
          flags = flags | INFO_FLAG;
          break;
        case 'f': /* log file to read and parse */
          fflag = 1;
          fp = fopen(optarg, "r");
          if (!fp) {
            fprintf(stderr, "failed to open %s\n", optarg);
            exit(1);
          }
          printf("Opened rsync log file: %s\n", optarg);
          fflush(stdout);
          break;
        case 'd':
  	topDir = strdup (optarg);
  	break;
        case 's': /* synchronize */
  	sflag = 1;
  	break;
        case 'h': /* help */
        default:
          myusage(argv[0]);
          break;
        }
      }
    }

  /* test for necessary flags */
  if (!fflag) {
    fprintf(stderr, "please specify rsync logfile with -f. Or -h for help\n");
    exit(1);
  }

  /* test for conflicting flags here... */
  if (tflag && uflag) {
    fprintf(stderr, "choose either tcp or udp, not both. or -h for help\n");
    exit(1);
  }

  if (!tflag && !uflag && !nflag) { /* if nflag then we don't care */
    fprintf(stderr, "must choose tcp or udp, or specify -n. -h for help\n");
    exit(1);
  }

  /* setup sockets... */
  if (!nflag) {
    if (tflag) {
      if (tcpsocket(&wport, portno) != TRUE) {
        fprintf(stderr, "tcpsocket failed...\n");
        exit(-1);
      }
    } else if (uflag) {
      if (udpsocket(&wport, portno) != TRUE) {
        fprintf(stderr, "udpsocket failed...\n");
        exit(-1);
      }
    }
  } else {
    wport.out_desc = STDOUT_FILENO;
    wport.protocol = LOCAL;
  }

  /* set the global pointer to the wport struct here - don't
     know if this will cause a fault or not. Can't remember.
     Doing this to be able to communicate with the server
     through the descriptor after a sigint or other signal
     has been caught. */
  global_wport = &wport;

  if (setup_sig_catchers() != TRUE) {
    fprintf(stderr, "failed to setup signal catchers... bailing.\n");
    exit(FALSE);
  }

  /****************************************************/
  /* Make the Start String                            */
  /* send the Start String                            */
  /* free it                                          */
  /****************************************************/
  sendStr = makeStartStr(&retlen);
  if (!sendStr) {
    fprintf(stderr, "failed to make Start String... bailing...\n");
    exit(1);
  }

  outputMsg(&wport, sendStr, retlen);
  retlen = 0;
  free(sendStr);

  /****************************************************/
  /* Make the Directory String                        */
  /* send the Directory String                        */
  /* free it                                          */
  /****************************************************/
  sendStr = makeCDStr(&retlen, topDir);
  if (!sendStr) {
    fprintf(stderr, "failed to make Directory String... bailing...\n");
    exit(1);
  }

  outputMsg(&wport, sendStr, retlen);
  retlen = 0;
  free(sendStr);

  /****************************************************/
  /* do the main parsing and sending of the file loop */
  /****************************************************/

  /* Process entire log file, one directory block at a time. */
  while (1) {
    const char DELIMS[] = " \r\n\t";
    long this_dirblock_pos;
    long next_dirblock_pos;
    const int NORMAL_PASS = 0;
    const int MANIFEST_PASS = 1;
    const int NUM_PASSES = 2;
    int pass_num;

    /* Find the end of the directory block (actually, where the next
       one begins). */
    this_dirblock_pos = ftell(fp);
    next_dirblock_pos = next_dirblock(fp);
    if (next_dirblock_pos < 0) {
      fprintf(stderr, "Error while trying to find a block of directories.\n");
      break;
    }
    if (this_dirblock_pos == next_dirblock_pos)	/*  end of file */
      break;

    /* Do two passes: first for non-manifests, second for manifests. */
    for (pass_num = 0; pass_num < NUM_PASSES; pass_num++) {
      fseek(fp, this_dirblock_pos, SEEK_SET);
      while (ftell(fp) < next_dirblock_pos) { /* per available line */
	char line[PATH_MAX+40];
	char fullpath[PATH_MAX];
	char *fullpath_start;
      
	/* Get next line. */
	if (!fgets(line, PATH_MAX+40, fp))
	  break;	   /* Stop searching; it's the end of file. */

	if (!exists_non_delimiter(line, DELIMS))
	  continue; /* Skip blank lines. */

	/* Get second field. */
	fullpath_start = start_of_next_field(line, DELIMS);
	if (!fullpath_start) {
	  fprintf(stderr, "Malformed rsync log file line: %s", line);
	  break;
	}
	if (!this_field(fullpath, PATH_MAX, fullpath_start, DELIMS)) {
	  fprintf(stderr, "Insufficient buffer to hold path: %s",
		  fullpath_start);
	  break;
	}

	/* Create/send socket message. */
	retlen = 0;
	if (!(sendStr = getMessageFromString(line, (unsigned int) strlen(line),
					     &retlen, flags))) {
	  (void)printf("Ignoring: %s", line);
	  continue;
	}
	if (pass_num == NORMAL_PASS && !is_manifest(fullpath)) {
	  outputMsg(&wport, sendStr, retlen);
	} else if (pass_num == MANIFEST_PASS && is_manifest(fullpath)) {
	  outputMsg(&wport, sendStr, retlen);
	}
	free(sendStr);
      }	/* per available line */
    } /* two passes */
  } /* Process entire logfile, one directory block at a time. */

  free (topDir);
  char *c;
  if (sflag) {
    outputMsg(&wport, "Y \r\n", 4);
    recv(wport.out_desc, &c, 1, MSG_WAITALL);
  }

  /****************************************************/
  /* Make the End String                              */
  /* send the End String                              */
  /* free it                                          */
  /****************************************************/
  sendStr = makeEndStr(&retlen);
  if (!sendStr) {
    fprintf(stderr, "failed to make End String... bailing...\n");
    exit(1);
  }
  outputMsg(&wport, sendStr, retlen);
  free(sendStr);

  /* close descriptors etc. */
  if (wport.protocol != LOCAL) {
    close(wport.out_desc);
    fprintf(stderr, "closed the descriptor %d\n", wport.out_desc);
  }
  return(0);
}
