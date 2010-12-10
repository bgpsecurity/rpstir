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
