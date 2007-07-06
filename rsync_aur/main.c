#include "main.h"

/*
  $Id$
*/

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

int
main(int argc, char *argv[])
{

  /* tflag = tcp, uflag = udp, nflag = do nothing, just print 
     what you would have done, {w,e,i}flag = {warning,error,
     information} flags for what will be sent, ch is for getopt */

  int tflag, uflag, nflag, fflag, sflag, ch, i, isTrust;
  int portno;
  unsigned int retlen;
  FILE *fp;
  char *sendStr;
  char *topDir = NULL;
  struct write_port wport;
  char holding[PATH_MAX+1];
  char flags;  /* our warning flags bit fields */
  char c;

  tflag = uflag = nflag = fflag = sflag = ch = 0;
  portno = retlen = 0;
  flags = 0;

  memset((char *)&wport, '\0', sizeof(struct write_port));

  while ((ch = getopt(argc, argv, "t:u:f:nweid:sh")) != -1) {
    switch (ch) {
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
        break;
      case 'd':
	topDir = strdup (optarg);
	break;
      case 's': /* synchronize */
	sflag = 1;
	break;
      case 'h': /* help */
      default:
        usage(argv[0]);
        break;
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
  if (topDir != NULL) free (topDir);

  /****************************************************/
  /* do the main parsing and sending of the file loop */
  /****************************************************/
  for (i = 0; i < 2; i++) {
    while (fgets(holding, PATH_MAX, fp) != NULL) {
      isTrust = strstr (holding, "TRUST") != NULL;
      if ((isTrust && (! i)) || ((! isTrust) && i)) {
	sendStr = getMessageFromString(holding, (unsigned int)strlen(holding), 
				       &retlen, flags);
	if (sendStr) {
	  outputMsg(&wport, sendStr, retlen);
	  retlen = 0;
	  free(sendStr);
	}
      }
      memset(holding, '\0', sizeof(holding));
    }
    fseek (fp, 0, SEEK_SET);
  }

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
  }
  return(0);
}

