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
 * Copyright (C) BBN Technologies 2007.  All Rights Reserved.
 *
 * Contributor(s):  Peiter "Mudge" Zatko
 *
 * ***** END LICENSE BLOCK ***** */

/*
  $Id$
*/

struct name_list
  {
  char *namep;
  struct name_list *nextp;
  };

static int bin2six(char **destpp, uchar *srcp, int lth)
  {
  char table[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  uchar *c, *e;
  char *a, *destp;
  int indx, tmp;

  destp = (char *)calloc(1, 3 + ((lth * 8) / 6));
  for (c = srcp, e = &c[lth], a = destp; c < e; )
    {
    indx = *c >> 2;
    *a++ = table[indx]; // write 1st char
    indx = *c++ & 0x3;  // c at 2nd uchar
    indx <<= 4;
    if (c == e)
      {
      *a++ = table[indx];
      *a++ = '=';
      *a++ = '=';
      break;
      }
    tmp = *c;
    tmp >>= 4;
    indx |= tmp;
    *a++ = table[indx]; // write 2nd char
    indx = *c++ & 0xF;  // c at 3rd char
    indx <<= 2;
    if (c == e)
      {
      *a++ = table[indx];
      *a++ = '=';
      break;
      }
    tmp = *c;
    tmp >>= 6;
    indx  |= tmp;
    *a++ = table[indx]; // write 3rd char
    indx = (*c++ & 0x3F); // c at next 1st char
    *a++ = table[indx];  // write 4th char
    }
  *destpp = destp;
  return (a - destp);
  }

static void free_name_list(struct name_list *root_listp)
  {
  struct name_list *currp, *nextp;
  for (currp = root_listp; currp; currp = nextp)
    {
    free(currp->namep);
    nextp = currp->nextp;
    free(currp);
    }
  }

static int isTrust(char *namep)
  {
  if (strstr(namep, "TRUST") != NULL)  return 1;
  return 0;
  }

static int isManifest(char *namep)
  {
  if (strstr(namep, ".man") || strstr(namep, "MANIFEST") != NULL) return 1;
  return 0;
  }

static int mustManifest(char *namep)
  {
  char *b;
  if (isTrust(namep)) return 0;
  for (b = namep; *b > ' '; b++);
  b -= 4;
  if (*b++ == '.' && (!strncmp(b, "der", 3) || !strncmp(b, "cer", 3) || !strncmp(b, "pem", 3) ||
    !strncmp(b, "crl", 3) || !strncmp(b, "roa", 3))) return 1;
  return 0;
  }

static ulong getTime(struct CertificateValidityDate *cvdp)
  {
  ulong val;
  struct casn *casnp;
  if (size_casn(&cvdp->generalTime) > 0) casnp = &cvdp->generalTime;
  else casnp = &cvdp->utcTime;
  read_casn_time(casnp, &val);
  return val;
  }

static int hash_it(uchar **hashpp, uchar *srcp, int lth)
  {
  uchar *hashp = (uchar *)calloc(1, 24);
  CRYPT_CONTEXT hashContext;
  int ansr;
  cryptInit();
  ansr = cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA);
  ansr = cryptEncrypt(hashContext, srcp, lth);
  ansr = cryptEncrypt(hashContext, srcp, 0);
  ansr = cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE,
    hashp, &lth);
  cryptDestroyContext(hashContext);
  cryptEnd();
  *hashpp = hashp;
  return lth;
  }
  
static struct name_list * check_manifest(struct ROA *roap, char *mfname, char *topDir)
  {
  int sig_err = 0;
  struct Certificate *certp = (struct Certificate *)member_casn(&roap->content.signedData.
      certificates.self, 0);
  ulong clo, chi, mlo, mhi, now = (ulong)time((time_t)0);
  struct Manifest *manp = &roap->content.signedData.encapContentInfo.eContent.manifest;
  struct name_list *rootp, *curr_namep;

  read_casn_time(&manp->thisUpdate, &mlo);
  read_casn_time(&manp->nextUpdate, &mhi);
  clo = getTime(&certp->toBeSigned.validity.notBefore);
  chi = getTime(&certp->toBeSigned.validity.notAfter);
  if (clo > now || chi < now || mlo > now || mhi < now) 
    {
    fprintf(stderr, "the manifest %s has invalid date(s)\n", mfname); 
    return (struct name_list *)0;
    }
  rootp = (struct name_list *)calloc(1, sizeof(struct name_list));
  curr_namep = rootp;
  char **badfilespp = (char **)0;
  if ((sig_err = manifestValidate2(roap, topDir, &badfilespp)) < 0)
    {
    fprintf(stderr, "the manifest %s had error %d\n", mfname, sig_err);
    }
  else   // make list of all certificates, CRLs and ROAs  in manifest
    {
    struct FileAndHash *fahp;
    for (fahp = (struct FileAndHash *)member_casn(&roap->content.signedData.encapContentInfo.
      eContent.manifest.fileList.self, 0); fahp;
      fahp = (struct FileAndHash *)next_of(&fahp->self))
      {
      int lth;
      char *fname;
      if((lth = readvsize_casn(&fahp->file, (uchar **)&fname)) < 0) ; // error
      else
        {
        if (mustManifest(fname))
          {
          if (curr_namep != rootp)
            {
            curr_namep->nextp = (struct name_list *)calloc(1, sizeof(struct name_list));
            curr_namep = curr_namep->nextp;
            }
          curr_namep->namep = fname;
          }
        }
      }
    }
  if (badfilespp)
    {
    char **pp;
    for (pp = badfilespp; *pp; free(*pp), pp++);
    free(badfilespp);
    }
  return rootp;
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

static void send_cert(struct Certificate *certp, char *topDir, struct write_port *wportp)
  {
  uchar *keyp;    // pull out its certificate and send that ahead 
  char *sixp;
  int klth;
  if ((klth = readvsize_casn(&certp->toBeSigned.subjectPublicKeyInfo.subjectPublicKey, 
      &keyp)) < 0); // ??
  uchar *hashp;
  klth = hash_it(&hashp, &keyp[1], klth - 1);
  free(keyp);
  klth = bin2six(&sixp, hashp, klth);
  char *certfname;
  while(sixp[klth-1] == '=') klth--;
  sixp[klth] = 0;
  certfname = (char *)calloc(1, klth + strlen(topDir) + 12);
  strcat(strcat(strcat(strcpy(certfname, topDir), "/"), sixp), ".cer");
  if (put_casn_file(&certp->self, &certfname[2], 0) < 0) /* what ? */ ;
  strcat(strcat(strcat(strcpy(certfname, "A "), sixp), ".cer"), "\r\n");
  outputMsg(wportp, certfname, strlen(certfname));
  free(sixp);
  free(certfname);
  }
 
static int wasManifested(struct name_list *rootp, char *fnamep)
  {
  char *b;
  int lth;
  if (!rootp) return 1;
  for (b = fnamep; *b > ' '; b++);
  lth = b - fnamep;
  if (!strncmp(rootp->namep, fnamep, lth)) return 1;
  if (!rootp->nextp) return 0;
  for (rootp = rootp->nextp; rootp && strncmp(rootp->namep, fnamep, lth); rootp = rootp->nextp);
  if (rootp && rootp->namep) return 1;
  return 0;
  }

int
main(int argc, char *argv[])
{

  /* tflag = tcp, uflag = udp, nflag = do nothing, just print
     what you would have done, {w,e,i}flag = {warning,error,
     information} flags for what will be sent, ch is for getopt */

  int tflag, uflag, nflag, fflag, mflag, sflag, ch, i;
  int portno;
  unsigned int retlen;
  FILE *fp;
  char *sendStr;
  char *topDir = NULL;
  struct write_port wport;
  char holding[PATH_MAX+1];
  char flags;  /* our warning flags bit fields */

  tflag = uflag = nflag = fflag = mflag = sflag = ch = 0;
  portno = retlen = 0;
  flags = 0;

  memset((char *)&wport, '\0', sizeof(struct write_port));

  if (argc == 2) // process a script file
    {
    char *cc, *cx, *buf, *e;
    int fd, bufsize;
    if ( (fd = open(argv[1], O_RDONLY)) < 0 || (bufsize = lseek(fd, 0, SEEK_END)) <= 0 ||
      (buf = (char *)calloc(1, bufsize + 4)) == 0 || lseek(fd, 0, SEEK_SET) != 0 ||
      read(fd, buf, bufsize + 4) != bufsize)
      {
      fprintf(stderr, "error opening %s\n", argv[1]);
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
        else if (*cc == 'm') mflag = 1;
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
          else usage(argv[0]);
          for (cc = cx; *cc > ' '; cc++);
          }
        cc++;
        }
      while (*cc == 0 && cc < e) cc++;
      }
    free(buf);
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
        case 'm':  // mflag
          mflag = 1;
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
#define MANPASS 0
#define TRUSTPASS 1
#define GENPASS 2
#define NUMPASSES 3
  retlen = 0;
  struct name_list *rootp = (struct name_list *)0;
  struct ROA roa;
  ROA(&roa, (ushort)0);
  for (i = MANPASS; i < NUMPASSES; i++)
    {
    while (fgets(holding, PATH_MAX, fp) != NULL)
      {
      if (!(sendStr = getMessageFromString(holding, (unsigned int)strlen(holding),
        &retlen, flags))) continue;
      int have_manifest = isManifest(sendStr);
      char *fname = (char *)0;
      if (have_manifest)
        {
        fname = (char *)calloc(1, strlen(topDir) + strlen(sendStr) + 4);
        strcat(strcat(strcpy(fname, topDir), "/"), &sendStr[2]);
        char *b;
        for (b = fname; *b >= ' '; b++); // trim off CRLF
        *b = 0;
        if (get_casn_file(&roa.self, fname, 0) < 0)
          {
          fprintf(stderr, "invalid manifest %s\n", fname);
          exit(1);
          }
        }
         // if doing manifests and it's a manifest, check contents & note file names
      if (i == MANPASS  && have_manifest != 0)
        {
        if (mflag)  rootp = check_manifest(&roa, fname, topDir);
        if (!mflag || rootp)         // manifest not out of date 
          {
          send_cert((struct Certificate *)member_casn(&roa.content.signedData.
            certificates.self, 0), topDir, &wport);
          outputMsg(&wport, sendStr, retlen);
          }
        }
        // else if doing trusts and it's a trust, send message
      else if (i == TRUSTPASS && isTrust(sendStr))
        {
        outputMsg(&wport, sendStr, retlen);
        }
        // else if doing other stuff and it's not a trust
      else if (i == GENPASS && !isTrust(sendStr))
        {
         
        if (!mflag ||                                // not doing strict OR
            mustManifest(&sendStr[2]) == 0 ||        // not a manifestable type OR
            wasManifested(rootp, &sendStr[2]) == 1)  // it was in a manifest
            outputMsg(&wport, sendStr, retlen);      // send it
        else
          {
          char *bb;
          for (bb = &sendStr[2]; *bb >= ' '; bb++);
          *bb = 0;
          fprintf(stderr, "File %s was not on a manifest\n", &sendStr[2]);
          }
        }
      retlen = 0;
      if (fname) free(fname);
      free(sendStr);
      memset(holding, '\0', sizeof(holding));
      }
    fseek (fp, 0, SEEK_SET);
    }
  free_name_list(rootp);
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
  }
  return(0);
}
