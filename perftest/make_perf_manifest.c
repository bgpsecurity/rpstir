/*
  $Id: make_manifest.c 453 2007-07-25 15:30:40Z gardiner $
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
 * Copyright (C) BBN Technologies 2008.  All Rights Reserved.
 *
 * Contributor(s):  Charles W. Gardiner
 *
 * ***** END LICENSE BLOCK ***** */

#include "manifest.h"
#include "roa.h"
#include "certificate.h"
#include "cryptlib.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <asn.h>
#include <casn.h>

extern char *signCMS(struct ROA *roap, char *keyfile, int bad); 
/*
  This file has a program to make manifests.
*/

char *msgs [] = 
    {
    "Finished %s OK\n",
    "Couldn't open %s\n",      //1
    "Error reading %s\n",
    "Error adding %s\n",      // 3
    "Error inserting %s\n",   
    "Error creating signature\n",    // 5
    "Error writing %s\n",
    "Signature failed in %s\n",   // 7
    };
    
static int fatal(int msg, char *paramp);
static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp);

static int add_name(char *curr_file, struct Manifest *manp, int num, int bad)
  {
  int fd, siz, hsiz;
  uchar *b, hash[40];
  if ((fd = open(curr_file, O_RDONLY)) < 0) {
    perror( "open");
    fatal(1, curr_file);
  }
  siz = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, 0);
  b = (uchar *)calloc(1, siz);
  if (read(fd, b, siz + 2) != siz) fatal(2, curr_file);
  hsiz = gen_hash(b, siz, hash);
  if (bad) hash[1]++;
  struct FileAndHash *fahp;
  if (!(fahp = (struct FileAndHash *)inject_casn(&manp->fileList.self, num))) 
    fatal(3, "fileList");
  write_casn(&fahp->file, (uchar *)curr_file, strlen(curr_file));
  write_casn_bits(&fahp->hash, hash, hsiz, 0);
  return  1;
  }

static int gen_hash(uchar *inbufp, int bsize, uchar *outbufp)
  { 
  CRYPT_CONTEXT hashContext;
  uchar hash[40];
  int ansr;

  memset(hash, 0, 40);
  cryptInit();
  cryptCreateContext(&hashContext, CRYPT_UNUSED, CRYPT_ALGO_SHA2);
  cryptEncrypt(hashContext, inbufp, bsize);
  cryptEncrypt(hashContext, inbufp, 0);
  cryptGetAttributeString(hashContext, CRYPT_CTXINFO_HASHVALUE, hash, &ansr);
  cryptDestroyContext(hashContext);
  cryptEnd();
  memcpy(outbufp, hash, ansr);
  return ansr;
  }

static int fatal(int msg, char *paramp)
  {
  fprintf(stderr, msgs[msg], paramp);
  exit(msg);
  }

int main(int argc, char **argv)
  {
  struct ROA roa;
  struct AlgorithmIdentifier *algidp;
  ulong now = time((time_t *)0);

  int	version = 0;
  
  if (argc < 2)
    {
    printf("Usage: manifest name, data offset\n");
    return 0;
    } 
  char*	manifestfile = (char* )NULL;
  char*	certfile = (char* )NULL;
  char*	pcertfile = (char* )NULL;
  char* keyfile = (char* )NULL;

  char *c;

  if ( argc > 2 ) {
    version = strtol( argv[ 2 ], NULL, 0);
  }

  manifestfile = strcpy( calloc( 1, strlen( argv[ 1 ]) + 6), argv[ 1 ]);
  strcat( manifestfile, ".man");
  *manifestfile = 'M';

  certfile = strdup( manifestfile);
  *certfile = 'C';
  strcpy( strrchr( certfile, (int)'.'), "M.cer");

  pcertfile = strdup( certfile);
  *strstr( pcertfile, "M.cer") = '\0';
  if ( strrchr( pcertfile, '.') )
    *(strrchr( pcertfile, '.')) = '\0';
  strcpy( &pcertfile[ strlen( pcertfile) ], ".cer");

  keyfile = strdup( pcertfile);
  strcpy( strrchr( keyfile, (int)'.'), ".p15");

  ROA(&roa, 0);
  write_objid(&roa.contentType, id_signedData);
  write_casn_num(&roa.content.signedData.version.self, (long)3);
  inject_casn(&roa.content.signedData.digestAlgorithms.self, 0);
  algidp = (struct AlgorithmIdentifier *)member_casn(&roa.content.signedData.
    digestAlgorithms.self, 0);
  write_objid(&algidp->algorithm, id_sha256);
  write_casn(&algidp->parameters.sha256, (uchar *)"", 0);
  write_objid(&roa.content.signedData.encapContentInfo.eContentType, id_roa_pki_manifest);
  struct Manifest *manp = &roa.content.signedData.encapContentInfo.eContent.manifest;
  // Insert the (optional) ROA version number
  write_casn_num( &(manp->version.self), version);
  write_casn_num(&manp->manifestNumber, (long)index);
  int timediff = 0;
  if (argc == 3)
    {
    sscanf(argv[2], "%d", &timediff);
    char u = argv[2][strlen(argv[2]) - 1];
    if (u == 'h') timediff *= 60;
    else if (u == 'D') timediff *= (3600 * 24);
    else if (u == 'W') timediff *= (3600 * 24 * 7);
    else if (u == 'M') timediff *= (3600 * 24 * 30);
    else if (u == 'M') timediff *= (3600 * 24 * 365);
    else fatal(2, argv[2]);
    now += timediff;
    } 
  write_casn_time(&manp->thisUpdate, now);
  now += (30*24*3600);
  write_casn_time(&manp->nextUpdate, now);
  write_objid(&manp->fileHashAlg, id_sha256);
  
    // now get the files 
  char curr_file[128];
  memset(curr_file, 0, 128);

  int num = 0;

  while ( fgets( curr_file, sizeof( curr_file), stdin) ) {
    if ( strchr( curr_file, '\n') )
      *strchr( curr_file, '\n') = '\0';

    add_name( curr_file, manp, num, 0);

    num += 1;
  }

  if (!inject_casn(&roa.content.signedData.certificates.self, 0)) 
    fatal(4, "signedData");
  struct Certificate *certp = (struct Certificate *)member_casn(
    &roa.content.signedData.  certificates.self, 0);
  if (get_casn_file(&certp->self, certfile, 0) < 0) fatal(2, certfile);
  if ((c = signCMS(&roa, keyfile, 0))) fatal(7, c);
  if (put_casn_file(&roa.self, manifestfile, 0) < 0) fatal(6, manifestfile);
  for (c = manifestfile; *c && *c != '.'; c++);
  strcpy(c, ".raw");
  char *rawp;
  int lth = dump_size(&roa.self);
  rawp = (char *)calloc(1, lth + 4);
  dump_casn(&roa.self, rawp);
  int fd = open(manifestfile, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRWXU));
  write(fd, rawp, lth);
  close(fd);
  free(rawp);
  fatal(0, manifestfile);  
  return 0;
  } 
